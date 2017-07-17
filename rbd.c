/*
 * Copyright 2016, China Mobile, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <endian.h>
#include <errno.h>
#include <pthread.h>

#include <scsi/scsi.h>

#include "tcmu-runner.h"
#include "libtcmu.h"

#include <rbd/librbd.h>

/*
 * rbd_lock_acquire exclusive lock support was added in librbd 0.1.11 (267)
 */
#if LIBRBD_VERSION_CODE > 266
#define RBD_LOCK_ACQUIRE_SUPPORT 1
#endif

/* rbd_aio_discard added in 0.1.2 */
#if LIBRBD_VERSION_CODE >= LIBRBD_VERSION(0, 1, 2)
#define LIBRBD_SUPPORTS_DISCARD
#endif

enum {
	TCMU_RBD_OPENING,
	TCMU_RBD_OPENED,
	TCMU_RBD_CLOSING,
	TCMU_RBD_CLOSED,
};

struct tcmu_rbd_state {
	rados_t cluster;
	rados_ioctx_t io_ctx;
	rbd_image_t image;

	char *image_name;
	char *pool_name;

	pthread_spinlock_t lock;	/* protect state */
	int state;
};

struct rbd_aio_cb {
	struct tcmu_device *dev;
	struct tcmulib_cmd *tcmulib_cmd;

	int64_t length;
	char *bounce_buffer;
};

static void tcmu_rbd_image_close(struct tcmu_device *dev)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);

	pthread_spin_lock(&state->lock);
	if (state->state != TCMU_RBD_OPENED) {
		tcmu_dev_dbg(dev, "skipping close. state %d\n", state->state);
		pthread_spin_unlock(&state->lock);
		return;
	}
	state->state = TCMU_RBD_CLOSING;
	pthread_spin_unlock(&state->lock);

	rbd_close(state->image);
	rados_ioctx_destroy(state->io_ctx);
	rados_shutdown(state->cluster);

	state->cluster = NULL;
	state->io_ctx = NULL;
	state->image = NULL;

	pthread_spin_lock(&state->lock);
	state->state = TCMU_RBD_CLOSED;
	pthread_spin_unlock(&state->lock);
}

static int tcmu_rbd_image_open(struct tcmu_device *dev)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	int ret;

	pthread_spin_lock(&state->lock);
	if (state->state == TCMU_RBD_OPENED) {
		tcmu_dev_dbg(dev, "skipping open. Already opened\n");
		pthread_spin_unlock(&state->lock);
		return 0;
	}

	if (state->state != TCMU_RBD_CLOSED) {
		tcmu_dev_dbg(dev, "skipping open. state %d\n", state->state);
		pthread_spin_unlock(&state->lock);
		return -EBUSY;
	}
	state->state = TCMU_RBD_OPENING;
	pthread_spin_unlock(&state->lock);

	ret = rados_create(&state->cluster, NULL);
	if (ret < 0) {
		tcmu_dev_dbg(dev, "Could not create cluster. (Err %d)\n", ret);
		goto set_closed;
	}

	/* Fow now, we will only read /etc/ceph/ceph.conf */
	rados_conf_read_file(state->cluster, NULL);
	rados_conf_set(state->cluster, "rbd_cache", "false");

	ret = rados_connect(state->cluster);
	if (ret < 0) {
		tcmu_dev_err(dev, "Could not connect to cluster. (Err %d)\n",
			     ret);
		goto set_cluster_null;
	}

	ret = rados_ioctx_create(state->cluster, state->pool_name,
				 &state->io_ctx);
	if (ret < 0) {
		tcmu_dev_err(dev, "Could not create ioctx for pool %s. (Err %d)\n",
			     state->pool_name, ret);
		goto rados_shutdown;
	}

	ret = rbd_open(state->io_ctx, state->image_name, &state->image, NULL);
	if (ret < 0) {
		tcmu_dev_err(dev, "Could not open image %s. (Err %d)\n",
			     state->image_name, ret);
		goto rados_destroy;
	}

	pthread_spin_lock(&state->lock);
	state->state = TCMU_RBD_OPENED;
	pthread_spin_unlock(&state->lock);
	return 0;

rados_destroy:
	rados_ioctx_destroy(state->io_ctx);
	state->io_ctx = NULL;
rados_shutdown:
	rados_shutdown(state->cluster);
set_cluster_null:
	state->cluster = NULL;
set_closed:
	pthread_spin_lock(&state->lock);
	state->state = TCMU_RBD_CLOSED;
	pthread_spin_unlock(&state->lock);
	return ret;
}

#ifdef RBD_LOCK_ACQUIRE_SUPPORT

/*
 * Returns:
 * 0 = client is not owner.
 * 1 = client is owner.
 * -ESHUTDOWN/-EBLACKLISTED(-108) = client is blacklisted.
 * -EIO = misc error.
 */
static int tcmu_rbd_has_lock(struct tcmu_device *dev)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	int ret, is_owner;

	ret = rbd_is_exclusive_lock_owner(state->image, &is_owner);
	if (ret == -ESHUTDOWN) {
		return ret;
	} else if (ret < 0) {
		/* let initiator figure things out */
		tcmu_dev_err(dev, "Could not check lock ownership. (Err %d).\n", ret);
		return -EIO;
	} else if (is_owner) {
		tcmu_dev_dbg(dev, "Is owner\n");
		return 1;
	}
	tcmu_dev_dbg(dev, "Not owner\n");

	return 0;
}

static int tcmu_rbd_image_reopen(struct tcmu_device *dev)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	int ret;

	tcmu_rbd_image_close(dev);
	ret = tcmu_rbd_image_open(dev);

	if (!ret) {
		tcmu_dev_warn(dev, "image %s/%s was blacklisted. Successfully reopened.\n",
			      state->pool_name, state->image_name);
	} else {
		tcmu_dev_warn(dev, "image %s/%s was blacklisted. Reopen failed with error %d.\n",
			      state->pool_name, state->image_name, ret);
	}

	return ret;
}

/**
 * tcmu_rbd_lock_break - break rbd exclusive lock if needed
 * @dev: device to break the lock for.
 * @orig_owner: if non null, only break the lock if get owners matches
 *
 * If orig_owner is null and tcmu_rbd_lock_break fails to break the lock
 * for a retryable error (-EAGAIN) the owner of the lock will be returned.
 * The caller must free the string returned.
 *
 * Returns:
 * 0 = lock has been broken.
 * -EAGAIN = retryable error
 * -EIO = hard failure.
 */
static int tcmu_rbd_lock_break(struct tcmu_device *dev, char **orig_owner)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	rbd_lock_mode_t lock_mode;
	char *owners[1];
	size_t num_owners = 1;
	int ret;

	ret = rbd_lock_get_owners(state->image, &lock_mode, owners,
				  &num_owners);
	if (ret == -ENOENT || (!ret && !num_owners))
		return 0;

	if (ret < 0) {
		tcmu_dev_err(dev, "Could not get lock owners %d\n", ret);
		return -EAGAIN;
	}

	if (lock_mode != RBD_LOCK_MODE_EXCLUSIVE) {
		tcmu_dev_err(dev, "Invalid lock type (%d) found\n", lock_mode);
		ret = -EIO;
		goto free_owners;
	}

	if (*orig_owner && strcmp(*orig_owner, owners[0])) {
		/* someone took the lock while we were retrying */
		ret = -EIO;
		goto free_owners;
	}

	tcmu_dev_dbg(dev, "Attempting to break lock from %s.\n", owners[0]);

	ret = rbd_lock_break(state->image, lock_mode, owners[0]);
	if (ret < 0) {
		tcmu_dev_err(dev, "Could not break lock from %s. (Err %d)\n",
			     owners[0], ret);
		ret = -EAGAIN;
		if (!*orig_owner) {
			*orig_owner = strdup(owners[0]);
			if (!*orig_owner)
				ret = -EIO;
		}
	}

free_owners:
	rbd_lock_get_owners_cleanup(owners, num_owners);
	return ret;
}

static int tcmu_rbd_lock(struct tcmu_device *dev)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	int ret = 0, attempts = 0;
	char *orig_owner = NULL;

	/*
	 * TODO: Add retry/timeout settings to handle windows/ESX.
	 * Or, set to transitioning and grab the lock in the background.
	 */
	while (attempts++ < 5) {
		ret = tcmu_rbd_has_lock(dev);
		if (ret == 1) {
			ret = 0;
			break;
		} else if (ret == -ESHUTDOWN) {
			ret = tcmu_rbd_image_reopen(dev);
			continue;
		} else if (ret < 0) {
			sleep(1);
			continue;
		}

		ret = tcmu_rbd_lock_break(dev, &orig_owner);
		if (ret == -EIO)
			break;
		else if (ret == -EAGAIN) {
			sleep(1);
			continue;
		}

		ret = rbd_lock_acquire(state->image, RBD_LOCK_MODE_EXCLUSIVE);
		if (!ret) {
			tcmu_dev_warn(dev, "Acquired exclusive lock.\n");
			break;
		}

		tcmu_dev_err(dev, "Unknown error %d while trying to acquire lock.\n",
			     ret);
	}

	if (orig_owner)
		free(orig_owner);

	return ret;
}

static int tcmu_rbd_unlock(struct tcmu_device *dev)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	return rbd_lock_release(state->image);
}

#endif

static void tcmu_rbd_state_free(struct tcmu_rbd_state *state)
{
	pthread_spin_destroy(&state->lock);

	if (state->image_name)
		free(state->image_name);
	if (state->pool_name)
		free(state->pool_name);
	free(state);
}

static int tcmu_rbd_open(struct tcmu_device *dev)
{
	rbd_image_info_t image_info;
	char *pool, *name;
	char *config, *dev_cfg_dup;
	struct tcmu_rbd_state *state;
	uint64_t rbd_size;
	int ret;

	state = calloc(1, sizeof(*state));
	if (!state)
		return -ENOMEM;
	state->state = TCMU_RBD_CLOSED;
	tcmu_set_dev_private(dev, state);

	ret = pthread_spin_init(&state->lock, 0);
	if (ret != 0) {
		free(state);
		return ret;
	}

	dev_cfg_dup = strdup(tcmu_get_dev_cfgstring(dev));
	config = dev_cfg_dup;
	if (!config) {
		ret = -ENOMEM;
		goto free_state;
	}

	tcmu_dev_dbg(dev, "tcmu_rbd_open config %s\n", config);
	config = strchr(config, '/');
	if (!config) {
		tcmu_dev_err(dev, "no configuration found in cfgstring\n");
		ret = -EINVAL;
		goto free_config;
	}
	config += 1; /* get past '/' */

	pool = strtok(config, "/");
	if (!pool) {
		tcmu_dev_err(dev, "Could not get pool name\n");
		ret = -EINVAL;
		goto free_config;
	}
	state->pool_name = strdup(pool);
	if (!state->pool_name) {
		ret = -ENOMEM;
		tcmu_dev_err(dev, "Could not copy pool name\n");
		goto free_config;
	}

	name = strtok(NULL, "/");
	if (!name) {
		tcmu_dev_err(dev, "Could not get image name\n");
		ret = -EINVAL;
		goto free_config;
	}

	state->image_name = strdup(name);
	if (!state->image_name) {
		ret = -ENOMEM;
		tcmu_dev_err(dev, "Could not copy image name\n");
		goto free_config;
	}

	ret = tcmu_rbd_image_open(dev);
	if (ret < 0) {
		goto free_config;
	}

	ret = rbd_get_size(state->image, &rbd_size);
	if (ret < 0) {
		tcmu_dev_err(dev, "error getting rbd_size %s\n", name);
		goto stop_image;
	}

	if (rbd_size !=
	    tcmu_get_dev_num_lbas(dev) * tcmu_get_dev_block_size(dev)) {
		tcmu_dev_err(dev, "device size and backing size disagree: device (num LBAs %lld, block size %ld) backing %lld\n",
			     tcmu_get_dev_num_lbas(dev),
			     tcmu_get_dev_block_size(dev), rbd_size);
		ret = -EIO;
		goto stop_image;
	}

	ret = rbd_stat(state->image, &image_info, sizeof(image_info));
	if (ret < 0) {
		tcmu_dev_err(dev, "Could not stat image.\n");
		goto stop_image;
	}
	tcmu_set_dev_max_xfer_len(dev, image_info.obj_size /
				  tcmu_get_dev_block_size(dev));

	tcmu_dev_dbg(dev, "config %s, size %lld\n", tcmu_get_dev_cfgstring(dev),
		     rbd_size);
	free(dev_cfg_dup);
	return 0;

stop_image:
	tcmu_rbd_image_close(dev);
free_config:
	free(dev_cfg_dup);
free_state:
	tcmu_rbd_state_free(state);
	return ret;
}

static void tcmu_rbd_close(struct tcmu_device *dev)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);

	tcmu_rbd_image_close(dev);
	tcmu_rbd_state_free(state);
}

/*
 * NOTE: RBD async APIs almost always return 0 (success), except
 * when allocation (via new) fails - which is not caught. So,
 * the only errno we've to bother about as of now are memory
 * allocation errors.
 */

static void rbd_finish_aio_read(rbd_completion_t completion,
				struct rbd_aio_cb *aio_cb)
{
	struct tcmu_device *dev = aio_cb->dev;
	struct tcmulib_cmd *tcmulib_cmd = aio_cb->tcmulib_cmd;
	struct iovec *iovec = tcmulib_cmd->iovec;
	size_t iov_cnt = tcmulib_cmd->iov_cnt;
	int64_t ret;
	int tcmu_r;

	ret = rbd_aio_get_return_value(completion);
	rbd_aio_release(completion);

	if (ret == -ESHUTDOWN) {
		tcmu_r = tcmu_set_sense_data(tcmulib_cmd->sense_buf,
					     NOT_READY, ASC_PORT_IN_STANDBY,
					     NULL);
	} else if (ret < 0) {
		tcmu_r = tcmu_set_sense_data(tcmulib_cmd->sense_buf,
					     MEDIUM_ERROR, ASC_READ_ERROR, NULL);
	} else {
		tcmu_r = SAM_STAT_GOOD;
		tcmu_memcpy_into_iovec(iovec, iov_cnt,
				       aio_cb->bounce_buffer, aio_cb->length);
	}

	tcmulib_cmd->done(dev, tcmulib_cmd, tcmu_r);

	free(aio_cb->bounce_buffer);
	free(aio_cb);
}

static int tcmu_rbd_read(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			     struct iovec *iov, size_t iov_cnt, size_t length,
			     off_t offset)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	struct rbd_aio_cb *aio_cb;
	rbd_completion_t completion;
	ssize_t ret;

	aio_cb = calloc(1, sizeof(*aio_cb));
	if (!aio_cb) {
		tcmu_dev_err(dev, "Could not allocate aio_cb.\n");
		goto out;
	}

	aio_cb->dev = dev;
	aio_cb->length = length;
	aio_cb->tcmulib_cmd = cmd;

	aio_cb->bounce_buffer = malloc(length);
	if (!aio_cb->bounce_buffer) {
		tcmu_dev_err(dev, "Could not allocate bounce buffer.\n");
		goto out_free_aio_cb;
	}

	ret = rbd_aio_create_completion
		(aio_cb, (rbd_callback_t) rbd_finish_aio_read, &completion);
	if (ret < 0) {
		goto out_free_bounce_buffer;
	}

	ret = rbd_aio_read(state->image, offset, length, aio_cb->bounce_buffer,
			   completion);
	if (ret < 0) {
		goto out_remove_tracked_aio;
	}

	return 0;

out_remove_tracked_aio:
	rbd_aio_release(completion);
out_free_bounce_buffer:
	free(aio_cb->bounce_buffer);
out_free_aio_cb:
	free(aio_cb);
out:
	return SAM_STAT_TASK_SET_FULL;
}

static void rbd_finish_aio_generic(rbd_completion_t completion,
				   struct rbd_aio_cb *aio_cb)
{
	struct tcmu_device *dev = aio_cb->dev;
	struct tcmulib_cmd *tcmulib_cmd = aio_cb->tcmulib_cmd;
	int64_t ret;
	int tcmu_r;

	ret = rbd_aio_get_return_value(completion);
	rbd_aio_release(completion);

	if (ret == -ESHUTDOWN) {
		tcmu_r = tcmu_set_sense_data(tcmulib_cmd->sense_buf,
					     NOT_READY, ASC_PORT_IN_STANDBY,
					     NULL);
	} else if (ret < 0) {
		tcmu_r = tcmu_set_sense_data(tcmulib_cmd->sense_buf,
					     MEDIUM_ERROR, ASC_WRITE_ERROR,
					     NULL);
	} else {
		tcmu_r = SAM_STAT_GOOD;
	}

	if (tcmulib_cmd->done)
		tcmulib_cmd->done(dev, tcmulib_cmd, tcmu_r);

	if (aio_cb->bounce_buffer) {
		free(aio_cb->bounce_buffer);
	}
	free(aio_cb);
}

static int tcmu_rbd_write(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			  struct iovec *iov, size_t iov_cnt, size_t length,
			  off_t offset)
{

	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	struct rbd_aio_cb *aio_cb;
	rbd_completion_t completion;
	ssize_t ret;

	aio_cb = calloc(1, sizeof(*aio_cb));
	if (!aio_cb) {
		tcmu_dev_err(dev, "Could not allocate aio_cb.\n");
		goto out;
	}

	aio_cb->dev = dev;
	aio_cb->length = length;
	aio_cb->tcmulib_cmd = cmd;

	aio_cb->bounce_buffer = malloc(length);
	if (!aio_cb->bounce_buffer) {
		tcmu_dev_err(dev, "Failed to allocate bounce buffer.\n");
		goto out_free_aio_cb;
	}

	tcmu_memcpy_from_iovec(aio_cb->bounce_buffer, length, iov, iov_cnt);

	ret = rbd_aio_create_completion
		(aio_cb, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		goto out_free_bounce_buffer;
	}

	ret = rbd_aio_write(state->image, offset,
			    length, aio_cb->bounce_buffer, completion);
	if (ret < 0) {
		goto out_remove_tracked_aio;
	}

	return 0;

out_remove_tracked_aio:
	rbd_aio_release(completion);
out_free_bounce_buffer:
	free(aio_cb->bounce_buffer);
out_free_aio_cb:
	free(aio_cb);
out:
	return SAM_STAT_TASK_SET_FULL;
}

#ifdef LIBRBD_SUPPORTS_DISCARD
static int tcmu_rbd_aio_discard(struct tcmu_device *dev,
				struct tcmulib_cmd *cmd,
				uint64_t off, uint64_t len)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	struct rbd_aio_cb *aio_cb;
	rbd_completion_t completion;
	ssize_t ret;

	aio_cb = calloc(1, sizeof(*aio_cb));
	if (!aio_cb) {
		tcmu_dev_err(dev, "Could not allocate aio_cb.\n");
		goto out;
	}

	aio_cb->dev = dev;
	aio_cb->tcmulib_cmd = cmd;
	aio_cb->bounce_buffer = NULL;

	ret = rbd_aio_create_completion
		(aio_cb, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0)
		goto out_free_aio_cb;

	ret = rbd_aio_discard(state->image, off, len, completion);
	if (ret < 0)
		goto out_remove_tracked_aio;

	return 0;

out_remove_tracked_aio:
	rbd_aio_release(completion);
out_free_aio_cb:
	free(aio_cb);
out:
	return SAM_STAT_TASK_SET_FULL;
}

static int tcmu_rbd_discard(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;
	size_t copied, data_length = tcmu_get_xfer_length(cdb);
	uint32_t block_size = tcmu_get_dev_block_size(dev);
	uint64_t end_lba = tcmu_get_dev_num_lbas(dev) - 1;
	uint8_t *sense = cmd->sense_buf;
	uint8_t *par, *p;
	uint16_t dl, bddl;
	int ret;

	/*
	 * ANCHOR bit check
	 *
	 * The ANCHOR in the Logical Block Provisioning VPD page is not
	 * supported, so the ANCHOR bit shouldn't be set here.
	 */
	if (cdb[1] & 0x01) {
		tcmu_dev_err(dev, "Illegal request: anchor is not supported for now!\n");
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB,
					   NULL);
	}

	/*
	 * PARAMETER LIST LENGTH field.
	 *
	 * The PARAMETER LIST LENGTH field specifies the length in bytes of
	 * the UNMAP parameter data that shall be sent from the application
	 * client to the device server.
	 *
	 * A PARAMETER LIST LENGTH set to zero specifies that no data shall
	 * be sent.
	 */
	if (!data_length) {
		tcmu_dev_dbg(dev, "Data-Out Buffer length is zero, just return okay\n");
		return SAM_STAT_GOOD;
	}

	/*
	 * From sbc4r13, section 5.32.1 UNMAP command overview.
	 *
	 * The PARAMETER LIST LENGTH should be greater than eight,
	 */
	if (data_length < 8) {
		tcmu_dev_err(dev, "Illegal parameter list length %llu and it should be >= 8\n",
			     data_length);
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_PARAMETER_LIST_LENGTH_ERROR,
					   NULL);
	}

	par = calloc(1, data_length);
	if (!par) {
		return tcmu_set_sense_data(sense, HARDWARE_ERROR,
					   ASC_INTERNAL_TARGET_FAILURE,
					   NULL);

	}
	copied = tcmu_memcpy_from_iovec(par, data_length, cmd->iovec,
					cmd->iov_cnt);
	if (copied != data_length) {
		tcmu_dev_err(dev, "Failed to copy the Data-Out Buffer !\n");
		ret = tcmu_set_sense_data(cmd->sense_buf, ILLEGAL_REQUEST,
					  ASC_PARAMETER_LIST_LENGTH_ERROR,
					  NULL);
		goto out_free_par;
	}

	/*
	 * If any UNMAP block descriptors in the UNMAP block descriptor
	 * list are truncated due to the parameter list length in the CDB,
	 * then that UNMAP block descriptor shall be ignored.
	 *
	 * So it will allow dl + 2 != data_length and bddl + 8 != data_length.
	 */
	dl = be16toh(*((uint16_t *)&par[0]));
	bddl = be16toh(*((uint16_t *)&par[2]));

	tcmu_dev_dbg(dev, "Data-Out Buffer Length: %zu, dl: %hu, bddl: %hu\n",
		     data_length, dl, bddl);

	/*
	 * If the unmap block descriptor data length is not a multiple
	 * of 16, then the last unmap block descriptor is incomplete
	 * and shall be ignored.
	 */
	bddl &= ~0xF;

	/*
	 * If the UNMAP BLOCK DESCRIPTOR DATA LENGTH is set to zero, then
	 * no unmap block descriptors are included in the UNMAP parameter
	 * list.
	 */
	if (!bddl) {
		ret = SAM_STAT_GOOD;
		goto out_free_par;
	}

	if (bddl / 16 > VPD_MAX_UNMAP_BLOCK_DESC_COUNT) {
		tcmu_dev_err(dev, "Illegal parameter list count %hu exceeds :%u\n",
			     bddl / 16, VPD_MAX_UNMAP_BLOCK_DESC_COUNT);
		ret = tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					  ASC_INVALID_FIELD_IN_PARAMETER_LIST,
					  NULL);
		goto out_free_par;
	}

	/* The first descriptor list offset is 8 in Data-Out buffer */
	p = par + 8;

	while (bddl) {
		uint64_t lba;
		uint32_t nlbas;
		uint16_t offset = 0, i = 0;

		lba = be64toh(*((uint64_t *)&p[offset]));
		nlbas = be32toh(*((uint32_t *)&p[offset + 8]));

		if (nlbas > VPD_MAX_UNMAP_LBA_COUNT) {
			tcmu_dev_err(dev, "Illegal parameter list LBA count %lu exceeds:%u\n",
				     nlbas, VPD_MAX_UNMAP_LBA_COUNT);
			ret = tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
						  ASC_INVALID_FIELD_IN_PARAMETER_LIST,
						  NULL);
			goto out_free_par;
		}

		if (lba + nlbas > end_lba || lba + nlbas < lba) {
			tcmu_dev_err(dev, "Illegal parameter list (lba + nlbas) %llu exceeds last lba %llu\n",
				     lba + nlbas, end_lba);
			ret = tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
						  ASC_LBA_OUT_OF_RANGE,
						  NULL);
			goto out_free_par;
		}

		tcmu_dev_dbg(dev, "Parameter list %d, lba: %llu, nlbas: %lu\n",
			     i++, lba, nlbas);

		ret = tcmu_rbd_aio_discard(dev, cmd, lba * block_size,
					   nlbas * block_size);
		if (ret < 0)
			goto out_free_par;

		/* The unmap block descriptor data length is 16 */
		offset += 16;
		bddl -= 16;
	}

out_free_par:
	free(par);
	return ret;
}
#endif

/*
 * Return scsi status or TCMU_NOT_HANDLED
 */
static int tcmu_rbd_handle_cmd(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;
	int ret;

	cmd->done = NULL;
	switch(cdb[0]) {
#ifdef LIBRBD_SUPPORTS_DISCARD
	case UNMAP:
		ret = tcmu_rbd_discard(dev, cmd);
		break;
#endif
	default:
		ret = TCMU_NOT_HANDLED;
	}

	return ret;
}

#ifdef LIBRBD_SUPPORTS_AIO_FLUSH

static int tcmu_rbd_flush(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	struct rbd_aio_cb *aio_cb;
	rbd_completion_t completion;
	ssize_t ret = -ENOMEM;

	aio_cb = calloc(1, sizeof(*aio_cb));
	if (!aio_cb) {
		tcmu_dev_err(dev, "Could not allocate aio_cb.\n");
		goto out;
	}

	aio_cb->dev = dev;
	aio_cb->tcmulib_cmd = cmd;
	aio_cb->bounce_buffer = NULL;

	ret = rbd_aio_create_completion
		(aio_cb, (rbd_callback_t) rbd_finish_aio_generic, &completion);
	if (ret < 0) {
		goto out_free_aio_cb;
	}

	ret = rbd_aio_flush(state->image, completion);
	if (ret < 0) {
		goto out_remove_tracked_aio;
	}

	return 0;

out_remove_tracked_aio:
	rbd_aio_release(completion);
out_free_aio_cb:
	free(aio_cb);
out:
	return SAM_STAT_TASK_SET_FULL;
}

#endif

/*
 * For backstore creation
 *
 * Specify poolname/devicename, e.g,
 *
 * $ targetcli create /backstores/user:rbd/test 2G rbd/test
 *
 * poolname must be the name of an existing rados pool.
 *
 * devicename is the name of the rbd image.
 */
static const char tcmu_rbd_cfg_desc[] =
	"RBD config string is of the form:\n"
	"poolname/devicename\n"
	"where:\n"
	"poolname:	Existing RADOS pool\n"
	"devicename:	Name of the RBD image\n";

struct tcmur_handler tcmu_rbd_handler = {
	.name	       = "Ceph RBD handler",
	.subtype       = "rbd",
	.cfg_desc      = tcmu_rbd_cfg_desc,
	.open	       = tcmu_rbd_open,
	.close	       = tcmu_rbd_close,
	.read	       = tcmu_rbd_read,
	.write	       = tcmu_rbd_write,
	.handle_cmd    = tcmu_rbd_handle_cmd,
#ifdef LIBRBD_SUPPORTS_AIO_FLUSH
	.flush	       = tcmu_rbd_flush,
#endif

#ifdef RBD_LOCK_ACQUIRE_SUPPORT
	.lock          = tcmu_rbd_lock,
	.unlock        = tcmu_rbd_unlock,
	.has_lock      = tcmu_rbd_has_lock,
#endif
};

int handler_init(void)
{
	return tcmur_register_handler(&tcmu_rbd_handler);
}
