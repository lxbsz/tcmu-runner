/*
 * Copyright 2017, Red Hat, Inc.
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
#include <scsi/scsi.h>
#include <errno.h>
#include <inttypes.h>

#include "ccan/list/list.h"

#include "libtcmu.h"
#include "libtcmu_log.h"
#include "libtcmu_priv.h"
#include "tcmur_aio.h"
#include "tcmur_device.h"
#include "tcmur_cmd_handler.h"
#include "tcmu-runner.h"
#include "alua.h"

void tcmur_command_complete(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			    int rc)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);

	pthread_cleanup_push(_cleanup_spin_lock, (void *)&rdev->lock);
	pthread_spin_lock(&rdev->lock);

	tcmulib_command_complete(dev, cmd, rc);

	pthread_spin_unlock(&rdev->lock);
	pthread_cleanup_pop(0);
}

static void aio_command_finish(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			       int rc)
{
	int wakeup;

	track_aio_request_finish(tcmu_get_daemon_dev_private(dev), &wakeup);
	tcmur_command_complete(dev, cmd, rc);
	if (wakeup)
		tcmulib_processing_complete(dev);
}

static int alloc_iovec(struct tcmulib_cmd *cmd, size_t length)
{
	struct iovec *iov;

	assert(!cmd->iovec);

	iov = calloc(1, sizeof(*iov));
	if (!iov)
		goto out;
	iov->iov_base = calloc(1, length);
	if (!iov->iov_base)
		goto free_iov;
	iov->iov_len = length;

	cmd->iovec = iov;
	cmd->iov_cnt = 1;
	return 0;

free_iov:
	free(iov);
out:
	return -ENOMEM;
}

static void free_iovec(struct tcmulib_cmd *cmd)
{
	assert(cmd->iovec);
	assert(cmd->iovec->iov_base);

	free(cmd->iovec->iov_base);
	free(cmd->iovec);

	cmd->iov_cnt = 0;
	cmd->iovec = NULL;
}

static int check_lba_and_length(struct tcmu_device *dev,
				struct tcmulib_cmd *cmd, uint32_t sectors)
{
	uint8_t *cdb = cmd->cdb;
	uint64_t lba = tcmu_get_lba(cdb);
	uint64_t num_lbas = tcmu_get_dev_num_lbas(dev);
	size_t iov_length = tcmu_iovec_length(cmd->iovec, cmd->iov_cnt);

	if (iov_length != sectors * tcmu_get_dev_block_size(dev)) {
		tcmu_err("iov len mismatch: iov len %zu, xfer len %" PRIu32 ", block size %" PRIu32 "\n",
			 iov_length, sectors, tcmu_get_dev_block_size(dev));

		return tcmu_set_sense_data(cmd->sense_buf, HARDWARE_ERROR,
					   ASC_INTERNAL_TARGET_FAILURE, NULL);
	}

	if (lba + sectors > num_lbas || lba + sectors < lba) {
		tcmu_err("cmd exceeds last lba %"PRIu64" (lba %"PRIu64", xfer len %"PRIu32")\n",
			 num_lbas, lba, sectors);
		return tcmu_set_sense_data(cmd->sense_buf, ILLEGAL_REQUEST,
					   ASC_LBA_OUT_OF_RANGE, NULL);
	}

	return SAM_STAT_GOOD;
}

static int read_work_fn(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	uint32_t block_size = tcmu_get_dev_block_size(dev);

	return rhandler->read(dev, cmd, cmd->iovec, cmd->iov_cnt,
			      tcmu_iovec_length(cmd->iovec, cmd->iov_cnt),
			      block_size * tcmu_get_lba(cmd->cdb));
}

static int write_work_fn(struct tcmu_device *dev,
				struct tcmulib_cmd *cmd)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	uint32_t block_size = tcmu_get_dev_block_size(dev);

	return rhandler->write(dev, cmd, cmd->iovec, cmd->iov_cnt,
				tcmu_iovec_length(cmd->iovec, cmd->iov_cnt),
				block_size * tcmu_get_lba(cmd->cdb));
}

/* async write verify */

struct write_verify_state {
	size_t requested;
	struct iovec *w_iovec;
	size_t w_iov_cnt;
	void *read_buf;
	struct tcmulib_cmd *readcmd;
};

static int write_verify_init(struct tcmulib_cmd *origcmd, size_t length)
{
	struct tcmulib_cmd *readcmd;
	struct write_verify_state *state;
	int i;

	readcmd = calloc(1, sizeof(*readcmd));
	if (!readcmd)
		goto out;
	readcmd->cmdstate = origcmd;
	readcmd->cdb = origcmd->cdb;

	if (alloc_iovec(readcmd, length))
		goto free_cmd;

	state = calloc(1, sizeof(*state));
	if (!state)
		goto free_iov;

	/* use @origcmd as writecmd */
	state->read_buf = readcmd->iovec->iov_base;
	state->requested = length;
	state->readcmd = readcmd;

	state->w_iovec = calloc(origcmd->iov_cnt, sizeof(struct iovec));
	if (!state->w_iovec)
		goto free_state;

	state->w_iov_cnt = origcmd->iov_cnt;
	for (i = 0; i < origcmd->iov_cnt; i++) {
		state->w_iovec[i].iov_base = origcmd->iovec[i].iov_base;
		state->w_iovec[i].iov_len = origcmd->iovec[i].iov_len;
	}
	origcmd->cmdstate = state;

	return 0;

free_state:
	free(state);
free_iov:
	free_iovec(readcmd);
free_cmd:
	free(readcmd);
out:
	return -ENOMEM;
}

static void write_verify_free(struct tcmulib_cmd *origcmd)
{
	struct write_verify_state *state = origcmd->cmdstate;
	struct tcmulib_cmd *readcmd = state->readcmd;

	/* some handlers update iov_base */
	readcmd->iovec->iov_base = state->read_buf;
	free_iovec(readcmd);
	free(readcmd);
	free(state->w_iovec);
	free(state);
}

static void handle_write_verify_read_cbk(struct tcmu_device *dev,
					 struct tcmulib_cmd *readcmd, int ret)
{
	uint32_t cmp_offset;
	struct tcmulib_cmd *writecmd = readcmd->cmdstate;
	struct write_verify_state *state = writecmd->cmdstate;
	uint8_t *sense = writecmd->sense_buf;

	/* failed read - bail out */
	if (ret != SAM_STAT_GOOD) {
		memcpy(writecmd->sense_buf, readcmd->sense_buf,
		       sizeof(writecmd->sense_buf));
		goto done;
	}

	ret = SAM_STAT_GOOD;
	cmp_offset = tcmu_compare_with_iovec(state->read_buf, state->w_iovec,
					     state->requested);
	if (cmp_offset != -1) {
		tcmu_err("Verify failed at offset %lu\n", cmp_offset);
		ret =  tcmu_set_sense_data(sense, MISCOMPARE,
					   ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
					   &cmp_offset);
	}

done:
	write_verify_free(writecmd);
	aio_command_finish(dev, writecmd, ret);
}

static void handle_write_verify_write_cbk(struct tcmu_device *dev,
					  struct tcmulib_cmd *writecmd,
					  int ret)
{
	struct write_verify_state *state = writecmd->cmdstate;

	/* write error - bail out */
	if (ret != SAM_STAT_GOOD)
		goto finish_err;

	state->readcmd->done = handle_write_verify_read_cbk;
	ret = async_handle_cmd(dev, state->readcmd, read_work_fn);
	if (ret != TCMU_ASYNC_HANDLED)
		goto finish_err;
	return;

finish_err:
	write_verify_free(writecmd);
	aio_command_finish(dev, writecmd, ret);
}

static int handle_write_verify(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	int ret = SAM_STAT_TASK_SET_FULL;
	uint8_t *cdb = cmd->cdb;
	size_t length = tcmu_get_xfer_length(cdb) * tcmu_get_dev_block_size(dev);

	ret = check_lba_and_length(dev, cmd, tcmu_get_xfer_length(cmd->cdb));
	if (ret)
		return ret;

	if (write_verify_init(cmd, length)) {
		ret = SAM_STAT_TASK_SET_FULL;
		goto out;
	}

	cmd->done = handle_write_verify_write_cbk;

	ret = async_handle_cmd(dev, cmd, write_work_fn);
	if (ret != TCMU_ASYNC_HANDLED)
		goto free_write_verify;

	return TCMU_ASYNC_HANDLED;

free_write_verify:
	write_verify_free(cmd);
out:
	return ret;
}

/* async compare_and_write */

struct caw_state {
	size_t requested;
	void *read_buf;
	struct tcmulib_cmd *origcmd;
};

static struct tcmulib_cmd *
caw_init_readcmd(struct tcmulib_cmd *origcmd, size_t length)
{
	struct tcmulib_cmd *readcmd;
	struct caw_state *state;

	state = calloc(1, sizeof(*state));
	if (!state)
		goto out;
	readcmd = calloc(1, sizeof(*readcmd));
	if (!readcmd)
		goto free_state;
	readcmd->cdb = origcmd->cdb;

	if (alloc_iovec(readcmd, length))
		goto free_cmd;

	/* multi-op state maintainance */
	state->read_buf = readcmd->iovec->iov_base;
	state->requested = length;
	state->origcmd = origcmd;

	readcmd->cmdstate = state;
	return readcmd;

free_cmd:
	free(readcmd);
free_state:
	free(state);
out:
	return NULL;
}

static void caw_free_readcmd(struct tcmulib_cmd *readcmd)
{
	struct caw_state *state = readcmd->cmdstate;

	/* some handlers update iov_base */
	readcmd->iovec->iov_base = state->read_buf;
	free_iovec(readcmd);
	free(state);
	free(readcmd);
}

static void handle_caw_write_cbk(struct tcmu_device *dev,
				 struct tcmulib_cmd *cmd, int ret)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);

	pthread_mutex_unlock(&rdev->caw_lock);
	aio_command_finish(dev, cmd, ret);
}

static void handle_caw_read_cbk(struct tcmu_device *dev,
				struct tcmulib_cmd *readcmd, int ret)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	uint32_t cmp_offset;
	struct caw_state *state = readcmd->cmdstate;
	struct tcmulib_cmd *origcmd = state->origcmd;
	uint8_t *sense = origcmd->sense_buf;

	/* read failed - bail out */
	if (ret != SAM_STAT_GOOD) {
		memcpy(origcmd->sense_buf, readcmd->sense_buf,
		       sizeof(origcmd->sense_buf));
		goto finish_err;
	}

	cmp_offset = tcmu_compare_with_iovec(state->read_buf, origcmd->iovec,
					     state->requested);
	if (cmp_offset != -1) {
		/* verify failed - bail out */
		ret = tcmu_set_sense_data(sense, MISCOMPARE,
					  ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
					  &cmp_offset);
		goto finish_err;
	}

	/* perform write */
	tcmu_seek_in_iovec(origcmd->iovec, state->requested);
	origcmd->done = handle_caw_write_cbk;

	ret = async_handle_cmd(dev, origcmd, write_work_fn);
	if (ret != TCMU_ASYNC_HANDLED)
		goto finish_err;

	caw_free_readcmd(readcmd);
	return;

finish_err:
	pthread_mutex_unlock(&rdev->caw_lock);
	aio_command_finish(dev, origcmd, ret);
	caw_free_readcmd(readcmd);
}

static int handle_caw(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	int ret;
	struct tcmulib_cmd *readcmd;
	size_t half = (tcmu_iovec_length(cmd->iovec, cmd->iov_cnt)) / 2;
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);

	ret = check_lba_and_length(dev, cmd, cmd->cdb[13] * 2);
	if (ret)
		return ret;

	readcmd = caw_init_readcmd(cmd, half);
	if (!readcmd) {
		ret = SAM_STAT_TASK_SET_FULL;
		goto out;
	}

	readcmd->done = handle_caw_read_cbk;

	pthread_mutex_lock(&rdev->caw_lock);

	ret = async_handle_cmd(dev, readcmd, read_work_fn);
	if (ret == TCMU_ASYNC_HANDLED)
		return TCMU_ASYNC_HANDLED;

	pthread_mutex_unlock(&rdev->caw_lock);
	caw_free_readcmd(readcmd);
out:
	return ret;
}

/* async flush */
static void handle_flush_cbk(struct tcmu_device *dev,
			     struct tcmulib_cmd *cmd, int ret)
{
	aio_command_finish(dev, cmd, ret);
}

static int flush_work_fn(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);

	return rhandler->flush(dev, cmd);
}

static int handle_flush(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	cmd->done = handle_flush_cbk;
	return async_handle_cmd(dev, cmd, flush_work_fn);
}

/* async write */
static void handle_write_cbk(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			     int ret)
{
	aio_command_finish(dev, cmd, ret);
}

static int handle_write(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	int ret;

	ret = check_lba_and_length(dev, cmd, tcmu_get_xfer_length(cmd->cdb));
	if (ret)
		return ret;

	cmd->done = handle_write_cbk;
	return async_handle_cmd(dev, cmd, write_work_fn);
}

/* async read */
static void handle_read_cbk(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			    int ret)
{
	aio_command_finish(dev, cmd, ret);
}

static int handle_read(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	int ret;

	ret = check_lba_and_length(dev, cmd, tcmu_get_xfer_length(cmd->cdb));
	if (ret)
		return ret;

	cmd->done = handle_read_cbk;
	return async_handle_cmd(dev, cmd, read_work_fn);
}

/* FORMAT UNIT */
struct format_unit_state {
	size_t length;
	off_t offset;
	void *write_buf;
	struct tcmulib_cmd *origcmd;
	uint32_t done_blocks;
};

static int format_unit_work_fn(struct tcmu_device *dev,
			       struct tcmulib_cmd *writecmd) {
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	struct tcmulib_cmd *origcmd = writecmd->cmdstate;
	struct format_unit_state *state = origcmd->cmdstate;

	return rhandler->write(dev, writecmd, writecmd->iovec,
			       writecmd->iov_cnt, state->length, state->offset);
}

static void handle_format_unit_cbk(struct tcmu_device *dev,
				   struct tcmulib_cmd *writecmd, int ret) {
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	struct tcmulib_cmd *origcmd = writecmd->cmdstate;
	struct format_unit_state *state = origcmd->cmdstate;
	uint8_t *sense = origcmd->sense_buf;
	int rc;

	writecmd->iovec->iov_base = state->write_buf;
	state->offset += state->length;
	state->done_blocks += state->length / dev->block_size;
	if (state->done_blocks < dev->num_lbas)
		rdev->format_progress = (0x10000 * state->done_blocks) /
				       dev->num_lbas;

	/* Check for last commmand */
	if (state->done_blocks == dev->num_lbas) {
		tcmu_dbg("last format cmd, done_blocks:%lu num_lbas:%lu block_size:%lu\n",
			 state->done_blocks, dev->num_lbas, dev->block_size);
		goto free_iovec;
	}

	if (state->done_blocks < dev->num_lbas) {
		/* free iovec on every write, because seek in handlers consume
		 * the iovec, thus we can't re-use.
		 */
		free_iovec(writecmd);
		if ((dev->num_lbas - state->done_blocks) * dev->block_size < state->length)
		    state->length = (dev->num_lbas - state->done_blocks) * dev->block_size;
		if (alloc_iovec(writecmd, state->length)) {
			ret = tcmu_set_sense_data(sense, HARDWARE_ERROR,
						  ASC_INTERNAL_TARGET_FAILURE,
						  NULL);
			goto free_cmd;
		}

		/* copy incase handler changes it */
		state->write_buf = writecmd->iovec->iov_base;

		writecmd->done = handle_format_unit_cbk;

		tcmu_dbg("next format cmd, done_blocks:%lu num_lbas:%lu block_size:%lu\n",
			 state->done_blocks, dev->num_lbas, dev->block_size);

		rc = async_handle_cmd(dev, writecmd, format_unit_work_fn);
		if (rc != TCMU_ASYNC_HANDLED) {
			tcmu_err(" async handle cmd failure");
			ret = tcmu_set_sense_data(sense, MEDIUM_ERROR,
						  ASC_WRITE_ERROR,
						  NULL);
			goto free_iovec;
		}
	}

	return;

free_iovec:
	free_iovec(writecmd);
free_cmd:
	free(writecmd);
	free(state);
	pthread_mutex_lock(&rdev->format_lock);
	rdev->flags &= ~TCMUR_DEV_FORMATTING;
	pthread_mutex_unlock(&rdev->format_lock);
	aio_command_finish(dev, origcmd, ret);
}

static int handle_format_unit(struct tcmu_device *dev, struct tcmulib_cmd *cmd) {
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	struct tcmulib_cmd *writecmd;
	struct format_unit_state *state;
	size_t length = 1024 * 1024;
	uint8_t *sense = cmd->sense_buf;
	uint32_t block_size = tcmu_get_dev_block_size(dev);
	uint64_t num_lbas = tcmu_get_dev_num_lbas(dev);
	int ret;

	pthread_mutex_lock(&rdev->format_lock);
	if (rdev->flags & TCMUR_DEV_FORMATTING) {
		pthread_mutex_unlock(&rdev->format_lock);
		return tcmu_set_sense_data(sense, NOT_READY,
					  ASC_NOT_READY_FORMAT_IN_PROGRESS,
					  &rdev->format_progress);
	}
	rdev->format_progress = 0;
	rdev->flags |= TCMUR_DEV_FORMATTING;
	pthread_mutex_unlock(&rdev->format_lock);

	writecmd = calloc(1, sizeof(*writecmd));
	if (!writecmd)
		goto clear_format;
	writecmd->done = handle_format_unit_cbk;
	writecmd->cmdstate = cmd;

	state = calloc(1, sizeof(*state));
	if (!state)
		goto free_cmd;

	cmd->cmdstate = state;
	state->done_blocks = 0;
	state->length = length;

	/* Check length on first write to make sure its not less than 1MB */
	if ((num_lbas - state->done_blocks) * block_size < length)
		state->length = (num_lbas - state->done_blocks) * block_size;

	if (alloc_iovec(writecmd, state->length)) {
		free(state);
		goto free_state;
	}

	tcmu_dbg("start emulate format, done_blocks:%lu num_lbas:%lu block_size:%lu\n",
		 state->done_blocks, num_lbas, block_size);

	/* copy incase handler changes it */
	state->write_buf = writecmd->iovec->iov_base;

	ret = async_handle_cmd(dev, writecmd, format_unit_work_fn);
	if (ret != TCMU_ASYNC_HANDLED)
		goto free_iov;

	return TCMU_ASYNC_HANDLED;

free_iov:
	free_iovec(writecmd);
free_state:
	free(state);
free_cmd:
	free(writecmd);
clear_format:
	pthread_mutex_lock(&rdev->format_lock);
	rdev->flags &= ~TCMUR_DEV_FORMATTING;
	pthread_mutex_unlock(&rdev->format_lock);
	return SAM_STAT_TASK_SET_FULL;
}

/* ALUA */
static int handle_stpg(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct list_head group_list;
	int ret;

	list_head_init(&group_list);

	ret = tcmu_get_tgt_port_grps(dev, &group_list);
	if (ret)
		return tcmu_set_sense_data(cmd->sense_buf, HARDWARE_ERROR,
					   ASC_INTERNAL_TARGET_FAILURE, NULL);

	ret = tcmu_emulate_set_tgt_port_grps(dev, &group_list, cmd);
	tcmu_release_tgt_port_grps(&group_list);
	return ret;
}

static int handle_rtpg(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct list_head group_list;
	int ret;

	list_head_init(&group_list);

	ret = tcmu_get_tgt_port_grps(dev, &group_list);
	if (ret)
		return tcmu_set_sense_data(cmd->sense_buf, HARDWARE_ERROR,
					   ASC_INTERNAL_TARGET_FAILURE, NULL);

	ret = tcmu_emulate_report_tgt_port_grps(dev, &group_list, cmd);
	tcmu_release_tgt_port_grps(&group_list);
	return ret;
}

/* command passthrough */
static void
handle_passthrough_cbk(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		       int ret)
{
	aio_command_finish(dev, cmd, ret);
}

static int passthrough_work_fn(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);

	return rhandler->handle_cmd(dev, cmd);
}

static int handle_passthrough(struct tcmu_device *dev,
			      struct tcmulib_cmd *cmd)
{
	cmd->done = handle_passthrough_cbk;
	return async_handle_cmd(dev, cmd, passthrough_work_fn);
}

bool tcmur_handler_is_passthrough_only(struct tcmur_handler *rhandler)
{
	if (rhandler->write || rhandler->read || rhandler->flush)
		return false;

	return true;
}

int tcmur_cmd_passthrough_handler(struct tcmu_device *dev,
				  struct tcmulib_cmd *cmd)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	int ret;

	if (!rhandler->handle_cmd)
		return TCMU_NOT_HANDLED;

	/*
	 * Support handlers that implement their own threading/AIO
	 * and only use runner's main event loop.
	 */
	if (!rhandler->nr_threads)
		return rhandler->handle_cmd(dev, cmd);
	/*
	 * Since we call ->handle_cmd via async_handle_cmd(), ->handle_cmd
	 * can finish in the callers context(asynchronous handler) or work
	 * queue context (synchronous handlers), thus we'd need to check if
	 * ->handle_cmd handled the passthough command here as well as in
	 * handle_passthrough_cbk().
	 */
	track_aio_request_start(rdev);
	ret = handle_passthrough(dev, cmd);
	if (ret != TCMU_ASYNC_HANDLED)
		track_aio_request_finish(rdev, NULL);

	return ret;
}

static int tcmur_cmd_handler(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	int ret = TCMU_NOT_HANDLED;
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	uint8_t *cdb = cmd->cdb;

	track_aio_request_start(rdev);

	switch(cdb[0]) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		ret = handle_read(dev, cmd);
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		ret = handle_write(dev, cmd);
		break;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		if (rhandler->flush)
			ret = handle_flush(dev, cmd);
		break;
	case COMPARE_AND_WRITE:
		ret = handle_caw(dev, cmd);
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_16:
		ret = handle_write_verify(dev, cmd);
		break;
	case FORMAT_UNIT:
		ret = handle_format_unit(dev, cmd);
		break;
	case MAINTENANCE_IN:
		if ((cdb[1] & 0x1f) == MI_REPORT_TARGET_PGS) {
			ret = handle_rtpg(dev, cmd);
			break;
		}
		goto passthrough;
	case MAINTENANCE_OUT:
		if (cdb[1] == MO_SET_TARGET_PGS) {
			ret = handle_stpg(dev, cmd);
			break;
		}
		goto passthrough;
	default:
passthrough:
		/* Try to passthrough the default cmds */
		if (rhandler->handle_cmd)
			ret = handle_passthrough(dev, cmd);
	}

	if (ret != TCMU_ASYNC_HANDLED)
		track_aio_request_finish(rdev, NULL);
	return ret;
}

static int handle_inquiry(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct list_head group_list;
	struct tgt_port *port;
	int ret;

	list_head_init(&group_list);

	ret = tcmu_get_tgt_port_grps(dev, &group_list);
	if (ret)
		return tcmu_set_sense_data(cmd->sense_buf, HARDWARE_ERROR,
					   ASC_INTERNAL_TARGET_FAILURE, NULL);

	/*
	 * Detect if the user did not setup ALUA or the kernel did not fully
	 * support it. ALUA tcmu support was added in 4.11. Before that and
	 * in the unsetup case, we will end up with at least the default ALUA
	 * group and a empty members (groups are not set to any LUNs) file. For
	 * these cases we just return tpgs=0.
	 */
	port = tcmu_get_enabled_port(&group_list);
	if (!port)
		tcmu_dbg("no enabled ports found. Skipping ALUA support\n");

	ret = tcmu_emulate_inquiry(dev, port, cmd->cdb, cmd->iovec,
				   cmd->iov_cnt, cmd->sense_buf);
	tcmu_release_tgt_port_grps(&group_list);
	return ret;
}

static int handle_generic_cmd(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	uint8_t *sense = cmd->sense_buf;
	uint32_t block_size = tcmu_get_dev_block_size(dev);
	uint64_t num_lbas = tcmu_get_dev_num_lbas(dev);

	switch (cdb[0]) {
	case INQUIRY:
		return handle_inquiry(dev, cmd);
	case TEST_UNIT_READY:
		return tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt, sense);
	case SERVICE_ACTION_IN_16:
		if (cdb[1] == READ_CAPACITY_16)
			return tcmu_emulate_read_capacity_16(num_lbas,
							     block_size,
							     cdb, iovec,
							     iov_cnt, sense);
		else
			return TCMU_NOT_HANDLED;
	case READ_CAPACITY:
		if ((cdb[1] & 0x01) || (cdb[8] & 0x01))
			/* Reserved bits for MM logical units */
			return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
						   ASC_INVALID_FIELD_IN_CDB,
						   NULL);
		else
			return tcmu_emulate_read_capacity_10(num_lbas,
							     block_size,
							     cdb, iovec,
							     iov_cnt, sense);
	case MODE_SENSE:
	case MODE_SENSE_10:
		return tcmu_emulate_mode_sense(cdb, iovec, iov_cnt, sense);
	case START_STOP:
		return tcmu_emulate_start_stop(dev, cdb, sense);
	case MODE_SELECT:
	case MODE_SELECT_10:
		return tcmu_emulate_mode_select(cdb, iovec, iov_cnt, sense);
	default:
		return TCMU_NOT_HANDLED;
	}
}

static bool command_is_generic(struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;

	switch(cdb[0]) {
	case INQUIRY:
	case TEST_UNIT_READY:
	case MODE_SENSE:
	case MODE_SENSE_10:
	case START_STOP:
	case MODE_SELECT:
	case MODE_SELECT_10:
	case READ_CAPACITY:
		return true;
	case SERVICE_ACTION_IN_16:
		if (cdb[1] == READ_CAPACITY_16)
			return true;
		/* fall through */
	default:
		return false;
	}
}

int tcmur_generic_handle_cmd(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);

	if (rdev->flags & TCMUR_DEV_FORMATTING && cmd->cdb[0] != INQUIRY)
		return tcmu_set_sense_data(cmd->sense_buf, NOT_READY,
					   ASC_NOT_READY_FORMAT_IN_PROGRESS,
					   &rdev->format_progress);

	if (command_is_generic(cmd))
		return handle_generic_cmd(dev, cmd);
	else
		return tcmur_cmd_handler(dev, cmd);
}
