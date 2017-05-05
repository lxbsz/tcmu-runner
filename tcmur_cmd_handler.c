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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "darray.h"
#include "libtcmu.h"
#include "libtcmu_log.h"
#include "libtcmu_priv.h"
#include "tcmur_aio.h"
#include "tcmur_device.h"
#include "tcmur_cmd_handler.h"
#include "tcmu-runner.h"

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

/*
 * The EXTENDED COPY parameter list begins with a 16 byte header
 * that contains the LIST IDENTIFIER field.
 */
#define XCOPY_HDR_LEN                   16
#define XCOPY_TARGET_DESC_LEN           32
#define XCOPY_SEGMENT_DESC_B2B_LEN      28
#define XCOPY_NAA_IEEE_REGEX_LEN        16
#define XCOPY_MAX_SECTORS               1024

struct xcopy {

	struct tcmu_device *src_dev;
	uint8_t src_tid_wwn[XCOPY_NAA_IEEE_REGEX_LEN];
	struct tcmu_device *dst_dev;
	uint8_t dst_tid_wwn[XCOPY_NAA_IEEE_REGEX_LEN];

	uint64_t src_lba;
	uint64_t dst_lba;
	unsigned long stdi;
	unsigned long dtdi;
	unsigned long nolb;
};

/* EXTENDED COPY segment descriptor type codes */
#define XCOPY_SEG_DESC_TYPE_CODE_B2B    0x02

/* For now we only support block -> block type */
static int xcopy_parse_segment_descs(uint8_t *seg_descs, struct xcopy *xcopy, unsigned int sdll, uint8_t *sense)
{
	uint8_t *seg_desc = seg_descs;
	uint8_t desc_len;
//	unsigned long off = 0;
#if 0
	int offset = sdll % XCOPY_SEGMENT_DESC_LEN, rc, ret = 0;

	*sense_ret = TCM_INVALID_PARAMETER_LIST;

	if (offset != 0) {
		pr_err("XCOPY segment descriptor list length is not"
			" multiple of %d\n", XCOPY_SEGMENT_DESC_LEN);
		*sense_ret = TCM_UNSUPPORTED_SEGMENT_DESC_TYPE_CODE;
		return -EINVAL;
	}
#endif
	if (sdll > RCR_OP_MAX_SG_DESC_COUNT * XCOPY_SEGMENT_DESC_B2B_LEN) {
		tcmu_err("Only %u segment descriptor(s) supported, but there are %u\n",
			 RCR_OP_MAX_SG_DESC_COUNT, sdll / XCOPY_SEGMENT_DESC_B2B_LEN);
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_PARAMETER_LIST,
					   NULL);
	}

	if (seg_desc[0] != XCOPY_SEG_DESC_TYPE_CODE_B2B) {
		tcmu_err("Unsupport segment descriptor type code 0x%x\n",
			 seg_desc[0]);
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_UNSUPPORTED_SEGMENT_DESC_TYPE_CODE,
					   NULL);
	}
	/* For block -> block the length is 4-byte header + 0x18-byte data */
	desc_len = be16toh(seg_desc[2]);
	if (desc_len != 0x18) {
		tcmu_err("Invalid length for block->block type 0x%x\n",
			 desc_len);
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_PARAMETER_LIST,
					   NULL);
	}

	xcopy->stdi = be16toh(seg_desc[4]);
	xcopy->dtdi = be16toh(seg_desc[6]);
	tcmu_dbg("XCOPY seg desc 0x02: desc_len: %hu stdi: %hu dtdi: %hu, DC: %d\n",
			desc_len, xcopy->stdi, xcopy->dtdi);

	xcopy->nolb = be16toh(seg_desc[10]);
	xcopy->src_lba = be64toh(seg_desc[12]);
	xcopy->dst_lba = be64toh(seg_desc[20]);
	tcmu_dbg("XCOPY seg desc 0x02: nolb: %hu src_lba: %llu dst_lba: %llu\n",
			xcopy->nolb, (unsigned long long)xcopy->src_lba,
			(unsigned long long)xcopy->dst_lba);

	return SAM_STAT_GOOD;
}

static int xcopy_gen_naa_ieee(struct tcmu_device *udev, uint8_t *wwn)
{
	char *buf, *p, ch;
	bool next = true;
	int ind = 0;

	wwn[ind++] = (0x6 << 4);
	wwn[ind++] = 0x01;
	wwn[ind++] = 0x40;
	wwn[ind] = (0x5 << 4);

	/* Parse the udev vpd unit serial number */
	buf = tcmu_get_wwn(udev);
	if (!buf)
		return -1;
	p = buf;

	/*
	 * Generate up to 36 bits of VENDOR SPECIFIC IDENTIFIER starting on
	 * byte 3 bit 3-0 for NAA IEEE Registered Extended DESIGNATOR field
	 * format, followed by 64 bits of VENDOR SPECIFIC IDENTIFIER EXTENSION
	 * to complete the payload.  These are based from VPD=0x80 PRODUCT SERIAL
	 * NUMBER set via vpd_unit_serial in target_core_configfs.c to ensure
	 * per device uniqeness.
	 */
	for (; *p && ind < XCOPY_NAA_IEEE_REGEX_LEN; p++) {
		int val = -1;
			ch = *p;
			if ((ch >= '0') && (ch <= '9'))
				val = ch - '0';
			ch = tolower(ch);
			if ((ch >= 'a') && (ch <= 'f'))
				val = ch - 'a' + 10;

		if (val == -1)
			continue;

		if (next) {
			next = false;
			wwn[ind++] |= val;
		} else {
			next = true;
			wwn[ind] = val << 4;
		}
	}

	free(buf);
	return 0;
}

static int xcopy_locate_udev(struct tcmulib_context *ctx, const uint8_t *dev_wwn, struct tcmu_device **udev)
{
	struct tcmu_device **dev_ptr;
	struct tcmu_device *dev;
	uint8_t wwn[XCOPY_NAA_IEEE_REGEX_LEN];

//	mutex_lock(&g_device_mutex);
	darray_foreach(dev_ptr, ctx->devices) {
		dev = *dev_ptr;
//	list_for_each_entry(se_dev, &g_device_list, g_dev_node) {

		memset(wwn, 0, XCOPY_NAA_IEEE_REGEX_LEN);
		xcopy_gen_naa_ieee(dev, wwn);

		if (memcmp(wwn, dev_wwn, XCOPY_NAA_IEEE_REGEX_LEN))
			continue;

		*udev = dev;
		tcmu_dbg("XCOPY 0xe4: located dev: %s\n", dev->dev_name);
#if 0
		rc = target_depend_item(&se_dev->dev_group.cg_item);
		if (rc != 0) {
			pr_err("configfs_depend_item attempt failed:"
				" %d for se_dev: %p\n", rc, se_dev);
			mutex_unlock(&g_device_mutex);
			return rc;
		}

		pr_debug("Called configfs_depend_item for se_dev: %p"
			" se_dev->se_dev_group: %p\n", se_dev,
			&se_dev->dev_group);

		mutex_unlock(&g_device_mutex);
#endif
		return 0;
	}
//	mutex_unlock(&g_device_mutex);

	return -1;
}

/* Identification descriptor target */
static int xcopy_parse_target_id(struct tcmu_device *udev,
				  struct xcopy *xcopy,
				  uint8_t *tgt_desc,
				  int32_t index,
				  uint8_t *sense)
{
	uint8_t wwn[XCOPY_NAA_IEEE_REGEX_LEN];
	/*
	 * Generate an IEEE Registered Extended designator based upon the
	 * se_device the XCOPY was received upon..
	 */
	memset(wwn, 0, XCOPY_NAA_IEEE_REGEX_LEN);
	xcopy_gen_naa_ieee(udev, wwn);

	/*
	 * CODE SET: for now only binary type code is support.
	 */
	if ((tgt_desc[4] & 0x0f) != 0x1) {
		tcmu_err("Id target CODE DET only support binary type!\n");
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_PARAMETER_LIST,
					   NULL);
	}

	/*
	 * ASSOCIATION: for now only LUN type code is support.
	 */
	if ((tgt_desc[5] & 0x30) != 0x00) {
		tcmu_err("Id target ASSOCIATION other than LUN not supported!\n");
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_PARAMETER_LIST,
					   NULL);
	}

	/*
	 * DESIGNATOR TYPE: for now only NAA type code is support.
	 */
	if ((tgt_desc[5] & 0x0f) != 0x3) {
		tcmu_err("Id target DESIGNATOR TYPE other than NAA not supported!\n");
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_PARAMETER_LIST,
					   NULL);
	}
	/*
	 * Check for matching 16 byte length for NAA IEEE Registered Extended
	 * Assigned designator
	 */
	if (tgt_desc[7] != 16) {
		tcmu_err("Id target DESIGNATOR LENGTH should be 16, but it's: %d\n",
			 tgt_desc[7]);
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_PARAMETER_LIST,
					   NULL);
	}

	/*
	 * Check for NAA IEEE Registered Extended Assigned header..
	 */
	if ((tgt_desc[8] >> 4) != 0x06) {
		tcmu_err("Id target NAA designator type: 0x%x\n",
			 tgt_desc[8] >> 4);
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_PARAMETER_LIST,
					   NULL);
	}

	if (index == xcopy->stdi) {
		memcpy(&xcopy->src_tid_wwn[0], &tgt_desc[8], XCOPY_NAA_IEEE_REGEX_LEN);
		/*
		 * Determine if the source designator matches the local device
		 */
		if (!memcmp(wwn, xcopy->src_tid_wwn,
				XCOPY_NAA_IEEE_REGEX_LEN)) {
			xcopy->src_dev = udev;
			tcmu_dbg("Id target source device == curent deivce!\n");
		}
	}

	if (index == xcopy->dtdi) {
		memcpy(&xcopy->dst_tid_wwn[0], &tgt_desc[8], XCOPY_NAA_IEEE_REGEX_LEN);
		/*
		 * Determine if the destination designator matches the local
		 * device. If @cscd_index corresponds to both source (stdi) and
		 * destination (dtdi), or dtdi comes after stdi, then
		 * XCOL_DEST_RECV_OP wins.
		 */
		if (!memcmp(wwn, &xcopy->dst_tid_wwn[0],
				XCOPY_NAA_IEEE_REGEX_LEN)) {
			xcopy->dst_dev = udev;
			tcmu_dbg("Id target destination device == curent deivce!\n");
		}
	}

	return 0;
}

static int xcopy_parse_target_descs(struct tcmu_device *udev,
				    struct xcopy *xcopy,
				    uint8_t *tgt_desc,
				    unsigned short tdll,
				    uint8_t *sense)
{
	int i, ret;

	if (tdll > RCR_OP_MAX_TARGET_DESC_COUNT * XCOPY_TARGET_DESC_LEN) {
		tcmu_err("Only %u target descriptor(s) supported, but there are %u\n",
			 RCR_OP_MAX_TARGET_DESC_COUNT, tdll / XCOPY_TARGET_DESC_LEN);
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_PARAMETER_LIST,
					   NULL);
	}

	for (i = 0; i < RCR_OP_MAX_TARGET_DESC_COUNT; i++) {
		/*
		 * Check target descriptor identification with 0xE4 type, and
		 * compare the current index with the CSCD descriptor IDs in
		 * the segment descriptor. Use VPD 0x83 WWPN matching ..
		 */
		if (tgt_desc[0] == 0xe4) {
			ret = xcopy_parse_target_id(udev, xcopy, tgt_desc, i, sense);
			if (ret != SAM_STAT_GOOD)
				return ret;

			tgt_desc += XCOPY_TARGET_DESC_LEN;
		} else {
			tcmu_err("Unsupport target descriptor type code 0x%x\n",
				 tgt_desc[0]);
			return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
						   ASC_UNSUPPORTED_TARGET_DESC_TYPE_CODE,
						   NULL);
		}
	}

	if (xcopy->src_dev) {
		ret = xcopy_locate_udev(udev->ctx, xcopy->dst_tid_wwn, &xcopy->dst_dev);
	} else if (xcopy->dst_dev) {
		ret = xcopy_locate_udev(udev->ctx, xcopy->src_tid_wwn, &xcopy->src_dev);
	} else {
		tcmu_err("XCOPY CSCD descriptor IDs not found in CSCD list - "
			"stdi: %hu dtdi: %hu\n", xcopy->stdi, xcopy->dtdi);
		ret = -1;
	}

	/*
	 * If a matching IEEE NAA 0x83 descriptor for the requested device
	 * is not located on this node, return COPY_ABORTED with ASQ/ASQC
	 * 0x0d/0x02 - COPY_TARGET_DEVICE_NOT_REACHABLE to request the
	 * initiator to fall back to normal copy method.
	 */

	if (ret != 0) {
		tcmu_err("udev not exsit stdi: %hu dtdi: %hu\n", xcopy->stdi, xcopy->dtdi);
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_UNSUPPORTED_TARGET_DESC_TYPE_CODE,
					   NULL);
	}

	tcmu_dbg("XCOPY TGT desc: Source dev: %p NAA IEEE WWN: 0x%16phN\n",
		 xcopy->src_dev, &xcopy->src_tid_wwn[0]);
	tcmu_dbg("XCOPY TGT desc: Dest dev: %p NAA IEEE WWN: 0x%16phN\n",
		 xcopy->dst_dev, &xcopy->dst_tid_wwn[0]);

	return i;

//out:
//	return -EINVAL;
}

#define min(a,b) \
	({ __typeof__ (a) _a = (a); \
		__typeof__ (b) _b = (b); \
		_a < _b ? _a : _b; })

static int xcopy_work_fn(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	uint32_t block_size = tcmu_get_dev_block_size(dev);
	struct xcopy *xcopy = cmd->cmdstate;
	struct tcmu_device *src_dev = xcopy->src_dev, *dst_dev = xcopy->dst_dev;
	uint64_t src_lba = xcopy->src_lba, dst_lba = xcopy->dst_lba, end_lba;
	unsigned short nolb = xcopy->nolb, cur_nolb, max_nolb, copied_nolb = 0;
	uint32_t max_sectors, src_max_sectors, dst_max_sectors;
	struct iovec iovec;
	size_t iov_cnt;
	int ret;

	end_lba = src_lba + nolb;

	src_max_sectors = tcmu_get_attribute(src_dev, "hw_max_sectors");
	dst_max_sectors = tcmu_get_attribute(dst_dev, "hw_max_sectors");

	max_sectors = min(src_max_sectors, dst_max_sectors);
	max_sectors = min(max_sectors, XCOPY_MAX_SECTORS);
	max_nolb = min(max_sectors, ((uint16_t)(~0U)));

	tcmu_dbg("target_xcopy_do_work: nolb: %hu, max_nolb: %hu end_lba: %llu\n",
			nolb, max_nolb, (unsigned long long)end_lba);
	tcmu_dbg("target_xcopy_do_work: Starting src_lba: %llu, dst_lba: %llu\n",
			(unsigned long long)src_lba, (unsigned long long)dst_lba);

	iovec.iov_len = min(nolb, max_nolb) * block_size;
	iovec.iov_base = malloc(iovec.iov_len);
	iov_cnt = 1;

	while (src_lba < end_lba) {
		cur_nolb = min(nolb, max_nolb);

		tcmu_dbg("target_xcopy_do_work: Calling read src_dev: %p src_lba: %llu,"
			" cur_nolb: %hu\n", src_dev, (unsigned long long)src_lba, cur_nolb);

		ret = rhandler->read(src_dev, cmd, &iovec, iov_cnt,
				     tcmu_iovec_length(&iovec, iov_cnt),
				     block_size * src_lba);
		if (ret) {
			free(iovec.iov_base);
			return ret;
		}

		src_lba += cur_nolb;
		tcmu_dbg("target_xcopy_do_work: Incremented READ src_lba to %llu\n",
				(unsigned long long)src_lba);

		tcmu_dbg("target_xcopy_do_work: Calling write dst_dev: %p dst_lba: %llu,"
			" cur_nolb: %hu\n", dst_dev, (unsigned long long)dst_lba, cur_nolb);

		ret = rhandler->write(dst_dev, cmd, &iovec, iov_cnt,
				      tcmu_iovec_length(&iovec, iov_cnt),
				      block_size * dst_lba);
		if (ret) {
			free(iovec.iov_base);
			return ret;
		}

		dst_lba += cur_nolb;
		tcmu_dbg("target_xcopy_do_work: Incremented WRITE dst_lba to %llu\n",
				(unsigned long long)dst_lba);

		copied_nolb += cur_nolb;
		nolb -= cur_nolb;
	}

	free(iovec.iov_base);
	return SAM_STAT_GOOD;
}

static int handle_xcopy(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
//	struct se_device *dev = se_cmd->se_dev;
	uint8_t *cdb = cmd->cdb;
	struct iovec *vec, *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	uint8_t *sense = cmd->sense_buf;
	struct xcopy *xcopy = NULL;
	unsigned int list_id, list_id_usage, sdll, inline_dl;
	int i, ret;
	unsigned short tdll;
	uint8_t *seg_desc, *tgt_desc, *buf;
	unsigned long buflen;
	size_t data_length = tcmu_get_xfer_length(cdb) * tcmu_get_dev_block_size(dev);

	/*
	 * A parameter list length of zero specifies that copy manager
	 * shall not transfer any data or alter any internal state
	 */
	if (data_length == 0)
		return SAM_STAT_GOOD;

	if (data_length < XCOPY_HDR_LEN) {
		tcmu_err("XCOPY parameter truncation: length %u < hdr_len %u\n",
				data_length, XCOPY_HDR_LEN);
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_PARAMETER_LIST_LENGTH_ERROR,
					   NULL);
	}

	xcopy = malloc(sizeof(struct xcopy));

	vec = iovec;
	for (i = 0; i < iov_cnt; i++) {
		buflen += vec->iov_len;
		vec++;
	}
	buf = malloc(buflen);

	tcmu_memcpy_from_iovec(buf, buflen, iovec, iov_cnt);

	list_id = buf[0];
	list_id_usage = (buf[1] & 0x18) >> 3;

	/*
	 * The maximum length of the target and segment descriptors permitted
	 * within a parameter list is indicated by the MAXIMUM DESCRIPTOR LIST
	 * LENGTH field in the copy managers operating parameters.
	 */
	tdll = be16toh(buf[2]);
	sdll = be32toh(buf[8]);
	if (tdll + sdll > RCR_OP_MAX_DESC_LIST_LEN) {
		tcmu_err("XCOPY descriptor list length %u exceeds maximum %u\n",
		       tdll + sdll, RCR_OP_MAX_DESC_LIST_LEN);
		ret = tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					  ASC_PARAMETER_LIST_LENGTH_ERROR,
					  NULL);
		goto out;
	}

	/*
	 * The INLINE DATA LENGTH field contains the number of bytes of inline
	 * data, after the last segment descriptor.
	 * */
	inline_dl = be32toh(buf[12]);

	if (data_length < (XCOPY_HDR_LEN + tdll + sdll + inline_dl)) {
		tcmu_err("XCOPY parameter truncation: data length %u too small "
			"for tdll: %hu sdll: %u inline_dl: %u\n",
			data_length, tdll, sdll, inline_dl);
		ret = tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					  ASC_PARAMETER_LIST_LENGTH_ERROR,
					  NULL);
		goto out;
	}

	tcmu_dbg("Processing XCOPY with list_id: 0x%02x list_id_usage: 0x%02x"
		 " tdll: %hu sdll: %u inline_dl: %u\n", list_id, list_id_usage,
		 tdll, sdll, inline_dl);

	/*
	 * skip over the target descriptors until segment descriptors
	 * have been passed - CSCD ids are needed to determine src and dest.
	 */
	seg_desc = buf + XCOPY_HDR_LEN + tdll;

	/*
	 * Parsing the segment descripter, and for now we only
	 * support block -> block type.
	 *
	 * The max seg_desc number support is 1(see RCR_OP_MAX_SG_DESC_COUNT)
	 */
	ret = xcopy_parse_segment_descs(seg_desc, xcopy, sdll, sense);
	if (ret != SAM_STAT_GOOD)
		goto out;

	/*
	 * Parsing the target descripter
	 *
	 * The max seg_desc number support is 2(see RCR_OP_MAX_TARGET_DESC_COUNT)
	 */
	tgt_desc = buf + XCOPY_HDR_LEN;
	ret = xcopy_parse_target_descs(dev, xcopy, tgt_desc, tdll, sense);
	if (ret < 0)
		goto out;

	if (tcmu_get_dev_block_size(xcopy->src_dev) !=
	    tcmu_get_dev_block_size(xcopy->dst_dev)) {
		tcmu_err("The block size of src dev %u != dst dev %u\n",
			 tcmu_get_dev_block_size(xcopy->src_dev),
			 tcmu_get_dev_block_size(xcopy->dst_dev));
		ret = tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					  ASC_PARAMETER_LIST_LENGTH_ERROR,
					  NULL);
		goto out;
	}

	cmd->cmdstate = xcopy;

	ret = async_handle_cmd(dev, cmd, xcopy_work_fn);

out:
	free(buf);
	free(xcopy);
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
	case EXTENDED_COPY:
		ret = handle_xcopy(dev, cmd);
		break;
	case COMPARE_AND_WRITE:
		ret = handle_caw(dev, cmd);
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_16:
		ret = handle_write_verify(dev, cmd);
		break;
	default:
		/* Try to passthrough the default cmds */
		if (rhandler->handle_cmd)
			ret = handle_passthrough(dev, cmd);
	}

	if (ret != TCMU_ASYNC_HANDLED)
		track_aio_request_finish(rdev, NULL);
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
	case RESERVE:
	case RELEASE:
		return 0;
	case INQUIRY:
		return tcmu_emulate_inquiry(dev, cdb, iovec, iov_cnt, sense);
	case TEST_UNIT_READY:
		return tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt, sense);
	case RECEIVE_COPY_RESULTS:
		if ((cdb[1] & 0x1f) == RCR_SA_OPERATING_PARAMETERS)
			return handle_receive_copy_results_op(cdb, iovec,
							      iov_cnt, sense);
		else
			return TCMU_NOT_HANDLED;
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
	case RESERVE:
	case RELEASE:
	case INQUIRY:
	case TEST_UNIT_READY:
	case MODE_SENSE:
	case MODE_SENSE_10:
	case START_STOP:
	case MODE_SELECT:
	case MODE_SELECT_10:
	case READ_CAPACITY:
		return true;
	case RECEIVE_COPY_RESULTS:
		if ((cdb[1] & 0x1f) == RCR_SA_OPERATING_PARAMETERS)
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
	if (command_is_generic(cmd))
		return handle_generic_cmd(dev, cmd);
	else
		return tcmur_cmd_handler(dev, cmd);
}
