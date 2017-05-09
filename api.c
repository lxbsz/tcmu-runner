/*
 * Copyright 2014, Red Hat, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>
#include <scsi/scsi.h>
#include <endian.h>
#include <errno.h>

#include "libtcmu_log.h"
#include "libtcmu_common.h"
#include "libtcmu_priv.h"
#include "alua.h"

#define SECTOR_SIZE 512

int tcmu_get_cdb_length(uint8_t *cdb)
{
	uint8_t group_code = cdb[0] >> 5;

	/* See spc-4 4.2.5.1 operation code */
	switch (group_code) {
	case 0: /*000b for 6 bytes commands */
		return 6;
	case 1: /*001b for 10 bytes commands */
	case 2: /*010b for 10 bytes commands */
		return 10;
	case 3: /*011b Reserved ? */
		if (cdb[0] == 0x7f)
			return 8 + cdb[7];
		return -EINVAL;
	case 4: /*100b for 16 bytes commands */
		return 16;
	case 5: /*101b for 12 bytes commands */
		return 12;
	case 6: /*110b Vendor Specific */
	case 7: /*111b Vendor Specific */
	default:
		/* TODO: */
		return -EINVAL;
	}
}

uint64_t tcmu_get_lba(uint8_t *cdb)
{
	uint16_t val;

	switch (tcmu_get_cdb_length(cdb)) {
	case 6:
		val = be16toh(*((uint16_t *)&cdb[2]));
		return ((cdb[1] & 0x1f) << 16) | val;
	case 10:
		return be32toh(*((u_int32_t *)&cdb[2]));
	case 12:
		return be32toh(*((u_int32_t *)&cdb[2]));
	case 16:
		return be64toh(*((u_int64_t *)&cdb[2]));
	default:
		return -EINVAL;
	}
}

uint32_t tcmu_get_xfer_length(uint8_t *cdb)
{
	switch (tcmu_get_cdb_length(cdb)) {
	case 6:
		return cdb[4];
	case 10:
		return be16toh(*((uint16_t *)&cdb[7]));
	case 12:
		return be32toh(*((u_int32_t *)&cdb[6]));
	case 16:
		return be32toh(*((u_int32_t *)&cdb[10]));
	default:
		return -EINVAL;
	}
}

/*
 * Returns location of first mismatch between bytes in mem and the iovec.
 * If they are the same, return -1.
 */
off_t tcmu_compare_with_iovec(void *mem, struct iovec *iovec, size_t size)
{
	off_t mem_off;
	int ret;

	mem_off = 0;
	while (size) {
		size_t part = min(size, iovec->iov_len);

		ret = memcmp(mem + mem_off, iovec->iov_base, part);
		if (ret) {
			size_t pos;
			char *spos = mem + mem_off;
			char *dpos = iovec->iov_base;

			/*
			 * Data differed, this is assumed to be 'rare'
			 * so use a much more expensive byte-by-byte
			 * comparison to find out at which offset the
			 * data differs.
			 */
			for (pos = 0; pos < part && *spos++ == *dpos++;
			     pos++)
				;

			return pos + mem_off;
		}

		size -= part;
		mem_off += part;
		iovec++;
	}

	return -1;
}

/*
 * Consume an iovec. Count must not exceed the total iovec[] size.
 */
void tcmu_seek_in_iovec(struct iovec *iovec, size_t count)
{
	while (count) {
		if (count >= iovec->iov_len) {
			count -= iovec->iov_len;
			iovec->iov_len = 0;
			iovec++;
		} else {
			iovec->iov_base += count;
			iovec->iov_len -= count;
			count = 0;
		}
	}
}

size_t tcmu_iovec_length(struct iovec *iovec, size_t iov_cnt)
{
	size_t length = 0;

	while (iov_cnt) {
		length += iovec->iov_len;
		iovec++;
		iov_cnt--;
	}

	return length;
}

int tcmu_set_sense_data(uint8_t *sense_buf, uint8_t key, uint16_t asc_ascq,
			uint32_t *info)
{
	memset(sense_buf, 0, 18);
	sense_buf[0] = 0x70;	/* fixed, current */
	sense_buf[2] = key;
	sense_buf[7] = 0xa;
	sense_buf[12] = (asc_ascq >> 8) & 0xff;
	sense_buf[13] = asc_ascq & 0xff;
	if (info) {
		if (key == MISCOMPARE) {
			uint32_t val32 = htobe32(*info);

			memcpy(&sense_buf[3], &val32, 4);
			sense_buf[0] |= 0x80;
		} else if (key == NOT_READY) {
			uint16_t val16 = htobe16((uint16_t)*info);

			memcpy(&sense_buf[16], &val16, 2);
			sense_buf[15] |= 0x80;
		}
	}

	/*
	 * It's very common to set sense and return check condition.
	 * Returning this lets us do both in one go. Or, just ignore
	 * this and return scsi_status yourself.
	 */
	return SAM_STAT_CHECK_CONDITION;
}

/*
 * Zero iovec.
 */
void tcmu_zero_iovec(struct iovec *iovec, size_t iov_cnt)
{
	while (iov_cnt) {
		bzero(iovec->iov_base, iovec->iov_len);

		iovec++;
		iov_cnt--;
	}
}
/*
 * Copy data into an iovec, and consume the space in the iovec.
 *
 * Will truncate instead of overrunning the iovec.
 */
size_t tcmu_memcpy_into_iovec(
	struct iovec *iovec,
	size_t iov_cnt,
	void *src,
	size_t len)
{
	size_t copied = 0;

	while (len && iov_cnt) {
		size_t to_copy = min(iovec->iov_len, len);

		if (to_copy) {
			memcpy(iovec->iov_base, src + copied, to_copy);

			len -= to_copy;
			copied += to_copy;
			iovec->iov_base += to_copy;
			iovec->iov_len -= to_copy;
		}

		iovec++;
		iov_cnt--;
	}

	return copied;
}

/*
 * Copy data from an iovec, and consume the space in the iovec.
 */
size_t tcmu_memcpy_from_iovec(
	void *dest,
	size_t len,
	struct iovec *iovec,
	size_t iov_cnt)
{
	size_t copied = 0;

	while (len && iov_cnt) {
		size_t to_copy = min(iovec->iov_len, len);

		if (to_copy) {
			memcpy(dest + copied, iovec->iov_base, to_copy);

			len -= to_copy;
			copied += to_copy;
			iovec->iov_base += to_copy;
			iovec->iov_len -= to_copy;
		}

		iovec++;
		iov_cnt--;
	}

	return copied;
}

int tcmu_emulate_std_inquiry(
	struct tgt_port *port,
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	uint8_t buf[36];

	memset(buf, 0, sizeof(buf));

	buf[2] = 0x05; /* SPC-3 */
	buf[3] = 0x02; /* response data format */

	/*
	 * A Third-Party Copy (3PC)
	 *
	 * Enable the XCOPY
	 */
	buf[5] = 0x08;
	if (port)
		buf[5] |= port->grp->tpgs;


	buf[7] = 0x02; /* CmdQue */

	memcpy(&buf[8], "LIO-ORG ", 8);
	memset(&buf[16], 0x20, 16);
	memcpy(&buf[16], "TCMU device", 11);
	memcpy(&buf[32], "0002", 4);
	buf[4] = 31; /* Set additional length to 31 */

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, sizeof(buf));
	return SAM_STAT_GOOD;
}

/* This func from CCAN str/hex/hex.c. Public Domain */
static bool char_to_hex(unsigned char *val, char c)
{
	if (c >= '0' && c <= '9') {
		*val = c - '0';
		return true;
	}
	if (c >= 'a' && c <= 'f') {
		*val = c - 'a' + 10;
		return true;
	}
	if (c >= 'A' && c <= 'F') {
		*val = c - 'A' + 10;
		return true;
	}
	return false;
}

int tcmu_emulate_evpd_inquiry(
	struct tcmu_device *dev,
	struct tgt_port *port,
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	switch (cdb[2]) {
	case 0x0: /* Supported VPD pages */
	{
		char data[8];

		memset(data, 0, sizeof(data));

		/* data[1] (page code) already 0 */

		data[5] = 0x83;
		data[6] = 0xb0;
		data[7] = 0xb1;

		data[3] = 4;

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, sizeof(data));
		return SAM_STAT_GOOD;
	}
	break;
	case 0x83: /* Device identification */
	{
		char data[512];
		char *ptr;
		size_t used = 0;
		char *wwn;
		size_t len;
		uint16_t *tot_len = (uint16_t*) &data[2];

		memset(data, 0, sizeof(data));

		data[1] = 0x83;

		wwn = tcmu_get_wwn(dev);
		if (!wwn) {
			return tcmu_set_sense_data(sense, HARDWARE_ERROR,
						   ASC_INTERNAL_TARGET_FAILURE, NULL);
		}

		ptr = &data[4];

		/* 1/5: T10 Vendor id */
		ptr[0] = 2; /* code set: ASCII */
		ptr[1] = 1; /* identifier: T10 vendor id */
		memcpy(&ptr[4], "LIO-ORG ", 8);
		len = snprintf(&ptr[12], sizeof(data) - 16, "%s", wwn);

		ptr[3] = 8 + len + 1;
		used += (uint8_t)ptr[3] + 4;
		ptr += used;

		/* 2/5: NAA binary */
		ptr[0] = 1; /* code set: binary */
		ptr[1] = 3; /* identifier: NAA */
		ptr[3] = 16; /* body length for naa registered extended format */

		/*
		 * Set type 6 and use OpenFabrics IEEE Company ID: 00 14 05
		 */
		ptr[4] = 0x60;
		ptr[5] = 0x01;
		ptr[6] = 0x40;
		ptr[7] = 0x50;

		/*
		 * Fill in the rest with a binary representation of WWN
		 *
		 * This implementation only uses a nibble out of every byte of
		 * WWN, but this is what the kernel does, and it's nice for our
		 * values to match.
		 */
		char *p = wwn;
		bool next = true;
		int i = 7;
		for ( ; *p && i < 20; p++) {
			uint8_t val;

			if (!char_to_hex(&val, *p))
				continue;

			if (next) {
				next = false;
				ptr[i++] |= val;
			} else {
				next = true;
				ptr[i] = val << 4;
			}
		}

		used += 20;
		ptr += 20;

		/* 3/6: Vendor specific */
		ptr[0] = 2; /* code set: ASCII */
		ptr[1] = 0; /* identifier: vendor-specific */

		len = snprintf(&ptr[4], sizeof(data) - used - 4, "%s", dev->cfgstring);
		ptr[3] = len + 1;

		used += (uint8_t)ptr[3] + 4;
		ptr += (uint8_t)ptr[3] + 4;

		if (!port)
			goto finish_page83;

		/* 4/5: Relative target port ID */
		ptr[0] = port->proto_id << 4; /* proto id */
		ptr[0] |= 0x1; /* Code set: binary */
		ptr[1] = 0x80; /* PIV set */
		ptr[1] |= 0x10; /* Association: 1b assoc with target port */
		ptr[1] |= 0x4; /* Designator type: Relative target port ID */
		ptr[3] = 4;
		/* rel tgt port ID */
		ptr[6] = (port->rel_port_id >> 8) & 0xff;
		ptr[7] = port->rel_port_id & 0xff;
		used += 8;
		ptr += 8;

		/* 5/5: Target port group */
		ptr[0] = port->proto_id << 4; /* proto id */
		ptr[0] |= 0x1; /* Code set: binary */
		ptr[1] = 0x80; /* PIV set */
		ptr[1] |= 0x10; /* Association: 1b assoc with target port */
		ptr[1] |= 0x5; /* Designator type: target port group */
		ptr[3] = 4;
		/* tpg id */
		ptr[6] = (port->grp->id >> 8) & 0xff;
		ptr[7] = port->grp->id & 0xff;
		used += 8;

finish_page83:
		/* Done with descriptor list */

		*tot_len = htobe16(used);

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, used + 4);

		free(wwn);
		wwn = NULL;

		return SAM_STAT_GOOD;
	}
	break;
	case 0xb0: /* Block Limits */
	{
		char data[64];
		int block_size;
		int max_sectors;
		int max_xfer_length;
		uint16_t val16;
		uint32_t val32;

		memset(data, 0, sizeof(data));

		data[1] = 0xb0;

		val16 = htobe16(0x3c);
		memcpy(&data[2], &val16, 2);

		/*
		 * From SCSI Commands Reference Manual, section Block Limits
		 * VPD page (B0h)
		 *
		 * MAXIMUM COMPARE AND WRITE LENGTH: set to a non-zero value
		 * indicates the maximum value that the device server accepts
		 * in the NUMBER OF LOGICAL BLOCKS field in the COMPARE AND
		 * WRITE command.
		 *
		 * It should be less than or equal to MAXIMUM TRANSFER LENGTH.
		 */
		data[5] = 0x01;

		block_size = tcmu_get_attribute(dev, "hw_block_size");
		if (block_size < 0) {
			return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
						   ASC_INVALID_FIELD_IN_CDB, NULL);
		}

		max_sectors = tcmu_get_attribute(dev, "hw_max_sectors");
		if (max_sectors < 0) {
			return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
						   ASC_INVALID_FIELD_IN_CDB, NULL);
		}

		/* Convert from sectors to blocks */
		max_xfer_length = max_sectors / (block_size / SECTOR_SIZE);

		val32 = htobe32(max_xfer_length);
		/* Max xfer length */
		memcpy(&data[8], &val32, 4);
		/* Optimal xfer length */
		memcpy(&data[12], &val32, 4);

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, sizeof(data));

		return SAM_STAT_GOOD;
	}
	break;
	case 0xb1: /* Block Device Characteristics VPD page */
	{
		char data[64];
		uint16_t val16;

		memset(data, 0, sizeof(data));

		/*
		 * From spc-5 Revision 14, section 6.7.2 Standard INQUIRY data
		 * set the devive type to Direct access block device.
		 */
		data[0] = 0x00;

		/* PAGE CODE (B1h) */
		data[1] = 0xb1;

		/* PAGE LENGTH (003Ch)*/
		val16 = htobe16(0x003c);
		memcpy(&data[2], &val16, 2);

		return SAM_STAT_GOOD;
	}
	break;
	default:
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB, NULL);
	}
}

/*
 * Emulate INQUIRY(0x12)
 */
int tcmu_emulate_inquiry(
	struct tcmu_device *dev,
	struct tgt_port *port,
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	if (!(cdb[1] & 0x01)) {
		if (!cdb[2])
			return tcmu_emulate_std_inquiry(port, cdb, iovec,
							iov_cnt, sense);
		else
			return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
						   ASC_INVALID_FIELD_IN_CDB, NULL);
	} else {
		return tcmu_emulate_evpd_inquiry(dev, port, cdb, iovec, iov_cnt,
						 sense);
	}
}

int tcmu_emulate_test_unit_ready(
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	return SAM_STAT_GOOD;
}

int tcmu_emulate_read_capacity_10(
	uint64_t num_lbas,
	uint32_t block_size,
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	uint8_t buf[8];
	uint32_t val32;

	memset(buf, 0, sizeof(buf));

	if (num_lbas < 0x100000000ULL) {
		// Return the LBA of the last logical block, so subtract 1.
		val32 = htobe32(num_lbas-1);
	} else {
		// This lets the initiator know that he needs to use
		// Read Capacity(16).
		val32 = 0xffffffff;
	}

	memcpy(&buf[0], &val32, 4);

	val32 = htobe32(block_size);
	memcpy(&buf[4], &val32, 4);

	/* all else is zero */

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, sizeof(buf));

	return SAM_STAT_GOOD;
}

int tcmu_emulate_read_capacity_16(
	uint64_t num_lbas,
	uint32_t block_size,
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	uint8_t buf[32];
	uint64_t val64;
	uint32_t val32;

	memset(buf, 0, sizeof(buf));

	// Return the LBA of the last logical block, so subtract 1.
	val64 = htobe64(num_lbas-1);
	memcpy(&buf[0], &val64, 8);

	val32 = htobe32(block_size);
	memcpy(&buf[8], &val32, 4);

	/* all else is zero */

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, sizeof(buf));

	return SAM_STAT_GOOD;
}

int handle_cache_page(uint8_t *buf, size_t buf_len)
{
	if (buf_len < 20)
		return -1;

	buf[0] = 0x8;
	buf[1] = 0x12;
	buf[2] = 0x4; // WCE=1

	return 20;
}

static int handle_control_page(uint8_t *buf, size_t buf_len)
{
	if (buf_len < 12)
		return -1;

	buf[0] = 0x0a;
	buf[1] = 0x0a;

	/* From spc4r31, section 7.5.7 Control mode Page
	 *
	 * GLTSD = 1: because we don't implicitly save log parameters
	 *
	 * A global logging target save disable (GLTSD) bit set to
	 * zero specifies that the logical unit implicitly saves, at
	 * vendor specific intervals, each log parameter in which the
	 * TSD bit (see 7.3) is set to zero. A GLTSD bit set to one
	 * specifies that the logical unit shall not implicitly save
	 * any log parameters.
	 */
	buf[2] = 0x02;

	/* From spc4r31, section 7.5.7 Control mode Page
	 *
	 * TAS = 1: Currently not settable by tcmu. Using the LIO default
	 *
	 * A task aborted status (TAS) bit set to zero specifies that
	 * aborted commands shall be terminated by the device server
	 * without any response to the application client. A TAS bit
	 * set to one specifies that commands aborted by the actions
	 * of an I_T nexus other than the I_T nexus on which the command
	 * was received shall be completed with TASK ABORTED status
	 */
	buf[5] = 0x40;

	/* From spc4r31, section 7.5.7 Control mode Page
	 *
	 * BUSY TIMEOUT PERIOD: Currently is unlimited
	 *
	 * The BUSY TIMEOUT PERIOD field specifies the maximum time, in
	 * 100 milliseconds increments, that the application client allows
	 * for the device server to return BUSY status for unanticipated
	 * conditions that are not a routine part of commands from the
	 * application client. This value may be rounded down as defined
	 * in 5.4(the Parameter rounding section).
	 *
	 * A 0000h value in this field is undefined by this standard.
	 * An FFFFh value in this field is defined as an unlimited period.
	 */
	buf[8] = 0xff;
	buf[9] = 0xff;

	return 12;
}


static struct {
	uint8_t page;
	uint8_t subpage;
	int (*get)(uint8_t *buf, size_t buf_len);
} modesense_handlers[] = {
	{0x8, 0, handle_cache_page},
	{0xa, 0, handle_control_page},
};

/*
 * Handle MODE_SENSE(6) and MODE_SENSE(10).
 *
 * For TYPE_DISK only.
 */
int tcmu_emulate_mode_sense(
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	bool sense_ten = (cdb[0] == MODE_SENSE_10);
	uint8_t page_code = cdb[2] & 0x3f;
	uint8_t subpage_code = cdb[3];
	size_t alloc_len = tcmu_get_xfer_length(cdb);
	int i;
	int ret;
	size_t used_len;
	uint8_t buf[512];
	bool got_sense = false;

	memset(buf, 0, sizeof(buf));

	/* Mode parameter header. Mode data length filled in at the end. */
	used_len = sense_ten ? 8 : 4;

	/* Don't fill in device-specific parameter */
	/* This helper fn doesn't support sw write protect (SWP) */

	/* Don't report block descriptors */

	if (page_code == 0x3f) {
		got_sense = true;
		for (i = 0; i < ARRAY_SIZE(modesense_handlers); i++) {
			ret = modesense_handlers[i].get(&buf[used_len], sizeof(buf) - used_len);
			if (ret <= 0)
				break;

			if  (sense_ten && (used_len + ret >= 255))
				break;

			if (used_len + ret > alloc_len)
				break;

			used_len += ret;
		}
	}
	else {
		for (i = 0; i < ARRAY_SIZE(modesense_handlers); i++) {
			if (page_code == modesense_handlers[i].page
			    && subpage_code == modesense_handlers[i].subpage) {
				ret = modesense_handlers[i].get(&buf[used_len],
								sizeof(buf) - used_len);
				if (ret <= 0)
					break;

				if  (!sense_ten && (used_len + ret >= 255))
					break;

				if (used_len + ret > alloc_len)
					break;

				used_len += ret;
				got_sense = true;
				break;
			}
		}
	}

	if (!got_sense)
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
				    ASC_INVALID_FIELD_IN_CDB, NULL);

	if (sense_ten) {
		uint16_t *ptr = (uint16_t*) buf;
		*ptr = htobe16(used_len - 2);
	}
	else {
		buf[0] = used_len - 1;
	}

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, sizeof(buf));

	return SAM_STAT_GOOD;
}

/*
 * Handle MODE_SELECT(6) and MODE_SELECT(10).
 *
 * For TYPE_DISK only.
 */
int tcmu_emulate_mode_select(
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	bool select_ten = (cdb[0] == MODE_SELECT_10);
	uint8_t page_code = cdb[2] & 0x3f;
	uint8_t subpage_code = cdb[3];
	size_t alloc_len = tcmu_get_xfer_length(cdb);
	int i;
	int ret = 0;
	size_t hdr_len = select_ten ? 8 : 4;
	uint8_t buf[512];
	uint8_t in_buf[512];
	bool got_sense = false;

	if (!alloc_len)
		return SAM_STAT_GOOD;

	if (tcmu_memcpy_from_iovec(in_buf, sizeof(in_buf), iovec, iov_cnt) >= sizeof(in_buf))
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_PARAMETER_LIST_LENGTH_ERROR, NULL);

	/* Abort if !pf or sp */
	if (!(cdb[1] & 0x10) || (cdb[1] & 0x01))
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB, NULL);

	memset(buf, 0, sizeof(buf));
	for (i = 0; i < ARRAY_SIZE(modesense_handlers); i++) {
		if (page_code == modesense_handlers[i].page
		    && subpage_code == modesense_handlers[i].subpage) {
			ret = modesense_handlers[i].get(&buf[hdr_len],
							sizeof(buf) - hdr_len);
			if (ret <= 0)
				return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
							   ASC_INVALID_FIELD_IN_CDB, NULL);

			if  (!select_ten && (hdr_len + ret >= 255))
				return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
							   ASC_INVALID_FIELD_IN_CDB, NULL);

			got_sense = true;
			break;
		}
	}

	if (!got_sense)
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB, NULL);

	if (alloc_len < (hdr_len + ret))
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_PARAMETER_LIST_LENGTH_ERROR, NULL);

	/* Verify what was selected is identical to what sense returns, since we
	   don't support actually setting anything. */
	if (memcmp(&buf[hdr_len], &in_buf[hdr_len], ret))
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_PARAMETER_LIST, NULL);

	return SAM_STAT_GOOD;
}

int tcmu_emulate_start_stop(struct tcmu_device *dev, uint8_t *cdb,
			    uint8_t *sense)
{
	if ((cdb[4] >> 4) & 0xf)
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB, NULL);

	/* Currently, we don't allow ejecting the medium, so we're
	 * ignoring the FBO_PREV_EJECT flag, but it may turn out that
	 * initiators do not handle this well, so we may have to change
	 * this behavior.
	 */

	if (!(cdb[4] & 0x01))
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB, NULL);

	return SAM_STAT_GOOD;
}

#define CDB_TO_BUF_SIZE(bytes) ((bytes) * 3 + 1)
#define CDB_FIX_BYTES 64 /* 64 bytes for default */
#define CDB_FIX_SIZE CDB_TO_BUF_SIZE(CDB_FIX_BYTES)
void tcmu_cdb_debug_info(const struct tcmulib_cmd *cmd)
{
	int i, n, bytes;
	char fix[CDB_FIX_SIZE], *buf;

	buf = fix;

	bytes = tcmu_get_cdb_length(cmd->cdb);
	if (bytes > CDB_FIX_SIZE) {
		buf = malloc(CDB_TO_BUF_SIZE(bytes));
		if (!buf) {
			tcmu_err("out of memory\n");
			return;
		}
	}

	for (i = 0, n = 0; i < bytes; i++) {
		n += sprintf(buf + n, "%x ", cmd->cdb[i]);
	}
	sprintf(buf + n, "\n");

	tcmu_dbg_scsi_cmd(buf);

	if (bytes > CDB_FIX_SIZE)
		free(buf);
}
