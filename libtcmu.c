/*
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#define _GNU_SOURCE
#define _BITS_UIO_H
#include <memory.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <dirent.h>
#include <scsi/scsi.h>


#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/mngt.h>
#include <libnl3/netlink/genl/ctrl.h>

#include "target_core_user_local.h"
#include "libtcmu.h"
#include "libtcmu_log.h"
#include "libtcmu_priv.h"
#include "libtcmu_aio.h"
#include "tcmur_cmd_handler.h"
#include "libtcmu_device.h"

#define TCMU_NL_VERSION 2

static struct nla_policy tcmu_attr_policy[TCMU_ATTR_MAX+1] = {
	[TCMU_ATTR_DEVICE]	= { .type = NLA_STRING },
	[TCMU_ATTR_MINOR]	= { .type = NLA_U32 },
	[TCMU_ATTR_CMD_STATUS]	= { .type = NLA_S32 },
	[TCMU_ATTR_DEVICE_ID]	= { .type = NLA_U32 },
	[TCMU_ATTR_DEV_CFG]	= { .type = NLA_STRING },
	[TCMU_ATTR_DEV_SIZE]	= { .type = NLA_U64 },
	[TCMU_ATTR_WRITECACHE]	= { .type = NLA_U8 },
	[TCMU_ATTR_SUPP_KERN_CMD_REPLY] = { .type = NLA_U8 },
};

static int add_device(struct tcmulib_context *ctx, char *dev_name,
		      char *cfgstring, bool reopen);
static void remove_device(struct tcmulib_context *ctx, char *dev_name,
			  char *cfgstring, bool should_block);
static int handle_netlink(struct nl_cache_ops *unused, struct genl_cmd *cmd,
			  struct genl_info *info, void *arg);

static struct genl_cmd tcmu_cmds[] = {
	{
		.c_id		= TCMU_CMD_ADDED_DEVICE,
		.c_name		= "ADDED DEVICE",
		.c_msg_parser	= handle_netlink,
		.c_maxattr	= TCMU_ATTR_MAX,
		.c_attr_policy	= tcmu_attr_policy,
	},
	{
		.c_id		= TCMU_CMD_REMOVED_DEVICE,
		.c_name		= "REMOVED DEVICE",
		.c_msg_parser	= handle_netlink,
		.c_maxattr	= TCMU_ATTR_MAX,
		.c_attr_policy	= tcmu_attr_policy,
	},
	{
		.c_id		= TCMU_CMD_RECONFIG_DEVICE,
		.c_name		= "RECONFIG DEVICE",
		.c_msg_parser	= handle_netlink,
		.c_maxattr	= TCMU_ATTR_MAX,
		.c_attr_policy	= tcmu_attr_policy,
	},
};

static struct genl_ops tcmu_ops = {
	.o_name		= "TCM-USER",
	.o_cmds		= tcmu_cmds,
	.o_ncmds	= ARRAY_SIZE(tcmu_cmds),
};

static int send_netlink_reply(struct tcmulib_context *ctx, int reply_cmd,
			      uint32_t dev_id, int status)
{
	struct nl_sock *sock = ctx->nl_sock;
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;

	msg = nlmsg_alloc();
	if (!msg)
		return ret;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, tcmu_ops.o_id,
			  0, 0, reply_cmd, TCMU_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nla_put_s32(msg, TCMU_ATTR_CMD_STATUS, status);
	if (ret < 0)
		goto free_msg;

	ret = nla_put_u32(msg, TCMU_ATTR_DEVICE_ID, dev_id);
	if (ret < 0)
		goto free_msg;

	/* Ignore ack. There is nothing we can do. */
	ret = nl_send_auto(sock, msg);
free_msg:
	nlmsg_free(msg);

	if (ret < 0)
		tcmu_err("Could not send netlink cmd %d\n", reply_cmd);
	return ret;
}

static struct tcmu_device *
lookup_dev_by_name(struct tcmulib_context *ctx, char *dev_name, int *index)
{
	struct tcmu_device **dev_ptr;
	struct tcmu_device *dev;
	int i = 0;

	*index = 0;

	darray_foreach(dev_ptr, ctx->devices) {
		dev = *dev_ptr;

		if (!strcmp(dev->dev_name, dev_name)) {
			*index = i;
			return dev;
		}
		i++;
	}

	return NULL;
}

static int reconfig_device(struct tcmulib_context *ctx, char *dev_name,
			   struct genl_info *info)
{
	struct tcmu_device *dev;
	struct tcmulib_cfg_info cfg;
	int i, ret;

	memset(&cfg, 0, sizeof(cfg));

	dev = lookup_dev_by_name(ctx, dev_name, &i);
	if (!dev) {
		tcmu_err("Could not reconfigure device %s: not found.\n",
			 dev_name);
		return -ENODEV;
	}

	if (info->attrs[TCMU_ATTR_DEV_CFG]) {
		cfg.type = TCMULIB_CFG_DEV_CFGSTR;
		cfg.data.dev_cfgstring =
				nla_get_string(info->attrs[TCMU_ATTR_DEV_CFG]);
	} else if (info->attrs[TCMU_ATTR_DEV_SIZE]) {
		cfg.type = TCMULIB_CFG_DEV_SIZE;
		cfg.data.dev_size = nla_get_u64(info->attrs[TCMU_ATTR_DEV_SIZE]);
	} else if (info->attrs[TCMU_ATTR_WRITECACHE]) {
		cfg.type = TCMULIB_CFG_WRITE_CACHE;
		cfg.data.write_cache =
				nla_get_u8(info->attrs[TCMU_ATTR_WRITECACHE]);
	} else {
		tcmu_dev_err(dev,
			     "Unknown reconfig attr. Try updating libtcmu.\n");
		return -EOPNOTSUPP;
	}

	ret = tcmu_dev_reconfig(dev, &cfg);
	if (ret < 0) {
		tcmu_dev_err(dev, "Handler reconfig failed with error %d.\n",
			     ret);
		return ret;
	}

	return 0;
}

static int handle_netlink(struct nl_cache_ops *unused, struct genl_cmd *cmd,
			  struct genl_info *info, void *arg)
{
	struct tcmulib_context *ctx = arg;
	int ret, reply_cmd, version = info->genlhdr->version;
	char buf[32];

	tcmu_dbg("cmd %d. Got header version %d. Supported %d.\n",
		 cmd->c_id, info->genlhdr->version, TCMU_NL_VERSION);

	if (!info->attrs[TCMU_ATTR_MINOR] || !info->attrs[TCMU_ATTR_DEVICE]) {
		tcmu_err("TCMU_ATTR_MINOR or TCMU_ATTR_DEVICE not set, dropping netlink command.\n");
		return 0;
	}

	if (version > 1 && !info->attrs[TCMU_ATTR_DEVICE_ID]) {
		tcmu_err("TCMU_ATTR_DEVICE_ID not set in v%d cmd %d, dropping netink command.\n", version, cmd->c_id);
		return 0;
	}

	snprintf(buf, sizeof(buf), "uio%d", nla_get_u32(info->attrs[TCMU_ATTR_MINOR]));

	switch (cmd->c_id) {
	case TCMU_CMD_ADDED_DEVICE:
		reply_cmd = TCMU_CMD_ADDED_DEVICE_DONE;
		ret = add_device(ctx, buf,
				 nla_get_string(info->attrs[TCMU_ATTR_DEVICE]),
				 false);
		break;
	case TCMU_CMD_REMOVED_DEVICE:
		reply_cmd = TCMU_CMD_REMOVED_DEVICE_DONE;
		remove_device(ctx, buf,
			      nla_get_string(info->attrs[TCMU_ATTR_DEVICE]),
			      false);
		ret = 0;
		break;
	case TCMU_CMD_RECONFIG_DEVICE:
		reply_cmd = TCMU_CMD_RECONFIG_DEVICE_DONE;
		ret = reconfig_device(ctx, buf, info);
		break;
	default:
		tcmu_err("Unknown netlink command %d. Netlink header received version %d. libtcmu supports %d\n",
			 cmd->c_id, version, TCMU_NL_VERSION);
		return -EOPNOTSUPP;
	}

	if (version > 1)
		ret = send_netlink_reply(ctx, reply_cmd,
				nla_get_u32(info->attrs[TCMU_ATTR_DEVICE_ID]),
				ret);

	return ret;
}

static int set_genl_features(struct nl_sock *sock)
{
	struct nl_msg *msg;
	void *hdr;
	int ret = -ENOMEM;

	msg = nlmsg_alloc();
	if (!msg)
		return ret;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, tcmu_ops.o_id,
			  0, NLM_F_ACK, TCMU_CMD_SET_FEATURES, TCMU_NL_VERSION);
	if (!hdr)
		goto free_msg;

	ret = nla_put_u8(msg, TCMU_ATTR_SUPP_KERN_CMD_REPLY, 1);
	if (ret < 0)
		goto free_msg;

	ret = nl_send_sync(sock, msg);
	goto done;

free_msg:
	nlmsg_free(msg);

done:
	if (ret < 0)
		tcmu_err("Could not set features. Error %d\n", ret);

	return ret;
}

static struct nl_sock *setup_netlink(struct tcmulib_context *ctx)
{
	struct nl_sock *sock;
	int ret;

	sock = nl_socket_alloc();
	if (!sock) {
		tcmu_err("couldn't alloc socket\n");
		return NULL;
	}

	nl_socket_disable_seq_check(sock);

	nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, genl_handle_msg, ctx);

	ret = genl_connect(sock);
	if (ret < 0) {
		tcmu_err("couldn't connect\n");
		goto err_free;
	}

	ret = genl_register_family(&tcmu_ops);
	if (ret < 0) {
		tcmu_err("couldn't register family\n");
		goto err_close;
	}

	ret = genl_ops_resolve(sock, &tcmu_ops);
	if (ret < 0) {
		tcmu_err("couldn't resolve ops, is target_core_user.ko loaded?\n");
		goto err_unregister;
	}

	ret = genl_ctrl_resolve_grp(sock, "TCM-USER", "config");
	if (ret < 0) {
		tcmu_err("couldn't resolve netlink family group, is target_core_user.ko loaded?\n");
		goto err_unregister;
	}

	ret = nl_socket_add_membership(sock, ret);
	if (ret < 0) {
		tcmu_err("couldn't add membership\n");
		goto err_unregister;
	}

	/*
	 * Could be a older kernel. Ignore failure and just work in degraded
	 * mode.
	 */
	set_genl_features(sock);

	return sock;

err_unregister:
	genl_unregister_family(&tcmu_ops);
err_close:
	nl_close(sock);
err_free:
	nl_socket_free(sock);

	return NULL;
}

static void teardown_netlink(struct nl_sock *sock)
{
	int ret;

	ret = genl_unregister_family(&tcmu_ops);
	if (ret != 0) {
		tcmu_err("genl_unregister_family failed, %d\n", ret);
	}

	nl_close(sock);
	nl_socket_free(sock);
}

static struct tcmulib_handler *find_handler(struct tcmulib_context *ctx,
					    char *cfgstring)
{
	struct tcmulib_handler *handler;
	size_t len;
	char *found_at;

	found_at = strchrnul(cfgstring, '/');
	len = found_at - cfgstring;

	darray_foreach(handler, ctx->handlers) {
		if (!strncmp(cfgstring, handler->subtype, len))
		    return handler;
	}

	return NULL;
}

void tcmu_flush_device(struct tcmu_device *dev)
{
	struct tcmu_mailbox *mb = dev->map;

	tcmu_dev_dbg(dev, "waiting for ring to clear\n");
	while (mb->cmd_head != mb->cmd_tail)
		usleep(50000);
	tcmu_dev_dbg(dev, "ring clear\n");
}

void tcmu_block_device(struct tcmu_device *dev)
{
	int rc;

	if (!tcmu_cfgfs_file_is_supported(dev, "action")) {
		tcmu_dev_warn(dev, "Kernel does not support the block_dev action.\n");
		return;
	}

	/*
	 * Afer we set block_dev=1 the kernel will have freed
	 * cmds in the qfull queue and no new commands will be sent to
	 * us.
	 */
	tcmu_dev_dbg(dev, "blocking kernel device\n");
	rc = tcmu_exec_cfgfs_dev_action(dev, "block_dev", 1);
	if (rc) {
		tcmu_dev_warn(dev, "Could not block device %d.\n", rc);
		return;
	}
	tcmu_dev_dbg(dev, "block done\n")
}

void tcmu_unblock_device(struct tcmu_device *dev)
{
	int rc;

	if (!tcmu_cfgfs_file_is_supported(dev, "action")) {
		tcmu_dev_warn(dev, "Kernel does not support the block_dev action.\n");
		return;
	}

	tcmu_dev_dbg(dev, "unblocking kernel device\n");
	rc = tcmu_exec_cfgfs_dev_action(dev, "block_dev", 0);
	if (rc) {
		tcmu_dev_warn(dev, "Could not block device %d.\n", rc);
		return;
	}
	tcmu_dev_dbg(dev, "unblock done\n");
}

static int add_device(struct tcmulib_context *ctx, char *dev_name,
		      char *cfgstring, bool reopen)
{
	struct tcmu_device *dev;
	struct tcmu_mailbox *mb;
	char str_buf[256];
	int fd;
	int ret;
	char *ptr, *oldptr;
	char *reason = NULL;
	int len;

	dev = calloc(1, sizeof(*dev));
	if (!dev) {
		tcmu_err("calloc failed in add_device\n");
		return -ENOMEM;
	}

	snprintf(dev->dev_name, sizeof(dev->dev_name), "%s", dev_name);

	oldptr = cfgstring;
	ptr = strchr(oldptr, '/');
	if (!ptr) {
		tcmu_err("invalid cfgstring\n");
		goto err_free;
	}

	if (strncmp(cfgstring, "tcm-user", ptr-oldptr)) {
		tcmu_err("invalid cfgstring\n");
		goto err_free;
	}

	/* Get HBA name */
	oldptr = ptr+1;
	ptr = strchr(oldptr, '/');
	if (!ptr) {
		tcmu_err("invalid cfgstring\n");
		goto err_free;
	}
	len = ptr-oldptr;
	snprintf(dev->tcm_hba_name, sizeof(dev->tcm_hba_name), "user_%.*s", len, oldptr);

	/* Get device name */
	oldptr = ptr+1;
	ptr = strchr(oldptr, '/');
	if (!ptr) {
		tcmu_err("invalid cfgstring\n");
		goto err_free;
	}
	len = ptr-oldptr;
	snprintf(dev->tcm_dev_name, sizeof(dev->tcm_dev_name), "%.*s", len, oldptr);

	/* The rest is the handler-specific cfgstring */
	oldptr = ptr+1;
	ptr = strchr(oldptr, '/');
	snprintf(dev->cfgstring, sizeof(dev->cfgstring), "%s", oldptr);

	dev->handler = find_handler(ctx, dev->cfgstring);
	if (!dev->handler) {
		tcmu_err("could not find handler for %s\n", dev->dev_name);
		goto err_free;
	}

	if (dev->handler->check_config &&
	    !dev->handler->check_config(dev->cfgstring, &reason)) {
		/* It may be handled by other handlers */
		tcmu_err("check_config failed for %s because of %s\n", dev->dev_name, reason);
		free(reason);
		goto err_free;
	}

	if (reopen) {
		/*
		 * We might not have cleanly shutdown and IO might be
		 * running in the kernel or have timed out. Block the device
		 * so new IO is stopped, and reset the ring so we can start
		 * from a fresh slate. We will unblock below when we are
		 * completely setup.
		 */
		tcmu_block_device(dev);
		/*
		 * Force a retry of the outstanding commands.
		 */
		if (tcmu_cfgfs_file_is_supported(dev, "action")) {
			ret = tcmu_exec_cfgfs_dev_action(dev, "reset_ring", 1);
			if (ret)
				tcmu_dev_err(dev, "Could not reset ring %d.\n", ret);
		}
	}

	snprintf(str_buf, sizeof(str_buf), "/dev/%s", dev_name);

	dev->fd = open(str_buf, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (dev->fd == -1) {
		tcmu_err("could not open %s\n", str_buf);
		goto err_unblock;
	}

	snprintf(str_buf, sizeof(str_buf), "/sys/class/uio/%s/maps/map0/size", dev->dev_name);
	fd = open(str_buf, O_RDONLY);
	if (fd == -1) {
		tcmu_err("could not open %s\n", str_buf);
		goto err_fd_close;
	}

	ret = read(fd, str_buf, sizeof(str_buf));
	close(fd);
	if (ret <= 0) {
		tcmu_err("could not read size of map0\n");
		goto err_fd_close;
	}
	str_buf[ret-1] = '\0'; /* null-terminate and chop off the \n */

	dev->map_len = strtoull(str_buf, NULL, 0);
	if (dev->map_len == ULLONG_MAX) {
		tcmu_err("could not get map length\n");
		goto err_fd_close;
	}

	dev->map = mmap(NULL, dev->map_len, PROT_READ|PROT_WRITE, MAP_SHARED, dev->fd, 0);
	if (dev->map == MAP_FAILED) {
		tcmu_err("could not mmap: %m\n");
		goto err_fd_close;
	}

	mb = dev->map;
	if (mb->version != KERN_IFACE_VER) {
		tcmu_err("Kernel interface version mismatch: wanted %d got %d\n",
			KERN_IFACE_VER, mb->version);
		goto err_munmap;
	}

	dev->cmd_tail = mb->cmd_tail;
	dev->ctx = ctx;

	ret = tcmu_dev_added(dev);
	if (ret != 0) {
		tcmu_err("handler open failed for %s\n", dev->dev_name);
		goto err_munmap;
	}

	darray_append(ctx->devices, dev);

	if (reopen)
		tcmu_unblock_device(dev);

	return 0;

err_munmap:
	munmap(dev->map, dev->map_len);
err_fd_close:
	close(dev->fd);
err_unblock:
	if (reopen)
		tcmu_unblock_device(dev);
err_free:
	free(dev);

	return -ENOENT;
}

static void close_devices(struct tcmulib_context *ctx)
{
	struct tcmu_device **dev_ptr;
	struct tcmu_device *dev;
	char *cfgstring = "";

	darray_foreach_reverse(dev_ptr, ctx->devices) {
		dev = *dev_ptr;
		remove_device(ctx, dev->dev_name, cfgstring, true);
	}
}

static void remove_device(struct tcmulib_context *ctx, char *dev_name,
			  char *cfgstring, bool should_block)
{
	struct tcmu_device *dev;
	int i, ret;

	dev = lookup_dev_by_name(ctx, dev_name, &i);
	if (!dev) {
		tcmu_err("Could not remove device %s: not found.\n", dev_name);
		return;
	}

	/*
	 * If called through nl, IO will be stopped. If called by a
	 * app/daemon, IO might be runnning. Try to do a ordered
	 * shutdown and allow IO to complete normally.
	 */
	if (should_block) {
		tcmu_block_device(dev);
		tcmu_flush_device(dev);
	}

	darray_remove(ctx->devices, i);

	tcmu_dev_removed(dev);

	ret = close(dev->fd);
	if (ret != 0) {
		tcmu_err("could not close device fd %s: %d\n", dev_name, errno);
	}
	ret = munmap(dev->map, dev->map_len);
	if (ret != 0) {
		tcmu_err("could not unmap device %s: %d\n", dev_name, errno);
	}

	if (should_block)
		tcmu_unblock_device(dev);

	tcmu_dev_dbg(dev, "removed from tcmulib.\n");
	free(dev);
}

static int read_uio_name(const char *uio_dev, char **dev_name)
{
	int fd;
	char *tmp_path;
	int ret = -1;
	char buf[PATH_MAX] = {'\0'};

	if (asprintf(&tmp_path, "/sys/class/uio/%s/name", uio_dev) == -1)
		return -1;

	fd = open(tmp_path, O_RDONLY);
	if (fd == -1) {
		tcmu_err("could not open %s\n", tmp_path);
		goto free_path;
	}

	ret = read(fd, buf, sizeof(buf));
	if (ret <= 0 || ret >= sizeof(buf)) {
		tcmu_err("read of %s had issues\n", tmp_path);
		goto close;
	}

	buf[ret-1] = '\0'; /* null-terminate and chop off the \n */

	*dev_name = strdup(buf);

	ret = 0;

close:
	close(fd);
free_path:
	free(tmp_path);
	return ret;
}

static int is_uio(const struct dirent *dirent)
{
	char *dev_name = NULL;
	ssize_t ret = 0;

	if (strncmp(dirent->d_name, "uio", 3))
		return 0;

	if (read_uio_name(dirent->d_name, &dev_name))
		goto out;

	/* we only want uio devices whose name is a format we expect */
	if (strncmp(dev_name, "tcm-user", 8))
		goto out;

	ret = 1;

out:
	if (dev_name)
		free(dev_name);
	return ret;
}

static int open_devices(struct tcmulib_context *ctx)
{
	struct dirent **dirent_list;
	int num_devs;
	int num_good_devs = 0;
	int i;

	num_devs = scandir("/dev", &dirent_list, is_uio, alphasort);
	if (num_devs == -1)
		return -1;

	for (i = 0; i < num_devs; i++) {
		char *dev_name = NULL;

		if (read_uio_name(dirent_list[i]->d_name, &dev_name))
			continue;

		if (add_device(ctx, dirent_list[i]->d_name, dev_name, true) < 0) {
			free (dev_name);
			continue;
		}
		free(dev_name);

		num_good_devs++;
	}

	for (i = 0; i < num_devs; i++)
		free(dirent_list[i]);
	free(dirent_list);

	return num_good_devs;
}

static void release_resources(struct tcmulib_context *ctx)
{
	teardown_netlink(ctx->nl_sock);
	darray_free(ctx->handlers);
	darray_free(ctx->devices);
	free(ctx);
}

struct tcmulib_context *tcmulib_initialize(
	struct tcmulib_handler *handlers,
	size_t handler_count)
{
	struct tcmulib_context *ctx;
	int ret;
	int i;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->nl_sock = setup_netlink(ctx);
	if (!ctx->nl_sock) {
		free(ctx);
		return NULL;
	}

	darray_init(ctx->handlers);
	darray_init(ctx->devices);

	for (i = 0; i < handler_count; i++) {
		struct tcmulib_handler handler = handlers[i];
		handler.ctx = ctx;
		darray_append(ctx->handlers, handler);
	}

	ret = open_devices(ctx);
	if (ret < 0) {
		release_resources(ctx);
		return NULL;
	}

	return ctx;
}

void tcmulib_close(struct tcmulib_context *ctx)
{
	close_devices(ctx);
	release_resources(ctx);
}

int tcmulib_get_master_fd(struct tcmulib_context *ctx)
{
	return nl_socket_get_fd(ctx->nl_sock);
}

int tcmulib_master_fd_ready(struct tcmulib_context *ctx)
{
	return nl_recvmsgs_default(ctx->nl_sock);
}

void *tcmu_get_daemon_dev_private(struct tcmu_device *dev)
{
	return dev->d_private;
}

void tcmu_set_daemon_dev_private(struct tcmu_device *dev, void *private)
{
	dev->d_private = private;
}

void *tcmu_get_dev_private(struct tcmu_device *dev)
{
	return dev->hm_private;
}

void tcmu_set_dev_private(struct tcmu_device *dev, void *private)
{
	dev->hm_private = private;
}

void tcmu_set_dev_num_lbas(struct tcmu_device *dev, uint64_t num_lbas)
{
	dev->num_lbas = num_lbas;
}

uint64_t tcmu_get_dev_num_lbas(struct tcmu_device *dev)
{
	return dev->num_lbas;
}

/**
 * tcmu_update_num_lbas - Update num LBAs based on the new size.
 * @dev: tcmu device to update
 * @new_size: new device size in bytes
 */
int tcmu_update_num_lbas(struct tcmu_device *dev, uint64_t new_size)
{
	if (!new_size)
		return -EINVAL;

	tcmu_set_dev_num_lbas(dev, new_size / tcmu_get_dev_block_size(dev));
	return 0;
}

void tcmu_set_dev_block_size(struct tcmu_device *dev, uint32_t block_size)
{
	dev->block_size = block_size;
}

uint32_t tcmu_get_dev_block_size(struct tcmu_device *dev)
{
	return dev->block_size;
}

/**
 * tcmu_set_dev_max_xfer_len - set device's max command size
 * @dev: tcmu device
 * @len: max transfer length in block_size sectors
 */
void tcmu_set_dev_max_xfer_len(struct tcmu_device *dev, uint32_t len)
{
	dev->max_xfer_len = len;
}

uint32_t tcmu_get_dev_max_xfer_len(struct tcmu_device *dev)
{
	return dev->max_xfer_len;
}

/**
 * tcmu_set/get_dev_opt_unmap_gran - set/get device's optimal unmap granularity
 * @dev: tcmu device
 * @len: optimal unmap granularity length in block_size sectors
 */
void tcmu_set_dev_opt_unmap_gran(struct tcmu_device *dev, uint32_t len)
{
	dev->opt_unmap_gran = len;
}

uint32_t tcmu_get_dev_opt_unmap_gran(struct tcmu_device *dev)
{
	return dev->opt_unmap_gran;
}

/**
 * tcmu_set/get_dev_unmap_gran_align - set/get device's unmap granularity alignment
 * @dev: tcmu device
 * @len: unmap granularity alignment length in block_size sectors
 */
void tcmu_set_dev_unmap_gran_align(struct tcmu_device *dev, uint32_t len)
{
	dev->unmap_gran_align = len;
}

uint32_t tcmu_get_dev_unmap_gran_align(struct tcmu_device *dev)
{
	return dev->unmap_gran_align;
}

void tcmu_set_dev_write_cache_enabled(struct tcmu_device *dev, bool enabled)
{
	dev->write_cache_enabled = enabled;
}

bool tcmu_get_dev_write_cache_enabled(struct tcmu_device *dev)
{
	return dev->write_cache_enabled;
}

void tcmu_set_dev_solid_state_media(struct tcmu_device *dev, bool solid_state)
{
	dev->solid_state_media = solid_state;
}

bool tcmu_get_dev_solid_state_media(struct tcmu_device *dev)
{
	return dev->solid_state_media;
}

int tcmu_get_dev_fd(struct tcmu_device *dev)
{
	return dev->fd;
}

char *tcmu_get_dev_cfgstring(struct tcmu_device *dev)
{
	return dev->cfgstring;
}

struct tcmulib_handler *tcmu_get_dev_handler(struct tcmu_device *dev)
{
	return dev->handler;
}

struct tcmulib_backstore_handler *tcmu_get_runner_handler(struct tcmu_device *dev)
{
	struct tcmulib_handler *handler = tcmu_get_dev_handler(dev);

	return handler->hm_private;
}

static inline struct tcmu_cmd_entry *
device_cmd_head(struct tcmu_device *dev)
{
	struct tcmu_mailbox *mb = dev->map;

	return (struct tcmu_cmd_entry *) ((char *) mb + mb->cmdr_off + mb->cmd_head);
}

static inline struct tcmu_cmd_entry *
device_cmd_tail(struct tcmu_device *dev)
{
	struct tcmu_mailbox *mb = dev->map;

	return (struct tcmu_cmd_entry *) ((char *) mb + mb->cmdr_off + dev->cmd_tail);
}

/* update the tcmu_device's tail */
#define TCMU_UPDATE_DEV_TAIL(dev, mb, ent) \
do { \
	dev->cmd_tail = (dev->cmd_tail + tcmu_hdr_get_len((ent)->hdr.len_op)) % mb->cmdr_size; \
} while (0)

struct tcmulib_cmd *tcmulib_get_next_command(struct tcmu_device *dev)
{
	struct tcmu_mailbox *mb = dev->map;
	struct tcmu_cmd_entry *ent;

	while ((ent = device_cmd_tail(dev)) != device_cmd_head(dev)) {

		switch (tcmu_hdr_get_op(ent->hdr.len_op)) {
		case TCMU_OP_PAD:
			/* do nothing */
			break;
		case TCMU_OP_CMD: {
			int i;
			struct tcmulib_cmd *cmd;
			uint8_t *cdb = (uint8_t *) mb + ent->req.cdb_off;
			int cdb_len = tcmu_get_cdb_length(cdb);

			if (cdb_len < 0) {
				/*
				 * This should never happen so just drop cmd
				 * for now instead of adding a lock in the
				 * main IO path.
				 */
				break;
			}

			/* Alloc memory for cmd itself, iovec and cdb */
			cmd = malloc(sizeof(*cmd) + sizeof(*cmd->iovec) * ent->req.iov_cnt + cdb_len);
			if (!cmd)
				return NULL;
			cmd->cmd_id = ent->hdr.cmd_id;

			/* Convert iovec addrs in-place to not be offsets */
			cmd->iov_cnt = ent->req.iov_cnt;
			cmd->iovec = (struct iovec *) (cmd + 1);
			for (i = 0; i < ent->req.iov_cnt; i++) {
				cmd->iovec[i].iov_base = (void *) mb +
					(size_t) ent->req.iov[i].iov_base;
				cmd->iovec[i].iov_len = ent->req.iov[i].iov_len;
			}

			/* Copy cdb that currently points to the command ring */
			cmd->cdb = (uint8_t *) (cmd->iovec + cmd->iov_cnt);
			memcpy(cmd->cdb, (void *) mb + ent->req.cdb_off, cdb_len);

			TCMU_UPDATE_DEV_TAIL(dev, mb, ent);
			return cmd;
		}
		default:
			/* We don't even know how to handle this TCMU opcode. */
			ent->hdr.uflags |= TCMU_UFLAG_UNKNOWN_OP;
		}

		TCMU_UPDATE_DEV_TAIL(dev, mb, ent);
	}

	return NULL;
}

static int tcmu_sts_to_scsi(int tcmu_sts, uint8_t *sense)
{
	switch (tcmu_sts) {
	case TCMU_STS_OK:
		return SAM_STAT_GOOD;
	case TCMU_STS_NO_RESOURCE:
		return SAM_STAT_TASK_SET_FULL;
	/*
	 * We drop the session during timeout handling so force
	 * a retry to have it handled during session level recovery.
	 */
	case TCMU_STS_TIMEOUT:
	case TCMU_STS_BUSY:
		return SAM_STAT_BUSY;
	case TCMU_STS_PASSTHROUGH_ERR:
		break;
	/* Check Conditions below */
	case TCMU_STS_RANGE:
		/* LBA out of range */
		tcmu_set_sense_data(sense, ILLEGAL_REQUEST, 0x2100);
		break;
	case TCMU_STS_HW_ERR:
		/* Internal target failure */
		tcmu_set_sense_data(sense, HARDWARE_ERROR, 0x4400);
		break;
	case TCMU_STS_MISCOMPARE:
		/* Miscompare during verify operation */
		__tcmu_set_sense_data(sense, MISCOMPARE, 0x1d00);
		break;
	case TCMU_STS_RD_ERR:
		/* Read medium error */
		tcmu_set_sense_data(sense, MEDIUM_ERROR, 0x1100);
		break;
	case TCMU_STS_WR_ERR:
		/* Write medium error */
		tcmu_set_sense_data(sense, MEDIUM_ERROR, 0x0C00);
		break;
	case TCMU_STS_INVALID_CDB:
		/* Invalid field in CDB */
		tcmu_set_sense_data(sense, ILLEGAL_REQUEST, 0x2400);
		break;
	case TCMU_STS_INVALID_PARAM_LIST:
		/* Invalid field in parameter list */
		tcmu_set_sense_data(sense, ILLEGAL_REQUEST, 0x2600);
		break;
	case TCMU_STS_INVALID_PARAM_LIST_LEN:
		/* Invalid list parameter list length */
		tcmu_set_sense_data(sense, ILLEGAL_REQUEST, 0x1a00);
		break;
	case TCMU_STS_NOTSUPP_SEG_DESC_TYPE:
		/* Unsupported segment descriptor type code */
		tcmu_set_sense_data(sense, ILLEGAL_REQUEST, 0x2609);
		break;
	case TCMU_STS_NOTSUPP_TGT_DESC_TYPE:
		/* Unsupported target descriptor type code */
		tcmu_set_sense_data(sense, ILLEGAL_REQUEST, 0x2607);
		break;
	case TCMU_STS_CP_TGT_DEV_NOTCONN:
		/* Copy target device not reachable */
		tcmu_set_sense_data(sense, COPY_ABORTED, 0x0D02);
		break;
	case TCMU_STS_INVALID_CP_TGT_DEV_TYPE:
		/* Invalid copy target device type */
		tcmu_set_sense_data(sense, COPY_ABORTED, 0x0D03);
		break;
	case TCMU_STS_CAPACITY_CHANGED:
		/* Device capacity has changed */
		tcmu_set_sense_data(sense, UNIT_ATTENTION, 0x2A09);
		break;
	case TCMU_STS_TRANSITION:
		/* ALUA state transition */
		tcmu_set_sense_data(sense, NOT_READY, 0x040A);
		break;
	case TCMU_STS_IMPL_TRANSITION_ERR:
		/* Implicit ALUA state transition failed */
		tcmu_set_sense_data(sense, UNIT_ATTENTION, 0x2A07);
		break;
	case TCMU_STS_EXPL_TRANSITION_ERR:
		/* STPG failed */
		tcmu_set_sense_data(sense, HARDWARE_ERROR, 0x670A);
		break;
	case TCMU_STS_FENCED:
		/* ALUA state in standby */
		tcmu_set_sense_data(sense, NOT_READY, 0x040B);
		break;
	case TCMU_STS_WR_ERR_INCOMPAT_FRMT:
		/* Can't write - incompatible format */
		tcmu_set_sense_data(sense, ILLEGAL_REQUEST, 0x3005);
		break;
	case TCMU_STS_NOTSUPP_SAVE_PARAMS:
		/* Saving params not supported */
		tcmu_set_sense_data(sense, ILLEGAL_REQUEST, 0x3900);
		break;
	case TCMU_STS_FRMT_IN_PROGRESS:
		/* Format in progress */
		__tcmu_set_sense_data(sense, NOT_READY, 0x0404);
		break;
	case TCMU_STS_NOT_HANDLED:
	case TCMU_STS_INVALID_CMD:
		/* Invalid op code */
		tcmu_set_sense_data(sense, ILLEGAL_REQUEST, 0x2000);
		break;
	default:
		tcmu_err("Invalid tcmu status code %d\n", tcmu_sts);
		/* Fall through. Kernel will translate to LUN comm failure */
	}

	return SAM_STAT_CHECK_CONDITION;
}

/* update the ring buffer's tail */
#define TCMU_UPDATE_RB_TAIL(mb, ent) \
do { \
	mb->cmd_tail = (mb->cmd_tail + tcmu_hdr_get_len((ent)->hdr.len_op)) % mb->cmdr_size; \
} while (0)

void tcmulib_command_complete(
	struct tcmu_device *dev,
	struct tcmulib_cmd *cmd,
	int result)
{
	struct tcmu_mailbox *mb = dev->map;
	struct tcmu_cmd_entry *ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;

	/* current command could be PAD in async case */
	while (ent != (void *) mb + mb->cmdr_off + mb->cmd_head) {
		if (tcmu_hdr_get_op(ent->hdr.len_op) == TCMU_OP_CMD)
			break;
		TCMU_UPDATE_RB_TAIL(mb, ent);
		ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;
	}

	/* cmd_id could be different in async case */
	if (cmd->cmd_id != ent->hdr.cmd_id) {
		ent->hdr.cmd_id = cmd->cmd_id;
	}

	ent->rsp.scsi_status = tcmu_sts_to_scsi(result, cmd->sense_buf);
	if (ent->rsp.scsi_status == SAM_STAT_CHECK_CONDITION) {
		memcpy(ent->rsp.sense_buffer, cmd->sense_buf,
		       TCMU_SENSE_BUFFERSIZE);
	}

	TCMU_UPDATE_RB_TAIL(mb, ent);
	free(cmd);
}

void tcmulib_processing_start(struct tcmu_device *dev)
{
	int r;
	uint32_t buf;

	/* Clear the event on the fd */
	do {
		r = read(dev->fd, &buf, 4);
	} while (r == -1 && errno == EINTR);
	if (r == -1 && errno != EAGAIN)
		tcmu_err("failed to read device /dev/%s, %d\n",
			 dev->dev_name, errno);
}

void tcmulib_processing_complete(struct tcmu_device *dev)
{
	int r;
	uint32_t buf = 0;

	/* Tell the kernel there are completed commands */
	do {
		r = write(dev->fd, &buf, 4);
	} while (r == -1 && errno == EINTR);
	if (r == -1 && errno != EAGAIN)
		tcmu_err("failed to write device /dev/%s, %d\n",
			 dev->dev_name, errno);
}
