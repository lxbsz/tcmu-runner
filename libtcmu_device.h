/*
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#ifndef __LIBTCMU_FAILOVER_H
#define __LIBTCMU_FAILOVER_H

#include "libtcmu.h"

bool tcmu_dev_in_recovery(struct tcmu_device *dev);
void tcmu_cancel_recovery(struct tcmu_device *dev);
int tcmu_cancel_lock_thread(struct tcmu_device *dev);

void tcmu_notify_conn_lost(struct tcmu_device *dev);
void tcmu_notify_lock_lost(struct tcmu_device *dev);

int __tcmu_reopen_dev(struct tcmu_device *dev, bool in_lock_thread, int retries);
int tcmu_reopen_dev(struct tcmu_device *dev, bool in_lock_thread, int retries);

int tcmu_acquire_dev_lock(struct tcmu_device *dev, bool is_sync, uint16_t tag);
void tcmu_release_dev_lock(struct tcmu_device *dev);
int tcmu_get_lock_tag(struct tcmu_device *dev, uint16_t *tag);
int tcmu_dev_added(struct tcmu_device *dev);
void tcmu_dev_removed(struct tcmu_device *dev);
int tcmu_dev_reconfig(struct tcmu_device *dev, struct tcmulib_cfg_info *cfg);

#endif
