/*
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#ifndef __TCMUR_DEVICE_H
#define __TCMUR_DEVICE_H

#include "pthread.h"

#include "ccan/list/list.h"

#include "tcmur_aio.h"

#define TCMU_INVALID_LOCK_TAG USHRT_MAX

#define TCMUR_DEV_FLAG_FORMATTING	(1 << 0)
#define TCMUR_DEV_FLAG_IN_RECOVERY	(1 << 1)
#define TCMUR_DEV_FLAG_IS_OPEN		(1 << 2)
#define TCMUR_DEV_FLAG_STOPPING		(1 << 3)
#define TCMUR_DEV_FLAG_STOPPED		(1 << 4)

#define TCMUR_UA_DEV_SIZE_CHANGED	0

enum {
	TCMUR_DEV_FAILOVER_ALL_ACTIVE,
	TCMUR_DEV_FAILOVER_IMPLICIT,
	TCMUR_DEV_FAILOVER_EXPLICIT,
};

enum {
	TCMUR_DEV_LOCK_UNLOCKED,
	TCMUR_DEV_LOCK_LOCKED,
	TCMUR_DEV_LOCK_LOCKING,
	TCMUR_DEV_LOCK_UNKNOWN,
};

struct tcmur_device {
	struct tcmu_device *dev;
	void *hm_private;

	pthread_t cmdproc_thread;

	/* TCMUR_DEV flags */
	uint32_t flags;
	uint8_t failover_type;

	pthread_t recovery_thread;
	struct list_node recovery_entry;

	bool lock_lost;
	uint8_t lock_state;
	pthread_t lock_thread;
	pthread_cond_t lock_cond;

	/* General lock for lock state, thread, dev state, etc */
	pthread_mutex_t state_lock;
	int pending_uas;

	/*
	 * lock order:
	 *  work_queue->aio_lock
	 *    track_queue->track_lock
	 */
        struct tcmu_io_queue work_queue;
        struct tcmu_track_aio track_queue;

	pthread_spinlock_t lock; /* protects concurrent updates to mailbox */
	pthread_mutex_t caw_lock; /* for atomic CAW operation */

	uint32_t format_progress;
	pthread_mutex_t format_lock; /* for atomic format operations */
};

bool tcmu_dev_in_recovery(struct tcmu_device *dev);
void tcmu_cancel_recovery(struct tcmu_device *dev);
int tcmu_cancel_lock_thread(struct tcmu_device *dev);

void tcmu_notify_conn_lost(struct tcmu_device *dev);
void tcmu_notify_lock_lost(struct tcmu_device *dev);

int __tcmu_reopen_dev(struct tcmu_device *dev, int retries);
int tcmu_reopen_dev(struct tcmu_device *dev, int retries);

int tcmu_acquire_dev_lock(struct tcmu_device *dev, uint16_t tag);
void tcmu_release_dev_lock(struct tcmu_device *dev);
int tcmu_get_lock_tag(struct tcmu_device *dev, uint16_t *tag);
void tcmu_update_dev_lock_state(struct tcmu_device *dev);

void tcmur_dev_set_private(struct tcmu_device *dev, void *private);
void *tcmur_dev_get_private(struct tcmu_device *dev);

#endif
