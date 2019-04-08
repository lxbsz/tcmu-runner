/*
 * Copyright (c) 2019 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#ifndef __TCMU_TIMER_H
#define __TCMU_TIMER_H

#include <stdbool.h>
#include <pthread.h>
#include <uv.h>

#include "ccan/list/list.h"

typedef uv_timer_t tcmu_timer_t;
typedef void (*tcmu_timer_cbk_t)(tcmu_timer_t *timer);

#if 0
struct tcmu_timer {
    /* Do not touch this */
    uv_timer_t uv_timer;

    /* The precision is in millisecond */
    uint64_t expires;
    uint64_t repeat;

    tcmu_timer_cbk_t cbk;

    void *data;
};
#endif
/* The timer helpers */
void tcmu_timer_base_init(void);
void tcmu_timer_base_fini(void);
/*
 * timeout: all the entries will time out after 'timeout' milliseconds.
 * repeat: repeat the timer for every 'repeat' milliseconds after 'timeout'.
 */
//void tcmu_init_timer(tcmu_timer_t *timer, uint64_t timeout, uint64_t repeat, tcmu_timer_cbk_t cbk);
//void tcmu_add_timer(tcmu_timer_t *timer);
void tcmu_mod_timer(tcmu_timer_t *timer, uint64_t timeout, tcmu_timer_cbk_t cbk);
void tcmu_del_timer(tcmu_timer_t *timer);
//void tcmu_reset_timer(tcmu_timer_t *timer);

#endif /* __TCMU_TIMER_H */
