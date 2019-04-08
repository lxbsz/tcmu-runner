/*
 * Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
 * This file is part of tcmu-runner.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 3 or any later version (LGPLv3 or
 * later), or the GNU General Public License, version 2 (GPLv2), in all
 * cases as published by the Free Software Foundation.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <uv.h>

#include "libtcmu_log.h"
#include "libtcmu_timer.h"

static pthread_t timer_thread;
static uv_loop_t *tcmu_uv_loop;
static tcmu_timer_t loop_timer;

static pthread_spinlock_t timer_lock;

static void tcmu_timer_cbk(uv_timer_t* uv_timer)
{
	tcmu_timer_t *timer;

	tcmu_err("lxb------\n");
	pthread_spin_lock(&timer_lock);
	timer = container_of(uv_timer, tcmu_timer_t, uv_timer);

	if (timer->cbk)
		timer->cbk(timer);
	pthread_spin_unlock(&timer_lock);
}

/*
 * timeout: all the entries will time out after 'timeout' milliseconds.
 * repeat: repeat the timer for every 'repeat' milliseconds after 'timeout'.
 */
void tcmu_init_timer(tcmu_timer_t *timer, uint64_t timeout, uint64_t repeat,
		     tcmu_timer_cbk_t cbk)
{
	if (!timer || !cbk)
		return;

	if (!timeout && !repeat)
		return;

	timer->expires = timeout * 1000;
	timer->repeat = repeat * 1000;
	timer->cbk = cbk;

	bzero(&timer->uv_timer, sizeof(uv_timer_t));
}

void tcmu_add_timer(tcmu_timer_t *timer)
{
	if (!timer)
		return;

	pthread_spin_lock(&timer_lock);
	if (!tcmu_uv_loop) {
		tcmu_err("Timer loop is not initialized yet!\n");
		goto unlock;
	}

	/*
	 * To avoid segment fault. If the timer is already
	 * running, the uv_timer_init will set the cbk to
	 * NULL, which will lead sigment fault for the running
	 * timer.
	 */
	if (uv_is_active((uv_handle_t*)(&timer->uv_timer))) {
		tcmu_warn("The timer %p is already running!\n", timer);
		goto unlock;
	}

	uv_timer_init(tcmu_uv_loop, &timer->uv_timer);
	uv_timer_start(&timer->uv_timer, tcmu_timer_cbk, timer->expires,
			timer->repeat);

unlock:
	pthread_spin_unlock(&timer_lock);
}

void tcmu_del_timer(tcmu_timer_t *timer)
{
	pthread_spin_lock(&timer_lock);
	uv_timer_stop(&timer->uv_timer);
	pthread_spin_unlock(&timer_lock);
}

void tcmu_reset_timer(tcmu_timer_t *timer)
{
	pthread_spin_lock(&timer_lock);
	uv_update_time(tcmu_uv_loop);

	/*
	 * The uv_timer_start will stop the timer first if
	 * the timer is already active, then start it again
	 */
	uv_timer_start(&timer->uv_timer, tcmu_timer_cbk, timer->expires,
		       timer->repeat);
	pthread_spin_unlock(&timer_lock);
}

static void *tcmu_timer_base_thread_start(void *arg)
{
	pthread_spin_lock(&timer_lock);
	if (!tcmu_uv_loop) {
		tcmu_err("Timer loop is not init yet!\n");
		pthread_spin_unlock(&timer_lock);
		return NULL;
	}
	pthread_spin_unlock(&timer_lock);

	tcmu_err("lxb ====== before Timer loop is not init yet!\n");
	uv_run(tcmu_uv_loop, UV_RUN_DEFAULT);
	tcmu_err("lxb ===== after Timer loop is not init yet!\n");

	return NULL;
}

void tcmu_timer_base_init(void)
{
	if (tcmu_uv_loop) {
		tcmu_warn("Timer loop is already start, do nothing!\n");
		return;
	}

	pthread_spin_init(&timer_lock, 0);

	tcmu_uv_loop = uv_default_loop();
	if (!tcmu_uv_loop) {
		tcmu_err("No memory for tcmu_uv_loop!\n");
		return;
	}

	/*
	 * Make sure that the loop_timer will be exist
	 * forever then the uv_run won't stop
	 */
//	loop_timer.expires = 0xefffffffffffffff;
//	loop_timer.repeat = 0xefffffffffffffff;
	loop_timer.expires = 5000;
	loop_timer.repeat = 5000;
	loop_timer.cbk = NULL;
	bzero(&loop_timer.uv_timer, sizeof(uv_timer_t));
	uv_timer_init(tcmu_uv_loop, &loop_timer.uv_timer);
	uv_timer_start(&loop_timer.uv_timer, tcmu_timer_cbk,
		       loop_timer.expires, loop_timer.repeat);

	pthread_create(&timer_thread, NULL, tcmu_timer_base_thread_start, NULL);
}

void tcmu_timer_base_fini(void)
{
	pthread_spin_lock(&timer_lock);
	if (!tcmu_uv_loop) {
		pthread_spin_unlock(&timer_lock);
		return;
	}

	/* Stop the pending timers if there has */
	uv_stop(tcmu_uv_loop);

	uv_loop_close(tcmu_uv_loop);
	tcmu_uv_loop = NULL;
	pthread_spin_unlock(&timer_lock);
	pthread_spin_destroy(&timer_lock);

	pthread_join(timer_thread, NULL);
}
