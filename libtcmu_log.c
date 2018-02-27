/*
 * Copyright 2016,2017 China Mobile, Inc.
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
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include "darray.h"
#include "libtcmu_log.h"
#include "libtcmu_config.h"
#include "libtcmu_time.h"
#include "libtcmu_priv.h"
#include "string_priv.h"

/* tcmu ring buffer for log */
#define LOG_ENTRY_LEN 256 /* rb[0] is reserved for pri */
#define LOG_MSG_LEN (LOG_ENTRY_LEN - 1) /* the length of the log message */
#define LOG_ENTRYS (1024 * 32)

struct log_buf {
	pthread_cond_t cond;
	pthread_mutex_t lock;

	bool thread_active;
	int init_state;
	bool finish_initialize;

	unsigned int head;
	unsigned int tail;
	char buf[LOG_ENTRYS][LOG_ENTRY_LEN];
	darray(struct log_output) outputs;
	pthread_t thread_id;
};

struct log_output {
	log_output_fn_t output_fn;
	log_close_fn_t close_fn;
	int priority;
	char *name;
	void *data;
	tcmu_log_destination dest;
	bool bypass;
};

static int tcmu_log_level = TCMU_LOG_INFO;
static struct log_buf *logbuf = NULL;

/* covert log level from tcmu config to syslog */
static inline int to_syslog_level(int level)
{
	switch (level) {
		case TCMU_CONF_LOG_ERROR:
			return TCMU_LOG_ERROR;
		case TCMU_CONF_LOG_WARN:
			return TCMU_LOG_WARN;
		case TCMU_CONF_LOG_INFO:
			return TCMU_LOG_INFO;
		case TCMU_CONF_LOG_DEBUG:
			return TCMU_LOG_DEBUG;
		case TCMU_CONF_LOG_DEBUG_SCSI_CMD:
			return TCMU_LOG_DEBUG_SCSI_CMD;
		default:
			return TCMU_LOG_INFO;
	}
}

/* get the log level of tcmu-runner */
unsigned int tcmu_get_log_level(void)
{
	return tcmu_log_level;
}

bool tcmu_logdir_getenv(void)
{
	char *log_path;

	if (tcmu_get_logdir())
		return true;

	log_path = getenv("TCMU_LOGDIR");
	if (!log_path)
		return true;

	if (!tcmu_logdir_create(log_path))
		return false;

	return true;
}

void tcmu_set_log_level(int level)
{
	if (level > TCMU_CONF_LOG_LEVEL_MAX)
		level = TCMU_CONF_LOG_LEVEL_MAX;
	else if (level < TCMU_CONF_LOG_LEVEL_MIN)
		level = TCMU_CONF_LOG_LEVEL_MIN;

	tcmu_log_level = to_syslog_level(level);
}

static inline uint8_t rb_get_pri(struct log_buf *logbuf, unsigned int cur)
{
	return logbuf->buf[cur][0];
}

static inline void rb_set_pri(struct log_buf *logbuf, unsigned int cur, uint8_t pri)
{
	logbuf->buf[cur][0] = (char)pri;
}

static inline char *rb_get_msg(struct log_buf *logbuf, unsigned int cur)
{
	return logbuf->buf[cur] + 1;
}

static inline bool rb_is_empty(struct log_buf *logbuf)
{
	return logbuf->tail == logbuf->head;
}

static inline bool rb_is_full(struct log_buf *logbuf)
{
	return logbuf->tail == (logbuf->head + 1) % LOG_ENTRYS;
}

static inline void rb_update_tail(struct log_buf *logbuf)
{
	logbuf->tail = (logbuf->tail + 1) % LOG_ENTRYS;
}

static inline void rb_update_head(struct log_buf *logbuf)
{
	/* when the ring buffer is full, the oldest log will be dropped */
	if (rb_is_full(logbuf))
		rb_update_tail(logbuf);

	logbuf->head = (logbuf->head + 1) % LOG_ENTRYS;
}

static void log_output(int pri, const char *msg, bool bypass)
{
	struct log_output *output;
	char timestamp[TCMU_TIME_STRING_BUFLEN] = {0, };
	int ret;

	ret = time_string_now(timestamp);
	if (ret < 0)
		return;

	darray_foreach (output, logbuf->outputs) {
		if (output->bypass == bypass && pri <= output->priority) {
			output->output_fn(pri, timestamp, msg, output->data);
		}
	}
}

static void
log_internal(int pri, struct tcmu_device *dev, const char *funcname,
	     int linenr, const char *fmt, va_list args)
{
	unsigned int head;
	char *msg, buf[LOG_MSG_LEN];
	int n;
	struct tcmur_handler *rhandler;

	if (pri > tcmu_log_level)
		return;

	if (!fmt)
		return;

	if (!logbuf || !logbuf->finish_initialize) {
		/* handle early log calls by config and deamon setup */
		vfprintf(stderr, fmt, args);
		return;
	}

	pthread_mutex_lock(&logbuf->lock);

	head = logbuf->head;
	rb_set_pri(logbuf, head, pri);
	msg = rb_get_msg(logbuf, head);

	if (dev) {
		rhandler = tcmu_get_runner_handler(dev);
		n = sprintf(msg, "%s:%d %s/%s: ", funcname, linenr,
		            rhandler ? rhandler->subtype: "",
		            dev ? dev->tcm_dev_name: "");
	} else {
		n = sprintf(msg, "%s:%d: ", funcname, linenr);
	}

	vsnprintf(msg + n, LOG_MSG_LEN - n, fmt, args);

	rb_update_head(logbuf);

	memcpy(buf, msg, LOG_MSG_LEN);
	log_output(pri, buf, true);

	if (logbuf->thread_active == false)
		pthread_cond_signal(&logbuf->cond);

	pthread_mutex_unlock(&logbuf->lock);
}

void tcmu_err_message(struct tcmu_device *dev, const char *funcname,
		      int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_ERROR, dev, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_warn_message(struct tcmu_device *dev, const char *funcname,
		       int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_WARN, dev, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_info_message(struct tcmu_device *dev, const char *funcname,
		       int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_INFO, dev, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_dbg_message(struct tcmu_device *dev, const char *funcname,
		      int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_DEBUG, dev, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_dbg_scsi_cmd_message(struct tcmu_device *dev, const char *funcname,
			       int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_DEBUG_SCSI_CMD, dev, funcname, linenr, fmt,
		     args);
	va_end(args);
}

static int append_output(log_output_fn_t output_fn, log_close_fn_t close_fn, void *data,
                         int pri, int dest, const char *name, bool bypass)
{
	char *ndup = NULL;
	struct log_output output;

	if (output_fn == NULL)
	    return -1;

	if (dest == TCMU_LOG_TO_FILE) {
		if (name == NULL)
			return -1;
		ndup = strdup(name);
		if (ndup == NULL)
			return -1;
	}

	output.output_fn = output_fn;
	output.close_fn = close_fn;
	output.data = data;
	output.priority = pri;
	output.dest = dest;
	output.name = ndup;
	output.bypass = bypass;

	darray_append(logbuf->outputs, output);

	return 0;
}

static int output_to_syslog(int pri, const char *timestamp,
                            const char *str, void *data)
{
	/* convert tcmu-runner private level to system level */
	if (pri > TCMU_LOG_DEBUG)
		pri = TCMU_LOG_DEBUG;
	syslog(pri, "%s", str);
	return strlen(str);
}

static void close_syslog(void *data)
{
	closelog();
}

static void close_fd(void *data)
{
	int fd = (intptr_t) data;
	close(fd);
}

static int create_syslog_output(int pri, const char *ident)
{
	openlog(ident, 0 ,0);
	if (append_output(output_to_syslog, close_syslog, NULL,
			  pri, TCMU_LOG_TO_SYSLOG, ident, false) < 0) {
		closelog();
		return -1;
	}
	return 0;
}

static const char *loglevel_string(int priority)
{
	switch (priority) {
	case TCMU_LOG_ERROR:
		return "ERROR";
	case TCMU_LOG_WARN:
		return "WARN";
	case TCMU_LOG_INFO:
		return "INFO";
	case TCMU_LOG_DEBUG:
		return "DEBUG";
	case TCMU_LOG_DEBUG_SCSI_CMD:
		return "DEBUG_SCSI_CMD";
	}
	return "UNKONWN";
}

static int output_to_fd(int pri, const char *timestamp,
                        const char *str,void *data)
{
	int fd = (intptr_t) data;
	char *buf, *msg;
	int count, ret, written = 0, r, pid = 0;

	if (fd < 0)
		return -1;

	pid = getpid();
	if (pid <= 0)
		return -1;

	/*
	 * format: timestamp pid [loglevel] msg
	 */
	ret = asprintf(&msg, "%s %d [%s] %s", timestamp, pid, loglevel_string(pri), str);
	if (ret < 0)
		return -1;

	buf = msg;

	/* safe write */
	count = strlen(buf);
	while (count > 0) {
		r = write(fd, buf, count);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0) {
			written = r;
			goto out;
		}
		if (r == 0)
			break;
		buf = (char *) buf + r;
		count -= r;
		written += r;
	}
out:
	free(msg);
	return written;
}

static int create_stdout_output(int pri)
{
	if (append_output(output_to_fd, close_fd, (void *)2L,
			  pri, TCMU_LOG_TO_STDOUT, NULL, true) < 0)
		return -1;

	return 0;
}

static int create_file_output(int pri, const char *filename)
{
	char log_file_path[PATH_MAX];
	int fd, ret;

	ret = tcmu_make_absolute_logfile(log_file_path, filename);
	if (ret < 0) {
		tcmu_err("tcmu_make_absolute_logfile failed\n");
		return ret;
	}

	fd = open(log_file_path, O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		tcmu_err("Failed to open %s:%m\n", log_file_path);
		return fd;
	}

	ret = append_output(output_to_fd, close_fd, (void *)(intptr_t) fd,
			    pri, TCMU_LOG_TO_FILE, filename, true);
	if (ret < 0) {
		close(fd);
		tcmu_err("Failed to append output file: %s\n", log_file_path);
		return ret;
	}

        return 0;
}

static bool log_buf_not_empty_output(struct log_buf *logbuf)
{
	unsigned int tail;
	uint8_t pri;
	char *msg, buf[LOG_MSG_LEN];

	if (!logbuf) {
		return false;
	}

	pthread_mutex_lock(&logbuf->lock);
	if (rb_is_empty(logbuf)) {
		pthread_mutex_unlock(&logbuf->lock);
		return false;
	}

	tail = logbuf->tail;
	pri = rb_get_pri(logbuf, tail);
	msg = rb_get_msg(logbuf, tail);
	memcpy(buf, msg, LOG_MSG_LEN);
	rb_update_tail(logbuf);
	pthread_mutex_unlock(&logbuf->lock);

	/*
	 * This may block due to rsyslog and syslog-ng, etc.
	 * And the log productors could still insert their log
	 * messages into the ring buffer without blocking. But
	 * the ring buffer may lose some old log rbs if the
	 * ring buffer is full.
	 */
	log_output(pri, buf, false);

	return true;
}

static void log_cleanup(void *arg)
{
	struct log_buf *logbuf = arg;
	struct log_output *output;

	pthread_cond_destroy(&logbuf->cond);
	pthread_mutex_destroy(&logbuf->lock);

	darray_foreach(output, logbuf->outputs) {
		if (output->close_fn != NULL)
			output->close_fn(output->data);
		if (output->name != NULL)
			free(output->name);
        }

	darray_free(logbuf->outputs);

	free(logbuf);
}

static void *log_thread_start(void *arg)
{
	struct log_buf *logbuf = arg;

	pthread_cleanup_push(log_cleanup, arg);

	pthread_mutex_lock(&logbuf->lock);
	if(!logbuf->finish_initialize){
		logbuf->finish_initialize = true;
		pthread_cond_signal(&logbuf->cond);
	}
	pthread_mutex_unlock(&logbuf->lock);

	while (1) {
		pthread_mutex_lock(&logbuf->lock);
		logbuf->thread_active = false;
		pthread_cond_wait(&logbuf->cond, &logbuf->lock);
		logbuf->thread_active = true;
		pthread_mutex_unlock(&logbuf->lock);

		while (log_buf_not_empty_output(logbuf));
	}

	pthread_cleanup_pop(1);
	return NULL;
}

/* tcmu log dir path */
static char *tcmu_log_dir = NULL;

static bool tcmu_logdir_check(const char *path)
{
	if (!path)
		return false;

	if (strlen(path) >= PATH_MAX - TCMU_LOG_FILENAME_MAX) {
		tcmu_err("--tcmu-log-dir='%s' cannot exceed %d characters\n",
			 path, PATH_MAX - TCMU_LOG_FILENAME_MAX - 1);
		return false;
	}

	return true;
}

/* get the log dir of tcmu-runner */
char *tcmu_get_logdir(void)
{
	return tcmu_log_dir;
}

static char *tcmu_alloc_and_set_log_dir(const char *log_dir)
{
	/*
	 * Do nothing here and will use the /var/log/
	 * as the default log dir
	 */
	if (!log_dir)
		return NULL;

	tcmu_log_dir = strdup(log_dir);
	if (!tcmu_log_dir)
		tcmu_err("Failed to copy log dir: %s\n", log_dir);

	return tcmu_log_dir;
}

void tcmu_logdir_destroy(void)
{
	free(tcmu_log_dir);
}

static int tcmu_mkdir(const char *path)
{
	DIR* dir;

	dir = opendir(path);
	if (dir) {
		closedir(dir);
	} else if (errno == ENOENT) {
		if (mkdir(path, 0755) == -1) {
			tcmu_err("mkdir(%s) failed: %m\n", path);
			return false;
		}
	} else {
		tcmu_err("opendir(%s) failed: %m\n", path);
		return false;
	}

	return true;
}

static int tcmu_mkdirs(const char *pathname)
{
	char path[PATH_MAX], *ch;
	int ind = 0;

	strlcpy(path, pathname, PATH_MAX);

	if (path[0] == '/')
		ind++;

	do {
		ch = strchr(path + ind, '/');
		if (!ch)
			break;

		*ch = '\0';

		if (!tcmu_mkdir(path))
			return false;

		*ch = '/';
		ind = ch - path + 1;
	} while (1);

	return tcmu_mkdir(path);
}

bool tcmu_logdir_create(const char *path)
{
	if (!tcmu_logdir_check(path))
		return false;

	if (!tcmu_mkdirs(path))
		return false;

	return !!tcmu_alloc_and_set_log_dir(path);
}

int tcmu_make_absolute_logfile(char *path, const char *filename)
{
	if (snprintf(path, PATH_MAX, "%s/%s",
	             tcmu_log_dir ? tcmu_log_dir : TCMU_LOG_DIR_DEFAULT,
	             filename) < 0)
		return -errno;
	return 0;
}

int tcmu_setup_log(void)
{
	int ret;

	logbuf = malloc(sizeof(struct log_buf));
	if (!logbuf)
		return -ENOMEM;

	logbuf->thread_active = false;
	logbuf->finish_initialize = false;
	logbuf->head = 0;
	logbuf->tail = 0;
	pthread_cond_init(&logbuf->cond, NULL);
	pthread_mutex_init(&logbuf->lock, NULL);

	darray_init(logbuf->outputs);

	ret = create_syslog_output(TCMU_LOG_INFO, NULL);
	if (ret < 0)
		tcmu_err("create syslog output error \n");

	ret = create_stdout_output(TCMU_LOG_DEBUG_SCSI_CMD);
	if (ret < 0)
		tcmu_err("create stdout output error \n");

	ret = create_file_output(TCMU_LOG_DEBUG, TCMU_LOG_FILENAME);
	if (ret < 0)
		tcmu_err("create file output error \n");

	ret = pthread_create(&logbuf->thread_id, NULL, log_thread_start, logbuf);
	if (ret)
		goto cleanup_log;

	pthread_mutex_lock(&logbuf->lock);
	while (!logbuf->finish_initialize)
		pthread_cond_wait(&logbuf->cond, &logbuf->lock);
	pthread_mutex_unlock(&logbuf->lock);

	return 0;

cleanup_log:
	log_cleanup(logbuf);
	return -ENOMEM;
}

void tcmu_destroy_log()
{
	pthread_t thread;
	void *join_retval;

	if (!logbuf)
		return;

	thread = logbuf->thread_id;
	if (pthread_cancel(thread))
		return;

	pthread_join(thread, &join_retval);
}
