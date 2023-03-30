/*************************************************************************
	> File Name: logging.h
	> Author:
	> Mail:
	> Created Time: 2018年06月18日 星期一 22时45分58秒
 ************************************************************************/

#ifndef _LOGGING_H
#define _LOGGING_H

#define MODULE_NAME "verify_policy"

#define RLOG_LV_DEBUG       10
#define RLOG_LV_INFO        20
#define RLOG_LV_FATAL       30

typedef struct RTLogInit2Data_ {
    int debug_switch;

	int run_log_level;

	char run_log_path[256];

	void *run_log_handle;
} RTLogInit2Data;

extern RTLogInit2Data logging_sc_lid;

/* The maximum length of the log message */
#define RT_LOG_MAX_LOG_MSG_LEN 4096

#define mesa_log(x, y, ...)         do {                                       \
                                  char _sc_log_msg[RT_LOG_MAX_LOG_MSG_LEN] = ""; \
                                  char *_sc_log_temp = _sc_log_msg;      \
                                  if ( !x )                       \
                                  { } else {                             \
                                      snprintf(_sc_log_temp,             \
                                               (RT_LOG_MAX_LOG_MSG_LEN - \
                                                (_sc_log_temp - _sc_log_msg)), \
                                               __VA_ARGS__);             \
                                      MESA_handle_runtime_log(logging_sc_lid.run_log_handle, y, __FUNCTION__, _sc_log_msg); \
                                  }                                      \
                              } while(0)

#define mesa_runtime_log(level, ...)   mesa_log(logging_sc_lid.debug_switch, level, __VA_ARGS__)

extern void * verify_syslog_init(const char *config);

#endif
