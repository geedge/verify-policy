#ifndef __RT_COMMON_H__
#define __RT_COMMON_H__

#include <assert.h>
#define EVAL_TM_STYLE   "%Y-%m-%d"

#define VERIFY_SYMBOL_MAX			64
#define VERIFY_PATH_MAX             258
#define VERIFY_STRING_MAX			2048
#define VERIFY_ARRAY_MAX			512

/** Alway treated the expr as true */
#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif

/** Alway treated the expr as false */
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif

#ifndef FOREVER
#define FOREVER for(;;)
#endif

#ifdef SOCK_NONBLOCK
#define EVUTIL_SOCK_NONBLOCK SOCK_NONBLOCK
#else
#define EVUTIL_SOCK_NONBLOCK 0x4000000
#endif
#ifdef SOCK_CLOEXEC
#define EVUTIL_SOCK_CLOEXEC SOCK_CLOEXEC
#else
#define EVUTIL_SOCK_CLOEXEC 0x80000000
#endif
#ifdef EFD_NONBLOCK
#define EVUTIL_EFD_NONBLOCK EFD_NONBLOCK
#else
#define EVUTIL_EFD_NONBLOCK 0x4000
#endif
#ifdef EFD_CLOEXEC
#define EVUTIL_EFD_CLOEXEC EFD_CLOEXEC
#else
#define EVUTIL_EFD_CLOEXEC 0x8000
#endif

#define	__rt_always_inline__	__attribute__((always_inline)) inline

#define ALLOC(type, number) ((type *)calloc(sizeof(type), number))
#define	FREE(p)	{free(*p);*p=NULL;}

char* rt_strdup(const char* s);

#define CHECK_OR_EXIT(condition, fmt, ...)                                                                          \
do { if(!(condition)) { mesa_runtime_log(RLOG_LV_FATAL, fmt, ##__VA_ARGS__); exit(EXIT_FAILURE);   }  } while(0) \

#endif
