#ifndef _LOGGING_H_
#define _LOGGING_H_

#include "common.h"

#define LOGSET(type) static const char * __logtype = type;
#define ELOG(levl, fmt, ...) log_err(__FILE__, __func__, __LINE__, levl, __logtype, -1, fmt, ##__VA_ARGS__)
#define ELOGERR(levl, fmt, ...) log_err(__FILE__, __func__, __LINE__, levl, __logtype, errno, fmt, ##__VA_ARGS__)

#define DEBUG3 800
#define DEBUG2 400
#define DEBUG 200
#define VERBOSE 50
#define INFO 20
#define WARNING 10
#define ERROR 0
#define CRITICAL -100


void log_setlevel(int level);
int log_getlevel(void);

void log_err(const char *file, const char *func, int lineno, int level, const char *type, int err, char *fmt, ...);
#endif
