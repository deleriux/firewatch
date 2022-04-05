#include "common.h"

#include <stdarg.h>
#include "logging.h"

LOGSET("logging")

static int loglevel = 0;


/* Retrieve the currently set log level */
int log_getlevel(
    void)
{
  return loglevel;
}


/* Sets the log level to avoid printing logs too or to
 *    permit verbose logging. Can be changed during runtime
 *    */
void log_setlevel(
    int level)
{
  loglevel = level;
  ELOG(VERBOSE, "Log level set to %d", level);
}



/* Print an error */
void log_err(
    const char *file,
    const char *func,
    int lineno,
    int level,
    const char *type,
    int err,
    char *fmt,
    ...)
{
  int rc;
  time_t now;
  char fmtstr[1024] = {0};
  struct tm tmnow;
  char thetime[96] = {0};
  char errbuf[96] = {0};
  char *eb;

  memset(fmtstr, 0, sizeof(fmtstr));

  if (level > log_getlevel())
    return;

  va_list ap;

  /* Format the time */
  now = time(NULL);
  memset(thetime, 0, sizeof(thetime));
  localtime_r(&now, &tmnow);
  strftime(thetime, 95, "%Y-%m-%d %H:%M:%S", &tmnow);

  if (err > -1) {
    eb = strerror_r(err, errbuf, sizeof(errbuf)-1);
  }

  if (level >= DEBUG) {
    if (err > -1) {
      rc = snprintf(fmtstr, sizeof(fmtstr), "%s: (%s) <%s:%s:%d> %s: %s",
             thetime, type, file, func, lineno, fmt, eb);
    }
    else {
      rc = snprintf(fmtstr, sizeof(fmtstr), "%s: (%s) <%s:%s:%d> %s\n",
             thetime, type, file, func, lineno, fmt);
    }
  }
  else {
    if (err > -1) {
      rc = snprintf(fmtstr, sizeof(fmtstr), "%s: (%s) %s: %s\n",
               thetime, type, fmt, eb);
    }
    else {
      rc = snprintf(fmtstr, sizeof(fmtstr), "%s: (%s) %s\n",
             thetime, type, fmt);
    }
  }
  assert(rc > 0);

  va_start(ap, fmt);
  vfprintf(stderr, fmtstr, ap);
  va_end(ap);

  return;
}
