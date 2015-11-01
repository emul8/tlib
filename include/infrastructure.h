#ifndef INFRASTRUCTURE_H_
#define INFRASTRUCTURE_H_

#include <stdlib.h>

enum log_level {
  LOG_LEVEL_NOISY = -1,
  LOG_LEVEL_DEBUG = 0,
  LOG_LEVEL_INFO = 1,
  LOG_LEVEL_WARNING = 2,
  LOG_LEVEL_ERROR = 3
};

void *tlib_mallocz(size_t size);
char *tlib_strdup(const char *str);
void tlib_printf(enum log_level level, char *fmt, ...);
void tlib_abort(char *message);
void tlib_abortf(char *fmt, ...);

#include "callbacks.h"

#endif
