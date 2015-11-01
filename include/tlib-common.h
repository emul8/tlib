/* Common header file that is included by all of qemu.  */
#ifndef TLIB_COMMON_H
#define TLIB_COMMON_H

#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include "compiler.h"

#include <stdlib.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#include "compiler.h"

#include "cpu.h"

void cpu_exec_init_all();

#endif
