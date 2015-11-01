#ifndef EXEC_SPARC_H
#define EXEC_SPARC_H 1
#include "dyngen-exec.h"

register struct CPUSPARCState *env asm(AREG0);

#include "cpu.h"
#include "exec-all.h"

#include "softmmu_exec.h"

#endif
