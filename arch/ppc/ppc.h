#ifndef PPC_HEADER_
#define PPC_HEADER_
#include "cpu.h"
/* Embedded PowerPC DCR management */
typedef uint32_t (*dcr_read_cb)(void *opaque, int dcrn);
typedef void (*dcr_write_cb)(void *opaque, int dcrn, uint32_t val);

#endif
