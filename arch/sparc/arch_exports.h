#ifndef ARCH_EXPORTS_H_
#define ARCH_EXPORTS_H_

#include <stdint.h>

void tlib_set_slot(uint32_t slot);

void tlib_set_entry_point(uint32_t entry_point);

void tlib_clear_wfi(void);

void tlib_set_wfi(void);

void tlib_before_save(void *env)

void tlib_after_load(void *env)

#endif
