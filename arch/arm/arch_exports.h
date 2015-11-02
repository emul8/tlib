#ifndef ARCH_EXPORTS_H_
#define ARCH_EXPORTS_H_

#include <stdint.h>

uint32_t tlib_get_cpu_id(void);
void tlib_set_cpu_id(uint32_t value);

#ifdef TARGET_PROTO_ARM_M
void tlib_toggle_fpu(int32_t enabled);
void tlib_set_interrupt_vector_base(uint32_t address);
uint32_t tlib_get_interrupt_vector_base(void);
#endif

#endif
