#ifndef ARCH_CALLBACKS_H_
#define ARCH_CALLBACKS_H_

#include <stdint.h>

#ifdef TARGET_PROTO_ARM_M
int32_t tlib_nvic_acknowledge_irq(void);
void tlib_nvic_complete_irq(int32_t number);
void tlib_nvic_set_pendinq_irq(int32_t number);
void tlib_nvic_write_basepri(int32_t number);
void tlib_nvic_write_primask(int32_t number);
int32_t tlib_nvic_get_pending_masked_irq(void);
void tlib_nvic_set_pending_irq(int32_t no);
#endif

uint32_t tlib_read_cp15_32(uint32_t instruction);
void tlib_write_cp15_32(uint32_t instruction, uint32_t value);
uint64_t tlib_read_cp15_64(uint32_t instruction);
void tlib_write_cp15_64(uint32_t instruction, uint64_t value);
uint32_t tlib_is_wfi_as_nop(void);
uint32_t tlib_do_semihosting(void);

#endif
