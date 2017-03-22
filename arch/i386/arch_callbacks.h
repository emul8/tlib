#ifndef ARCH_CALLBACKS_H_
#define ARCH_CALLBACKS_H_

#include <stdint.h>

uint8_t tlib_read_byte_from_port(uint16_t address);
uint16_t tlib_read_word_from_port(uint16_t address);
uint32_t tlib_read_double_word_from_port(uint16_t address);
void tlib_write_byte_to_port(uint16_t address, uint8_t value);
void tlib_write_word_to_port(uint16_t address, uint16_t value);
void tlib_write_double_word_to_port(uint16_t address, uint32_t value);
int32_t tlib_get_pending_interrupt(void);
uint64_t tlib_get_instruction_count(void);

#endif
