#ifndef EXPORTS_H_
#define EXPORTS_H_

#include <stdint.h>

int32_t tlib_init(char *cpu_name);
void tlib_dispose(void);
void tlib_reset(void);

void tlib_execute(void);
void tlib_restart_translation_block(void);
void tlib_set_paused(void);
void tlib_clear_paused(void);
int32_t tlib_is_wfi(void);
void tlib_set_single_step(int32_t enabled);

uint32_t tlib_get_page_size(void);
void tlib_map_range(uint32_t start_addr, uint32_t length);
void tlib_unmap_range(uint32_t start, uint32_t end);
uint32_t tlib_is_range_mapped(uint32_t start, uint32_t end);
void tlib_invalidate_translation_blocks(unsigned long start, unsigned long end);

void tlib_set_irq(int32_t interrupt, int32_t state);
int32_t tlib_is_irq_set(void);
void tlib_add_breakpoint(uint32_t address);
void tlib_remove_breakpoint(uint32_t address);
void tlib_set_translation_cache_size(unsigned long size);
void tlib_invalidate_translation_cache(void);
uint32_t tlib_set_maximum_block_size(uint32_t size);
uint32_t tlib_get_maximum_block_size(void);
void tlib_restore_context_direction(int forward);
void tlib_restore_context();
void* tlib_export_state();
int32_t tlib_get_state_size();

#endif
