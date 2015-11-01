/*
 *  Common interface for translation libraries.
 *
 *  Copyright (c) Antmicro
 *  Copyright (c) Realtime Embedded
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdint.h>
#include "cpu.h"
#include "tcg.h"
#include "tcg-additional.h"
#include "exec-all.h"

static void init_tcg()
{
  attach_gen_opc_buf((void*)&GLOBAL_gen_opc_buf);
  attach_tcg_ctx((void*)&GLOBAL_tcg_ctx);
  attach_code_gen_prologue((void*)&GLOBAL_code_gen_prologue);
  attach_gen_opparam_buf((void*)&GLOBAL_gen_opparam_buf);
  attach_ld_helpers((void*)__ldb_mmu, (void*)__ldw_mmu, (void*)__ldl_mmu, (void*)__ldq_mmu);
  attach_st_helpers((void*)__stb_mmu, (void*)__stw_mmu, (void*)__stl_mmu, (void*)__stq_mmu);
  set_temp_buf_offset(offsetof(CPUState, temp_buf));
  int i;
  for (i = 0; i < 7; i++)
  {
    set_tlb_table_n_0_rwa(i, offsetof(CPUState, tlb_table[i][0].addr_read), offsetof(CPUState, tlb_table[i][0].addr_write), offsetof(CPUState, tlb_table[i][0].addend));
    set_tlb_table_n_0(i, offsetof(CPUState, tlb_table[i][0]));
  }
  set_tlb_entry_addr_rwu(offsetof(CPUTLBEntry, addr_read), offsetof(CPUTLBEntry, addr_write), offsetof(CPUTLBEntry, addend));
  set_sizeof_CPUTLBEntry(sizeof(CPUTLBEntry));
  set_TARGET_PAGE_BITS(TARGET_PAGE_BITS);
  attach_malloc(tlib_malloc);
  attach_realloc(tlib_realloc);
}

int32_t tlib_init(char *cpu_name)
{
  init_tcg();
  cpu_exec_init_all();
  CPUState *env = cpu_init(cpu_name);
  if (!env)
  {
    return -1;
  }
#ifndef TARGET_PPC
  cpu_reset(env);
#endif
  return 0;
}

void tlib_dispose()
{
  code_gen_free();
}

void tlib_reset()
{
  cpu_reset(cpu);
}

void tlib_execute()
{
  cpu_exec(cpu);
}

void tlib_set_paused()
{
  cpu_interrupt(cpu, CPU_INTERRUPT_DEBUG);
}

void tlib_clear_paused()
{
  cpu_reset_interrupt(cpu, CPU_INTERRUPT_DEBUG);
  cpu_reset_exit_request(cpu);
}

int32_t tlib_is_wfi()
{
     return cpu->wfi;
}

void tlib_set_single_step(int32_t enabled)
{
  cpu_single_step(cpu, enabled ? SSTEP_ENABLE | SSTEP_NOIRQ | SSTEP_NOTIMER : 0);
}

uint32_t tlib_get_page_size()
{
  return TARGET_PAGE_SIZE;
}

void tlib_map_range(uint32_t start_addr, uint32_t length)
{
  ram_addr_t phys_offset = start_addr;
  ram_addr_t size = length;
  //remember that phys_dirty covers the whole memory range from 0 to the end
  //of the registered memory. Most offsets are probably unused. When a new
  //region is registered before any already registered memory, the array
  //does not need to be expanded.
  uint8_t *phys_dirty;
  size_t array_start_addr, array_size, new_size;
  array_start_addr = start_addr >> TARGET_PAGE_BITS;
  array_size = size >> TARGET_PAGE_BITS;
  new_size = array_start_addr + array_size;
  if(new_size > dirty_ram.current_size)
  {
    phys_dirty = tlib_malloc(new_size);
    memcpy(phys_dirty, dirty_ram.phys_dirty, dirty_ram.current_size);
    if(dirty_ram.phys_dirty != NULL)
    {
      tlib_free(dirty_ram.phys_dirty);
    }
    dirty_ram.phys_dirty = phys_dirty;
    dirty_ram.current_size = new_size;
  }
  memset(dirty_ram.phys_dirty + array_start_addr, 0xff, array_size);
  cpu_register_physical_memory(start_addr, size, phys_offset | IO_MEM_RAM);
}

void tlib_unmap_range(uint32_t start, uint32_t end)
{
  uint32_t new_start;

  while(start <= end)
  {
    unmap_page(start);
    new_start = start + TARGET_PAGE_SIZE;
    if(new_start < start)
    {
      return;
    }
    start = new_start;
  }
}

uint32_t tlib_is_range_mapped(uint32_t start, uint32_t end)
{
  PhysPageDesc *pd;

  while(start < end)
  {
    pd = phys_page_find(start >> TARGET_PAGE_BITS);
    if(pd != NULL && pd->phys_offset != IO_MEM_UNASSIGNED)
    {
      return 1; // at least one page of this region is mapped
    }
    start += TARGET_PAGE_SIZE;
  }
  return 0;
}

void tlib_invalidate_translation_blocks(unsigned long start, unsigned long end)
{
  tb_invalidate_phys_page_range_inner(start, end, 0, 0);
}

uint32_t tlib_translate_to_physical_address(uint32_t address)
{
  return virt_to_phys(address);
}

void tlib_set_irq(int32_t interrupt, int32_t state)
{
  if(state)
  {
    cpu_interrupt(cpu, interrupt);
  }
  else
  {
    cpu_reset_interrupt(cpu, interrupt);
  }
}

int32_t tlib_is_irq_set()
{
  return cpu->interrupt_request;
}

void tlib_add_breakpoint(uint32_t address)
{
  cpu_breakpoint_insert(cpu, address, BP_GDB, NULL);
}

void tlib_remove_breakpoint(uint32_t address)
{
  cpu_breakpoint_remove(cpu, address, BP_GDB);
}

void tlib_add_watchpoint(uint32_t address, uint32_t length)
{
  cpu_watchpoint_insert(cpu, address, length, BP_GDB, NULL);
}

void tlib_remove_watchpoint(uint32_t address, uint32_t length)
{
  cpu_watchpoint_remove(cpu, address, length, BP_GDB);
}

unsigned long translation_cache_size;

void tlib_set_translation_cache_size(unsigned long size)
{
  translation_cache_size = size;
}

void tlib_invalidate_translation_cache()
{
  if(cpu)
  {
    tb_flush(cpu);
  }
}

uint32_t maximum_block_size;

uint32_t tlib_set_maximum_block_size(uint32_t size)
{
  uint32_t effective_value;

  effective_value = size & CF_COUNT_MASK;
  maximum_block_size = effective_value;
  return effective_value;
}

uint32_t tlib_get_maximum_block_size()
{
  return maximum_block_size;
}

extern void *global_retaddr;

void tlib_restore_context()
{
  unsigned long pc;
  TranslationBlock *tb;

  pc = (unsigned long)global_retaddr;
  tb = tb_find_pc(pc);
  cpu_restore_state(tb, cpu, pc);
}

void* tlib_export_state()
{
  return cpu;
}

#ifndef CPU_STATE_SIZE
#define CPU_STATE_SIZE 0
#endif
int32_t tlib_get_state_size()
{
  return CPU_STATE_SIZE;
}
