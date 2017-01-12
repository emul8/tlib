#include "dyngen-exec.h"
#include <global_helper.h>
#include "callbacks.h"

void HELPER(update_insn_count)(int inst_count)
{
  tlib_update_instruction_counter(inst_count);
}

void HELPER(block_begin_event)(uint32_t address, uint32_t size)
{
  tlib_on_block_begin(address, size);
}
