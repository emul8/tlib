/*
 *  Host code generation
 *
 *  Copyright (c) 2003 Fabrice Bellard
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
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "cpu.h"
#include "tcg.h"

/* '*gen_code_size_ptr' contains the size of the generated code (host
   code).
*/
void cpu_gen_code(CPUState *env, TranslationBlock *tb, int *gen_code_size_ptr)
{
    TCGContext *s = tcg->ctx;
    uint8_t *gen_code_buf;
    int gen_code_size;

    tcg_func_start(s);

    gen_intermediate_code(env, tb, 0);

    /* generate machine code */
    gen_code_buf = tb->tc_ptr;
    tb->tb_next_offset[0] = 0xffff;
    tb->tb_next_offset[1] = 0xffff;
    s->tb_next_offset = tb->tb_next_offset;
    s->tb_jmp_offset = tb->tb_jmp_offset;
    s->tb_next = NULL;

    gen_code_size = tcg_gen_code(s, gen_code_buf);
    *gen_code_size_ptr = gen_code_size;
}

/* The cpu state corresponding to 'searched_pc' is restored.
 */
int cpu_restore_state(CPUState *env,
		TranslationBlock *tb, unsigned long searched_pc)
{
    TCGContext *s = tcg->ctx;
    int j, k;
    unsigned long tc_ptr;
    int instructions_executed_so_far = 0;

    tcg_func_start(s);
    memset((void*)tcg->gen_opc_instr_start, 0, OPC_BUF_SIZE);
    gen_intermediate_code(env, tb, 1);

    /* find opc index corresponding to search_pc */
    tc_ptr = (unsigned long)tb->tc_ptr;
    if (searched_pc < tc_ptr)
        return -1;

    s->tb_next_offset = tb->tb_next_offset;
    s->tb_jmp_offset = tb->tb_jmp_offset;
    s->tb_next = NULL;
    j = tcg_gen_code_search_pc(s, (uint8_t *)tc_ptr, searched_pc - tc_ptr);
    if (j < 0)
        return -1;
    /* now find start of instruction before */
    while (tcg->gen_opc_instr_start[j] == 0)
        j--;

    k = j;
    while (k > 0)
    {
      instructions_executed_so_far += tcg->gen_opc_instr_start[k];
      k--;
    }
    cpu->instructions_count_value -= (tb->icount - instructions_executed_so_far);

    restore_state_to_opc(env, tb, j);

    return 0;
}
