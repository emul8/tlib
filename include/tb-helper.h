#include <infrastructure.h>

#include <global_helper.h>
#define GEN_HELPER 1
#include <global_helper.h>

/* Helpers for instruction counting code generation.  */

static TCGArg *icount_arg;
static int stopflag_label;

static inline void gen_block_header(void)
{
    TCGv_i32 flag;
    stopflag_label = gen_new_label();
    flag = tcg_temp_local_new_i32();
    tcg_gen_ld_i32(flag, cpu_env, offsetof(CPUState, exit_request));
    tcg_gen_brcondi_i32(TCG_COND_NE, flag, 0, stopflag_label);
    tcg_temp_free_i32(flag);

    if(tlib_is_instruction_count_enabled())
    {
        icount_arg = gen_opparam_ptr + 1;
        // at this moment this const contains magic value 88888
        // which is replaced at gen_block_footer near the end of
        // the block
        TCGv_i32 instruction_count = tcg_const_i32(88888);
        gen_helper_update_insn_count(instruction_count);
        tcg_temp_free_i32(instruction_count);
    }
}

static void gen_block_footer(TranslationBlock *tb, int num_insns)
{
    gen_set_label(stopflag_label);
    tcg_gen_exit_tb((long)tb + 2);
    if(tlib_is_instruction_count_enabled())
    {
        *icount_arg = num_insns;
    }
}
