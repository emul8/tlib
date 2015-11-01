/*
 * QEMU generic PowerPC hardware System Emulator
 *
 * Copyright (c) 2003-2007 Jocelyn Mayer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "ppc.h"
#include "infrastructure.h"

void ppc_set_irq(CPUState *env, int n_IRQ, int level)
{
    if (level) {
        env->pending_interrupts |= 1 << n_IRQ;
        cpu_interrupt(env, CPU_INTERRUPT_HARD);
    } else {
        env->pending_interrupts &= ~(1 << n_IRQ);
        if (env->pending_interrupts == 0)
            cpu_reset_interrupt(env, CPU_INTERRUPT_HARD);
    }
}

// returns 1 if one should clear CPU's interrupt
int ppc_set_pending_interrupt(int n_IRQ, int level)
{
    if (level) {
        cpu->pending_interrupts |= 1 << n_IRQ;
    } else {
        cpu->pending_interrupts &= ~(1 << n_IRQ);
        if (cpu->pending_interrupts == 0)
        {
          return 1;
        }
    }
    return 0;
}

#if defined(TARGET_PPC64)
/* PowerPC 970 internal IRQ controller */
static void ppc970_set_irq (void *opaque, int pin, int level)
{
    CPUState *env = opaque;
    int cur_level;

    cur_level = (env->irq_input_state >> pin) & 1;
    /* Don't generate spurious events */
    if ((cur_level == 1 && level == 0) || (cur_level == 0 && level != 0)) {
        switch (pin) {
        case PPC970_INPUT_INT:
            /* Level sensitive - active high */
            ppc_set_irq(env, PPC_INTERRUPT_EXT, level);
            break;
        case PPC970_INPUT_THINT:
            /* Level sensitive - active high */
            ppc_set_irq(env, PPC_INTERRUPT_THERM, level);
            break;
        case PPC970_INPUT_MCP:
            /* Negative edge sensitive */
            /* XXX: TODO: actual reaction may depends on HID0 status
             *            603/604/740/750: check HID0[EMCP]
             */
            if (cur_level == 1 && level == 0) {
                ppc_set_irq(env, PPC_INTERRUPT_MCK, 1);
            }
            break;
        case PPC970_INPUT_CKSTP:
            /* Level sensitive - active low */
            /* XXX: TODO: relay the signal to CKSTP_OUT pin */
            if (level) {
                env->wfi = 1;
            } else {
                env->wfi = 0;
            }
            break;
        case PPC970_INPUT_HRESET:
            /* Level sensitive - active low */
            break;
        case PPC970_INPUT_SRESET:
            ppc_set_irq(env, PPC_INTERRUPT_RESET, level);
            break;
        case PPC970_INPUT_TBEN:
            /* XXX: TODO */
            break;
        default:
            /* Unknown pin - do nothing */
            return;
        }
        if (level)
            env->irq_input_state |= 1 << pin;
        else
            env->irq_input_state &= ~(1 << pin);
    }
}

/* POWER7 internal IRQ controller */
static void power7_set_irq (void *opaque, int pin, int level)
{
    CPUState *env = opaque;

    switch (pin) {
    case POWER7_INPUT_INT:
        /* Level sensitive - active high */
        ppc_set_irq(env, PPC_INTERRUPT_EXT, level);
        break;
    default:
        /* Unknown pin - do nothing */
        return;
    }
    if (level) {
        env->irq_input_state |= 1 << pin;
    } else {
        env->irq_input_state &= ~(1 << pin);
    }
}

#endif /* defined(TARGET_PPC64) */

uint64_t a,b,c;
uint64_t cpu_ppc_get_tb(ppc_tb_t *tb_env, uint64_t vmclk, int64_t tb_offset)
{
printf("cpu_ppc_get_tb");
return a++;
}


uint64_t cpu_ppc_load_tbl (CPUState *env)
{
printf("cpu_ppc_load_tbl");
return b++;
}

static inline uint32_t _cpu_ppc_load_tbu(CPUState *env)
{
printf("_cpu_ppc_load_tbu");
return c++;
}

uint32_t cpu_ppc_load_tbu (CPUState *env)
{
printf("cpu_ppc_load_tbu");
return 0;
}


static inline void cpu_ppc_store_tb(ppc_tb_t *tb_env, uint64_t vmclk,
                                    int64_t *tb_offsetp, uint64_t value)
{
printf("cpu_ppc_load_tbu");
}
void cpu_ppc_store_tbl (CPUState *env, uint32_t value)
{
printf("cpu_ppc_load_tbu");
}
static inline void _cpu_ppc_store_tbu(CPUState *env, uint32_t value)
{
printf("cpu_ppc_load_tbu");
}
void cpu_ppc_store_tbu (CPUState *env, uint32_t value)
{
printf("cpu_ppc_load_tbu");
}
uint64_t cpu_ppc_load_atbl (CPUState *env)
{
printf("cpu_ppc_load_tbu");
return 0;
}
uint32_t cpu_ppc_load_atbu (CPUState *env)
{
printf("cpu_ppc_load_tbu");
return 0;
}
void cpu_ppc_store_atbl (CPUState *env, uint32_t value)
{
printf("cpu_ppc_load_tbu");
}
void cpu_ppc_store_atbu (CPUState *env, uint32_t value)
{
printf("cpu_ppc_load_tbu");
}
static inline uint32_t _cpu_ppc_load_decr(CPUState *env, uint64_t next)
{
printf("cpu_ppc_load_tbu");
return 0;
}
uint32_t cpu_ppc_load_decr (CPUState *env)
{
printf("cpu_ppc_load_tbu");
return 0;
}
uint32_t cpu_ppc_load_hdecr (CPUState *env)
{
printf("cpu_ppc_load_tbu");
return 0;
}
uint64_t cpu_ppc_load_purr (CPUState *env)
{
printf("cpu_ppc_load_tbu");
return 0;
}
static inline void cpu_ppc_decr_excp(CPUState *env)
{
printf("cpu_ppc_load_tbu");
}
static inline void cpu_ppc_hdecr_excp(CPUState *env)
{
printf("cpu_ppc_load_tbu");
}
static inline void _cpu_ppc_store_decr(CPUState *env, uint32_t decr,
                                       uint32_t value, int is_excp)
{
printf("cpu_ppc_load_tbu");
}
void cpu_ppc_store_decr (CPUState *env, uint32_t value)
{
printf("cpu_ppc_load_tbu");
}
static inline void _cpu_ppc_store_hdecr(CPUState *env, uint32_t hdecr,
                                        uint32_t value, int is_excp)
{
printf("cpu_ppc_load_tbu");
}
void cpu_ppc_store_hdecr (CPUState *env, uint32_t value)
{
printf("cpu_ppc_load_tbu");
}
void cpu_ppc_store_purr (CPUState *env, uint64_t value)
{
printf("cpu_ppc_load_tbu");
}
clk_setup_cb cpu_ppc_tb_init (CPUState *env, uint32_t freq)
{
printf("cpu_ppc_load_tbu");
return 0;
}
void cpu_ppc601_store_rtcu (CPUState *env, uint32_t value)
{
printf("cpu_ppc_load_tbu");
}
uint32_t cpu_ppc601_load_rtcu (CPUState *env)
{
printf("cpu_ppc_load_tbu");
return 0;
}
void cpu_ppc601_store_rtcl (CPUState *env, uint32_t value)
{
printf("cpu_ppc_load_tbu");
}
uint32_t cpu_ppc601_load_rtcl (CPUState *env)
{
printf("cpu_ppc_load_tbu");
return 0;
}
void store_40x_pit (CPUState *env, target_ulong val)
{
printf("cpu_ppc_load_tbu");
}
target_ulong load_40x_pit (CPUState *env)
{
printf("load_40x_pit");
return 0;
}
clk_setup_cb ppc_40x_timers_init (CPUState *env, uint32_t freq,
                                  unsigned int decr_excp)
{
printf("ppc_40x_timers_init");
return 0;
}
/*****************************************************************************/
/* Embedded PowerPC Device Control Registers */
typedef struct ppc_dcrn_t ppc_dcrn_t;
struct ppc_dcrn_t {
    dcr_read_cb dcr_read;
    dcr_write_cb dcr_write;
    void *opaque;
};

/* XXX: on 460, DCR addresses are 32 bits wide,
 *      using DCRIPR to get the 22 upper bits of the DCR address
 */
#define DCRN_NB 1024
struct ppc_dcr_t {
    ppc_dcrn_t dcrn[DCRN_NB];
    int (*read_error)(int dcrn);
    int (*write_error)(int dcrn);
};

int ppc_dcr_read (ppc_dcr_t *dcr_env, int dcrn, uint32_t *valp)
{
    ppc_dcrn_t *dcr;

    if (dcrn < 0 || dcrn >= DCRN_NB)
        goto error;
    dcr = &dcr_env->dcrn[dcrn];
    if (dcr->dcr_read == NULL)
        goto error;
    *valp = (*dcr->dcr_read)(dcr->opaque, dcrn);

    return 0;

 error:
    if (dcr_env->read_error != NULL)
        return (*dcr_env->read_error)(dcrn);

    return -1;
}

int ppc_dcr_write (ppc_dcr_t *dcr_env, int dcrn, uint32_t val)
{
    ppc_dcrn_t *dcr;

    if (dcrn < 0 || dcrn >= DCRN_NB)
        goto error;
    dcr = &dcr_env->dcrn[dcrn];
    if (dcr->dcr_write == NULL)
        goto error;
    (*dcr->dcr_write)(dcr->opaque, dcrn, val);

    return 0;

 error:
    if (dcr_env->write_error != NULL)
        return (*dcr_env->write_error)(dcrn);

    return -1;
}

int ppc_dcr_register (CPUState *env, int dcrn, void *opaque,
                      dcr_read_cb dcr_read, dcr_write_cb dcr_write)
{
    ppc_dcr_t *dcr_env;
    ppc_dcrn_t *dcr;

    dcr_env = env->dcr_env;
    if (dcr_env == NULL)
        return -1;
    if (dcrn < 0 || dcrn >= DCRN_NB)
        return -1;
    dcr = &dcr_env->dcrn[dcrn];
    if (dcr->opaque != NULL ||
        dcr->dcr_read != NULL ||
        dcr->dcr_write != NULL)
        return -1;
    dcr->opaque = opaque;
    dcr->dcr_read = dcr_read;
    dcr->dcr_write = dcr_write;

    return 0;
}

int ppc_dcr_init (CPUState *env, int (*read_error)(int dcrn),
                  int (*write_error)(int dcrn))
{
    ppc_dcr_t *dcr_env;

    dcr_env = tlib_mallocz(sizeof(ppc_dcr_t));
    dcr_env->read_error = read_error;
    dcr_env->write_error = write_error;
    env->dcr_env = dcr_env;

    return 0;
}

