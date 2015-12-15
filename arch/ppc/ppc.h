#ifndef PPC_HEADER_
#define PPC_HEADER_
#include "cpu.h"
void ppc_set_irq (CPUState *env, int n_IRQ, int level);

/* PowerPC hardware exceptions management helpers */
typedef void (*clk_setup_cb)(void *opaque, uint32_t freq);
typedef struct clk_setup_t clk_setup_t;
struct clk_setup_t {
    clk_setup_cb cb;
    void *opaque;
};
static inline void clk_setup (clk_setup_t *clk, uint32_t freq)
{
    if (clk->cb != NULL)
        (*clk->cb)(clk->opaque, freq);
}

struct ppc_tb_t {
    /* Time base management */
    int64_t  tb_offset;    /* Compensation                    */
    int64_t  atb_offset;   /* Compensation                    */
    uint32_t tb_freq;      /* TB frequency                    */
    uint64_t purr_load;
    uint64_t purr_start;
    void *opaque;
    uint32_t flags;
};

uint64_t cpu_ppc_get_tb(ppc_tb_t *tb_env, uint64_t vmclk, int64_t tb_offset);
clk_setup_cb cpu_ppc_tb_init (CPUState *env, uint32_t freq);
/* Embedded PowerPC DCR management */
typedef uint32_t (*dcr_read_cb)(void *opaque, int dcrn);
typedef void (*dcr_write_cb)(void *opaque, int dcrn, uint32_t val);
int ppc_dcr_init (CPUState *env, int (*dcr_read_error)(int dcrn),
                  int (*dcr_write_error)(int dcrn));
int ppc_dcr_register (CPUState *env, int dcrn, void *opaque,
                      dcr_read_cb drc_read, dcr_write_cb dcr_write);
clk_setup_cb ppc_40x_timers_init (CPUState *env, uint32_t freq,
                                  unsigned int decr_excp);

/* Embedded PowerPC reset */
void ppc40x_core_reset (CPUState *env);
void ppc40x_chip_reset (CPUState *env);
void ppc40x_system_reset (CPUState *env);

extern CPUWriteMemoryFunc * const PPC_io_write[];
extern CPUReadMemoryFunc * const PPC_io_read[];

/* PPC machines for OpenBIOS */
enum {
    ARCH_PREP = 0,
    ARCH_MAC99,
    ARCH_HEATHROW,
    ARCH_MAC99_U3,
};

#define FW_CFG_PPC_WIDTH	(FW_CFG_ARCH_LOCAL + 0x00)
#define FW_CFG_PPC_HEIGHT	(FW_CFG_ARCH_LOCAL + 0x01)
#define FW_CFG_PPC_DEPTH	(FW_CFG_ARCH_LOCAL + 0x02)
#define FW_CFG_PPC_TBFREQ	(FW_CFG_ARCH_LOCAL + 0x03)
#define FW_CFG_PPC_IS_KVM       (FW_CFG_ARCH_LOCAL + 0x05)
#define FW_CFG_PPC_KVM_HC       (FW_CFG_ARCH_LOCAL + 0x06)
#define FW_CFG_PPC_KVM_PID      (FW_CFG_ARCH_LOCAL + 0x07)

#define PPC_SERIAL_MM_BAUDBASE 399193
#endif
