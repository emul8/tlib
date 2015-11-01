#include "cpu-defs.h"

typedef enum {
    R_0_32 = 0,
    R_1_32 = 1,
    R_2_32 = 2,
    R_3_32 = 3,
    R_4_32 = 4,
    R_5_32 = 5,
    R_6_32 = 6,
    R_7_32 = 7,
    R_8_32 = 8,
    R_9_32 = 9,
    R_10_32 = 10,
    R_11_32 = 11,
    R_12_32 = 12,
    R_13_32 = 13,
    SP_32 = 13,
    R_14_32 = 14,
    LR_32 = 14,
    R_15_32 = 15,
    PC_32 = 15,
    CPSR_32 = 16,
    SPSR_32 = 17,
#ifdef TARGET_PROTO_ARM_M
    Control_32 = 18,
    BasePri_32 = 19,
    VecBase_32 = 20,
    CurrentSP_32 = 21,
    OtherSP_32 = 22
#endif
} Registers;
