#ifdef ARITH_GE
#define GE_ARG , void *gep
#else
#define GE_ARG
#endif

uint32_t HELPER(glue(PFX,add16))(uint32_t a, uint32_t b GE_ARG)
{
    return 0;
}

uint32_t HELPER(glue(PFX,add8))(uint32_t a, uint32_t b GE_ARG)
{
    return 0;
}

uint32_t HELPER(glue(PFX,sub16))(uint32_t a, uint32_t b GE_ARG)
{
    return 0;
}

uint32_t HELPER(glue(PFX,sub8))(uint32_t a, uint32_t b GE_ARG)
{
    return 0;
}

uint32_t HELPER(glue(PFX,subaddx))(uint32_t a, uint32_t b GE_ARG)
{
    return 0;
}

uint32_t HELPER(glue(PFX,addsubx))(uint32_t a, uint32_t b GE_ARG)
{
    return 0;
}

#undef GE_ARG
#undef ARITH_GE
#undef PFX

