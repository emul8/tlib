#include <infrastructure.h>

#include <global_helper.h>
#define GEN_HELPER 1
#include <global_helper.h>

#include "helper.h"
#define GEN_HELPER 1
#include "helper.h"

extern TCGv_ptr cpu_env;

void gen_helpers(void)
{
#define GEN_HELPER 2
#include "helper.h"
}

