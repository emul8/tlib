/*
 *  ARM interface functions.
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

uint32_t tlib_get_cpu_id()
{
  return cpu->cp15.c0_cpuid;
}

void tlib_set_cpu_id(uint32_t value)
{
  cpu->cp15.c0_cpuid = value;
}

#ifdef TARGET_PROTO_ARM_M

void tlib_toggle_fpu(int32_t enabled)
{
  cpu->vfp.xregs[ARM_VFP_FPEXC] = enabled ? (1 << 30) : 0;
}

void tlib_set_interrupt_vector_base(uint32_t address)
{
  cpu->v7m.vecbase = address;
}

uint32_t tlib_get_interrupt_vector_base()
{
  return cpu->v7m.vecbase;
}

#endif
