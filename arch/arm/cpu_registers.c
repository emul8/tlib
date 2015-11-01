/*
 *  ARM registers interface.
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
#include "cpu_registers.h"

uint32_t* get_reg_pointer_32(int reg)
{
    switch(reg)
    {
        case R_0_32 ... R_15_32:
            return &(cpu->regs[reg]);
        case CPSR_32:
			return &(cpu->uncached_cpsr);
		case SPSR_32:
			return &(cpu->spsr);
#ifdef TARGET_PROTO_ARM_M
		case Control_32:
			return &(cpu->v7m.control);
		case BasePri_32:
			return &(cpu->v7m.basepri);
		case VecBase_32:
			return &(cpu->v7m.vecbase);
		case CurrentSP_32:
			return &(cpu->v7m.current_sp);
		case OtherSP_32:
			return &(cpu->v7m.other_sp);
#endif
        default:
            return NULL;
    }
}

void set_thumb(int value)
{
    cpu->thumb = value & 0x1;
}

CPU_REGISTER_ACCESSOR(32)
