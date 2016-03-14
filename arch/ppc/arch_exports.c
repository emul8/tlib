/*
 *  PPC interface functions.
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

int32_t tlib_set_pending_interrupt(int32_t interruptNo, int32_t level)
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

