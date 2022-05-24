// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, GlobalLogic
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright (c) 2021-2022, Renesas Electronics Corporation.
 */

#include <console.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <drivers/scif.h>
#include <drivers/gic.h>
#include <kernel/boot.h>
#include <trace.h>
#include <kernel/misc.h>
#include <kernel/spinlock.h>

static void main_hook_gic_add(struct itr_chip *chip, size_t it, uint32_t flags);

uint32_t cpu_on_core_lock __nex_bss = (uint32_t)SPINLOCK_UNLOCK;
uint8_t cpu_on_core_bit __nex_bss = 0U;
static void (*gic_add_ptr_bk)(struct itr_chip *chip, size_t it,
				uint32_t flags) __nex_bss;
static struct itr_ops main_itr_ops __nex_bss;

void main_secondary_init_gic(void)
{
	uint32_t exceptions;
	uint8_t cpu_mask;

	DMSG("IN cpu_on_core_bit=0x%x, get_core_pos()=%lu",
					cpu_on_core_bit, get_core_pos());
	exceptions = cpu_spin_lock_xsave(&cpu_on_core_lock);

	cpu_on_core_bit |= (uint8_t)(0x1U << get_core_pos());
	cpu_mask = cpu_on_core_bit;

	itr_set_all_cpu_mask(cpu_mask);

	cpu_spin_unlock_xrestore(&cpu_on_core_lock, exceptions);
	DMSG("OUT cpu_mask=0x%x", cpu_mask);
}

unsigned long thread_cpu_off_handler(unsigned long a0 __unused,
				unsigned long a1 __unused)
{
	uint32_t exceptions;
	uint8_t cpu_mask;

	DMSG("IN cpu_on_core_bit=0x%x, get_core_pos()=%lu",
				cpu_on_core_bit, get_core_pos());
	exceptions = cpu_spin_lock_xsave(&cpu_on_core_lock);

	cpu_on_core_bit &= (0xFFU ^ (uint8_t)(0x1U << get_core_pos()));
	cpu_mask = cpu_on_core_bit;

	itr_set_all_cpu_mask(cpu_mask);

	cpu_spin_unlock_xrestore(&cpu_on_core_lock, exceptions);
	DMSG("OUT cpu_mask=0x%x", cpu_mask);
	return 0;
}

struct gic_data gic_data __nex_bss;

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_DIST_REG_SIZE);

#ifdef MEMORY1_BASE
register_phys_mem_pgdir(MEMORY1_TYPE, MEMORY1_BASE, MEMORY1_SIZE);
#endif
#ifdef MEMORY2_BASE
register_phys_mem(MEMORY2_TYPE, MEMORY2_BASE, MEMORY2_SIZE);
#endif
#ifdef MEMORY3_BASE
register_phys_mem_pgdir(MEMORY3_TYPE, MEMORY3_BASE, MEMORY3_SIZE);
#endif
#ifdef MEMORY4_BASE
register_phys_mem(MEMORY4_TYPE, MEMORY4_BASE, MEMORY4_SIZE);
#endif
#ifdef MEMORY5_BASE
register_phys_mem_pgdir(MEMORY5_TYPE, MEMORY5_BASE, MEMORY5_SIZE);
#endif
#ifdef MEMORY6_BASE
register_phys_mem_pgdir(MEMORY6_TYPE, MEMORY6_BASE, MEMORY6_SIZE);
#endif
#ifdef MEMORY7_BASE
register_phys_mem_pgdir(MEMORY7_TYPE, MEMORY7_BASE, MEMORY7_SIZE);
#endif
#ifdef MEMORY8_BASE
register_phys_mem_pgdir(MEMORY8_TYPE, MEMORY8_BASE, MEMORY8_SIZE);
#endif
#ifdef DEVICE0_PA_BASE
register_phys_mem_pgdir(DEVICE0_TYPE, DEVICE0_PA_BASE, DEVICE0_SIZE);
#endif
#ifdef DEVICE1_PA_BASE
register_phys_mem_pgdir(DEVICE1_TYPE, DEVICE1_PA_BASE, DEVICE1_SIZE);
#endif
#ifdef DEVICE2_PA_BASE
register_phys_mem_pgdir(DEVICE2_TYPE, DEVICE2_PA_BASE, DEVICE2_SIZE);
#endif

/* Legacy platforms */
#if defined(PLATFORM_FLAVOR_salvator_h3) || \
	defined(PLATFORM_FLAVOR_salvator_h3_4x2g) || \
	defined(PLATFORM_FLAVOR_salvator_m3) || \
	defined(PLATFORM_FLAVOR_salvator_m3_2x4g)
register_ddr(NSEC_DDR_0_BASE, NSEC_DDR_0_SIZE);
register_ddr(NSEC_DDR_1_BASE, NSEC_DDR_1_SIZE);
#ifdef NSEC_DDR_2_BASE
register_ddr(NSEC_DDR_2_BASE, NSEC_DDR_2_SIZE);
#endif
#ifdef NSEC_DDR_3_BASE
register_ddr(NSEC_DDR_3_BASE, NSEC_DDR_3_SIZE);
#endif
#endif

void main_init_gic(void)
{
	vaddr_t gicc_base;
	vaddr_t gicd_base;

	gicc_base = (vaddr_t)phys_to_virt(GICC_BASE, MEM_AREA_IO_SEC);
	gicd_base = (vaddr_t)phys_to_virt(GICD_BASE, MEM_AREA_IO_SEC);
	assert(gicc_base && gicd_base);

	/* On ARMv8, GIC configuration is initialized in ARM-TF */
	gic_init_base_addr(&gic_data, gicc_base, gicd_base);

	itr_init(&gic_data.chip);

	cpu_on_core_bit = (uint8_t)(0x1U << get_core_pos());

	gic_add_ptr_bk = gic_data.chip.ops->add;
	main_itr_ops = *gic_data.chip.ops;
	main_itr_ops.add = main_hook_gic_add;
	gic_data.chip.ops = (const struct itr_ops *)&main_itr_ops;
}

static void main_hook_gic_add(struct itr_chip *chip, size_t it, uint32_t flags)
{
	uint32_t exceptions;
	uint8_t cpu_mask;

	DMSG("IN cpu_on_core_bit=0x%x, it=0x%lu", cpu_on_core_bit, it);
	gic_add_ptr_bk(chip, it, flags);

	exceptions = cpu_spin_lock_xsave(&cpu_on_core_lock);
	cpu_mask = cpu_on_core_bit;
	itr_set_affinity(it, cpu_mask);

	cpu_spin_unlock_xrestore(&cpu_on_core_lock, exceptions);
	DMSG("OUT cpu_mask=0x%x", cpu_mask);
}

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
	/* No Operation */
}

int32_t is_normal_world_initialized __nex_bss;
