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
 * Copyright (c) 2021-2024, Renesas Electronics Corporation.
 */

#include <console.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <drivers/hscif.h>
#include <drivers/gic.h>
#include <kernel/boot.h>
#include <trace.h>
#include <kernel/misc.h>
#include <kernel/spinlock.h>
#include <sm/optee_smc.h>
#include <tee/entry_fast.h>
#include "rcar_log_func.h"
#include "rcar_common.h"
#include "rcar_suspend_to_ram.h"

static void main_hook_gic_add(struct itr_chip *chip, size_t it, uint32_t flags, uint32_t prio);
static void main_init_gic(void);
static void main_secondary_init_gic(void);

uint32_t cpu_on_core_lock __nex_bss = (uint32_t)SPINLOCK_UNLOCK;
uint8_t cpu_on_core_bit __nex_bss = 0U;
static uint32_t suspend_to_ram_save_flag __nex_bss = 0U;
static uint32_t main_cpu_lock __nex_bss = (uint32_t)SPINLOCK_UNLOCK;
static void (*gic_add_ptr_bk)(struct itr_chip *chip, size_t it,
				uint32_t flags, uint32_t prio) __nex_bss;
static struct itr_ops main_itr_ops __nex_bss;

/* Overriding the default __weak tee_entry_fast() */
void tee_entry_fast(struct thread_smc_args *args)
{
	DMSG("IN args->a0=0x%lX", args->a0);
#ifdef CFG_NS_VIRTUALIZATION
	if (args->a0 == OPTEE_SMC_ENABLE_SHM_CACHE) {
#else
	if ((args->a0 == OPTEE_SMC_GET_SHM_CONFIG) &&
	    (args->a1 == SMC_RCAR_CMD) &&
	    (args->a2 == START_DLOG_OUTPUT)) {
#endif
		is_normal_world_initialized = 1;
		DMSG("Normal World was initialized");
	}
	__tee_entry_fast(args);
	DMSG("OUT Received SMC from Normal World");
}

unsigned long thread_cpu_suspend_handler(unsigned long a0,
				unsigned long a1 __unused)
{

	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&main_cpu_lock);
	TMSG("a0=0x%lX, a1=0x%lX", a0, a1);

	if (a0 >= TFW_ARG_SYSTEM_SUSPEND) {
		if (suspend_to_ram_save_flag == 0U) {
			suspend_to_ram_save();
			suspend_to_ram_save_flag = 1U;
			DMSG("END suspend_to_ram_save");
		} else {
			/* no operation */
		}
	} else {
		/* in case of CPU_SUSPEND(CPU Idle), no operation */
	}

	cpu_spin_unlock_xrestore(&main_cpu_lock, exceptions);
	return 0U;
}

unsigned long thread_cpu_resume_handler(unsigned long a0 __unused,
				unsigned long a1 __unused)
{
	uint32_t exceptions;
	uint32_t exceptions2;

	exceptions = cpu_spin_lock_xsave(&main_cpu_lock);
	TMSG("a0=0x%lX, a1=0x%lX", a0, a1);

	if (suspend_to_ram_save_flag == 1U) {
		suspend_to_ram_restore();
		suspend_to_ram_save_flag = 0U;
		DMSG("END suspend_to_ram_restore");
	} else {
		/* no operation */
	}

	if (smc_prohibit_flag) {
		exceptions2 = cpu_spin_lock_xsave(&cpu_on_core_lock);

		/* Unmask the FIQ on the primary CPU */
		cpu_on_core_bit |= (uint8_t)(0x1U << get_core_pos());
		itr_set_all_cpu_mask(cpu_on_core_bit);

		cpu_spin_unlock_xrestore(&cpu_on_core_lock, exceptions2);
	}

	cpu_spin_unlock_xrestore(&main_cpu_lock, exceptions);
	return 0U;
}

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
#ifdef MEMORY9_BASE
register_phys_mem_pgdir(MEMORY9_TYPE, MEMORY9_BASE, MEMORY9_SIZE);
#endif
#ifdef MEMORY10_BASE
register_phys_mem_pgdir(MEMORY10_TYPE, MEMORY10_BASE, MEMORY10_SIZE);
#endif
#ifdef MEMORY11_BASE
register_phys_mem_pgdir(MEMORY11_TYPE, MEMORY11_BASE, MEMORY11_SIZE);
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

#ifdef CFG_SCIF
static struct hscif_uart_data console_data __nex_bss;
#endif

#if defined(CFG_CORE_DYN_SHM) && !defined(CFG_CORE_RESERVED_SHM)
register_ddr(NSEC_DDR_0_BASE, NSEC_DDR_0_SIZE);
register_ddr(NSEC_DDR_1_BASE, NSEC_DDR_1_SIZE);
#endif

void main_init_gic(void)
{
	// Use custom itr_ops.add (instead of gic_op_add).
	cpu_on_core_bit = (uint8_t)(0x1U << get_core_pos());
	gic_add_ptr_bk = gic_data.chip.ops->add;
	main_itr_ops = *gic_data.chip.ops;
	main_itr_ops.add = main_hook_gic_add;
	gic_data.chip.ops = (const struct itr_ops *)&main_itr_ops;

#ifndef CFG_SCIF
	// Initialize logging feature
	log_buf_init();
#endif
}

static void main_hook_gic_add(struct itr_chip *chip, size_t it, uint32_t flags, uint32_t prio)
{
	uint32_t exceptions;
	uint8_t cpu_mask;

	DMSG("IN cpu_on_core_bit=0x%x, it=0x%lu", cpu_on_core_bit, it);
	gic_add_ptr_bk(chip, it, flags, prio);

	exceptions = cpu_spin_lock_xsave(&cpu_on_core_lock);
	cpu_mask = cpu_on_core_bit;
	interrupt_set_affinity(chip, it, cpu_mask);

	cpu_spin_unlock_xrestore(&cpu_on_core_lock, exceptions);
	DMSG("OUT cpu_mask=0x%x", cpu_mask);
}

/* Not defined. Use implementation from gic driver in core/drivers/gic.c
void interrupt_main_handler(void){ }
*/

void plat_console_init(void)
{
#ifdef CFG_SCIF
	hscif_uart_init(&console_data, CONSOLE_UART_START);
	register_serial_console(&console_data.chip);
#endif
}

void boot_primary_init_intc(void)
{
	gic_init(GICC_BASE, GICD_BASE);

	main_init_gic();
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
	main_secondary_init_gic();
}
