// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015-2019, Renesas Electronics Corporation
 */

#include <platform_config.h>

#include <stdint.h>
#include <string.h>

#include <drivers/gic.h>

#include <arm.h>
#include <kernel/generic_boot.h>
#include <kernel/pm_stubs.h>
#include <trace.h>
#include <kernel/misc.h>
#include <kernel/tee_time.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <console.h>
#include <io.h>

#include <sm/optee_smc.h>
#include <kernel/spinlock.h>
#include "rcar_common.h"
#include "rcar_log_func.h"
#include "rcar_suspend_to_ram.h"

static void main_tee_entry_fast(struct thread_smc_args *args);
static unsigned long main_cpu_suspend(unsigned long a0, unsigned long a1);
static unsigned long main_cpu_resume(unsigned long a0, unsigned long a1);
static void main_fiq(void);
static void main_hook_gic_add(struct itr_chip *chip, size_t it, uint32_t flags);

static uint32_t suspend_to_ram_save_flag = 0U;
static uint32_t main_cpu_lock = (uint32_t)SPINLOCK_UNLOCK;
static uint32_t cpu_on_core_lock = (uint32_t)SPINLOCK_UNLOCK;
static uint8_t cpu_on_core_bit = 0U;
static void (*gic_add_ptr_bk)(struct itr_chip *chip, size_t it,
				uint32_t flags);
static struct itr_ops main_itr_ops;

static void main_tee_entry_fast(struct thread_smc_args *args)
{
	DMSG("IN args->a0=0x%lX", args->a0);
	if (args->a0 == OPTEE_SMC_GET_SHM_CONFIG) {
		is_normal_world_initialized = 1;
		DMSG("Normal World was initialized");
	}
	tee_entry_fast(args);
	DMSG("OUT Received SMC from Normal World");
}

static unsigned long main_cpu_suspend(unsigned long a0,
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

static unsigned long main_cpu_resume(unsigned long a0 __unused,
				unsigned long a1 __unused)
{
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&main_cpu_lock);
	TMSG("a0=0x%lX, a1=0x%lX", a0, a1);

	if (suspend_to_ram_save_flag == 1U) {
		suspend_to_ram_restore();
		suspend_to_ram_save_flag = 0U;
		DMSG("END suspend_to_ram_restore");
	} else {
		/* no operation */
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

static unsigned long main_cpu_off(unsigned long a0 __unused,
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

static const struct thread_handlers handlers = {
	.std_smc = tee_entry_std,
	.fast_smc = main_tee_entry_fast,
	.nintr = main_fiq,
	.cpu_on = cpu_on_handler,
	.cpu_off = main_cpu_off,
	.cpu_suspend = main_cpu_suspend,
	.cpu_resume = main_cpu_resume,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
};

struct gic_data gic_data;

register_phys_mem(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, GICC_BASE, GIC_DIST_REG_SIZE);

#ifdef MEMORY1_BASE
register_phys_mem(MEMORY1_TYPE, MEMORY1_BASE, MEMORY1_SIZE);
#endif
#ifdef MEMORY2_BASE
register_phys_mem(MEMORY2_TYPE, MEMORY2_BASE, MEMORY2_SIZE);
#endif
#ifdef MEMORY3_BASE
register_phys_mem(MEMORY3_TYPE, MEMORY3_BASE, MEMORY3_SIZE);
#endif
#ifdef MEMORY4_BASE
register_phys_mem(MEMORY4_TYPE, MEMORY4_BASE, MEMORY4_SIZE);
#endif
#ifdef MEMORY5_BASE
register_phys_mem(MEMORY5_TYPE, MEMORY5_BASE, MEMORY5_SIZE);
#endif
#ifdef MEMORY6_BASE
register_phys_mem(MEMORY6_TYPE, MEMORY6_BASE, MEMORY6_SIZE);
setopt_exec_attr(MEMORY6_BASE); /* MaskROM API memory */
#endif
#ifdef MEMORY7_BASE
register_phys_mem(MEMORY7_TYPE, MEMORY7_BASE, MEMORY7_SIZE);
#endif
#ifdef MEMORY8_BASE
register_phys_mem(MEMORY8_TYPE, MEMORY8_BASE, MEMORY8_SIZE);
#endif
#ifdef MEMORY9_BASE
register_phys_mem(MEMORY9_TYPE, MEMORY9_BASE, MEMORY9_SIZE);
#endif
#ifdef MEMORY10_BASE
register_phys_mem(MEMORY10_TYPE, MEMORY10_BASE, MEMORY10_SIZE);
#endif
#ifdef DEVICE0_PA_BASE
register_phys_mem(DEVICE0_TYPE, DEVICE0_PA_BASE, DEVICE0_SIZE);
#endif
#ifdef DEVICE1_PA_BASE
register_phys_mem(DEVICE1_TYPE, DEVICE1_PA_BASE, DEVICE1_SIZE);
#endif
#ifdef DEVICE2_PA_BASE
register_phys_mem(DEVICE2_TYPE, DEVICE2_PA_BASE, DEVICE2_SIZE);
#endif
#ifdef DEVICE3_PA_BASE
register_phys_mem(DEVICE3_TYPE, DEVICE3_PA_BASE, DEVICE3_SIZE);
#endif

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

void main_init_gic(void)
{
	vaddr_t gicc_base;
	vaddr_t gicd_base;

	gicc_base = (vaddr_t)phys_to_virt(GIC_BASE + GICC_OFFSET,
					  MEM_AREA_IO_SEC);
	gicd_base = (vaddr_t)phys_to_virt(GIC_BASE + GICD_OFFSET,
					  MEM_AREA_IO_SEC);
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

static void main_fiq(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
	/* No Operation */
}
