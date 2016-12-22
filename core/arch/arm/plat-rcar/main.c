/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
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
#include "rcar_common.h"
#include "rcar_log_func.h"
#include "rcar_suspend_to_ram.h"

static void main_tee_entry_fast(struct thread_smc_args *args);
static unsigned long main_cpu_suspend(unsigned long a0, unsigned long a1);
static unsigned long main_cpu_resume(unsigned long a0, unsigned long a1);
static void main_fiq(void);
static void main_hook_gic_disable(struct itr_chip *chip, size_t it);

static void main_tee_entry_fast(struct thread_smc_args *args)
{
	if (args->a0 == OPTEE_SMC_GET_SHM_CONFIG) {
		is_normal_world_initialized = 1;
	}
	tee_entry_fast(args);
}

static unsigned long main_cpu_suspend(unsigned long a0 __unused,
				unsigned long a1 __unused)
{
	suspend_to_ram_save();

	return 0U;
}

static unsigned long main_cpu_resume(unsigned long a0 __unused,
				unsigned long a1 __unused)
{
	suspend_to_ram_restore();

	return 0U;
}

static const struct thread_handlers handlers = {
	.std_smc = tee_entry_std,
	.fast_smc = main_tee_entry_fast,
	.fiq = main_fiq,
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = main_cpu_suspend,
	.cpu_resume = main_cpu_resume,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
};

struct gic_data gic_data;
static struct itr_ops main_base_gic_ops;
static struct itr_ops main_hook_gic_ops;

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

	main_base_gic_ops = *gic_data.chip.ops;
	main_hook_gic_ops = *gic_data.chip.ops;
	main_hook_gic_ops.disable = main_hook_gic_disable;
	gic_data.chip.ops = (const struct itr_ops *)&main_hook_gic_ops;

	itr_init(&gic_data.chip);
}

static void main_fiq(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
	/* No Operation */
}

static void main_hook_gic_disable(struct itr_chip *chip, size_t it)
{
	const size_t spurious_id = 1022U; /* Used only if the GIC supports
						interrupt grouping */

	if (it == spurious_id) {
		/* the interrupt acknowledge is a read of GICC_IAR */
		(void)read32(gic_data.gicc_base + 0x00C);
	} else {
		main_base_gic_ops.disable(chip, it);
	}
}
