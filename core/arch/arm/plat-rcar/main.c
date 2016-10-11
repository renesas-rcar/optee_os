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
#include <console.h>
#include <keep.h>
#include <initcall.h>

#include <sm/optee_smc.h>
#include "rcar_common.h"
#include "rcar_log_func.h"
#include "rcar_ddr_training.h"

static void main_tee_entry_fast(struct thread_smc_args *args);
static void main_fiq(void);
static enum itr_return main_fiq_cb(struct itr_handler *h);
static TEE_Result init_dev_itr(void);

static void main_tee_entry_fast(struct thread_smc_args *args)
{
	if (args->a0 == OPTEE_SMC_GET_SHM_CONFIG) {
		is_normal_world_initialized = 1;
	}
	tee_entry_fast(args);
}

static const struct thread_handlers handlers = {
	.std_smc = tee_entry_std,
	.fast_smc = main_tee_entry_fast,
	.fiq = main_fiq,
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = pm_do_nothing,
	.cpu_resume = pm_do_nothing,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
};

static struct gic_data gic_data;

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

void main_init_gic(void)
{
	/* On ARMv8, GIC configuration is initialized in ARM-TF */
	gic_init_base_addr(&gic_data, GIC_BASE + GICC_OFFSET,
			   GIC_BASE + GICD_OFFSET);
	itr_init(&gic_data.chip);
}

static void main_fiq(void)
{
	gic_it_handle(&gic_data);
}

static enum itr_return main_fiq_cb(struct itr_handler *h)
{
	DMSG("enter id=%zu", h->it);

	switch (h->it) {
	/* System Timer */
	case INTID_SCMT:
		ddr_training_execute();
		break;

		/* Crypto Engines */
	case INTID_PKA:
	case INTID_CC:
		break;

	default:
		EMSG("Unexpected fiq. id=%zu", h->it);
		panic();
		break;
	}

	return ITRR_HANDLED;
}

void console_init(void)
{
	/* No Operation */
}

static struct itr_handler dev_itr[] = {
	/* System Timer */
	{
	.it = INTID_SCMT,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = main_fiq_cb
	}
};
KEEP_PAGER(dev_itr);
static const size_t dev_itr_num = sizeof(dev_itr) / sizeof(struct itr_handler);

static TEE_Result init_dev_itr(void)
{
	size_t i;
	uint8_t cpu_mask;

	cpu_mask = (uint8_t)(1U << get_core_pos());

	/* Enable GIC */
	for (i = 0U; i < dev_itr_num; i++) {
		itr_add(&dev_itr[i]);
		/* Set the CPU mask to deliver interrupts to primary CPU */
		gic_it_set_cpu_mask(&gic_data, dev_itr[i].it, cpu_mask);

		itr_enable(&dev_itr[i]);
	}

	return TEE_SUCCESS;
}
driver_init(init_dev_itr);
