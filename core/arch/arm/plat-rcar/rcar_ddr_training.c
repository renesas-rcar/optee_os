/*
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

#include <io.h>
#include <trace.h>
#include <initcall.h>
#include <keep.h>
#include "rcar_common.h"
#include "rcar_suspend_to_ram.h"

#define DDR_TRAINING_SCMT_START		0

#if DDR_TRAINING_SCMT_START
static void ddr_training_timer_init(void);
static void ddr_training_timer_start(void);
static void ddr_training_timer_stop(void);
#endif
static void ddr_training_execute(void);
static enum itr_return ddr_training_fiq_cb(struct itr_handler *h);
static TEE_Result ddr_training_init(void);

#if DDR_TRAINING_SCMT_START

static struct itr_handler scmt_itr;

static struct reg_backup_info ddr_training_reg_backup[] = {
	/* reg_paddr	, reg_rsize, reg_wsize */
	{ CMSSTR	, 2, 2 },
	{ CMSCSR	, 2, 2 },
	{ CMSCOR	, 4, 4 }
};

suspend_to_ram_backup(ddr_training_reg_backup);

static void ddr_training_backup_cb(enum suspend_to_ram_state state,
			uint32_t cpu_id __unused)
{
	if (state == SUS2RAM_STATE_SUSPEND) {
		ddr_training_timer_stop();
		itr_disable(&scmt_itr);
		itr_del(&scmt_itr);
	} else if (state == SUS2RAM_STATE_RESUME) {
		itr_add(&scmt_itr);
		itr_enable(&scmt_itr);
		ddr_training_timer_start();
	}
}

suspend_to_ram_cbfunc(ddr_training_backup_cb);

static void ddr_training_timer_init(void)
{
	uint16_t sr;
	uint32_t interval_ms;
	uint32_t count;
	uint32_t mdpin_data;
	uint32_t oscclk_hz;
	const uint16_t clear_mask = (uint16_t)~(
			CMSCSR_BIT_CMF | CMSCSR_BIT_CMM |
			CMSCSR_BIT_CMR | CMSCSR_BIT_CKS);

	/* Timer stop */
	write16(0x0000U, CMSSTR);

	/* Set clock select and compare match mode */
	sr = read16(CMSCSR);
	sr &= clear_mask;
	sr |= (CMM_FREE_RUN_OPERATION
		| CMR_INTERRUPT_ENABLE
		| CKS_DIVISION_RATIO_1);
	write16(sr, CMSCSR);

	/* Set timer interval [ms] */
	interval_ms = 20U;	/* T.B.D */

	/* Set the frequency of OSCCLK */
	mdpin_data = read32(MODEMR) & CHECK_MD13_MD14;
	switch (mdpin_data) {
	case MD14_L_MD13_H:
		oscclk_hz = 131570U;	/* 131.57kHz */
		break;
	default:
		oscclk_hz = 130200U;	/* 130.20kHz */
		break;
	}

	/* Calculate the match count */
	count = (interval_ms * oscclk_hz) / 1000U;

	/* Set match count */
	write32(count, CMSCOR);
}

static void ddr_training_timer_start(void)
{
	/* Counter reset */
	write32(0x00000000U, CMSCNT);

	/* Timer start */
	write16(CMSSTR_BIT_STR5, CMSSTR);
}

static void ddr_training_timer_stop(void)
{
	/* Timer stop */
	write16(0x0000U, CMSSTR);
}

#endif /* DDR_TRAINING_SCMT_START */

static void ddr_training_execute(void)
{
	uint16_t sr;
	const uint16_t clear_mask = (uint16_t)~(
			CMSCSR_BIT_CMF | CMSCSR_BIT_OVF);

	/* Clear an internal interrupt request */
	sr = read16(CMSCSR);
	sr &= clear_mask;
	write16(sr, CMSCSR);

	/* Dummy read */
	(void)read16(CMSCSR);

	/* T.B.D. */
}

static enum itr_return ddr_training_fiq_cb(struct itr_handler *h)
{
	FMSG("enter id=%zu", h->it);

	switch (h->it) {
	/* System Timer */
	case INTID_SCMT:
		ddr_training_execute();
		break;

	default:
		EMSG("Unexpected fiq. id=%zu", h->it);
		panic();
		break;
	}

	return ITRR_HANDLED;
}

static struct itr_handler scmt_itr = {
	.it = INTID_SCMT,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ddr_training_fiq_cb
};
KEEP_PAGER(scmt_itr);

static TEE_Result ddr_training_init(void)
{
	/* Enable GIC */
	itr_add(&scmt_itr);
	itr_enable(&scmt_itr);

#if DDR_TRAINING_SCMT_START
	/* Initialize DDR training */
	ddr_training_timer_init();
	ddr_training_timer_start();
#endif

	return TEE_SUCCESS;
}

driver_init(ddr_training_init);
