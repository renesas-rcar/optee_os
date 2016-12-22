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
#include <kernel/panic.h>
#include <kernel/interrupt.h>
#include <initcall.h>
#include <drivers/mfis_driver.h>
#include "rcar_common.h"
#include "rcar_suspend_to_ram.h"

/******************************************************************************/
/* Defines                                                                    */
/******************************************************************************/
/* Register */
#define	MFIERRCTLR(a)	((volatile uint32_t *)(0xE6260200U + (uintptr_t)((a) * 4U)))
#define	MFIERRSTSR(a)	((volatile uint32_t *)(0xE6260240U + (uintptr_t)((a) * 4U)))
#define	MFIERRTGTR(a)	((volatile uint32_t *)(0xE6260280U + (uintptr_t)((a) * 4U)))
#define	MFIERRCTLR7	((volatile uint32_t *)(0xE6260260U))
#define	MFIERRSTSR7	((volatile uint32_t *)(0xE6260264U))
#define	MFIERRTGTR7	((volatile uint32_t *)(0xE6260268U))
#define	MFIERRTGTR6	((volatile uint32_t *)(0xE626025CU))

#define SMSTPCR2	(0xE6150138U)
#define SMSTP_MFISFLG	((uint32_t)1U<<13U)

typedef struct {
	struct {
		volatile uint32_t *MFIERRCTLR;
		volatile uint32_t *MFIERRSTSR;
		volatile uint32_t *MFIERRTGTR;
	}array[MFIS_ERR_DET_MAX];
}MFIS_REG_T;

#define MFIS_ERR_0	(409U + 32U)
#define MFIS_ERR_1	(410U + 32U)
#define MFIS_ERR_2	(411U + 32U)
#define MFIS_ERR_3	(412U + 32U)
#define MFIS_ERR_4	(413U + 32U)
#define MFIS_ERR_5	(414U + 32U)
#define MFIS_ERR_6	(415U + 32U)
#define MFIS_ERR_7	(307U + 32U)

#define MFIS_STATE_NOACTIVE	(0U)
#define MFIS_STATE_ACTIVE	(1U)

/******************************************************************************/
/* Prototype                                                                  */
/******************************************************************************/
static void mfis_backup_cb(enum suspend_to_ram_state state, uint32_t cpu_id);
static enum itr_return mfis_err_handler(struct itr_handler *h);
static TEE_Result mfis_err_init(void);
static void mfis_err_itr_del(void);

/******************************************************************************/
/* Global                                                                     */
/******************************************************************************/
static uint32_t		mfis_state = MFIS_STATE_NOACTIVE;
static uint32_t		mfis_reg_num = MFIS_ERR_DET_MAX - 1U;
static uint32_t		mfis_suspend_flag = 0U;
static MFIS_REG_T	mfis_reg;
static MFIS_ERR_SETTING_T	local_setting;
static void (*user_cb)(MFIS_ERR_FACTOR_T*) = NULL;

static void mfis_backup_cb(enum suspend_to_ram_state state,
			uint32_t cpu_id __unused)
{
	if ((SUS2RAM_STATE_SUSPEND == state) && (MFIS_STATE_NOACTIVE != mfis_state)) {
		(void)mfis_error_detection_stop();
		mfis_suspend_flag = 1U;
	} else if (SUS2RAM_STATE_RESUME == state) {
		mfis_err_itr_del();
		(void)mfis_err_init();
		if (1U == mfis_suspend_flag) {
			(void)mfis_error_detection_start(&local_setting, user_cb);
			mfis_suspend_flag = 0U;
		}
	} else {
		/* Nothing. Because state is a suspend request to the driver but the driver is not running. */
		;
	}
}

suspend_to_ram_cbfunc(mfis_backup_cb);

static enum itr_return mfis_err_handler(struct itr_handler *h)
{
	MFIS_ERR_FACTOR_T factor = {{0U}};
	uint32_t table;

	if (NULL != h) {
		if (MFIS_ERR_7 == h->it) {
			table = MFIS_ERR_DET_MAX - 1U;
		} else {
			table = h->it - MFIS_ERR_0;
		}

		factor.error[table] = *(mfis_reg.array[table].MFIERRSTSR);

		if (NULL != user_cb) {
			user_cb(&factor);
		}

		*(mfis_reg.array[table].MFIERRSTSR) = factor.error[table];
		(void)*(mfis_reg.array[table].MFIERRSTSR);
		dsb();
	}
	return ITRR_HANDLED;
}

static struct itr_handler mfis_err_itr[] = {
	{
	.it = MFIS_ERR_0,
	.flags = (uint32_t)ITRF_TRIGGER_LEVEL,
	.handler = &mfis_err_handler
	},
	{
	.it = MFIS_ERR_1,
	.flags = (uint32_t)ITRF_TRIGGER_LEVEL,
	.handler = &mfis_err_handler
	},
	{
	.it = MFIS_ERR_2,
	.flags = (uint32_t)ITRF_TRIGGER_LEVEL,
	.handler = &mfis_err_handler
	},
	{
	.it = MFIS_ERR_3,
	.flags = (uint32_t)ITRF_TRIGGER_LEVEL,
	.handler = &mfis_err_handler
	},
	{
	.it = MFIS_ERR_4,
	.flags = (uint32_t)ITRF_TRIGGER_LEVEL,
	.handler = &mfis_err_handler
	},
	{
	.it = MFIS_ERR_5,
	.flags = (uint32_t)ITRF_TRIGGER_LEVEL,
	.handler = &mfis_err_handler
	},
	{
	.it = MFIS_ERR_6,
	.flags = (uint32_t)ITRF_TRIGGER_LEVEL,
	.handler = &mfis_err_handler
	},
	{
	.it = MFIS_ERR_7,
	.flags = (uint32_t)ITRF_TRIGGER_LEVEL,
	.handler = &mfis_err_handler
	}
};

int32_t mfis_error_detection_start(MFIS_ERR_SETTING_T *err,
		void (*cb)(MFIS_ERR_FACTOR_T*))
{
	int32_t ret = MFIS_SUCCESS;
	uint32_t loop;
	uint32_t reg;
	uint32_t enable_flag = 0U;

	if (NULL == err) {
		ret = MFIS_ERR_PARAMETER;
	} else {
		for (loop = 0U; loop < mfis_reg_num; loop++) {
			if ((0U != err->control[loop]) &&
				(0U != err->target[loop])) {
				enable_flag = 1U;
				break;
			}
		}
		if (1U == enable_flag) {
			if (NULL == cb) {
				ret = MFIS_ERR_PARAMETER;
			}
		}
		enable_flag = 0U;
	}

	if ((MFIS_SUCCESS == ret) && (MFIS_STATE_NOACTIVE != mfis_state)) {
		ret = MFIS_ERR_SEQUENCE;
	}

	if (MFIS_SUCCESS == ret) {
		for (loop = 0U; loop < mfis_reg_num; loop++) {
			if (0U != err->control[loop]) {
				reg = *(mfis_reg.array[loop].MFIERRSTSR);
				*(mfis_reg.array[loop].MFIERRTGTR) =
						err->target[loop];
				*(mfis_reg.array[loop].MFIERRSTSR) = reg;
				*(mfis_reg.array[loop].MFIERRCTLR) =
						err->control[loop];

				itr_enable(&mfis_err_itr[loop]);
				
				enable_flag = 1U;
			}
		}
		if (1U == enable_flag) {
			local_setting = *err;
			user_cb = cb;
			mfis_state = MFIS_STATE_ACTIVE;
			
			reg = read32(SMSTPCR2);
			reg &= ~SMSTP_MFISFLG;
			write32(reg, SMSTPCR2);

		} else {
			ret = MFIS_ERR_PARAMETER;
		}
	}

	return ret;
}

int32_t mfis_error_detection_stop(void)
{
	uint32_t reg;
	uint32_t loop;
	int32_t ret = MFIS_SUCCESS;

	if (MFIS_STATE_ACTIVE != mfis_state) {
		ret = MFIS_ERR_SEQUENCE;
	} else {
		
		for (loop = 0U; loop < mfis_reg_num; loop++) {
			if (0U != local_setting.control[loop]) {
				itr_disable(&mfis_err_itr[loop]);
				reg = *(mfis_reg.array[loop].MFIERRSTSR);
				*(mfis_reg.array[loop].MFIERRSTSR) = reg;
				*(mfis_reg.array[loop].MFIERRTGTR) = 0U;
				*(mfis_reg.array[loop].MFIERRCTLR) = 0U;
			}
		}
		
		reg = read32(SMSTPCR2);
		reg |= SMSTP_MFISFLG;
		write32(reg, SMSTPCR2);

		mfis_state = MFIS_STATE_NOACTIVE;
	}

	return ret;
}

static TEE_Result mfis_err_init(void)
{
	uint32_t loop;
	uint32_t type;
	
	(void)memset(&mfis_reg, 0x00, sizeof(MFIS_REG_T));

	for(loop = 0U; loop < (MFIS_ERR_DET_MAX - 1U); loop++)
	{
		mfis_reg.array[loop].MFIERRCTLR = MFIERRCTLR(loop);
		mfis_reg.array[loop].MFIERRSTSR = MFIERRSTSR(loop);
		mfis_reg.array[loop].MFIERRTGTR = MFIERRTGTR(loop);
		itr_add(&mfis_err_itr[loop]);
	}
	mfis_reg.array[6U].MFIERRTGTR = MFIERRTGTR6;

	type = read32(PRR) & PRR_PRODUCT_MASK;

	if (PRR_PRODUCT_M3 == type) {
		mfis_reg.array[7U].MFIERRCTLR = MFIERRCTLR7;
		mfis_reg.array[7U].MFIERRSTSR = MFIERRSTSR7;
		mfis_reg.array[7U].MFIERRTGTR = MFIERRTGTR7;
		itr_add(&mfis_err_itr[7U]);
		mfis_reg_num = MFIS_ERR_DET_MAX;
	}

	return TEE_SUCCESS;
}

static void mfis_err_itr_del(void)
{
	uint32_t loop;

	for(loop = 0U; loop < mfis_reg_num; loop++)
	{
		itr_del(&mfis_err_itr[loop]);
	}
}

driver_init(mfis_err_init);
