// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2021, Renesas Electronics Corporation
 */

#include <io.h>
#include <kernel/panic.h>
#include <kernel/interrupt.h>
#include <kernel/spinlock.h>
#include <initcall.h>
#include <drivers/mfis_driver.h>
#include "rcar_common.h"
#include "rcar_suspend_to_ram.h"

/******************************************************************************/
/* Defines                                                                    */
/******************************************************************************/
/* Register */
#define	MFIERRCTLR(a)	((volatile uint32_t *)(p2v_ioadr(0xE6260214U) + (vaddr_t)((a) * 4U)))
#define	MFIERRSTSR(a)	((volatile uint32_t *)(p2v_ioadr(0xE6260254U) + (vaddr_t)((a) * 4U)))
#define	MFIERRTGTR(a)	((volatile uint32_t *)(p2v_ioadr(0xE6260294U) + (vaddr_t)((a) * 4U)))
#define	MFIERRTGTR6	((volatile uint32_t *)(p2v_ioadr(0xE626025CU)))

typedef struct {
	struct {
		volatile uint32_t *MFIERRCTLR;
		volatile uint32_t *MFIERRSTSR;
		volatile uint32_t *MFIERRTGTR;
	}array[MFIS_ERR_DET_MAX];
}MFIS_REG_T;

#define MFIS_ERR_5	(414U + 32U)
#define MFIS_ERR_6	(415U + 32U)

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
static uint32_t		thread_global_lock __nex_data = (uint32_t)SPINLOCK_UNLOCK;
static uint32_t		mfis_state __nex_data = MFIS_STATE_NOACTIVE;
static uint32_t		mfis_reg_num __nex_data = MFIS_ERR_DET_MAX;
static MFIS_REG_T	mfis_reg __nex_bss;
static MFIS_ERR_SETTING_T	local_setting __nex_bss;
static void (*user_cb)(MFIS_ERR_FACTOR_T*) __nex_bss = NULL;
static uint32_t mfis_err_init_flag __nex_bss = INIT_FLAG_UNINITIALIZED;

static void mfis_backup_cb(enum suspend_to_ram_state state,
			uint32_t cpu_id __unused)
{
	static uint32_t mfis_suspend_flag __nex_bss = 0U;

	if (SUS2RAM_STATE_SUSPEND == state) {
		if (MFIS_STATE_NOACTIVE != mfis_state) {
			(void)mfis_error_detection_stop();
			mfis_suspend_flag = 1U;
		}
		mfis_err_init_flag = INIT_FLAG_UNINITIALIZED;
	} else {
		/* SUS2RAM_STATE_RESUME == state */
		mfis_err_itr_del();
		(void)mfis_err_init();
		if (1U == mfis_suspend_flag) {
			(void)mfis_error_detection_start(&local_setting, user_cb);
			mfis_suspend_flag = 0U;
		}
	}
}

suspend_to_ram_cbfunc(mfis_backup_cb);

static enum itr_return mfis_err_handler(struct itr_handler *h)
{
	MFIS_ERR_FACTOR_T factor = {{0U}};
	uint32_t table;

	if (NULL != h) {
		table = h->it - MFIS_ERR_5;

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
	.it = MFIS_ERR_5,
	.flags = (uint32_t)ITRF_TRIGGER_LEVEL,
	.handler = &mfis_err_handler
	},
	{
	.it = MFIS_ERR_6,
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
	uint32_t exceptions;

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

	exceptions = cpu_spin_lock_xsave(&thread_global_lock);
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

				itr_enable(mfis_err_itr[loop].it);
				
				enable_flag = 1U;
			}
		}
		if (1U == enable_flag) {
			local_setting = *err;
			user_cb = cb;
			mfis_state = MFIS_STATE_ACTIVE;
		} else {
			ret = MFIS_ERR_PARAMETER;
		}
	}
	cpu_spin_unlock_xrestore(&thread_global_lock, exceptions);
	return ret;
}

int32_t mfis_error_detection_stop(void)
{
	uint32_t reg;
	uint32_t loop;
	int32_t ret = MFIS_SUCCESS;
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&thread_global_lock);
	if (MFIS_STATE_ACTIVE != mfis_state) {
		ret = MFIS_ERR_SEQUENCE;
	} else {
		
		for (loop = 0U; loop < mfis_reg_num; loop++) {
			if (0U != local_setting.control[loop]) {
				itr_disable(mfis_err_itr[loop].it);
				reg = *(mfis_reg.array[loop].MFIERRSTSR);
				*(mfis_reg.array[loop].MFIERRSTSR) = reg;
				*(mfis_reg.array[loop].MFIERRTGTR) = 0U;
				*(mfis_reg.array[loop].MFIERRCTLR) = 0U;
			}
		}

		mfis_state = MFIS_STATE_NOACTIVE;
	}
	cpu_spin_unlock_xrestore(&thread_global_lock, exceptions);
	return ret;
}

static TEE_Result mfis_err_init(void)
{
	uint32_t loop;
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&thread_global_lock);
	if (mfis_err_init_flag == INIT_FLAG_UNINITIALIZED) {
		(void)memset(&mfis_reg, 0x00, sizeof(MFIS_REG_T));

		for(loop = 0U; loop < mfis_reg_num; loop++)
		{
			mfis_reg.array[loop].MFIERRCTLR = MFIERRCTLR(loop);
			mfis_reg.array[loop].MFIERRSTSR = MFIERRSTSR(loop);
			mfis_reg.array[loop].MFIERRTGTR = MFIERRTGTR(loop);
			itr_add(&mfis_err_itr[loop]);
		}
		mfis_reg.array[1U].MFIERRTGTR = MFIERRTGTR6;

		/* MFIS ERROR has been initialized */
		mfis_err_init_flag = INIT_FLAG_INITIALIZED;
		DMSG("MFIS driver: initialized");
	} else {
		DMSG("MFIS driver: already initialized");
	}
	cpu_spin_unlock_xrestore(&thread_global_lock, exceptions);

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
