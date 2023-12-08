// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2020, Renesas Electronics Corporation
 */

#include <io.h>
#include <kernel/panic.h>
#include <kernel/interrupt.h>
#include <kernel/spinlock.h>
#include <initcall.h>
#include <drivers/swdt_driver.h>
#include "rcar_suspend_to_ram.h"
#include "rcar_common.h"

/******************************************************************************/
/* Defines                                                                    */
/******************************************************************************/
/* Register */
#define RST_WDTRSTCR		p2v_ioadr(0xE6160054U)
#define SWDT_SWTCNT		p2v_ioadr(0xE6030000U)
#define SWDT_SWTCSRA		p2v_ioadr(0xE6030004U)
#define SWDT_SWTCSRB		p2v_ioadr(0xE6030008U)

#define SWDT_WDTRSTCR_UPPER_BYTE	(0xA55A0000U)
#define SWDT_WDTRSTCR_LOWER_BYTE	(0x0000FFFFU)
#define SWDT_SWTCSRA_UPPER_BYTE		(0xA5A5A500U)
#define SWDT_SWTCSRA_WRFLG		((uint32_t)1U<<5U)
#define SWDT_SWTCSRA_TME		((uint32_t)1U<<7U)
#define SWDT_SWTCSRA_WOVF		((uint32_t)1U<<4U)
#define SWDT_SWTCSRA_WOVFE		((uint32_t)1U<<3U)
#define SWDT_SWTCSRA_BIT_CKS		(0x00000007U)
#define SWDT_SWTCSRB_UPPER_BYTE		(0xA5A5A500U)
#define SWDT_SWTCSRB_BIT_CKS		(0x0000003FU)
#define SWDT_SWTCNT_UPPER_BYTE		(0x5A5A0000U)
#define SWDT_SWTCNT_RESET_VALUE		(0x0000F488U)
#define RST_WDTRSTCR_RSTMSK             ((uint32_t)1U<<1U)

#define SPI_SWDT		(141U + 32U)	/* System WDT */

#define SWDT_STATE_NOACTIVE	(0U)
#define SWDT_STATE_ACTIVE	(1U)

/******************************************************************************/
/* Prototype                                                                  */
/******************************************************************************/
static void swdt_backup_cb(enum suspend_to_ram_state state, uint32_t cpu_id);
static void swdt_is_ready(void);
static enum itr_return swdt_handler(struct itr_handler *h);
static TEE_Result swdt_init(void);
static void swdt_itr_del(void);

/******************************************************************************/
/* Global                                                                     */
/******************************************************************************/
static uint32_t		thread_global_lock __nex_data = (uint32_t)SPINLOCK_UNLOCK;
static uint16_t		swdt_initial_count __nex_bss = 0U;
static uint32_t		swdt_state __nex_data = SWDT_STATE_NOACTIVE;
static uint16_t		swdt_count __nex_bss = 0U;
static uint8_t		swdt_clk __nex_bss = 0U;
static uint8_t		swdt_expanded_clk __nex_bss = 0U;
static void		(*user_cb)(void) __nex_bss = NULL;
static uint32_t		swdt_init_flag __nex_bss = INIT_FLAG_UNINITIALIZED;

static void swdt_backup_cb(enum suspend_to_ram_state state,
			uint32_t cpu_id __unused)
{
	static uint32_t swdt_suspend_flag __nex_bss = 0U;

	if (SUS2RAM_STATE_SUSPEND == state) {
		if (SWDT_STATE_NOACTIVE != swdt_state) {
			(void)swdt_stop();
			swdt_suspend_flag = 1U;
		}
		swdt_init_flag = INIT_FLAG_UNINITIALIZED;
	} else {
		/* SUS2RAM_STATE_RESUME == state */
		swdt_itr_del();
		(void)swdt_init();
		if (1U == swdt_suspend_flag) {
			(void)swdt_start(swdt_count, swdt_clk, swdt_expanded_clk, user_cb);
			swdt_suspend_flag = 0U;
		}
	}
}

suspend_to_ram_cbfunc(swdt_backup_cb);

static void swdt_is_ready(void)
{
	while (0U != (io_read8(SWDT_SWTCSRA) & SWDT_SWTCSRA_WRFLG)) {
		;
	}
}

static enum itr_return swdt_handler(struct itr_handler *h)
{
	uint32_t reg;
	(void)h;

	if (NULL != user_cb) {
		user_cb();
	}

	reg = io_read8(SWDT_SWTCSRA);
	reg &= ~SWDT_SWTCSRA_WOVF;
	reg |= SWDT_SWTCSRA_UPPER_BYTE;
	io_write32(SWDT_SWTCSRA, reg);

	return ITRR_HANDLED;
}

static struct itr_handler swdt_itr[] = {
	/* System Timer */
	{
	.it = SPI_SWDT,
	.flags = (uint32_t)ITRF_TRIGGER_LEVEL,
	.handler = &swdt_handler
	}
};

int32_t swdt_start(uint16_t count, uint8_t clk,
		uint8_t expanded_clk, void (*cb)(void))
{
	int32_t ret = SWDT_SUCCESS;
	uint32_t reg;
	uint32_t reg_WTCSRA = 0U;
	uint32_t exceptions;

	/* parameter check */
	if ((SWDT_FREQ_EXPANDED < clk) || (0U == count)) {
		ret = SWDT_ERR_PARAMETER;	/* parameter error */
	}

	exceptions = cpu_spin_lock_xsave(&thread_global_lock);
	if ((SWDT_SUCCESS == ret) && (SWDT_STATE_NOACTIVE != swdt_state)) {
		ret = SWDT_ERR_SEQUENCE;
	}

	if (SWDT_SUCCESS == ret) {
		swdt_is_ready();
		
		swdt_count = count;
		swdt_clk = clk;
		swdt_expanded_clk = expanded_clk;
		user_cb = cb;

		/* counter setting */
		swdt_initial_count = (0xFFFFU - count) + 1U;
		io_write32(SWDT_SWTCNT, SWDT_SWTCNT_UPPER_BYTE | swdt_initial_count);

		/* interrupt or reset setting */
		if (NULL == cb) {		/* reset route */
			/* Reset mask register setting */
			reg = io_read32(RST_WDTRSTCR) & SWDT_WDTRSTCR_LOWER_BYTE;
			reg &= ~RST_WDTRSTCR_RSTMSK;
			io_write32(RST_WDTRSTCR, reg | SWDT_WDTRSTCR_UPPER_BYTE);
		} else {			/* interrupt route */
			/* Reset mask register setting */
			reg = io_read32(RST_WDTRSTCR) & SWDT_WDTRSTCR_LOWER_BYTE;
			reg |= RST_WDTRSTCR_RSTMSK;
			io_write32(RST_WDTRSTCR, reg | SWDT_WDTRSTCR_UPPER_BYTE);

			itr_enable(swdt_itr[0].it);

			/* enable interrupt */
			reg_WTCSRA = SWDT_SWTCSRA_WOVFE;
		}

		if (SWDT_FREQ_EXPANDED == clk) {
			reg = io_read8(SWDT_SWTCSRB);
			reg &= ~(uint32_t)SWDT_SWTCSRB_BIT_CKS;
			reg |= SWDT_SWTCSRB_UPPER_BYTE | ((uint32_t)expanded_clk & SWDT_SWTCSRB_BIT_CKS);
			io_write32(SWDT_SWTCSRB, reg);
		}

		/* start */
		reg_WTCSRA |= clk;
		io_write32(SWDT_SWTCSRA, reg_WTCSRA | SWDT_SWTCSRA_UPPER_BYTE);
		
		reg = io_read8(SWDT_SWTCSRA);
		reg |= SWDT_SWTCSRA_TME;
		io_write32(SWDT_SWTCSRA, reg | SWDT_SWTCSRA_UPPER_BYTE);

		swdt_state = SWDT_STATE_ACTIVE;
	}
	cpu_spin_unlock_xrestore(&thread_global_lock, exceptions);
	return ret;
}

int32_t swdt_stop(void)
{
	uint32_t reg;
	int32_t ret = SWDT_SUCCESS;
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&thread_global_lock);
	if (SWDT_STATE_ACTIVE != swdt_state) {
		ret = SWDT_ERR_SEQUENCE;
	} else {

		itr_disable(swdt_itr[0].it);

		reg = io_read8(SWDT_SWTCSRA);
		reg &= ~SWDT_SWTCSRA_TME;
		reg |= SWDT_SWTCSRA_UPPER_BYTE;
		io_write32(SWDT_SWTCSRA, reg);

		/* Reset mask register setting */
		reg = io_read32(RST_WDTRSTCR) & SWDT_WDTRSTCR_LOWER_BYTE;
		reg |= RST_WDTRSTCR_RSTMSK;
		io_write32(RST_WDTRSTCR, reg | SWDT_WDTRSTCR_UPPER_BYTE);

		swdt_state = SWDT_STATE_NOACTIVE;
	}
	cpu_spin_unlock_xrestore(&thread_global_lock, exceptions);
	return ret;
}

int32_t swdt_kick(void)
{
	int32_t ret = SWDT_SUCCESS;
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&thread_global_lock);
	if (SWDT_STATE_ACTIVE != swdt_state) {
		ret = SWDT_ERR_SEQUENCE;
	} else {
		swdt_is_ready();
		
		io_write32(SWDT_SWTCNT, SWDT_SWTCNT_UPPER_BYTE | swdt_initial_count);
	}
	cpu_spin_unlock_xrestore(&thread_global_lock, exceptions);
	return ret;
}


static TEE_Result swdt_init(void)
{
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&thread_global_lock);
	if (swdt_init_flag == INIT_FLAG_UNINITIALIZED) {
		itr_add(swdt_itr);

		/* SWDT has been initialized */
		swdt_init_flag = INIT_FLAG_INITIALIZED;
		DMSG("SWDT driver: initialized");
	} else {
		DMSG("SWDT driver: already initialized");
	}
	cpu_spin_unlock_xrestore(&thread_global_lock, exceptions);

	return TEE_SUCCESS;
}

static void swdt_itr_del(void)
{
	itr_del(swdt_itr);
}

driver_init(swdt_init);
