// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Renesas Electronics Corporation
 */

#include <io.h>
#include <kernel/panic.h>
#include <kernel/interrupt.h>
#include <kernel/spinlock.h>
#include <initcall.h>
#include <drivers/swdt.h>
#include "rcar-common.h"

/******************************************************************************/
/* Defines                                                                    */
/******************************************************************************/
/* Register */
#define RST_WDTRSTCR	p2v_ioadr(0xC1320420U, MEMORY3_PA_END - 0xC1320420U)
#define SWDT_SWTCNT	p2v_ioadr(0x1C050000U, DEVICE0_PA_END - 0x1C050000U)
#define SWDT_SWTCSRA	p2v_ioadr(0x1C050004U, DEVICE0_PA_END - 0x1C050004U)
#define SWDT_SWTCSRB	p2v_ioadr(0x1C050008U, DEVICE0_PA_END - 0x1C050008U)

#define SWDT_WDTRSTCR_UPPER_BYTE	(0xA55A0000U)
#define SWDT_WDTRSTCR_LOWER_BYTE	(0x0000FFFFU)
#define SWDT_SWTCSRA_UPPER_BYTE		(0xA5A5A500U)
#define SWDT_SWTCSRA_WRFLG		((uint32_t)1U << 5U)
#define SWDT_SWTCSRA_TME		((uint32_t)1U << 7U)
#define SWDT_SWTCSRA_WOVF		((uint32_t)1U << 4U)
#define SWDT_SWTCSRA_WOVFE		((uint32_t)1U << 3U)
#define SWDT_SWTCSRA_BIT_CKS		(0x00000007U)
#define SWDT_SWTCSRB_UPPER_BYTE		(0xA5A5A500U)
#define SWDT_SWTCSRB_BIT_CKS		(0x0000003FU)
#define SWDT_SWTCNT_UPPER_BYTE		(0x5A5A0000U)
#define SWDT_SWTCNT_RESET_VALUE		(0x0000F488U)
#define RST_WDTRSTCR_RSTMSK             ((uint32_t)1U << 1U)

#define SPI_SWDT		(0x1062U)	/* System WDT */

#define SWDT_STATE_NOACTIVE	(0U)
#define SWDT_STATE_ACTIVE	(1U)

/******************************************************************************/
/* Prototype                                                                  */
/******************************************************************************/
static void swdt_is_ready(void);
static enum itr_return swdt_handler(struct itr_handler *h);
static TEE_Result swdt_init(void);
static void __maybe_unused swdt_itr_del(void);

/******************************************************************************/
/* Global                                                                     */
/******************************************************************************/
static uint32_t	thread_global_lock __nex_data = (uint32_t)SPINLOCK_UNLOCK;
static uint16_t	swdt_initial_count __nex_bss;
static uint32_t	swdt_state __nex_data = SWDT_STATE_NOACTIVE;
static uint16_t	swdt_count __nex_bss;
static uint8_t	swdt_clk __nex_bss;
static uint8_t	swdt_expanded_clk __nex_bss;
static void	(*user_cb)(void)__nex_bss;
static uint32_t	swdt_init_flag __nex_bss = INIT_FLAG_UNINITIALIZED;

static void swdt_is_ready(void)
{
	while (0U != (io_read8(SWDT_SWTCSRA) & SWDT_SWTCSRA_WRFLG))
		;
}

static enum itr_return swdt_handler(struct itr_handler *h)
{
	uint32_t reg;
	(void)h;

	if (user_cb)
		user_cb();

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
	if (clk > SWDT_FREQ_EXPANDED || count == 0U)
		ret = SWDT_ERR_PARAMETER;	/* parameter error */

	exceptions = cpu_spin_lock_xsave(&thread_global_lock);
	if (ret == SWDT_SUCCESS && swdt_state != SWDT_STATE_NOACTIVE)
		ret = SWDT_ERR_SEQUENCE;

	if (ret == SWDT_SUCCESS) {
		swdt_is_ready();

		swdt_count = count;
		swdt_clk = clk;
		swdt_expanded_clk = expanded_clk;
		user_cb = cb;

		/* counter setting */
		swdt_initial_count = (0xFFFFU - count) + 1U;
		io_write32(SWDT_SWTCNT, SWDT_SWTCNT_UPPER_BYTE
				| swdt_initial_count);

		/* interrupt or reset setting */
		if (!cb) {		/* reset route */
			/* Reset mask register setting */
			reg = io_read32(RST_WDTRSTCR)
				& SWDT_WDTRSTCR_LOWER_BYTE;
			reg &= ~RST_WDTRSTCR_RSTMSK;
			io_write32(RST_WDTRSTCR,
					reg | SWDT_WDTRSTCR_UPPER_BYTE);
		} else {			/* interrupt route */
			/* Reset mask register setting */
			reg = io_read32(RST_WDTRSTCR)
				& SWDT_WDTRSTCR_LOWER_BYTE;
			reg |= RST_WDTRSTCR_RSTMSK;
			io_write32(RST_WDTRSTCR,
					reg | SWDT_WDTRSTCR_UPPER_BYTE);

			interrupt_enable(swdt_itr->chip, swdt_itr[0].it);

			/* enable interrupt */
			reg_WTCSRA = SWDT_SWTCSRA_WOVFE;
		}

		if (clk == SWDT_FREQ_EXPANDED) {
			reg = io_read8(SWDT_SWTCSRB);
			reg &= ~(uint32_t)SWDT_SWTCSRB_BIT_CKS;
			reg |= SWDT_SWTCSRB_UPPER_BYTE |
				((uint32_t)expanded_clk & SWDT_SWTCSRB_BIT_CKS);
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
	if (swdt_state != SWDT_STATE_ACTIVE) {
		ret = SWDT_ERR_SEQUENCE;
	} else {
		interrupt_disable(swdt_itr->chip, swdt_itr[0].it);

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
	if (swdt_state != SWDT_STATE_ACTIVE) {
		ret = SWDT_ERR_SEQUENCE;
	} else {
		swdt_is_ready();
		io_write32(SWDT_SWTCNT, SWDT_SWTCNT_UPPER_BYTE
				| swdt_initial_count);
	}
	cpu_spin_unlock_xrestore(&thread_global_lock, exceptions);
	return ret;
}

static TEE_Result swdt_init(void)
{
	uint32_t exceptions;
	const char *init_msg;

	exceptions = cpu_spin_lock_xsave(&thread_global_lock);
	if (swdt_init_flag == INIT_FLAG_UNINITIALIZED) {
		interrupt_add_handler_with_chip(interrupt_get_main_chip(),
						swdt_itr);

		/* SWDT has been initialized */
		swdt_init_flag = INIT_FLAG_INITIALIZED;
		init_msg = "SWDT driver: initialized";
	} else {
		init_msg = "SWDT driver: already initialized";
	}
	cpu_spin_unlock_xrestore(&thread_global_lock, exceptions);
	DMSG("%s\n", init_msg);

	return TEE_SUCCESS;
}

static void swdt_itr_del(void)
{
	interrupt_remove_handler(swdt_itr);
}

driver_init(swdt_init);
