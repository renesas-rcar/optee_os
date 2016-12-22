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
#include <drivers/swdt_driver.h>
#include "rcar_suspend_to_ram.h"

/******************************************************************************/
/* Defines                                                                    */
/******************************************************************************/
/* Register */
#define RST_WDTRSTCR		(0xE6160054U)
#define SWDT_SWTCNT		(0xE6030000U)
#define SWDT_SWTCSRA		(0xE6030004U)
#define SWDT_SWTCSRB		(0xE6030008U)

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
static uint16_t		swdt_initial_count = 0U;
static uint32_t		swdt_state = SWDT_STATE_NOACTIVE;
static uint16_t		swdt_count = 0U;
static uint8_t		swdt_clk = 0U;
static uint8_t		swdt_expanded_clk = 0U;
static uint32_t		swdt_suspend_flag = 0U;
static void		(*user_cb)(void) = NULL;

static void swdt_backup_cb(enum suspend_to_ram_state state,
			uint32_t cpu_id __unused)
{
	if ((SUS2RAM_STATE_SUSPEND == state) && (SWDT_STATE_NOACTIVE != swdt_state)) {
		(void)swdt_stop();
		swdt_suspend_flag = 1U;
	} else if (SUS2RAM_STATE_RESUME == state) {
		swdt_itr_del();
		(void)swdt_init();
		if (1U == swdt_suspend_flag) {
			(void)swdt_start(swdt_count, swdt_clk, swdt_expanded_clk, user_cb);
			swdt_suspend_flag = 0U;
		}
	} else {
		/* Nothing. Because state is a suspend request to the driver but the driver is not running. */
		;
	}
}

suspend_to_ram_cbfunc(swdt_backup_cb);

static void swdt_is_ready(void)
{
	while (0U != (read8(SWDT_SWTCSRA) & SWDT_SWTCSRA_WRFLG)) {
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

	reg = read8(SWDT_SWTCSRA);
	reg &= ~SWDT_SWTCSRA_WOVF;
	reg |= SWDT_SWTCSRA_UPPER_BYTE;
	write32(reg, SWDT_SWTCSRA);

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

	/* parameter check */
	if ((SWDT_FREQ_EXPANDED < clk) || (0U == count)) {
		ret = SWDT_ERR_PARAMETER;	/* parameter error */
	}

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
		write32(SWDT_SWTCNT_UPPER_BYTE | swdt_initial_count, SWDT_SWTCNT);

		/* interrupt or reset setting */
		if (NULL == cb) {		/* reset route */
			/* Reset mask register setting */
			reg = read32(RST_WDTRSTCR) & SWDT_WDTRSTCR_LOWER_BYTE;
			reg &= ~RST_WDTRSTCR_RSTMSK;
			write32(reg | SWDT_WDTRSTCR_UPPER_BYTE, RST_WDTRSTCR);
		} else {			/* interrupt route */
			/* Reset mask register setting */
			reg = read32(RST_WDTRSTCR) & SWDT_WDTRSTCR_LOWER_BYTE;
			reg |= RST_WDTRSTCR_RSTMSK;
			write32(reg | SWDT_WDTRSTCR_UPPER_BYTE, RST_WDTRSTCR);

			itr_enable(swdt_itr);

			/* enable interrupt */
			reg_WTCSRA = SWDT_SWTCSRA_WOVFE;
		}

		if (SWDT_FREQ_EXPANDED == clk) {
			reg = read8(SWDT_SWTCSRB);
			reg &= ~(uint32_t)SWDT_SWTCSRB_BIT_CKS;
			reg |= SWDT_SWTCSRB_UPPER_BYTE | ((uint32_t)expanded_clk & SWDT_SWTCSRB_BIT_CKS);
			write32(reg, SWDT_SWTCSRB);
		}

		/* start */
		reg_WTCSRA |= clk;
		write32(reg_WTCSRA | SWDT_SWTCSRA_UPPER_BYTE, SWDT_SWTCSRA);
		
		reg = read8(SWDT_SWTCSRA);
		reg |= SWDT_SWTCSRA_TME;
		write32(reg | SWDT_SWTCSRA_UPPER_BYTE, SWDT_SWTCSRA);

		swdt_state = SWDT_STATE_ACTIVE;
	}

	return ret;
}

int32_t swdt_stop(void)
{
	uint32_t reg;
	int32_t ret = SWDT_SUCCESS;

	if (SWDT_STATE_ACTIVE != swdt_state) {
		ret = SWDT_ERR_SEQUENCE;
	} else {

		itr_disable(swdt_itr);

		reg = read8(SWDT_SWTCSRA);
		reg &= ~SWDT_SWTCSRA_TME;
		reg |= SWDT_SWTCSRA_UPPER_BYTE;
		write32(reg, SWDT_SWTCSRA);

		/* Reset mask register setting */
		reg = read32(RST_WDTRSTCR) & SWDT_WDTRSTCR_LOWER_BYTE;
		reg |= RST_WDTRSTCR_RSTMSK;
		write32(reg | SWDT_WDTRSTCR_UPPER_BYTE, RST_WDTRSTCR);

		swdt_state = SWDT_STATE_NOACTIVE;
	}
	return ret;
}

int32_t swdt_kick(void)
{
	int32_t ret = SWDT_SUCCESS;

	if (SWDT_STATE_ACTIVE != swdt_state) {
		ret = SWDT_ERR_SEQUENCE;
	} else {
		swdt_is_ready();
		
		write32(SWDT_SWTCNT_UPPER_BYTE | swdt_initial_count, SWDT_SWTCNT);
	}
	return ret;
}


static TEE_Result swdt_init(void)
{
	itr_add(swdt_itr);

	return TEE_SUCCESS;
}

static void swdt_itr_del(void)
{
	itr_del(swdt_itr);
}

driver_init(swdt_init);
