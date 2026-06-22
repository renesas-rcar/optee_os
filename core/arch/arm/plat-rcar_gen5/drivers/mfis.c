// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026, Renesas Electronics Corporation. All rights reserved.
 *
 */

/******************************************************************************/
/* Header file                                                                */
/******************************************************************************/
#include <stdint.h>
#include <stddef.h>
#include <io.h>
#include <drivers/mfis.h>
#include <drivers/mfis_register.h>
#include <mm/core_mmu.h>
#include "rcar-common.h"

/******************************************************************************/
/* Variable                                                                   */
/******************************************************************************/
/* MFIS locks are used base on convention as below order.
 * The 5th MFIS lock is dedicated to protect exclusive
 * control for serial console.
 */
static const uint32_t mfis_mfislckr_table[] = {
/*
 *	MFIS_MFISLCKR0,	MFIS_RPC
 *	MFIS_MFISLCKR1,	Reserved
 *	MFIS_MFISLCKR2,	MFIS_UFS
 *	MFIS_MFISLCKR3,	MFIS_OVERLAP_CHECK
 *	MFIS_MFISLCKR4,	MFIS_MEASUREMENT
 */
	MFIS_MFISLCKR5	/* MFIS_TARGET_HSCIF	*/
};

/******************************************************************************/
/* Function                                                                   */
/******************************************************************************/
void rcar_mfis_init(void)
{
	uint32_t register_value;

	/* Write Protection Control Register */
	/* Disable write protection setting */
	register_value = (MFISWPCNTR_CODEVALUE_SET | MFISWPCNTR_WPD_SET);
	io_write32(MFIS_MFISWPCNTR, register_value);
}

void rcar_mfis_lock(mfis_target_t target)
{
	uintptr_t lock_reg;
	uint32_t val;
	uint32_t i;
	bool mmu_enabled = cpu_mmu_enabled();

	if (mmu_enabled)
		lock_reg = (uintptr_t)(p2v_ioadr(mfis_mfislckr_table[target],
			MEMORY8_PA_END - (mfis_mfislckr_table[target])));
	else
		lock_reg = mfis_mfislckr_table[target];

	/* Wait until acquired (with timeout to avoid hang) */
	for (i = 0; i < MFIS_LOCK_TIMEOUT; i++) {
		val = io_read32(lock_reg);
		if ((val & MFISLCKR_LCK_MASK) ==
			MFISLCKR_LCK_NOT_ACQUIRED_CHECK) {
			return;
		}
	}
}

void rcar_mfis_unlock(mfis_target_t target)
{
	uint32_t register_value_mfis_mfislckr;
	bool mmu_enabled = cpu_mmu_enabled();
	vaddr_t address =  p2v_ioadr(mfis_mfislckr_table[target],
			MEMORY8_PA_END - (mfis_mfislckr_table[target]));

	if (mmu_enabled) {
		register_value_mfis_mfislckr = io_read32(address);
		register_value_mfis_mfislckr &= (~(MFISLCKR_LCK_MASK));
		register_value_mfis_mfislckr |= MFISLCKR_LCK_RELEASE_SET;
		/* MFIS Lock Register [j] (MFISLCKR[j]) */
		io_write32(address, register_value_mfis_mfislckr);
	} else {
		register_value_mfis_mfislckr =
			io_read32(mfis_mfislckr_table[target]);
		register_value_mfis_mfislckr &= (~(MFISLCKR_LCK_MASK));
		register_value_mfis_mfislckr |= MFISLCKR_LCK_RELEASE_SET;
		/* MFIS Lock Register [j] (MFISLCKR[j]) */
		io_write32(mfis_mfislckr_table[target],
				register_value_mfis_mfislckr);
	}
}

