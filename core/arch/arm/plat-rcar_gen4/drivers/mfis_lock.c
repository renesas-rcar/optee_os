// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <io.h>
#include <kernel/delay.h>
#include <drivers/mfis_lock.h>
#include <drivers/qspi_hyper_flash.h>

void mfis_lock(void)
{
	while((io_read32((vaddr_t)MFIS_LCKR) & MFISLCKR_LOCK_BIT) !=
		MFISLCKR_UNLOCK)
	{
		udelay(10U);
	}
	/* this bit is automatically set to "1" */
}

void mfis_unlock(void)
{
	io_write32((vaddr_t)MFIS_WACNTR, (uint32_t)(MFIS_CODE_VALID +
		MFISLCKR_TARGET_ADDRESS));
	io_write32((vaddr_t)MFIS_LCKR, (uint32_t)MFISLCKR_UNLOCK);
}
