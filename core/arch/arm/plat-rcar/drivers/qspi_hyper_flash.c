// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2019, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <kernel/delay.h>
#include <io.h>
#include <drivers/qspi_hyper_flash.h>

#include "qspi_hyper_flash_common.h"
#include "qspi_flash_common.h"
#include "hyper_flash_control.h"
#include "rcar_suspend_to_ram.h"
#include "rcar_common.h"

uint32_t rpc_clock_mode = RPC_CLK_80M;
uint32_t phycnt_reg;

static void qspi_hyper_flash_backup_cb(enum suspend_to_ram_state state,
				uint32_t cpu_id);
static uint32_t erase_flash_unsupported(uint32_t sector_addr);
static uint32_t ext_addr_read_mode_flash_unsupported(uint32_t read_ext_top_addr,
			uint32_t flash_addr, uint8_t *buf, size_t rsize);
static uint32_t write_flash_unsupported(uint32_t buf_addr,
					uint32_t flash_addr, uint32_t wsize);
static uint32_t init_rpc_reg_depends_soc(void);
static uint32_t init_rpc(void);

static struct flash_control_operations flash_control_ops = {
	.erase = erase_flash_unsupported,
	.set_ext_addr_read_mode = ext_addr_read_mode_flash_unsupported,
	.write = write_flash_unsupported,
};

static void qspi_hyper_flash_backup_cb(enum suspend_to_ram_state state,
				uint32_t cpu_id __unused)
{
	if (state == SUS2RAM_STATE_RESUME) {
		(void)init_rpc();
	}
}

suspend_to_ram_cbfunc(qspi_hyper_flash_backup_cb);

uint32_t qspi_hyper_flash_init(void)
{
	uint32_t ret;

	ret = init_rpc_reg_depends_soc();

	if (ret == FL_DRV_OK) {
		ret = init_rpc();
	}

	if (ret == FL_DRV_OK) {
		ret = hyper_flash_init(&flash_control_ops);
	}

	if (ret != FL_DRV_OK) {
		ret = qspi_common_init(&flash_control_ops);
	}

	return ret;
}

uint32_t qspi_hyper_flash_erase(uint32_t sector_addr)
{
	uint32_t ret = FL_DRV_OK;
	uint32_t check_sector_size;

	DMSG("sector_addr=%x", sector_addr);

	check_sector_size = (sector_addr) % (SECTOR_SIZE);
	if (check_sector_size != 0U) {
		ret = FL_DRV_ERR_SECTOR_ADDR;
		EMSG("sector_addr is not sector top address. sector_addr=%x",
			sector_addr);
	}

	if (ret == FL_DRV_OK) {
		/* erase the according to device id */
		ret = flash_control_ops.erase(sector_addr);
	}

	DMSG("ret=%d", ret);

	return ret;
}

uint32_t qspi_hyper_flash_read(uint32_t flash_addr, uint8_t *buf, size_t rsize)
{
	uint32_t ret = FL_DRV_OK;
	uint32_t check_sector_size;
	uint32_t ext_top_addr;
	uint32_t quotient;

	volatile uintptr_t v_flash_addr = (SPI_IOADDRESS_TOP + flash_addr);
	uint8_t *p_flash_addr;

	DMSG("flash_addr=%x, buf=%p, rsize=%zu", flash_addr, buf, rsize);

	if (buf == NULL) {
		ret = FL_DRV_ERR_BUF_INCORRECT;
		EMSG("buf is incorrect.");
	}
	if (ret == FL_DRV_OK) {
		if ((rsize > SECTOR_SIZE) ||
		    (rsize < FLASH_DATA_READ_BYTE_COUNT_8) ||
		   ((rsize % FLASH_DATA_READ_BYTE_COUNT_8) > 0U)) {
			ret = FL_DRV_ERR_OUT_OF_RANGE;
			EMSG("rsize is out of range. rsize=%zu", rsize);
		}
	}

	/* Ex. )
	 *	Each value is not an actual value.Each value is for description
	 *      ---------------------------------------------------------
	 *	flash_addr      : 0x408(1032)
	 *	SECTOR_SIZE     : 0x100(256)
	 *	rsize           : 50
	 *	already written : 8 ( from 0x400(1024) to 0x407 (1031))
	 *	---------------------------------------------------------
	 *	[calculate] already written size at sector
	 *		1032 % 256 = 8
	 *	[compare] check aector exceed
	 *		(8 + 50) is over 256 ?
	 *		No : Not sector exceeded
	 *		Yes: Sector exceeded
	 *	---------------------------------------------------------
	 */
	if (ret == FL_DRV_OK) {
		check_sector_size = ((flash_addr) % (SECTOR_SIZE)) + rsize;

		if (check_sector_size > SECTOR_SIZE) {
			ret = FL_DRV_ERR_SECTOR_EXCEED;
			EMSG("Sector exceeded. flash_addr=%x, rsize=%zu",
				flash_addr, rsize);
		}
	}

	if (ret == FL_DRV_OK) {
		/*
		 *  External address reading position calculation
		 *  From 64MB boundary.
		 */
		if (flash_addr > EXT_ADD_BORDER_SIZE_64MB) {
			quotient = (flash_addr / EXT_ADD_BORDER_SIZE_64MB);
			v_flash_addr = SPI_IOADDRESS_TOP +
			   (flash_addr - (quotient * EXT_ADD_BORDER_SIZE_64MB));
			p_flash_addr = (uint8_t *)v_flash_addr;
			DMSG("p_flash_addr=%p", p_flash_addr);
			(void)p_flash_addr; /* suppress compile error */
		}
	}

	if (ret == FL_DRV_OK) {
		/* Switch to the external address read mode */
		ext_top_addr = (flash_addr & EXT_ADDR_MASK);
		ret = flash_control_ops.set_ext_addr_read_mode(ext_top_addr,
						flash_addr, buf, rsize);
	}

	DMSG("ret=%d", ret);

	return ret;

}

uint32_t qspi_hyper_flash_write(uint32_t flash_addr, const uint8_t *buf,
				size_t wsize)
{
	uint32_t ret = FL_DRV_OK;
	uint32_t check_sector_size;

	DMSG("flash_addr=%x, buf=%p, wsize=%zu", flash_addr, buf, wsize);

	if (buf == NULL) {
		ret = FL_DRV_ERR_BUF_INCORRECT;
		EMSG("buf is incorrect.");
	}
	if (ret == FL_DRV_OK) {
		if ((wsize > SECTOR_SIZE) ||
		    (wsize < FLASH_DATA_READ_BYTE_COUNT_8) ||
		   ((wsize % FLASH_DATA_READ_BYTE_COUNT_8) > 0U)) {
			ret = FL_DRV_ERR_OUT_OF_RANGE;
			EMSG("wsize is out of range. wsize=%zu", wsize);
		}
	}

	if (ret == FL_DRV_OK) {
		check_sector_size = ((flash_addr) % (SECTOR_SIZE)) + wsize;

		if (check_sector_size > SECTOR_SIZE) {
			ret = FL_DRV_ERR_SECTOR_EXCEED;
			EMSG("Sector exceeded. flash_addr=%x, wsize=%zu",
				flash_addr, wsize);
		}
	}

	if (ret == FL_DRV_OK) {
		/* To write the according to device id */
		ret = flash_control_ops.write((uintptr_t)buf,
							flash_addr, wsize);
	}

	DMSG("ret=%d", ret);

	return ret;
}

static uint32_t erase_flash_unsupported(uint32_t sector_addr __maybe_unused)
{
	EMSG("Not execute erase. Unsupport device. sector_addr=%x",
								sector_addr);
	return FL_DRV_ERR_UNSUPPORT_DEV;
}

static uint32_t ext_addr_read_mode_flash_unsupported(
			uint32_t read_ext_top_addr __maybe_unused,
			uint32_t flash_addr __maybe_unused,
			uint8_t *buf __maybe_unused,
			size_t rsize __maybe_unused)
{
	EMSG(
	"Not execute ext_addr_read_mode. Unsupport device. read_ext_addr=%x",
							read_ext_top_addr);
	EMSG("flash_addr=%x , buf=%p, rsize=%zu", flash_addr, buf, rsize);
	return FL_DRV_ERR_UNSUPPORT_DEV;
}

static uint32_t write_flash_unsupported(uint32_t buf_addr __maybe_unused,
			uint32_t flash_addr __maybe_unused,
			uint32_t wsize __maybe_unused)
{
	EMSG(
	"Not execute write.Unsupport device.buf_addr=%x flash_addr=%x wsize=%d",
		buf_addr, flash_addr, wsize);

	return FL_DRV_ERR_UNSUPPORT_DEV;
}

static uint32_t init_rpc_reg_depends_soc(void)
{
	uint32_t ret = FL_DRV_OK;
	uint32_t prr_product = product_type & PRR_PRODUCT_MASK;

	/*
	 *  When PHYCNT Bit31 (CAL) is set to 1,
	 *  if SoC type is M3 (Ver.1.x), STRTIM [2:0] should be set to 110.
	 *  If SoC type is H3, M3N, E3, M3 (Ver.3.0 or later),
	 *  STRTIM [2:0] should be set to 111.
	 */

	phycnt_reg = 0;

	switch (prr_product) {
	case PRR_PRODUCT_H3:
	case PRR_PRODUCT_M3N:
	case PRR_PRODUCT_E3:
		/* Set PHYCNT Bit15 (STRTIM[0]) */
		phycnt_reg = 0x00008000U;
		break;
	case PRR_PRODUCT_M3:
		if ((prr_cut != PRR_CUT_10) &&
		    (prr_cut != PRR_CUT_M3_11_OR_12) &&
		    (prr_cut != PRR_CUT_M3_13)) { /*  M3 Ver.3.0 or later */
			/* Set PHYCNT Bit15 (STRTIM[0]) */
			phycnt_reg = 0x00008000U;
		}
		break;
	default:
		ret = FL_DRV_ERR_UNSUPPORT_DEV;
		EMSG("Unsupported product. PRR_PRODUCT=0x%x", prr_product);
		break;
	}

	DMSG("PRR_PRODUCT=0x%x, PRR_CUT=0x%x, phycnt_reg=0x%08x",
		prr_product, prr_cut, phycnt_reg);

	return ret;
}

static uint32_t init_rpc(void)
{
	uint32_t ret;
	uint32_t dataL;
	/* wait: tRPH(30us) >= tRP(200ns) + tRH(150ns) */
	const uint32_t wait_time_us_tRP_margin = 1U;
	const uint32_t wait_time_us_tRH_margin = 29U;

	ret = set_rpc_clock_mode(rpc_clock_mode);

	/* Reset RPC */
	if (ret == FL_DRV_OK) {
		dataL = 0x00020000U;	/* Bit17 RPC reset */

		*((volatile uint32_t *)CPG_CPGWPR)	= ~dataL;
		*((volatile uint32_t *)CPG_SRCR9)	=  dataL;
		udelay(wait_time_us_tRP_margin);

		*((volatile uint32_t *)CPG_CPGWPR)	= ~dataL;
		*((volatile uint32_t *)CPG_SRSTCLR9)	=  dataL;
		udelay(wait_time_us_tRH_margin);

		DMSG("rpc_clock_mode=%d, RPCCKCR=0x%08x",
			rpc_clock_mode, read32(CPG_RPCCKCR));
	}

	return ret;
}
