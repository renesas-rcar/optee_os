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

#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <drivers/qspi_hyper_flash.h>

#include "qspi_hyper_flash_common.h"
#include "qspi_flash_common.h"
#include "hyper_flash_control.h"

static uint32_t erase_flash_unsupported(uint32_t sector_addr);
static uint32_t ext_addr_read_mode_flash_unsupported(uint32_t read_ext_top_addr,
			uint32_t flash_addr, uint8_t *buf, size_t rsize);
static uint32_t write_flash_unsupported(uint32_t buf_addr,
					uint32_t flash_addr, uint32_t wsize);
static uint32_t init_rpc(void);

static struct flash_control_operations flash_control_ops = {
	.erase = erase_flash_unsupported,
	.set_ext_addr_read_mode = ext_addr_read_mode_flash_unsupported,
	.write = write_flash_unsupported,
};

uint32_t qspi_hyper_flash_init(void)
{
	uint32_t ret;

	ret = init_rpc();

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
	if ((rsize > SECTOR_SIZE) || (rsize < FLASH_DATA_READ_BYTE_COUNT_8) ||
				((rsize % FLASH_DATA_READ_BYTE_COUNT_8) > 0U)) {
		ret = FL_DRV_ERR_OUT_OF_RANGE;
		EMSG("rsize is out of range. rsize=%zu", rsize);
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
	check_sector_size = ((flash_addr) % (SECTOR_SIZE)) + rsize;

	if (check_sector_size > SECTOR_SIZE) {
		ret = FL_DRV_ERR_SECTOR_EXCEED;
		EMSG("Sector exceeded. flash_addr=%x, rsize=%zu",
			flash_addr, rsize);
	}

	/* External address reading position calculation From 64MB boundary. */
	if (flash_addr > EXT_ADD_BORDER_SIZE_64MB) {
		quotient = (flash_addr / EXT_ADD_BORDER_SIZE_64MB);
		v_flash_addr = SPI_IOADDRESS_TOP +
			(flash_addr - (quotient * EXT_ADD_BORDER_SIZE_64MB));
		p_flash_addr = (uint8_t *)v_flash_addr;
		DMSG("p_flash_addr=%p", p_flash_addr);
		(void)p_flash_addr; /* suppress compile error */
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
	if ((wsize > SECTOR_SIZE) || (wsize < FLASH_DATA_READ_BYTE_COUNT_8) ||
				((wsize % FLASH_DATA_READ_BYTE_COUNT_8) > 0U)) {
		ret = FL_DRV_ERR_OUT_OF_RANGE;
		EMSG("wsize is out of range. wsize=%zu", wsize);
	}

	check_sector_size = ((flash_addr) % (SECTOR_SIZE)) + wsize;

	if (check_sector_size > SECTOR_SIZE) {
		ret = FL_DRV_ERR_SECTOR_EXCEED;
		EMSG("Sector exceeded. flash_addr=%x, wsize=%zu",
			flash_addr, wsize);
	}

	if (ret == FL_DRV_OK) {
		/* To write the according to device id */
		ret = flash_control_ops.write((uintptr_t)buf,
							flash_addr, wsize);
	}

	DMSG("ret=%d", ret);

	return ret;
}

static uint32_t erase_flash_unsupported(uint32_t sector_addr)
{
	EMSG("Not execute erase. Unsupport device. sector_addr=%x",
								sector_addr);
	return FL_DRV_ERR_UNSUPPORT_DEV;
}

static uint32_t ext_addr_read_mode_flash_unsupported(uint32_t read_ext_top_addr,
			uint32_t flash_addr, uint8_t *buf, size_t rsize)
{
	EMSG(
	"Not execute ext_addr_read_mode. Unsupport device. read_ext_addr=%x",
							read_ext_top_addr);
	EMSG("flash_addr=%x , buf=%p, rsize=%zu", flash_addr, buf, rsize);
	return FL_DRV_ERR_UNSUPPORT_DEV;
}

static uint32_t write_flash_unsupported(uint32_t buf_addr,
					uint32_t flash_addr, uint32_t wsize)
{
	EMSG(
	"Not execute write.Unsupport device.buf_addr=%x flash_addr=%x wsize=%d",
		buf_addr, flash_addr, wsize);

	return FL_DRV_ERR_UNSUPPORT_DEV;
}

static uint32_t init_rpc(void)
{
	uint32_t ret = FL_DRV_OK;
	uint32_t dataL;

	/* Set RPC clock mode */

	dataL = 0x00000013;	/* RPC clock 80MHz */

	*((volatile uint32_t *)CPG_CPGWPR)	= ~dataL;
	*((volatile uint32_t *)CPG_RPCCKCR)	=  dataL;

	soft_delay(1);		/* wait 1ms */

	/* Reset RPC */

	dataL = 0x00020000;	/* Bit17 RPC reset */

	*((volatile uint32_t *)CPG_CPGWPR)	= ~dataL;
	*((volatile uint32_t *)CPG_SRCR9)	=  dataL;
	soft_delay(1);		/* wait 1ms (20us) */

	*((volatile uint32_t *)CPG_CPGWPR)	= ~dataL;
	*((volatile uint32_t *)CPG_SRSTCLR9)	=  dataL;
	soft_delay(1);		/* wait 1ms (40us) */

	return ret;
}
