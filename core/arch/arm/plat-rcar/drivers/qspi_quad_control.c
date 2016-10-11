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
#include <drivers/qspi_hyper_flash.h>

#include "qspi_hyper_flash_common.h"
#include "qspi_flash_common.h"
#include "qspi_quad_control.h"

static uint32_t qspi_quad_erase_control(uint32_t sector_addr);
static uint32_t qspi_quad_read_flash_data4Byte(uint32_t readFlAddr,
							uint32_t *readData);
static uint32_t qspi_quad_set_ext_addr_read_mode(uint32_t read_ext_top_addr,
			uint32_t r_flash_addr, uint8_t *buf, size_t rsize);
static uint32_t qspi_quad_write_main(uint32_t buf_addr, uint32_t flash_addr,
								uint32_t wsize);
static uint32_t qspi_quad_set_quad_mode(void);
static uint32_t qspi_quad_read_config(uint32_t *read_cnfig);
static uint32_t qspi_quad_request_write_buffer(uint32_t flash_addr,
						uint32_t write_data_addr);
static uint32_t qspi_quad_write_buffer(uint32_t manual_set_addr,
						uint32_t write_data_addr);
static uint32_t qspi_quad_write_register_status_config(uint32_t write_status,
						uint32_t write_config);

static uint32_t qspi_quad_erase_control(uint32_t sector_addr)
{
/*
 * Qspi:Sector Erase
 */
	uint32_t ret;

	ret = qspi_common_erase_control(sector_addr);
	return ret;
}

static uint32_t qspi_quad_read_flash_data4Byte(uint32_t readFlAddr,
							uint32_t *readData)
{
	uint32_t ret;
	uint32_t status = 0U;

	*((volatile uint32_t *)RPC_PHYCNT)    = 0x80000260U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit1-0 PHYMEM[1:0] = 00 : QSPI-SDR
	 */
	*((volatile uint32_t *)RPC_CMNCR)      = 0x81FFF300U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 00 : QSPI Flash x 1
	 */
	*((volatile uint32_t *)RPC_SMCMR)      = 0x006C0000U;
	/*
	 * bit23-16 CMD[7:0] = 0x6C : Quad Output Read (4QOR 6Ch)
	 */
	*((volatile uint32_t *)RPC_SMADR)      = readFlAddr;
	*((volatile uint32_t *)RPC_SMDMCR)     = 0x00000007U;
	/*
	 * bit2-0 DMCYC[2:0] = 111 : 8 cycle dummy wait
	 */
	*((volatile uint32_t *)RPC_SMDRENR)    = 0x00000000U;
	/*
	 * bit8 ADDRE  = 0 : Address SDR transfer
	 * bit0 SPIDRE = 0 : DATA SDR transfer
	 */
	*((volatile uint32_t *)RPC_SMENR)      = 0x0002CF0FU;
	/*
	 * bit31-30 CDB[1:0]   =   00 : 1bit width command (QSPI0_MOSI)
	 * bit25-24 ADB[1:0]   =   00 : 1bit width address (QSPI0_MOSI)
	 * bit17-16 SPIDB[1:0] =   10 : 1bit width transfer data (QSPI0_IO0-3)
	 * bit15    DME        =    1 : dummy cycle enable
	 * bit14    CDE        =    1 : Command enable
	 * bit11-8  ADE[3:0]   = 1111 : ADR[31:0] output (32 Bit Address)
	 * bit3-0   SPIDE[3:0] = 1111 : 32bit transfer
	 */
	*((volatile uint32_t *)RPC_SMCR)       = 0x00000005U;
	/*
	 * bit2     SPIRE      = 1 : Data read enable
	 * bit1     SPIWE      = 0 : Data write disable
	 * bit0     SPIE       = 1 : SPI transfer start
	 */

	ret = common_wait(common_wait_spi_transfer, &status,
					QSPI_READ_TIMEOUT, QSPI_READ_WAIT);

	if (ret == FL_DRV_OK) {
		/* read data[31:0] */
		*readData = *((volatile uint32_t *)RPC_SMRDR0);
	}

	return ret;
}

static uint32_t qspi_quad_set_ext_addr_read_mode(uint32_t read_ext_top_addr,
			uint32_t r_flash_addr, uint8_t *buf, size_t rsize)
{
	uint32_t readFlAddr;
	uint32_t readData;
	uint32_t DREAR_value;
	uint32_t ret = FL_DRV_OK;

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80000260U;
	*((volatile uint32_t *)RPC_CMNCR)	=	0x01FFF300U;
	*((volatile uint32_t *)RPC_DRCR)	=	0x001F0100U;
	/*
	 * bit20-16 RBURST[4:0] = 11111 : 32 continuous data unit
	 * bit8     RBE         =     1 : Burst read
	 */

	*((volatile uint32_t *)RPC_DRCMR)	=	0x000C0000U;
	/*
	 * bit23-16 CMD[7:0] = 0x0C :
	 *                      4FAST_READ 0Ch Command 4-byte address command
	 */
	DREAR_value = (read_ext_top_addr >> EXT_ADDR_BIT_SHIFT_9);
	*((volatile uint32_t *)RPC_DREAR)   =	(DREAR_value | 0x00000001U);
	/*
	 * bit23-16 EAV[7:0]   = ADR[32:26]      : set
	 * bit2-0   EAC[2:0]   = 001  : ADR[25:0 ] Enable
	 */

	*((volatile uint32_t *)RPC_DRENR)	=	0x0000CF00U;
	/*
	 * bit31-30 CDB[1:0]   =   00 : 1bit width command (QSPI0_MOSI)
	 * bit25-24 ADB[1:0]   =   00 : 1bit width address (QSPI0_MOSI)
	 * bit17-16 DRDB[1:0]  =   00 : 1bit width transfer data (QSPI0_IO0)
	 * bit15    DME        =    1 : dummy cycle enable
	 * bit14    CDE        =    1 : Command enable
	 * bit11-8  ADE[3:0]   = 1111 : ADR[23:0] output (24 Bit Address)
	 */

	*((volatile uint32_t *)RPC_DRDMCR)	=	0x00000007U;
	/*
	 * bit2-0 DMCYC[2:0]   = 111 : 8 cycle dummy wait
	 */

	*((volatile uint32_t *)RPC_DRDRENR)	=	0x00000000U;
	/*
	 * bit8 ADDRE  = 0 : Address SDR transfer
	 * bit0 DRDRE  = 0 : DATA SDR transfer
	 */

	/* Output read data */
	for (readFlAddr = r_flash_addr;
		readFlAddr < (r_flash_addr+rsize);
		readFlAddr += FLASH_DATA_READ_BYTE_COUNT_4) {

		ret = qspi_quad_read_flash_data4Byte(readFlAddr, &readData);
		(void)memcpy(buf, &readData, FLASH_DATA_READ_BYTE_COUNT_4);
		buf += FLASH_DATA_READ_BYTE_COUNT_4;
	}

	return ret;
}

static uint32_t qspi_quad_write_main(uint32_t buf_addr, uint32_t flash_addr,
								uint32_t wsize)
{
	uint32_t wbuf_size;
	uint32_t wcount;
	uint32_t write_num;
	uint32_t rest_wsize;
	uint32_t work_flash_addr;
	uint32_t write_data_addr;
	uint32_t work_flash_256top;
	uint32_t w_offset;
	uint8_t wbuff[WRITE_BUFF_SIZE];
	uintptr_t uptr_wbuff;
	volatile uintptr_t v_flash_addr = flash_addr;
	uint8_t *p_flash_addr;
	uint32_t ret = FL_DRV_OK;

	write_data_addr = buf_addr;
	work_flash_addr = flash_addr;
	write_num = wsize / WRITE_BUFF_SIZE;
	rest_wsize = wsize % WRITE_BUFF_SIZE;
	if (rest_wsize > 0U) {
		write_num++;
	}

	/* RPC Write Buffer size : 256byte , and rest size writing */
	for (wcount = 0U; wcount < write_num; wcount++) {
		if (wcount == (write_num - 1U)) {
			if (rest_wsize > 0U) {
				wbuf_size = rest_wsize;
				work_flash_256top =
					(work_flash_addr / WRITE_BUFF_SIZE) *
								WRITE_BUFF_SIZE;
				(void)memset(wbuff, 0xffU, WRITE_BUFF_SIZE);
				w_offset = work_flash_addr - work_flash_256top;
				v_flash_addr = write_data_addr;
				p_flash_addr = (uint8_t *)v_flash_addr;
				(void)memcpy(wbuff+w_offset, p_flash_addr,
								wbuf_size);
				uptr_wbuff = (uintptr_t)wbuff;
				ret = qspi_quad_request_write_buffer(
					work_flash_256top, uptr_wbuff);
				break;
			}
		}
		ret = qspi_quad_request_write_buffer(work_flash_addr,
							write_data_addr);
		work_flash_addr += WRITE_BUFF_SIZE;
		write_data_addr += WRITE_BUFF_SIZE;
	}

	return ret;
}

void qspi_quad_set_control_ops(struct flash_control_operations *ops)
{
	ops->erase = qspi_quad_erase_control;
	ops->set_ext_addr_read_mode = qspi_quad_set_ext_addr_read_mode;
	ops->write = qspi_quad_write_main;
}

static uint32_t qspi_quad_set_quad_mode(void)
{
	uint32_t status = 0U;
	uint32_t config = 0U;
	uint32_t read_status = 0U;
	uint32_t ret;

	ret = qspi_quad_read_config(&config);

	if (ret == FL_DRV_OK) {
		if ((config & BIT1) == 0U) {
			/* WRITE ENABLE */
			ret = qspi_common_set_command(
						QSPI_FL_COMMAND_WRITE_ENABLE);
			if (ret == FL_DRV_OK) {
				ret = common_wait(
					qspi_common_read_device_status,
 					&read_status, QSPI_WRITE_TIMEOUT,
					QSPI_WRITE_WAIT);
			}
			if (ret == FL_DRV_OK) {
				/* set QUAD=1 */
				config |= BIT1;
				ret = qspi_quad_write_register_status_config(
									status,
									config);
			}
			if (ret == FL_DRV_OK) {
				ret = common_wait(
					qspi_common_read_device_status,
					&read_status, QSPI_WRITE_TIMEOUT,
					QSPI_WRITE_WAIT);
			}
		}
	}
	return ret;
}

static uint32_t qspi_quad_read_config(uint32_t *read_cnfig)
{
	uint8_t read_data;
	uint32_t ret;
	uint32_t status = 0U;

	/*
	 * Manual mode / No dummy / On Command /
	 *                              No Address /  Data:8bit transfer
	 */

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80000260U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit1-0 PHYMEM[1:0] = 00 : QSPI-SDR
	 */

	*((volatile uint32_t *)RPC_CMNCR)	=	0x81FFF300U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 00 : QSPI Flash x 1
	 */

	*((volatile uint32_t *)RPC_SMCMR)	=	0x00350000U;
	/*
	 * bit23-16 CMD[7:0] = 0x35 : Read Configuration Register (CFG)
	 */

	*((volatile uint32_t *)RPC_SMDRENR)	=	0x00000000U;
	/*
	 * bit8 ADDRE  = 0 : Address SDR transfer
	 * bit0 SPIDRE = 0 : DATA SDR transfer
	 */

	*((volatile uint32_t *)RPC_SMENR)	=	0x00004008U;
	/*
	 * bit15    DME        =    0 : No dummy cycle
	 * bit14    CDE        =    1 : Command enable
	 * bit11-8  ADE[3:0]   = 0000 : Address output disable
	 * bit3-0   SPIDE[3:0] = 1000 : 8bit transfer
	 */

	*((volatile uint32_t *)RPC_SMCR)	=	0x00000005U;
	/*
	 * bit2     SPIRE      = 1 : Data read enable
	 * bit1     SPIWE      = 0 : Data write disable
	 * bit0     SPIE       = 1 : SPI transfer start
	 */

	ret = common_wait(common_wait_spi_transfer, &status,
					QSPI_READ_TIMEOUT, QSPI_READ_WAIT);

	if (ret == FL_DRV_OK) {
		/* read data[7:0] */
		read_data    = *((volatile uint8_t *)RPC_SMRDR0);
		*read_cnfig  = read_data;
	}

	return ret;
}

static uint32_t qspi_quad_request_write_buffer(uint32_t flash_addr,
						uint32_t write_data_addr)
{
	uint32_t read_status = 0U;
	uint32_t ret;

	ret = qspi_quad_set_quad_mode();

	if (ret == FL_DRV_OK) {
		/* WRITE ENABLE */
		ret = qspi_common_set_command(QSPI_FL_COMMAND_WRITE_ENABLE);
	}

	if (ret == FL_DRV_OK) {
		ret = qspi_quad_write_buffer(flash_addr, write_data_addr);
	}

	if (ret == FL_DRV_OK) {
		ret = common_wait(qspi_common_read_device_status, &read_status,
					QSPI_WRITE_TIMEOUT, QSPI_WRITE_WAIT);
	}

	return ret;
}

static uint32_t qspi_quad_write_buffer(uint32_t manual_set_addr,
						uint32_t write_data_addr)
{
	uintptr_t offset;
	uint32_t ret;
	uint32_t status = 0U;

	*((volatile uint32_t *)RPC_DRCR)	=	0x01FF0301U;
	/*
	 * bit9   RCF         =  1 : Read Cache Clear
	 */

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80000274U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit2   WBUF        =  1 : Write Buffer Enable
	 * bit1-0 PHYMEM[1:0] = 00 : QSPI-SDR
	 */

	for (offset = 0U; offset < WRITE_BUFF_SIZE;
						offset = offset + WORD_SIZE) {
		(*(volatile uint32_t *)(0xEE208000U+offset)) =
			(*(volatile uint32_t *)(write_data_addr+offset));
	}

	*((volatile uint32_t *)RPC_CMNCR)	=	0x81FFF300U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 00 : QSPI Flash x 1
	 */

	*((volatile uint32_t *)RPC_SMCMR)	=	0x00340000U;
	/*
	 * bit23-16 CMD[7:0] = 0x34 : Quad Page Program 4-byte address
	 */

	*((volatile uint32_t *)RPC_SMADR)	=	manual_set_addr;

	*((volatile uint32_t *)RPC_SMDRENR)	=	0x00000000U;
	/*
	 * bit8 ADDRE  = 0 : Address SDR transfer
	 * bit0 SPIDRE = 0 : DATA SDR transfer
	 */

	*((volatile uint32_t *)RPC_SMENR)	=	0x00024F0FU;
	/*
	 * bit31-30 CDB[1:0]   =   00 : 1bit width command (QSPI0_MOSI)
	 * bit25-24 ADB[1:0]   =   00 : 1bit width address (QSPI0_MOSI)
	 * bit17-16 SPIDB[1:0] =   10 : 4bit width transfer data (QSPI0_MISO)
	 * bit15    DME        =    0 : No dummy cycle
	 * bit14    CDE        =    1 : Command enable
	 * bit11-8  ADE[3:0]   = 1111 : ADR[23:0] is output
	 * bit3-0   SPIDE[3:0] = 1111 : 32bit transfer
	 */

	*((volatile uint32_t *)RPC_SMCR)	=	0x00000003U;
	/*
	 * bit2     SPIRE      = 0 : Data read disable
	 * bit1     SPIWE      = 1 : Data write enable
	 * bit0     SPIE       = 1 : SPI transfer start
	 */

	ret = common_wait(common_wait_spi_transfer, &status,
					QSPI_WRITE_TIMEOUT, QSPI_WRITE_WAIT);

	if (ret == FL_DRV_OK) {
		*((volatile uint32_t *)RPC_PHYCNT)	=	0x00000273U;
		/*
		 * bit31  CAL         =  0 : No PHY calibration
		 * bit2   WBUF        =  0 : Write Buffer Disable
		 * bit1-0 PHYMEM[1:0] = 11 : HyperFlash
		 */

		*((volatile uint32_t *)RPC_DRCR)	=	0x01FF0301U;
		/*
		 * bit9   RCF         =  1 : Read Cache Clear
		 */
	}

	return ret;
}

static uint32_t qspi_quad_write_register_status_config(uint32_t write_status,
						uint32_t write_config)
{
	uint32_t ret;
	uint32_t status = 0U;

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80000260U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit1-0 PHYMEM[1:0] = 00 : QSPI-SDR
	 */

	*((volatile uint32_t *)RPC_CMNCR)	=	0x81FFF300U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 00 : QSPI Flash x 1
	 */

	*((volatile uint32_t *)RPC_SMCMR)	=	0x00010000U;
	/*
	 * bit23-16 CMD[7:0] = 0x01 : Write (Status & Configuration) Register
	 */

	*((volatile uint32_t *)RPC_SMDRENR)	=	0x00000000U;
	/*
	 * bit8 ADDRE  = 0 : Address SDR transfer
	 * bit0 SPIDRE = 0 : DATA SDR transfer
	 */

	*((volatile uint32_t *)RPC_SMENR)	=	0x00004008U;
	/*
	 * bit31-30 CDB[1:0]   =   00 : 1bit width command (QSPI0_MOSI)
	 * bit25-24 ADB[1:0]   =   00 : 1bit width address (QSPI0_MOSI)
	 * bit17-16 SPIDB[1:0] =   00 : 1bit width transfer data (QSPI0_MISO)
	 * bit15    DME        =    0 : No dummy cycle
	 * bit14    CDE        =    1 : Command enable
	 * bit11-8  ADE[3:0]   = 0000 : ADR[23:0] is disable
	 * bit3-0   SPIDE[3:0] = 1000 : 8bit transfer
	 */

	/* First ByteData */
	*((volatile uint8_t *)RPC_SMWDR0) =
					(volatile uint8_t)write_status;
	*((volatile uint32_t *)RPC_SMCR)	=	0x00000103U;
	/*
	 * bit8     SSLKP      = 1 : SSL After the transfer assert continue
	 * bit2     SPIRE      = 0 : Data read disable
	 * bit1     SPIWE      = 1 : Data write enable
	 * bit0     SPIE       = 1 : SPI transfer start
	 */

	ret = common_wait(common_wait_spi_transfer, &status,
					QSPI_WRITE_TIMEOUT, QSPI_WRITE_WAIT);

	if (ret == FL_DRV_OK) {
		/* Second ByteData */
		*((volatile uint32_t *)RPC_SMENR)	=	0x00000008U;
		/*
		 * bit3-0   SPIDE[3:0] = 1000 : 8bit transfer
		 */

		*((volatile uint8_t *)RPC_SMWDR0) =
					(volatile uint8_t)write_config;
		*((volatile uint32_t *)RPC_SMCR)	=	0x00000003U;
		/*
		 * bit8     SSLKP      = 0 : SSL After the transfer negated
		 * bit2     SPIRE      = 0 : Data read disable
		 * bit1     SPIWE      = 1 : Data write enable
		 * bit0     SPIE       = 1 : SPI transfer start
		 */
	}

	if (ret == FL_DRV_OK) {
		ret = common_wait(common_wait_spi_transfer, &status,
					QSPI_WRITE_TIMEOUT, QSPI_WRITE_WAIT);

		*((volatile uint32_t *)RPC_PHYCNT)	=	0x00000273U;
		/*
		 * bit31  CAL         =  0 : No PHY calibration
		 * bit2   WBUF        =  0 : Write Buffer Disable
		 * bit1-0 PHYMEM[1:0] = 11 : HyperFlash
		 */

		*((volatile uint32_t *)RPC_DRCR)	=	0x01FF0301U;
		/*
		 * bit9   RCF         =  1 : Read Cache Clear
		 */
	}

	return ret;
}
