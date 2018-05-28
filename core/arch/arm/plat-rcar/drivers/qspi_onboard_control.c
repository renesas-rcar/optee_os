// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2018, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <drivers/qspi_hyper_flash.h>

#include "qspi_hyper_flash_common.h"
#include "qspi_flash_common.h"
#include "qspi_onboard_control.h"

static uint32_t qspi_onboard_erase_main(uint32_t sector_addr);
static uint32_t qspi_onboard_set_ext_addr_read_mode(uint32_t read_ext_top_addr,
			uint32_t r_flash_addr, uint8_t *buf, size_t rsize);
static uint32_t qspi_onboard_write_main(uint32_t buf_addr,
					uint32_t flash_addr, uint32_t wsize);
static uint32_t qspi_onboard_set_sector_erase_size(uint32_t sector_size_bit);
static uint32_t qspi_onboard_read_register_data(uint32_t manual_set_addr,
						uint8_t *read_register_data);
static uint32_t qspi_onboard_read_flash_data4Byte(uint32_t readFlAddr,
							uint32_t *readData);
static uint32_t qspi_onboard_request_write_buffer(uint32_t flash_addr,
						uint32_t write_data_addr);
static uint32_t qspi_onboard_write_buffer(uint32_t manual_set_addr,
						uint32_t write_data_addr);
static uint32_t qspi_onboard_write_register_data(uint32_t manual_set_addr,
						uint8_t write_data);

static uint32_t qspi_onboard_erase_main(uint32_t sector_addr)
{
	uint32_t sector_size_bit = BIT1;
	uint32_t sector_size = SECTOR_SIZE;
	uint32_t ret;

	switch (sector_size) {
	/* sector size is 64KB. */
	case ERASE_SIZE_64KB:
		sector_size_bit = ~sector_size_bit;
		break;
	default:
		DMSG("SECTOR_SIZE =%x", SECTOR_SIZE);
		break;
	}

	ret = qspi_onboard_set_sector_erase_size(sector_size_bit);
	if (ret == FL_DRV_OK) {
		ret = qspi_common_erase_control(sector_addr);
	}

	return ret;
}

static uint32_t qspi_onboard_set_ext_addr_read_mode(uint32_t read_ext_top_addr,
			uint32_t r_flash_addr, uint8_t *buf, size_t rsize)
{
/*
 * for OnBoard QspiFlash(S25FS128S)
 * FAST_READ 0Bh (CR2V[7]=0) is followed by a 3-byte address
 */
	uint32_t readFlAddr;
	uint32_t readData;
	uint32_t DREAR_value;
	uint32_t ret = FL_DRV_OK;

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80030260U;
	*((volatile uint32_t *)RPC_CMNCR)	=	0x01FF7300U;
	*((volatile uint32_t *)RPC_DRCR)	=	0x001F0100U;
	/*
	 * bit20-16 RBURST[4:0] = 11111 : 32 continuous data unit
	 * bit8     RBE         =     1 : Burst read
	 */

	*((volatile uint32_t *)RPC_DRCMR)	=	0x000B0000U;
	/*
	 * bit23-16 CMD[7:0] = 0x0B : FAST_READ 0Bh
	 */
	DREAR_value = (read_ext_top_addr >> EXT_ADDR_BIT_SHIFT_9);
	*((volatile uint32_t *)RPC_DREAR)	=	DREAR_value;
	/*
	 * bit23-16 EAV[7:0]   = ADR[32:25]      : set
	 * bit2-0   EAC[2:0]   = 000  : ADR[24:0 ] Enable
	 */

	*((volatile uint32_t *)RPC_DROPR)	=	0x00000000U;
	/*
	 * bit31-24 OPD3[7:0]  = H'0  : Option Data 3 (Set Mode)
	 */

	*((volatile uint32_t *)RPC_DRENR)	=	0x0000C700U;
	/*
	 * bit31-30 CDB[1:0]   =   00 : 1bit width command (QSPI0_MOSI)
	 * bit25-24 ADB[1:0]   =   00 : 1bit width address (QSPI0_MOSI)
	 * bit17-16 DRDB[1:0]  =   00 : 1bit width transfer data (QSPI0_IO0-3)
	 * bit15    DME        =    1 : dummy cycle enable
	 * bit14    CDE        =    1 : Command enable
	 * bit11-8  ADE[3:0]   = 0111 : ADR[23:0] output (24 Bit Address)
	 */

	*((volatile uint32_t *)RPC_DRDMCR)	=	0x00000007U;
	/* 8 cycle dummy
	 * bit17-16 DMCYC[2:0] =  10 : 4 bit width
	 * bit2-0 DMCYC[2:0]   = 111 : 8 cycle dummy wait
	 * bit2-0 DMCYC[2:0]   = 011 : 4 cycle dummy wait
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

		ret = qspi_onboard_read_flash_data4Byte(readFlAddr, &readData);
		(void)memcpy(buf, &readData, FLASH_DATA_READ_BYTE_COUNT_4);
		buf += FLASH_DATA_READ_BYTE_COUNT_4;
	}

	return ret;
}

static uint32_t qspi_onboard_write_main(uint32_t buf_addr,
					uint32_t flash_addr, uint32_t wsize)
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
				ret = qspi_onboard_request_write_buffer(
					work_flash_256top, uptr_wbuff);
				break;
			}
		}
		ret = qspi_onboard_request_write_buffer(work_flash_addr,
							write_data_addr);
		work_flash_addr += WRITE_BUFF_SIZE;
		write_data_addr += WRITE_BUFF_SIZE;
	}

	return ret;
}

void qspi_onboard_set_control_ops(struct flash_control_operations *ops)
{
	ops->erase = qspi_onboard_erase_main;
	ops->set_ext_addr_read_mode = qspi_onboard_set_ext_addr_read_mode;
	ops->write = qspi_onboard_write_main;
}

static uint32_t qspi_onboard_set_sector_erase_size(uint32_t sector_size_bit)
{
/*
 * Qspi:Set Sector Erase size (CR3V[1]=1   0:64kb 1:256kb)
 */
	uint8_t register_data = 0U;
	uint32_t read_status = 0U;
	uint8_t read_sector_size_bit;
	uint8_t set_register = READ_SECTOR_SIZE_BIT_ON;
	uint32_t ret;

	ret = qspi_onboard_read_register_data(SPIREG_CR3V, &register_data);

	read_sector_size_bit = (uint8_t)(register_data & BIT1);

	if ((read_sector_size_bit == BIT1) && (sector_size_bit == ~BIT1)) {
		/* setting pattern is [64kb] sector erase size */
		register_data = register_data & (uint8_t)sector_size_bit;
	} else if ((read_sector_size_bit == 0U) && (sector_size_bit == BIT1)) {
		/* setting pattern is [256kb] sector erase size  */
		register_data = register_data | (uint8_t)sector_size_bit;
	} else {
		set_register = READ_SECTOR_SIZE_BIT_OFF;
	}

	if (set_register == READ_SECTOR_SIZE_BIT_ON) {
		if (ret == FL_DRV_OK) {
		/* WRITE ENABLE */
			ret = qspi_common_set_command(
						QSPI_FL_COMMAND_WRITE_ENABLE);
		}
		/* Bit1=Block Erase Size  1:256KB , 0:64KB */

		if (ret == FL_DRV_OK) {
			ret = qspi_onboard_write_register_data(SPIREG_CR3V,
								register_data);
		}

		if (ret == FL_DRV_OK) {
			ret = common_wait(qspi_common_read_device_status,
					&read_status, QSPI_ERASE_TIMEOUT,
					QSPI_ERASE_WAIT);
		}

	}
	return ret;
}

static uint32_t qspi_onboard_read_register_data(uint32_t manual_set_addr,
						uint8_t *read_register_data)
{
/*
 * For OnBoard QspiFlash(S25FS128S)
 * 65h Read Any Register command (RADR 65h)
 * Add24bit,Data8bit
 */
	uint32_t ret;
	uint32_t status = 0U;

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80030260U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit1-0 PHYMEM[1:0] = 00 : QSPI-SDR
	 */

	*((volatile uint32_t *)RPC_CMNCR)	=	0x81FF7300U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 00 : QSPI Flash x 1
	 */

	*((volatile uint32_t *)RPC_SMCMR)	=	0x00650000U;
	/*
	 * bit23-16 CMD[7:0] = 0x65 : Read Any Register command (RADR 65h)
	 */

	*((volatile uint32_t *)RPC_SMADR)	=	manual_set_addr;
	*((volatile uint32_t *)RPC_SMDMCR)	=	0x00000007U;
	/*
	 * bit2-0 DMCYC[2:0] = 111 : 8 cycle dummy wait
	 */

	*((volatile uint32_t *)RPC_SMDRENR)	=	0x00000000U;
	/*
	 * bit8 ADDRE  = 0 : Address SDR transfer
	 * bit0 SPIDRE = 0 : DATA SDR transfer
	 */

	*((volatile uint32_t *)RPC_SMENR)	=	0x0000C708U;
	/*
	 * bit31-30 CDB[1:0]   =   00 : 1bit width command (QSPI0_MOSI)
	 * bit25-24 ADB[1:0]   =   00 : 1bit width address (QSPI0_MOSI)
	 * bit17-16 SPIDB[1:0] =   00 : 1bit width transfer data (QSPI0_MISO)
	 * bit15    DME        =    1 : dummy cycle enable
	 * bit14    CDE        =    1 : Command enable
	 * bit11-8  ADE[3:0]   = 0111 : ADR[23:0] output (24 Bit Address)
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
		*read_register_data   = *((volatile uint8_t *)RPC_SMRDR0);
	}

	return ret;
}

static uint32_t qspi_onboard_read_flash_data4Byte(uint32_t readFlAddr,
							uint32_t *readData)
{
	uint32_t ret;
	uint32_t status = 0U;

	*((volatile uint32_t *)RPC_PHYCNT)    = 0x80030260U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit1-0 PHYMEM[1:0] = 00 : QSPI-SDR
	 */
	*((volatile uint32_t *)RPC_CMNCR)      = 0x81FF7300U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 00 : QSPI Flash x 1
	 */
	*((volatile uint32_t *)RPC_SMCMR)      = 0x000C0000U;
	/*
	 * bit23-16 CMD[7:0] = 0x0C : Fast Read command (4FAST_READ 0Ch)
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
	*((volatile uint32_t *)RPC_SMENR)      = 0x0000CF0FU;
	/* bit31-30 CDB[1:0]   =   00 : 1bit width command (QSPI0_MOSI)
	 * bit25-24 ADB[1:0]   =   00 : 1bit width address (QSPI0_MOSI)
	 * bit17-16 SPIDB[1:0] =   00 : 1bit width transfer data (QSPI0_MISO)
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

static uint32_t qspi_onboard_request_write_buffer(uint32_t flash_addr,
						uint32_t write_data_addr)
{
	uint32_t read_status = 0U;
	uint32_t ret;

	/* WRITE ENABLE */
	ret = qspi_common_set_command(QSPI_FL_COMMAND_WRITE_ENABLE);

	if (ret == FL_DRV_OK) {
		ret = qspi_onboard_write_buffer(flash_addr, write_data_addr);
	}

	if (ret == FL_DRV_OK) {
		ret = common_wait(qspi_common_read_device_status, &read_status,
					QSPI_WRITE_TIMEOUT, QSPI_WRITE_WAIT);
	}

	return ret;
}

static uint32_t qspi_onboard_write_buffer(uint32_t manual_set_addr,
						uint32_t write_data_addr)
{
	uintptr_t offset;
	uint32_t ret;
	uint32_t status = 0U;

	*((volatile uint32_t *)RPC_DRCR)	=	0x011F0301U;
	/*
	 * bit9   RCF         =  1 : Read Cache Clear
	 */

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80030274U;
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

	*((volatile uint32_t *)RPC_CMNCR)	=	0x81FF7300U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 00 : QSPI Flash x 1
	 */

	*((volatile uint32_t *)RPC_SMCMR)	=	0x00020000U;
	/*
	 * bit23-16 CMD[7:0] = 0x02 : Page Program 3-byte address
	 */

	*((volatile uint32_t *)RPC_SMADR)	=	manual_set_addr;

	*((volatile uint32_t *)RPC_SMDRENR)	=	0x00000000U;
	/*
	 * bit8 ADDRE  = 0 : Address SDR transfer
	 * bit0 SPIDRE = 0 : DATA SDR transfer
	 */

	*((volatile uint32_t *)RPC_SMENR)	=	0x0000470FU;
	/*
	 * bit31-30 CDB[1:0]   =   00 : 1bit width command (QSPI0_MOSI)
	 * bit25-24 ADB[1:0]   =   00 : 1bit width address (QSPI0_MOSI)
	 * bit17-16 SPIDB[1:0] =   00 : 1bit width transfer data (QSPI0_MISO)
	 * bit15    DME        =    0 : No dummy cycle
	 * bit14    CDE        =    1 : Command enable
	 * bit11-8  ADE[3:0]   = 0111 : ADR[23:0] is output
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
		*((volatile uint32_t *)RPC_PHYCNT)	=	0x00030273U;
		/*
		 * bit31  CAL         =  0 : No PHY calibration
		 * bit2   WBUF        =  0 : Write Buffer Disable
		 * bit1-0 PHYMEM[1:0] = 11 : HyperFlash
		 */

		*((volatile uint32_t *)RPC_DRCR)	=	0x011F0301U;
		/*
		 * bit9   RCF         =  1 : Read Cache Clear
		 */
	}

	return ret;
}

static uint32_t qspi_onboard_write_register_data(uint32_t manual_set_addr,
						uint8_t write_data)
{
	uint32_t ret;
	uint32_t status = 0U;

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80030260U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit1-0 PHYMEM[1:0] = 00 : QSPI-SDR
	 */

	*((volatile uint32_t *)RPC_CMNCR)	=	0x81FF7300U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 00 : QSPI Flash x 1
	 */

	*((volatile uint32_t *)RPC_SMCMR)	=	0x00710000U;
	/*
	 * bit23-16 CMD[7:0] = 0x71 : Write Any Register Command  (WRAR)
	 */

	*((volatile uint32_t *)RPC_SMADR)	=	manual_set_addr;
	*((volatile uint32_t *)RPC_SMDRENR)	=	0x00000000U;
	/*
	 * bit8 ADDRE  = 0 : Address SDR transfer
	 * bit0 SPIDRE = 0 : DATA SDR transfer
	 */

	*((volatile uint32_t *)RPC_SMENR)	=	0x00004708U;
	/*
	 * bit31-30 CDB[1:0]   =   00 : 1bit width command (QSPI0_MOSI)
	 * bit25-24 ADB[1:0]   =   00 : 1bit width address (QSPI0_MOSI)
	 * bit17-16 SPIDB[1:0] =   00 : 1bit width transfer data (QSPI0_MISO)
	 * bit15    DME        =    0 : No dummy cycle
	 * bit14    CDE        =    1 : Command enable
	 * bit11-8  ADE[3:0]   = 0111 : ADR[24:0] is output
	 * bit3-0   SPIDE[3:0] = 1000 : 8bit transfer
	 */

	*((volatile uint8_t *)RPC_SMWDR0)	=	write_data;
	*((volatile uint32_t *)RPC_SMCR)	=	0x00000003U;
	/*
	 * bit2     SPIRE      = 0 : Data read disable
	 * bit1     SPIWE      = 1 : Data write enable
	 * bit0     SPIE       = 1 : SPI transfer start
	 */

	ret = common_wait(common_wait_spi_transfer, &status,
					QSPI_WRITE_TIMEOUT, QSPI_WRITE_WAIT);

	if (ret == FL_DRV_OK) {
		*((volatile uint32_t *)RPC_PHYCNT)	=	0x00030273U;
		/*
		 * bit31  CAL         =  0 : No PHY calibration
		 * bit2   WBUF        =  0 : Write Buffer Disable
		 * bit1-0 PHYMEM[1:0] = 11 : HyperFlash
		 */

		*((volatile uint32_t *)RPC_DRCR)	=	0x011F0301U;
		/*
		 * bit9   RCF         =  1 : Read Cache Clear
		 */
	}

	return ret;
}
