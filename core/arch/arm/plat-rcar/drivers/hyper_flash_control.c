/*
 * Copyright (c) 2015-2017, Renesas Electronics Corporation
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
#include <trace.h>
#include <drivers/qspi_hyper_flash.h>
#include "qspi_hyper_flash_common.h"
#include "hyper_flash_control.h"

static uint32_t hyper_flash_erase_sector(uint32_t sector_addr);
static uint32_t hyper_flash_set_ext_addr_read_mode(uint32_t read_ext_top_addr,
			uint32_t r_flash_addr, uint8_t *buf, size_t rsize);
static uint32_t hyper_flash_write_main(uint32_t buf_addr,
					uint32_t flash_addr, uint32_t wsize);
static void hyper_flash_set_control_ops(struct flash_control_operations *ops);
static uint32_t hyper_flash_set_command(uint32_t manual_set_addr,
							uint32_t command);
static void hyper_flash_set_disable_write_protect(void);
static uint32_t hyper_flash_reset_to_read_mode(void);
static uint32_t hyper_flash_read_register_data(uint32_t manual_set_addr,
				uint32_t *read_data, uint32_t byte_count);
static uint32_t hyper_flash_read_device_id(uint32_t *read_device_id);
static uint32_t hyper_flash_request_write_buffer(uint32_t flash_addr,
						uint32_t write_data_addr);
static uint32_t hyper_flash_write_buffer_control(uint32_t flash_addr,
						uint32_t write_data_addr);
static uint32_t hyper_flash_write_buffer(uint32_t manual_set_addr,
						uint32_t write_data_addr);

uint32_t hyper_flash_init(struct flash_control_operations *ops)
{
	uint32_t read_device_id = DEVICE_UNKNOWN;
	uint32_t ret;

	/* read hyper flash device id */
	ret = hyper_flash_read_device_id(&read_device_id);

	if (ret == FL_DRV_OK) {
		/* HyperFlash : S26KS512S */
		if (read_device_id == HYPER_FLASH) {
			hyper_flash_set_control_ops(ops);
			ret = FL_DRV_OK;
		} else {
			ret = FL_DRV_ERR_UNSUPPORT_DEV;
		}
	} else {
		ret = FL_DRV_ERR_UNSUPPORT_DEV;
	}
	DMSG("device id=%x", read_device_id);

	return ret;
}

static uint32_t hyper_flash_erase_sector(uint32_t sector_addr)
{
	uint32_t status = 0U;
	uint32_t ret;

	/* 1st command write */
	ret = hyper_flash_set_command(HYPER_FL_UNLOCK1_ADD,
							HYPER_FL_UNLOCK1_DATA);

	if (ret == FL_DRV_OK) {
		/* 2nd command write */
		ret = hyper_flash_set_command(HYPER_FL_UNLOCK2_ADD,
							HYPER_FL_UNLOCK2_DATA);
	}

	if (ret == FL_DRV_OK) {
		/* 3rd command write */
		ret = hyper_flash_set_command(HYPER_FL_UNLOCK3_ADD,
							HYPER_FL_ERASE_1ST_COM);
	}

	if (ret == FL_DRV_OK) {
		/* 4th command write */
		ret = hyper_flash_set_command(HYPER_FL_UNLOCK1_ADD,
							HYPER_FL_UNLOCK1_DATA);
	}

	if (ret == FL_DRV_OK) {
		/* 5th command write */
		ret = hyper_flash_set_command(HYPER_FL_UNLOCK2_ADD,
							HYPER_FL_UNLOCK2_DATA);
	}

	if (ret == FL_DRV_OK) {
		/* 6th Command command write */
		ret = hyper_flash_set_command((sector_addr>>1U),
						HYPER_FL_SECTOR_ERASE_COM);
	}

	if (ret == FL_DRV_OK) {
		/* BIT7: Device Ready Bit (0=Busy, 1=Ready) */
		ret = common_wait(hyper_flash_read_device_status, &status,
					HF_ERASE_TIMEOUT, HF_ERASE_WAIT);
	}

	return ret;
}

static uint32_t hyper_flash_set_ext_addr_read_mode(uint32_t read_ext_top_addr,
			uint32_t r_flash_addr, uint8_t *buf, size_t rsize)
{
/*
 *Read (External Address Space Read Mode)
 */
	uint32_t readFlAddr;
	uint32_t readData[2];
	uint32_t ret = FL_DRV_OK;

	uint32_t DREAR_value;

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80070263U;
	*((volatile uint32_t *)RPC_CMNCR)	=	0x01FFF301U;
	*((volatile uint32_t *)RPC_DRCR)	=	0x001F0100U;
	*((volatile uint32_t *)RPC_DRCMR)	=	0x00A00000U;
	DREAR_value = (read_ext_top_addr >> EXT_ADDR_BIT_SHIFT_9);
	*((volatile uint32_t *)RPC_DREAR)   =	(DREAR_value | 0x00000001U);
	/*
	 * bit23-16 EAV[7:0]   = ADR[32:26]      : set
	 * bit2-0   EAC[2:0]   = 001  : ADR[25:0 ] Enable
	 */
	*((volatile uint32_t *)RPC_DRENR)	=	0xA222D400U;
	*((volatile uint32_t *)RPC_DRDMCR)	=	0x0000000EU;
	*((volatile uint32_t *)RPC_DRDRENR)	=	0x00005101U;
	*((volatile uint32_t *)RPC_OFFSET1)	=	0x21511144U;
	*((volatile uint32_t *)RPC_PHYINT)	=	0x07070002U;
	/*
	 * bit18 RSTEN = 1 : RPC_RESET# pin is enabled
	 * bit17 WPEN  = 1 : RPC_WP# pin is enabled
	 * bit16 INTEN = 1 : RPC_INT# pin is enabled
	 * bit2  RSTVAL= 0 : RPC_RESET# = H
	 * bit1  WPVAL = 1 : RPC_WP# = L
	 * bit0  INT   = 0 : Interrupt Status
	 */

	/* Output read data */
	for (readFlAddr = r_flash_addr;
		readFlAddr < (r_flash_addr+rsize);
		readFlAddr += FLASH_DATA_READ_BYTE_COUNT_8) {

		ret = hyper_flash_read_register_data(readFlAddr,
						readData,
						FLASH_DATA_READ_BYTE_COUNT_8);
		(void)memcpy(buf, readData, FLASH_DATA_READ_BYTE_COUNT_8);
		buf += FLASH_DATA_READ_BYTE_COUNT_8;
	}

	return ret;
}

static uint32_t hyper_flash_write_main(uint32_t buf_addr,
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

	ret = set_rpc_clock_mode(RPC_CLK_40M);	/* 50MHz(max) */

	if (ret == FL_DRV_OK) {
		hyper_flash_set_disable_write_protect();

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
					work_flash_256top = (work_flash_addr /
						WRITE_BUFF_SIZE) *
						WRITE_BUFF_SIZE;
					(void)memset(wbuff, 0xffU,
						WRITE_BUFF_SIZE);
					w_offset = work_flash_addr -
						work_flash_256top;
					v_flash_addr = write_data_addr;
					p_flash_addr = (uint8_t *)v_flash_addr;
					(void)memcpy(wbuff+w_offset,
						p_flash_addr, wbuf_size);
					uptr_wbuff = (uintptr_t)wbuff;
					ret = hyper_flash_request_write_buffer(
						work_flash_256top, uptr_wbuff);
					break;
				}
			}
			ret = hyper_flash_request_write_buffer(work_flash_addr,
							write_data_addr);
			work_flash_addr += WRITE_BUFF_SIZE;
			write_data_addr += WRITE_BUFF_SIZE;
		}

		ret = set_rpc_clock_mode(RPC_CLK_80M);
	}

	return ret;
}

static void hyper_flash_set_control_ops(struct flash_control_operations *ops)
{
	ops->erase = hyper_flash_erase_sector;
	ops->set_ext_addr_read_mode = hyper_flash_set_ext_addr_read_mode;
	ops->write = hyper_flash_write_main;
}

static uint32_t hyper_flash_set_command(uint32_t manual_set_addr,
							uint32_t command)
{
	uint32_t ret;
	uint32_t status = 0U;

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80030263U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit1-0 PHYMEM[1:0] = 11 : HyperFlash
	 */

	*((volatile uint32_t *)RPC_CMNCR)	=	0x81FFF301U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 01 : QSPI Flash x 2 or HyperFlash
	 */

	*((volatile uint32_t *)RPC_SMCMR)	=	0x00000000U;
	/*
	 * bit23-21 CMD[7:5] = 000 : CA47-45 = 000 =>
	 *                                      Write/memory space/WrrapedBrst
	 */

	*((volatile uint32_t *)RPC_SMADR)	=	manual_set_addr;
	*((volatile uint32_t *)RPC_SMOPR)	=	0x00000000U;
	/*
	 * CA15-3(Reserved) = all 0
	 */

	*((volatile uint32_t *)RPC_SMDRENR)	=	0x00005101U;
	/*
	 * bit14-12 HYPE =101:Hyperflash mode
	 * bit8 ADDRE  = 1 : Address DDR transfer
	 * bit0 SPIDRE = 1 : DATA DDR transfer
	 */

	*((volatile uint32_t *)RPC_SMENR)	=	0xA2225408U;
	/*
	 * bit31-30 CDB[1:0]   =   10 : 4bit width command
	 * bit25-24 ADB[1:0]   =   10 : 4bit width address
	 * bit17-16 SPIDB[1:0] =   10 : 4bit width transfer data
	 * bit15    DME        =    0 : dummy cycle disable
	 * bit14    CDE        =    1 : Command enable
	 * bit12    OCDE       =    1 : Option Command enable
	 * bit11-8  ADE[3:0]   = 0100 : ADR[23:0] output (24 Bit Address)
	 * bit7-4   OPDE[3:0]  = 0000 : Option data disable
	 * bit3-0   SPIDE[3:0] = 1000 : 16bit transfer
	 */

	*((volatile uint32_t *)RPC_SMWDR0)	=	command;

	*((volatile uint32_t *)RPC_SMCR)	=	0x00000003U;
	/*
	 * bit2     SPIRE      = 0 : Data read disable
	 * bit1     SPIWE      = 1 : Data write enable
	 * bit0     SPIE       = 1 : SPI transfer start
	 */

	ret = common_wait(common_wait_spi_transfer, &status,
					HF_WRITE_TIMEOUT, HF_WRITE_WAIT);
	return ret;
}

static void hyper_flash_set_disable_write_protect(void)
{
	uint32_t dataL;

	dataL = *((volatile uint32_t *)RPC_PHYINT);

	/*
	 * bit1:WPVAL(0:RPC_WP#=H(Protect Disable),1:RPC_WP#=L(Protect Enable))
	 */
	if ((dataL & BIT1) != 0U) {
		dataL &= ~BIT1;
		*((volatile uint32_t *)RPC_PHYINT) = dataL;
	}
}

static uint32_t hyper_flash_reset_to_read_mode(void)
{
	uint32_t ret;

	/* Reset / ASO Exit */
	ret = hyper_flash_set_command(HYPER_FL_SMADR_TOP_ADD,
							HYPER_FL_RESET_COM);
	return ret;
}

static uint32_t hyper_flash_read_register_data(uint32_t manual_set_addr,
				uint32_t *read_data, uint32_t byte_count)
{
	uint32_t status = 0U;
	uint32_t ret;

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80030263U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit1-0 PHYMEM[1:0] = 11 : HyperFlash
	 */

	*((volatile uint32_t *)RPC_CMNCR)	=	0x81FFF301U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 01 : QSPI Flash x 2 or HyperFlash
	 */

	*((volatile uint32_t *)RPC_SMCMR)	=	0x00800000U;
	/*
	 * bit23-21 CMD[7:5] = 100 : CA47-45 = 100 =>
	 *                                      Read/memory space/WrrapedBrst
	 */

	*((volatile uint32_t *)RPC_SMADR)	=	(manual_set_addr>>1U);
	/*
	 * ByteAddress(8bit) => WordAddress(16bit)
	 */

	*((volatile uint32_t *)RPC_SMOPR)	=	0x00000000U;
	/*
	 * CA15-3(Reserved) = all 0
	 */

	*((volatile uint32_t *)RPC_SMDMCR)	=	0x0000000EU;
	/*
	 *                           15 cycle dummy wait
	 */

	*((volatile uint32_t *)RPC_SMDRENR)	=	0x00005101U;
	/*
	 * bit8 ADDRE  = 1 : Address DDR transfer
	 * bit0 SPIDRE = 1 : DATA DDR transfer
	 */

	switch (byte_count) {
	/* 2byte Read */
	case FLASH_DATA_READ_BYTE_COUNT_2:
		*((volatile uint32_t *)RPC_SMENR)	= 0xA222D408U;
		/* bit3-0   SPIDE[3:0] = 1000 : 16bit transfer*/
		break;
	/* 4byte Read */
	case FLASH_DATA_READ_BYTE_COUNT_4:
		*((volatile uint32_t *)RPC_SMENR)	= 0xA222D40CU;
		/* bit3-0   SPIDE[3:0] = 1100 : 32bit transfer */
		break;
	/* 8byte Read */
	case FLASH_DATA_READ_BYTE_COUNT_8:
		*((volatile uint32_t *)RPC_SMENR)	= 0xA222D40FU;
	/*
	 * bit31-30 CDB[1:0]   =   10 : 4bit width command
	 * bit25-24 ADB[1:0]   =   10 : 4bit width address
	 * bit17-16 SPIDB[1:0] =   10 : 4bit width transfer data
	 * bit15    DME        =    1 : dummy cycle enable
	 * bit14    CDE        =    1 : Command enable
	 * bit12    OCDE       =    1 : Option Command enable
	 * bit11-8  ADE[3:0]   = 0100 : ADR[23:0]output(24Bit Address)
	 * bit7-4   OPDE[3:0]  = 0000 : Option data disable
	 * bit3-0   SPIDE[3:0] = 1111 : 64bit transfer
	 */
		break;
	default:
		EMSG("Incollect read size. byte_count=%d", byte_count);
		break;
	}

	*((volatile uint32_t *)RPC_SMCR)	=	0x00000005U;
	/*
	 * bit2     SPIRE      = 1 : Data read enable
	 * bit1     SPIWE      = 0 : Data write disable
	 * bit0     SPIE       = 1 : SPI transfer start
	 */

	ret = common_wait(common_wait_spi_transfer, &status,
					HF_READ_TIMEOUT, HF_READ_WAIT);

	if (ret == FL_DRV_OK) {
		if (byte_count == FLASH_DATA_READ_BYTE_COUNT_8) {
			read_data[1] = *((volatile uint32_t *)RPC_SMRDR0);
			/* read data[63:32] */
		}

		read_data[0] = *((volatile uint32_t *)RPC_SMRDR1);
		/* read data[31:0] */
	}

	return ret;
}



static uint32_t hyper_flash_read_device_id(uint32_t *read_device_id)
{
	uint32_t read_data[2];
	uint32_t set_addr;
	uint32_t ret;

	/* 1st command write */
	ret = hyper_flash_set_command(HYPER_FL_UNLOCK1_ADD,
							HYPER_FL_UNLOCK1_DATA);

	if (ret == FL_DRV_OK) {
		/* 2nd command write */
		ret = hyper_flash_set_command(HYPER_FL_UNLOCK2_ADD,
							HYPER_FL_UNLOCK2_DATA);
	}

	if (ret == FL_DRV_OK) {
		/* 3rd command write */
		ret = hyper_flash_set_command(HYPER_FL_UNLOCK3_ADD,
							HYPER_FL_ID_ENTRY_COM);
	}

	for (set_addr = 0U; set_addr < (FLASH_DATA_OFFSET_BYTE_8*2U);
		set_addr += FLASH_DATA_OFFSET_BYTE_8) {

		ret = hyper_flash_read_register_data(set_addr,
						read_data,
						FLASH_DATA_READ_BYTE_COUNT_8);

		if (set_addr == 0U) {
			*read_device_id =
			(((read_data[0]&0xFF000000U)>>FLASH_DATA_BIT_SHIFT_8) |
			((read_data[0]&0x00FF0000U)<<FLASH_DATA_BIT_SHIFT_8) |
			((read_data[0]&0x0000FF00U)>>FLASH_DATA_BIT_SHIFT_8) |
			((read_data[0]&0x000000FFU)<<FLASH_DATA_BIT_SHIFT_8));
		}
	}

	if (ret == FL_DRV_OK) {
		ret = hyper_flash_reset_to_read_mode();
	}

	return ret;
}

static uint32_t hyper_flash_request_write_buffer(uint32_t flash_addr,
						uint32_t write_data_addr)
{
	uint32_t status = 0U;
	uint32_t ret;

	ret = hyper_flash_write_buffer_control(flash_addr, write_data_addr);

	if (ret == FL_DRV_OK) {
		/* BIT7: Device Ready Bit (0=Busy, 1=Ready) */
		ret = common_wait(hyper_flash_read_device_status, &status,
					HF_WRITE_TIMEOUT, HF_WRITE_WAIT);
	}

	return ret;
}

static uint32_t hyper_flash_write_buffer_control(uint32_t flash_addr,
						uint32_t write_data_addr)
{
	uint32_t ret;

	/* 1st command write */
	ret = hyper_flash_set_command(HYPER_FL_UNLOCK1_ADD,
							HYPER_FL_UNLOCK1_DATA);

	if (ret == FL_DRV_OK) {
		/* 2nd command write */
		ret = hyper_flash_set_command(HYPER_FL_UNLOCK2_ADD,
							HYPER_FL_UNLOCK2_DATA);
	}

	if (ret == FL_DRV_OK) {
		/* 3rd command write */
		ret = hyper_flash_set_command(HYPER_FL_UNLOCK3_ADD,
						HYPER_FL_WORD_PROGRAM_COM);
	}

	if (ret == FL_DRV_OK) {
		/* 4th command write */
		flash_addr = (flash_addr/2U);
		ret = hyper_flash_write_buffer(flash_addr, write_data_addr);
	}

	return ret;
}

static uint32_t hyper_flash_write_buffer(uint32_t manual_set_addr,
						uint32_t write_data_addr)
{
	uintptr_t offset;
	uint32_t ret;
	uint32_t status = 0U;

	*((volatile uint32_t *)RPC_DRCR)	=	0x01FF0301U;
	/*
	 * bit9   RCF         =  1 : Read Cache Clear
	 */

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80030277U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit2   WBUF        =  1 : Write Buffer Enable
	 * bit1-0 PHYMEM[1:0] = 11 : HyperFlash
	 */

	for (offset = 0U; offset < WRITE_BUFF_SIZE;
						offset = offset + WORD_SIZE) {
		(*(volatile uint32_t *)(0xEE208000U+offset)) =
			(*(volatile uint32_t *)(write_data_addr+offset));
	}

	*((volatile uint32_t *)RPC_CMNCR)	=	0x81FFF301U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 01 : QSPI Flash x 2 or HyperFlash
	 */

	*((volatile uint32_t *)RPC_SMCMR)	=	0x00000000U;
	/*
	 * bit23-21 CMD[7:5] = 000 : CA47-45 = 000 =>
	 *                                      Write/memory space/WrrapedBrst
	 */

	*((volatile uint32_t *)RPC_SMADR)	=	manual_set_addr;
	*((volatile uint32_t *)RPC_SMOPR)	=	0x00000000U;
	/*
	 * CA15-3(Reserved) = all 0
	 */

	*((volatile uint32_t *)RPC_SMDRENR)	=	0x00005101U;
	/*
	 * bit8 ADDRE  = 1 : Address DDR transfer
	 * bit0 SPIDRE = 1 : DATA DDR transfer
	 */

	*((volatile uint32_t *)RPC_SMENR)	=	0xA222540FU;
	/*
	 * bit31-30 CDB[1:0]   =   10 : 4bit width command
	 * bit25-24 ADB[1:0]   =   10 : 4bit width address
	 * bit17-16 SPIDB[1:0] =   10 : 4bit width transfer data
	 * bit15    DME        =    0 : dummy cycle disable
	 * bit14    CDE        =    1 : Command enable
	 * bit12    OCDE       =    1 : Option Command enable
	 * bit11-8  ADE[3:0]   = 0100 : ADR[23:0] output (24 Bit Address)
	 * bit7-4   OPDE[3:0]  = 0000 : Option data disable
	 * bit3-0   SPIDE[3:0] = 1111 : 64bit transfer
	 */

	*((volatile uint32_t *)RPC_SMCR)	=	0x00000003U;
	/*
	 * bit2     SPIRE      = 0 : Data read disable
	 * bit1     SPIWE      = 1 : Data write enable
	 * bit0     SPIE       = 1 : SPI transfer start
	 */

	ret = common_wait(common_wait_spi_transfer, &status,
					HF_WRITE_TIMEOUT, HF_WRITE_WAIT);

	if (ret == FL_DRV_OK) {
		*((volatile uint32_t *)RPC_PHYCNT)	=	0x00030273U;
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

uint32_t hyper_flash_read_device_status(uint32_t *read_status)
{
	uint32_t read_data[2];
	uint32_t ret;

	/* 1st command write */
	ret = hyper_flash_set_command(HYPER_FL_UNLOCK1_ADD,
							HYPER_FL_RD_STATUS_COM);

	if (ret == FL_DRV_OK) {
		/* Status Register read */
		ret = hyper_flash_read_register_data(HYPER_FL_SMADR_TOP_ADD,
				read_data, FLASH_DATA_READ_BYTE_COUNT_8);
		if (ret == FL_DRV_OK) {
			*read_status =
			(((read_data[0] & 0xFF000000U)>>FLASH_DATA_BIT_SHIFT_8))
		       | ((read_data[0] & 0x00FF0000U)<<FLASH_DATA_BIT_SHIFT_8)
		       | ((read_data[0] & 0x0000FF00U)>>FLASH_DATA_BIT_SHIFT_8)
		       | ((read_data[0] & 0x000000FFU)<<FLASH_DATA_BIT_SHIFT_8);

			*read_status = (*read_status & 0x0000FFFFU);

			if ((*read_status & BIT7) != 0U) {
				ret = FL_DEVICE_READY;
			} else {
				ret = FL_DEVICE_BUSY;
			}
		} else {
			ret = FL_DEVICE_ERR;
		}
	} else {
		ret = FL_DEVICE_ERR;
	}

	return ret;
}
