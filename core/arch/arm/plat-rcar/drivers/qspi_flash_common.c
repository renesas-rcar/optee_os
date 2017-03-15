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
#include <trace.h>
#include <drivers/qspi_hyper_flash.h>

#include "qspi_hyper_flash_common.h"
#include "qspi_flash_common.h"
#include "qspi_onboard_control.h"

static uint32_t qspi_common_read_device_id(uint32_t *read_device_id);
static uint32_t qspi_common_erase_sector(uint32_t manual_set_addr);

uint32_t qspi_common_init(struct flash_control_operations *ops)
{
/*
 * S25FS128S and S25FL512S are common logic
 */
	uint32_t read_device_id = DEVICE_UNKNOWN;
	uint32_t ret;

	/* read qspi flash device id */
	ret = qspi_common_read_device_id(&read_device_id);
	if (ret == FL_DRV_OK) {
		/* update the device id */
		switch (read_device_id) {
		/* QSPI_ONBOARD : S25S128S */
		case QSPI_ONBOARD:
			qspi_onboard_set_control_ops(ops);
			ret = FL_DRV_OK;
			break;
		/* Unsupport device id */
		default:
			ret = FL_DRV_ERR_UNSUPPORT_DEV;
			EMSG("Unsupport device id=%x", read_device_id);
			break;
		}
	} else {
		ret = FL_DRV_ERR_UNSUPPORT_DEV;
	}
	DMSG("device id=%x", read_device_id);

	return ret;
}

uint32_t qspi_common_erase_control(uint32_t sector_addr)
{
/*
 * Qspi:Sector Erase
 * 4SE DCh
 */
	uint32_t read_status = 0U;
	uint32_t ret;

	/* WRITE ENABLE */
	ret = qspi_common_set_command(QSPI_FL_COMMAND_WRITE_ENABLE);
	
	if (ret == FL_DRV_OK) {
		ret = qspi_common_erase_sector(sector_addr);
	}

	if (ret == FL_DRV_OK) {
		ret = common_wait(qspi_common_read_device_status, &read_status,
					QSPI_ERASE_TIMEOUT, QSPI_ERASE_WAIT);
	}

	return ret;
}

static uint32_t qspi_common_erase_sector(uint32_t manual_set_addr)
{
/*
 * 4SE DCh 4-byte address
 * S25FS128S and S25FL512S are common logic
 */
	uint32_t ret;
	uint32_t status = 0U;

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80030260U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit1-0 PHYMEM[1:0] = 00 : QSPI-SDR
	 */

	*((volatile uint32_t *)RPC_CMNCR)	=	0x81FFF300U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 00 : QSPI Flash x 1
	 */

	*((volatile uint32_t *)RPC_SMCMR)	=	0x00DC0000U;
	/*
	 * bit23-16 CMD[7:0] = 0xDC : Sector Erase 4-byte address command
	 */

	*((volatile uint32_t *)RPC_SMADR)	=	manual_set_addr;
	*((volatile uint32_t *)RPC_SMDRENR)	=	0x00000000U;
	/*
	 * bit8 ADDRE  = 0 : Address SDR transfer
	 * bit0 SPIDRE = 0 : DATA SDR transfer
	 */

	*((volatile uint32_t *)RPC_SMENR)	=	0x00004F00U;
	/*
	 * bit31-30 CDB[1:0]   =   00 : 1bit width command (QSPI0_MOSI)
	 * bit25-24 ADB[1:0]   =   00 : 1bit width address (QSPI0_MOSI)
	 * bit17-16 SPIDB[1:0] =   00 : 1bit width transfer data (QSPI0_MISO)
	 * bit15    DME        =    0 : No dummy cycle
	 * bit14    CDE        =    1 : Command enable
	 * bit11-8  ADE[3:0]   = 1111 : ADR[31:0] output (32 Bit Address)
	 * bit3-0   SPIDE[3:0] = 0000 : No transfer
	 */

	*((volatile uint32_t *)RPC_SMCR)	=	0x00000001U;
	/*
	 * bit2     SPIRE      = 0 : Data read disable
	 * bit1     SPIWE      = 0 : Data write disable
	 * bit0     SPIE       = 1 : SPI transfer start
	 */

	ret = common_wait(common_wait_spi_transfer, &status,
					QSPI_READ_TIMEOUT, QSPI_READ_WAIT);

	return ret;
}

static uint32_t qspi_common_read_device_id(uint32_t *read_device_id)
{
/*
 * S25FS128S and S25FL512S are common logic
 */
	uint32_t ret;
	uint32_t status = 0U;

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80030260U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit1-0 PHYMEM[1:0] = 00 : QSPI-SDR
	 */

	*((volatile uint32_t *)RPC_CMNCR)	=	0x81FFF300U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 00 : QSPI Flash x 1
	 */

	*((volatile uint32_t *)RPC_SMCMR)	=	0x009F0000U;
	/*
	 * bit23-16 CMD[7:0] = 0x9F : Read ID command(for Palladium QSPI model)
	 */

	*((volatile uint32_t *)RPC_SMDRENR)	=	0x00000000U;
	/*
	 * bit8 ADDRE  = 0 : Address SDR transfer
	 * bit0 SPIDRE = 0 : DATA SDR transfer
	 */

	*((volatile uint32_t *)RPC_SMENR)	=	0x0000400FU;
	/*
	 * bit31-30 CDB[1:0]   =   00 : 1bit width command (QSPI0_MOSI)
	 * bit25-24 ADB[1:0]   =   00 : 1bit width address (QSPI0_MOSI)
	 * bit17-16 SPIDB[1:0] =   00 : 1bit width transfer data (QSPI0_MISO)
	 * bit15    DME        =    0 : No dummy cycle
	 * bit14    CDE        =    1 : Command enable
	 * bit11-8  ADE[3:0]   = 0000 : Address output disable
	 * bit3-0   SPIDE[3:0] = 1111 : 32bit transfer
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
		/* read data[31:0] */
		*read_device_id = *((volatile uint32_t *)RPC_SMRDR0);

		/* mask : device id 03h */
		*read_device_id = *read_device_id & 0x00FFFFFFU;
	}

	return ret;
}

uint32_t qspi_common_read_device_status(uint32_t *read_status)
{
/*
 * S25FS128S and S25FL512S are common logic
 */
	uint32_t ret;
	uint32_t status = 0U;

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80030260U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit1-0 PHYMEM[1:0] = 00 : QSPI-SDR
	 */

	*((volatile uint32_t *)RPC_CMNCR)	=	0x81FFF300U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 00 : QSPI Flash x 1
	 */

	*((volatile uint32_t *)RPC_SMCMR)	=	0x00050000U;
	/*
	 * bit23-16 CMD[7:0] = 0x05 : StatusReadCommand(for PalladiumQSPImodel)
	 */

	*((volatile uint32_t *)RPC_SMDRENR)	=	0x00000000U;
	/*
	 * bit8 ADDRE  = 0 : Address SDR transfer
	 * bit0 SPIDRE = 0 : DATA SDR transfer
	 */

	*((volatile uint32_t *)RPC_SMENR)	=	0x0000400FU;
	/*
	 * bit31-30 CDB[1:0]   =   00 : 1bit width command (QSPI0_MOSI)
	 * bit25-24 ADB[1:0]   =   00 : 1bit width address (QSPI0_MOSI)
	 * bit17-16 SPIDB[1:0] =   00 : 1bit width transfer data (QSPI0_MISO)
	 * bit15    DME        =    0 : No dummy cycle
	 * bit14    CDE        =    1 : Command enable
	 * bit11-8  ADE[3:0]   = 0000 : Address output disable
	 * bit3-0   SPIDE[3:0] = 1111 : 32bit transfer
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
		/* read data[31:0] */
		*read_status = *((volatile uint32_t *)RPC_SMRDR0);

		if ((*read_status & BIT0) == 0U) {
			ret = FL_DEVICE_READY;
		} else {
			ret = FL_DEVICE_BUSY;
		}

		if ((*read_status & BIT5) != 0U) {
			ret = FL_DEVICE_ERR;
		}
	} else {
		ret = FL_DEVICE_ERR;
	}

	return ret;
}

uint32_t qspi_common_set_command(uint32_t command)
{
/*
 * S25FS128S and S25FL512S are common logic
 */
	uint32_t ret;
	uint32_t status = 0U;

	*((volatile uint32_t *)RPC_PHYCNT)	=	0x80030260U;
	/*
	 * bit31  CAL         =  1 : PHY calibration
	 * bit1-0 PHYMEM[1:0] = 00 : QSPI-SDR
	 */

	*((volatile uint32_t *)RPC_CMNCR)	=	0x81FFF300U;
	/*
	 * bit31  MD       =  1 : Manual mode
	 * bit1-0 BSZ[1:0] = 00 : QSPI Flash x 1
	 */

	*((volatile uint32_t *)RPC_SMCMR)	=	command;
	/*
	 * bit23-16 CMD[7:0] : command
	 */

	*((volatile uint32_t *)RPC_SMDRENR)	=	0x00000000U;
	/*
	 * bit8 ADDRE  = 0 : Address SDR transfer
	 * bit0 SPIDRE = 0 : DATA SDR transfer
	 */

	*((volatile uint32_t *)RPC_SMENR)	=	0x00004000U;
	/*
	 * bit31-30 CDB[1:0]   =   00 : 1bit width command (QSPI0_MOSI)
	 * bit25-24 ADB[1:0]   =   00 : 1bit width address (QSPI0_MOSI)
	 * bit17-16 SPIDB[1:0] =   00 : 1bit width transfer data (QSPI0_MISO)
	 * bit15    DME        =    0 : No dummy cycle
	 * bit14    CDE        =    1 : Command enable
	 * bit11-8  ADE[3:0]   = 0000 : Address output disable
	 * bit3-0   SPIDE[3:0] = 0000 : No transfer
	 */

	*((volatile uint32_t *)RPC_SMCR)	=	0x00000001U;
	/*
	 * bit2     SPIRE      = 0 : Data read disable
	 * bit1     SPIWE      = 0 : Data write disable
	 * bit0     SPIE       = 1 : SPI transfer start
	 */

	ret = common_wait(common_wait_spi_transfer, &status,
					QSPI_WRITE_TIMEOUT, QSPI_WRITE_WAIT);

	return ret;
}
