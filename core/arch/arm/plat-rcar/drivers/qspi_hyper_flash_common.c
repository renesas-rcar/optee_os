// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2021, Renesas Electronics Corporation
 */

#include <io.h>
#include <kernel/tee_time.h>
#include <kernel/delay.h>
#include <kernel/thread.h>
#include <tee/tee_svc.h>
#include <drivers/qspi_hyper_flash.h>
#include <trace.h>
#include "qspi_hyper_flash_common.h"
#include "qspi_flash_common.h"
#include "hyper_flash_control.h"
#include "rcar_common.h"

uint32_t common_wait_spi_transfer(uint32_t *dataL)
{
	uint32_t ret = FL_DEVICE_BUSY;

	/* Wait for TEND = 1 */
	*dataL = io_read32((vaddr_t)RPC_CMNSR);
	if ((*dataL & BIT0) != 0U) {
		ret = FL_DEVICE_READY;
	}

	return ret;
}

uint32_t common_wait(uint32_t (*read_status)(uint32_t *), uint32_t *data,
						uint32_t timeout, uint32_t wait)
{
	uint32_t ret = FL_DRV_OK;
	TEE_Result res;
	TEE_Time base;
	uint32_t result;
	const uint32_t delay = 1U;

	res = tee_time_get_sys_time(&base);
	if (res != TEE_SUCCESS) {
		ret = FL_DRV_ERR_GET_SYS_TIME;
		EMSG("get_sys_time:base res=%x", res);
	} else {
		while (ret == FL_DRV_OK) {

			result = read_status(data);
			if (result != FL_DEVICE_BUSY) {
				break;
			}

			res = thread_hw_wait_cmd(&base, timeout, wait, delay);
			if (res != TEE_SUCCESS) {
				switch(res) {
				case TEE_ERROR_OVERFLOW:
					ret = FL_DRV_ERR_TIMEOUT;
					break;
				case TEE_ERROR_OUT_OF_MEMORY:
					ret = FL_DRV_ERR_OUT_OF_MEMORY;
					break;
				default:
					ret = FL_DRV_ERR_GET_SYS_TIME;
					break;
				}
				EMSG("thread_hw_wait_cmd() error res=%x ret=%d"
					, res, ret);
			}
		}
		if (result == FL_DEVICE_ERR) {
			ret = FL_DRV_ERR_STATUS_INCORRECT;
		}
	}

	return ret;
}

uint32_t set_rpc_clock_mode(uint32_t mode)
{
	uint32_t ret = FL_DRV_OK;
	uint32_t dataL;
	uint32_t reg;
	int32_t i;
	const int32_t polling_max = 100;
	const uint32_t wait_time_us = 10;
	uint32_t prr_product = product_type & PRR_PRODUCT_MASK;

	switch (prr_product) {
	case PRR_PRODUCT_H3:
	case PRR_PRODUCT_M3:
	case PRR_PRODUCT_M3N:
		if (mode == RPC_CLK_40M) {
			dataL = 0x00000017U;	/* RPC clock 40MHz */
		} else if (mode == RPC_CLK_80M) {
			dataL = 0x00000013U;	/* RPC clock 80MHz */
		} else if (mode == RPC_CLK_160M) {
			dataL = 0x00000011U;	/* RPC clock 160MHz */
		} else {
			ret = FL_DRV_ERR_STATUS_INCORRECT;
			EMSG("Invalid argument. mode=%d", mode);
		}
		break;
	case PRR_PRODUCT_E3:
	case PRR_PRODUCT_D3:
		if (mode == RPC_CLK_40M) {
			dataL = 0x00000003U;	/* RPC clock 40MHz */
		} else if (mode == RPC_CLK_80M) {
			dataL = 0x00000001U;	/* RPC clock 80MHz */
		} else if (mode == RPC_CLK_150M) {
			dataL = 0x00000011U;	/* RPC clock 150MHz */
		} else {
			ret = FL_DRV_ERR_STATUS_INCORRECT;
			EMSG("Invalid argument. mode=%d", mode);
		}
		break;
	default:
		ret = FL_DRV_ERR_UNSUPPORT_DEV;
		EMSG("Unsupported product. PRR_PRODUCT=0x%x", prr_product);
		break;
	}

	/*
	 bit[9]=1'b0: RPCD2 clock supply
	 bit[8]=1'b0: RPC clock supply
	 In the case other than E3 or D3,
	 bit[4:0]=1'b10001: RPC clock=320MHz, RPCD2 clock=160MHz (160MHz)
	 bit[4:0]=1'b10011: RPC clock=160MHz, RPCD2 clock= 80MHz ( 80MHz)
	 bit[4:0]=1'b10111: RPC clock= 80MHz, RPCD2 clock= 40MHz ( 40MHz)
	 In the case than E3 or D3,
	 bit[4:0]=1'b10001: RPC clock=300MHz, RPCD2 clock=150MHz (150MHz)
	 bit[4:0]=1'b00001: RPC clock=160MHz, RPCD2 clock= 80MHz ( 80MHz)
	 bit[4:0]=1'b00011: RPC clock= 80MHz, RPCD2 clock= 40MHz ( 40MHz)
	 */
	if (ret == FL_DRV_OK) {
		io_write32((vaddr_t)CPG_CPGWPR, 
				(io_read32((vaddr_t)CPG_CPGWPR) &
				(~CPG_CPGWPR_WPRTCT_MASK)) | (~dataL));
		io_write32((vaddr_t)CPG_RPCCKCR, 
				(io_read32((vaddr_t)CPG_RPCCKCR) & 
				(~CPG_RPCCKCR_MASK_BIT)) | dataL);

		ret = FL_DRV_ERR_TIMEOUT;
		for (i = 0; i < polling_max; i++) {
			reg = io_read32((vaddr_t)CPG_RPCCKCR);
			if ((reg & CPG_RPCCKCR_MASK_BIT) == dataL) {
				ret = FL_DRV_OK;
				break;
			}
			udelay(wait_time_us);
		}
	}

	return ret;
}
