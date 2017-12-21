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

#include <kernel/tee_time.h>
#include <kernel/delay.h>
#include <tee/tee_svc.h>
#include <drivers/qspi_hyper_flash.h>
#include <trace.h>
#include "qspi_hyper_flash_common.h"
#include "qspi_flash_common.h"
#include "hyper_flash_control.h"

uint32_t common_wait_spi_transfer(uint32_t *dataL)
{
	uint32_t ret = FL_DEVICE_BUSY;

	/* Wait for TEND = 1 */
	*dataL = *((volatile uint32_t *)RPC_CMNSR);
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
	uint32_t mytime;
	TEE_Time base;
	TEE_Time current;
	uint32_t result;

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

			res = tee_time_get_sys_time(&current);
			if (res != TEE_SUCCESS) {
				ret = FL_DRV_ERR_GET_SYS_TIME;
				EMSG("get_sys_time:current res=%x", res);
			} else {
				mytime = ((current.seconds - base.seconds)
				     * 1000U) + (current.millis - base.millis);
				if (mytime >= timeout) {
					ret = FL_DRV_ERR_TIMEOUT;
					EMSG("Time out of device status Ready");
					break;
				}
				/*
				 * continues for one ms.
				 * over one ms is syscall_wait running.
				 */
				if (mytime > 1U) {
					res = syscall_wait(wait);
					if (res != TEE_SUCCESS) {
						ret = FL_DRV_ERR_SYSCALL_WAIT;
						EMSG("syscall_wait res=%x",
									res);
					}
				}
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

	if (mode == RPC_CLK_40M) {
		dataL = 0x00000017U;	/* RPC clock 40MHz */
	} else if (mode == RPC_CLK_80M) {
		dataL = 0x00000013U;	/* RPC clock 80MHz */
	} else if (mode == RPC_CLK_160M) {
		dataL = 0x00000011U;	/* RPC clock 160MHz */
	} else {
		ret = FL_DRV_ERR_STATUS_INCORRECT;
		EMSG("%s: Invalid argument. mode=%d", __func__, mode);
	}
	/*
	 bit[9]=1'b0: RPCD2 clock supply
	 bit[8]=1'b0: RPC clock supply
	 bit[4:0]=1'b10001: RPC clock=320MHz, RPCD2 clock=160MHz (160MHz)
	 bit[4:0]=1'b10011: RPC clock=160MHz, RPCD2 clock= 80MHz ( 80MHz)
	 bit[4:0]=1'b10111: RPC clock= 80MHz, RPCD2 clock= 40MHz ( 40MHz)
	 */
	if (ret == FL_DRV_OK) {
		*((volatile uint32_t*)CPG_CPGWPR)	= ~dataL;
		*((volatile uint32_t*)CPG_RPCCKCR)	=  dataL;

		ret = FL_DRV_ERR_TIMEOUT;
		for (i = 0; i < polling_max; i++) {
			reg = *((volatile uint32_t*)CPG_RPCCKCR);
			if (reg == dataL) {
				ret = FL_DRV_OK;
				break;
			}
			udelay(wait_time_us);
		}
	}

	return ret;
}
