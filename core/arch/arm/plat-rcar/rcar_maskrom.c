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

#include <string.h>
#include <io.h>
#include <tee_api_types.h>
#include <trace.h>
#include <initcall.h>
#include "platform_config.h"
#include "rcar_common.h"
#include "rcar_maskrom.h"

/* Definitions */

#ifdef ARM32
/* H3 1.0/1.1 */
#define ADDR_ROM_SECURE_API_H3_1_X	(0xeb101f54U)
#define ADDR_ROM_GETLCS_API_H3_1_X	(0xeb1021b4U)
/* H3 2.0 */
#define ADDR_ROM_SECURE_API_H3_2_0	(0xeb1041d4U)
#define ADDR_ROM_GETLCS_API_H3_2_0	(0xeb104434U)
/* M3 */
#define ADDR_ROM_SECURE_API_M3		(0xeb103efcU)
#define ADDR_ROM_GETLCS_API_M3		(0xeb10415cU)
#else /* ARM64 */
/* H3 1.0/1.1 */
#define ADDR_ROM_SECURE_API_H3_1_X	(0xeb10dd64U)
#define ADDR_ROM_GETLCS_API_H3_1_X	(0xeb10dfe0U)
/* H3 2.0 */
#define ADDR_ROM_SECURE_API_H3_2_0	(0xeb116ed4U)
#define ADDR_ROM_GETLCS_API_H3_2_0	(0xeb117150U)
/* M3 */
#define ADDR_ROM_SECURE_API_M3		(0xeb1102fcU)
#define ADDR_ROM_GETLCS_API_M3		(0xeb110578U)
#endif

/* default value : R-Car H3 1.0/1.1 */
uint32_t product_type = PRR_PRODUCT_H3;
const int8_t *product_name = (const int8_t *)"H3 1.x";
ROM_SECURE_API ROM_SecureBootAPI = (ROM_SECURE_API)ADDR_ROM_SECURE_API_H3_1_X;
ROM_GETLCS_API ROM_GetLcs = (ROM_GETLCS_API)ADDR_ROM_GETLCS_API_H3_1_X;

static TEE_Result product_setup(void);

static TEE_Result product_setup(void)
{
	uint32_t reg;
	uint32_t type;
	uint32_t cut_ver;

	reg = read32(PRR);
	type = reg & PRR_PRODUCT_MASK;
	cut_ver = reg & PRR_CUT_MASK;

	switch (type) {
	case PRR_PRODUCT_H3:
		if (cut_ver == PRR_CUT_H3_20) {
			product_name = (const int8_t *)"H3 2.0";
			ROM_SecureBootAPI =
				(ROM_SECURE_API)ADDR_ROM_SECURE_API_H3_2_0;
			ROM_GetLcs =
				(ROM_GETLCS_API)ADDR_ROM_GETLCS_API_H3_2_0;
		} else { /* H3 1.0/1.1 */
			/* No Operation */
		}
		break;
	case PRR_PRODUCT_M3:
		product_type = PRR_PRODUCT_M3;
		product_name = (const int8_t *)"M3";
		ROM_SecureBootAPI = (ROM_SECURE_API)ADDR_ROM_SECURE_API_M3;
		ROM_GetLcs = (ROM_GETLCS_API)ADDR_ROM_GETLCS_API_M3;
		break;
	default:
		EMSG("Unknown product. PRR=0x%x", reg);
		product_type = type | PRR_PRODUCT_UNKNOWN;
		product_name = (const int8_t *)"unknown";
		break;
	}

	return TEE_SUCCESS;
}

service_init(product_setup);

uint32_t get_PRR_type(void)
{
	uint32_t reg;
	uint32_t type;

	reg = read32(PRR);
	type = reg & PRR_PRODUCT_MASK;
	return type;
}

uint32_t switch_stack_pointer(void *func, uint8_t *data)
{
	return asm_switch_stack_pointer((uintptr_t)func,
			NONCACHE_STACK_AREA, data);
}

