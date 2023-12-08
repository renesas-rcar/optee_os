// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2021, Renesas Electronics Corporation
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
/* M3 1.0/1.05 */
#define ADDR_ROM_SECURE_API_M3		(0xeb103efcU)
#define ADDR_ROM_GETLCS_API_M3		(0xeb10415cU)
/* API table */
#define ADDR_ROM_SECURE_API_TABLE	(0xeb100100U)
#define ADDR_ROM_GETLCS_API_TABLE	(0xeb10010cU)
#else /* ARM64 */
/* H3 1.0/1.1 */
#define ADDR_ROM_SECURE_API_H3_1_X	(0xeb10dd64U)
#define ADDR_ROM_GETLCS_API_H3_1_X	(0xeb10dfe0U)
/* H3 2.0 */
#define ADDR_ROM_SECURE_API_H3_2_0	(0xeb116ed4U)
#define ADDR_ROM_GETLCS_API_H3_2_0	(0xeb117150U)
/* M3 1.0/1.05 */
#define ADDR_ROM_SECURE_API_M3		(0xeb1102fcU)
#define ADDR_ROM_GETLCS_API_M3		(0xeb110578U)
/* API table */
#define ADDR_ROM_SECURE_API_TABLE	(0xeb100180U)
#define ADDR_ROM_GETLCS_API_TABLE	(0xeb10018cU)
#endif

/* default value : R-Car H3 1.0/1.1 */
uint32_t product_type = PRR_PRODUCT_H3;
const int8_t *product_name = (const int8_t *)"H3 1.x";
ROM_SECURE_API ROM_SecureBootAPI = (ROM_SECURE_API)ADDR_ROM_SECURE_API_H3_1_X;
ROM_GETLCS_API ROM_GetLcs = (ROM_GETLCS_API)ADDR_ROM_GETLCS_API_H3_1_X;
uint32_t prr_cut = 0U;

static TEE_Result product_setup(void);

static TEE_Result product_setup(void)
{
	uint32_t reg;
	uint32_t type;
	uint32_t cut_ver;
	uint32_t dummy5;
	int32_t new_api_table = 0;

	reg = io_read32(PRR);
	type = reg & PRR_PRODUCT_MASK;
	cut_ver = reg & PRR_CUT_MASK;

	switch (type) {
	case PRR_PRODUCT_H3:
		if (cut_ver == PRR_CUT_20) {
			product_name = (const int8_t *)"H3 2.0";
			ROM_SecureBootAPI =
				(ROM_SECURE_API)ADDR_ROM_SECURE_API_H3_2_0;
			ROM_GetLcs =
				(ROM_GETLCS_API)ADDR_ROM_GETLCS_API_H3_2_0;
		} else if ((cut_ver == PRR_CUT_10) || (cut_ver == PRR_CUT_11)) {
			/* No Operation */
		} else {
			new_api_table = 1;	/* Later than H3 2.0 */
		}
		break;
	case PRR_PRODUCT_M3:
		if (cut_ver == PRR_CUT_10) {
			dummy5 = io_read32(FUSE_DUMMY5) & FUSE_M3_MASK;
			if ((dummy5 == M3_100) || (dummy5 == M3_105)) {
				product_type = PRR_PRODUCT_M3;
				product_name = (const int8_t *)"M3 1.0/1.05";
				ROM_SecureBootAPI =
					(ROM_SECURE_API)ADDR_ROM_SECURE_API_M3;
				ROM_GetLcs =
					(ROM_GETLCS_API)ADDR_ROM_GETLCS_API_M3;
			} else {
				new_api_table = 1;	/* M3 1.06 */
			}
		} else {
			new_api_table = 1;	/* M3 1.1 or later */
		}
		break;
	default:
		new_api_table = 1;	/* assume that M3N, E3 and D3 */
		break;
	}

	if (new_api_table == 1) {
		product_type = type | PRR_PRODUCT_API_TABLE;
		product_name = (const int8_t *)"API table";
		ROM_SecureBootAPI = (ROM_SECURE_API)ADDR_ROM_SECURE_API_TABLE;
		ROM_GetLcs = (ROM_GETLCS_API)ADDR_ROM_GETLCS_API_TABLE;
	}

	prr_cut = cut_ver;

	return TEE_SUCCESS;
}

service_init(product_setup);

uint32_t switch_stack_pointer(void *func, uint8_t *data)
{
	return asm_switch_stack_pointer((uintptr_t)func,
		(vaddr_t)phys_to_virt(NONCACHE_STACK_AREA, MEM_AREA_RAM_SEC),
		 data);
}

