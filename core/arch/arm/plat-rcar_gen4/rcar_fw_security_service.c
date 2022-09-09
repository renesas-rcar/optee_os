// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Renesas Electronics Corporation
 */

#include "r_icumif_api.h"
#include "r_icumif_pub.h"
#include "shared.h"
#include "rcar_fw_security_service.h"
#include "rcar_ta_auth.h"
#include "platform_config.h"
#include "rcar_common.h"
#include <io.h>
#include <trace.h>
#include <kernel/delay.h>

static void *g_ISD_BUFFER __nex_data = NULL;
static void *g_LCS_BUFFER __nex_data = NULL;
static void *g_CMAC_BUFFER __nex_data = NULL;
static void *g_HASH_BUFFER __nex_data = NULL;

static uint32_t fw_service_request(r_icumif_isd_t *p_ISD);

uint32_t fwss_service_init(void)
{
	int32_t res;
	volatile uint32_t *fw_status;
	uint32_t ret = FW_SERVICE_SUCCESS;

	if (g_ISD_BUFFER == NULL) {
		g_ISD_BUFFER = (void *)ICUM_FW_SHARED_AREA_ADDR;
		g_LCS_BUFFER = (void *)(ICUM_FW_SHARED_AREA_ADDR +
						BUF_OFS_LCS);
		g_CMAC_BUFFER = (void *)(ICUM_FW_SHARED_AREA_ADDR +
							BUF_OFS_CMAC);
		g_HASH_BUFFER = (void *)(ICUM_FW_SHARED_AREA_ADDR +
							BUF_OFS_HASH);
	}

	fw_status = (volatile uint32_t *)R_ICUMIF_GetStatus();

	do {
		if((*fw_status & ICUMIF_STATUS) != 0UL) {
			break;
		} else {
			udelay(100U);
		}
	} while (true);

	res = R_ICUMIF_Init((uint32_t *)((uintptr_t)ICU_FW_SHMEM_BASE));
	if (res != R_ICUMIF_ER_OK) {
		EMSG("R_ICUMIF_Init res = 0x%x", res);
		ret = FW_SERVICE_FAILURE;
	}

	return ret;
}

uint32_t fwss_secureboot_get_lcs(uint32_t *lcs_out)
{
	uint32_t *p_lcs;
	r_icumif_isd_t *p_ISD;
	uint32_t ret;

	/* Initialize the global buffer */
	(void)memset(g_ISD_BUFFER, 0, SIZE_OF_ISD_BUFFER);
	(void)memset(g_LCS_BUFFER, 0, SIZE_OF_LCS_BUFFER);

	/* Set parameter */
	p_ISD = (r_icumif_isd_t *)g_ISD_BUFFER;
	p_lcs = (uint32_t *)g_LCS_BUFFER;

	p_ISD->service_id = SERVICE_00_SECURE_BOOT_API;
	p_ISD->ptr.p_callbackfunc = NULL;
	p_ISD->job_id = 0U;
	p_ISD->res_nointerrupt = R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.SECURE_BOOT_API.boot_api_id = ROM_GET_LCS;
	p_ISD->prm.SECURE_BOOT_API.api.get_lcs.ptr.p_lcs = p_lcs;
	p_ISD->prm.SECURE_BOOT_API.api.get_lcs.lcs_size_in_bytes
						= SIZE_OF_LCS_BUFFER;

	/* Run ICU FW Security services */
	ret = fw_service_request(p_ISD);

	if (ret == FW_SERVICE_SUCCESS) {
		if (p_ISD->prm.SECURE_BOOT_API.api_return_value ==
			BOOTROMAPI_OK) {
			*lcs_out = *p_lcs;
		} else {
			EMSG("SECURE_BOOT_API return_value = 0x%x",
			p_ISD->prm.SECURE_BOOT_API.api_return_value);
			ret = FW_SERVICE_FAILURE;
		}
	} else {
		EMSG("ret = 0x%x", ret);
	}

	return ret;
}

uint32_t fwss_secureboot_verify(uint8_t *key_cert, uint8_t *cnt_cert,
							uint32_t *cmac)
{
	uint32_t *p_cmac_buf;
	r_icumif_isd_t *p_ISD;
	uint32_t i;
	volatile uintptr_t p_cnt_cert;
	volatile uintptr_t p_key_cert;
	uint32_t ret;

	/* Initialize the global buffer */
	(void)memset(g_ISD_BUFFER, 0, SIZE_OF_ISD_BUFFER);
	(void)memset(g_CMAC_BUFFER, 0, SIZE_OF_CMAC_BUFFER);

	/* Set parameter */
	p_ISD = (r_icumif_isd_t *)g_ISD_BUFFER;
	p_cmac_buf = (uint32_t *)g_CMAC_BUFFER;

	p_ISD->service_id = SERVICE_00_SECURE_BOOT_API;
	p_ISD->ptr.p_callbackfunc = NULL;
	p_ISD->job_id = 0U;
	p_ISD->res_nointerrupt = R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.SECURE_BOOT_API.boot_api_id = ROM_SECURE_BOOT_VERIFY;

	p_key_cert = (uintptr_t)key_cert;
	p_cnt_cert = (uintptr_t)cnt_cert;

	p_ISD->prm.SECURE_BOOT_API.api.boot_verify.ptr1.p_key_cert =
						(uint32_t*)p_key_cert;
	p_ISD->prm.SECURE_BOOT_API.api.boot_verify.ptr2.p_content_cert =
						(uint32_t*)p_cnt_cert;
	p_ISD->prm.SECURE_BOOT_API.api.boot_verify.ptr3.p_cmac = p_cmac_buf;

	/* Run ICU FW Security services */
	ret = fw_service_request(p_ISD);
	if ((ret == FW_SERVICE_SUCCESS) &&
	    (p_ISD->prm.SECURE_BOOT_API.api_return_value == BOOTROMAPI_OK)) {
		for (i = 0U; i < CMAC_COPY; i++) {
			cmac[i] = *p_cmac_buf;
			p_cmac_buf++;
		}
	} else if (ret != FW_SERVICE_SUCCESS){
		EMSG("ret = 0x%x", ret);
		p_ISD->prm.SECURE_BOOT_API.api_return_value =
						FW_SERVICE_FAILURE;
	} else {
		EMSG("SECURE_BOOT_API return_value = 0x%x",
			p_ISD->prm.SECURE_BOOT_API.api_return_value);
	}

	return p_ISD->prm.SECURE_BOOT_API.api_return_value;
}

uint32_t fwss_secureboot_dec_and_comp(uint8_t *cnt_cert, uint32_t *cmac)
{
	uint32_t *p_cmac_buf;
	uint32_t *p_hash_buf;
	r_icumif_isd_t *p_ISD;
	uint32_t i;
	uint32_t ret;
	volatile uintptr_t p_cnt_cert;

	/* Initialize the global buffer */
	(void)memset(g_ISD_BUFFER, 0, SIZE_OF_ISD_BUFFER);
	(void)memset(g_CMAC_BUFFER, 0, SIZE_OF_CMAC_BUFFER);
	(void)memset(g_HASH_BUFFER, 0, SIZE_OF_HASH_BUFFER);

	p_ISD = (r_icumif_isd_t *)g_ISD_BUFFER;
	p_cmac_buf = (uint32_t *)g_CMAC_BUFFER;
	p_hash_buf = (uint32_t *)g_HASH_BUFFER;

	for (i = 0U; i < CMAC_COPY; i++) {
		*p_cmac_buf = cmac[i];
		p_cmac_buf++;
	}

	/* Set parameter */
	p_ISD->service_id = SERVICE_00_SECURE_BOOT_API;
	p_ISD->ptr.p_callbackfunc = NULL;
	p_ISD->job_id = 0U;
	p_ISD->res_nointerrupt = R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.SECURE_BOOT_API.boot_api_id = ROM_SECURE_BOOT_DECRYPT;

	p_cnt_cert = (uintptr_t)cnt_cert;

	p_ISD->prm.SECURE_BOOT_API.api.
		boot_decrypt.ptr1.p_content_cert = (uint32_t*)p_cnt_cert;
	p_ISD->prm.SECURE_BOOT_API.api.
		boot_decrypt.ptr2.p_cmac = p_cmac_buf;

	/* Run ICU FW Security services */
	ret = fw_service_request(p_ISD);
	if ((ret == FW_SERVICE_SUCCESS) ||
	    (p_ISD->prm.SECURE_BOOT_API.api_return_value == BOOTROMAPI_OK) ||
	    (p_ISD->prm.SECURE_BOOT_API.api_return_value ==
	   			ROM_ERR_IMG_VERIFIER_NO_ENCRYPT_IMG)) {
		/* Set parameter */
		p_ISD->service_id = SERVICE_00_SECURE_BOOT_API;
		p_ISD->ptr.p_callbackfunc = NULL;
		p_ISD->job_id = 0U;
		p_ISD->res_nointerrupt = R_ICUMIF_REQRES_NOINTERRPUT;
		p_ISD->prm.SECURE_BOOT_API.boot_api_id =
			ROM_SECURE_BOOT_COMPARE;
		p_ISD->prm.SECURE_BOOT_API.api.boot_compare.
			ptr1.p_content_cert = (uint32_t*)p_cnt_cert;
		p_ISD->prm.SECURE_BOOT_API.api.boot_compare.ptr2.p_hash =
			p_hash_buf;
		p_ISD->prm.SECURE_BOOT_API.api.boot_compare.
			hash_size_in_bytes = SIZE_OF_HASH_BUFFER;
		p_ISD->prm.SECURE_BOOT_API.api.boot_compare.
			ptr3.p_cmac = p_cmac_buf;

		/* Run ICU FW Security services */
		ret = fw_service_request(p_ISD);
	}

	if (ret != FW_SERVICE_SUCCESS) {
		EMSG("ret = 0x%x", ret);
		p_ISD->prm.SECURE_BOOT_API.api_return_value =
						FW_SERVICE_FAILURE;
	} else if (p_ISD->prm.SECURE_BOOT_API.api_return_value !=
						BOOTROMAPI_OK) {
		EMSG("SECURE_BOOT_API return_value = 0x%x",
			p_ISD->prm.SECURE_BOOT_API.api_return_value);
		p_ISD->prm.SECURE_BOOT_API.api_return_value =
						FW_SERVICE_FAILURE;
	} else {
		/* no operation */
	}

	return p_ISD->prm.SECURE_BOOT_API.api_return_value;
}

static uint32_t fw_service_request(r_icumif_isd_t *p_ISD)
{
	int32_t res;
	uint32_t ret = FW_SERVICE_SUCCESS;

	res = R_ICUMIF_ServiceRequest(p_ISD);
	if (res == R_ICUMIF_ER_OK) {
		do {
			res = R_ICUMIF_IsServiceCompleted(p_ISD);
			if(res != R_ICUMIF_RTN_SERV_RUNNING) {
				break;
			}
		} while (true);
	}

	if (p_ISD->service_result == SERV_OK) {
		res = R_ICUMIF_ServiceResponse();
	}

	if (res != R_ICUMIF_ER_OK) {
		EMSG("res = 0x%x", res);
		ret = FW_SERVICE_FAILURE;
	} else if (p_ISD->service_result != SERV_OK) {
		EMSG("p_ISD->service_result = 0x%x", p_ISD->service_result);
		ret = FW_SERVICE_FAILURE;
	} else {
		/* no operation */
	}

	return ret;
}
