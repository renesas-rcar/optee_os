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
#ifdef RCAR_TRNG_BY_ICUMX_HWENGINE
#include <tee_api_defines.h>
#endif

static void *g_ISD_BUFFER __nex_data = NULL;
static void *g_LCS_BUFFER __nex_data = NULL;
static void *g_CMAC_BUFFER __nex_data = NULL;
static void *g_HASH_BUFFER __nex_data = NULL;
#if defined(RCAR_TRNG_BY_ICUMX_HWENGINE) || defined(RCAR_STORAGE_KEY_BY_ICUMX_HWENGINE)
static void *g_ISD_SEC_SVC_BUFFER __nex_data = NULL;
uint8_t is_init_icum = 0;

/* Convert buffer length in bytes to number of word blocks */
inline uint32_t byte_to_block(uint32_t buf_len){
	/* A block is equal to 4 bytes */
	return (buf_len + WORD_BLOCK_SIZE - 1) / WORD_BLOCK_SIZE;
}
#endif
#if defined(RCAR_TRNG_BY_ICUMX_HWENGINE) || defined(RCAR_STORAGE_KEY_BY_ICUMX_HWENGINE)
uint32_t key_size_to_block_num(uint32_t buf_len);
uint32_t key_size_to_block_num(uint32_t buf_len) {
	/* Block number is complied with ICUMX Firmware convention*/
	return buf_len == 16 ? 2 :
		buf_len == 32 ? 3 :
		(EMSG("Please input AES key size 16 or 32 bytes!\n"),0);
}

uint8_t she_key_to_logical_index(uint8_t she_key_index)
{
	if(she_key_index >= 4 && she_key_index <= 13) {
		/* SHE_KEY_1 -> SHE_KEY_10 */
		return she_key_index - 3;
	} else if(she_key_index >= 15 && she_key_index <= 94) {
		// SHE_KEY_11 -> SHE_KEY_90 (except SHE_RAM_KEY)
		return she_key_index - 4;
	} else {
		/* Invalid value */
		return 0xFF;
	}
}
#endif
static uint32_t fw_service_request(r_icumif_isd_t *p_ISD);

uint32_t fwss_service_init(void)
{
	int32_t res;
	volatile uint32_t *fw_status;
	uint32_t ret = FW_SERVICE_SUCCESS;

	if (g_ISD_BUFFER == NULL) {
#if defined(RCAR_TRNG_BY_ICUMX_HWENGINE) || defined(RCAR_STORAGE_KEY_BY_ICUMX_HWENGINE)
		g_ISD_SEC_SVC_BUFFER = (void *)ICUM_FW_SHARED_AREA_SEC_SRV_ADDR;
#endif
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
		boot_decrypt.ptr2.p_cmac = (uint32_t *)g_CMAC_BUFFER;

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
			ptr3.p_cmac = (uint32_t *)g_CMAC_BUFFER;

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

#if defined(RCAR_TRNG_BY_ICUMX_HWENGINE) || defined(RCAR_STORAGE_KEY_BY_ICUMX_HWENGINE)
uint32_t fwss_trng_generate(void *buf, size_t buf_len)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;
	uint32_t *trng_output;

	/* Init ICUM Firmware interface */
	res = fwss_service_init();
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fwss_service_init() error");
		ret = TEE_ERROR_SECURITY;
	}

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if(ret != TEE_SUCCESS) {
		goto out;
	}

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	/* Set parameter */
	p_ISD = (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	trng_output = (uint32_t *)p_ISD + NEXT_ADDR_ALIGN4(sizeof(r_icumif_isd_t));

	p_ISD->service_id                        = SERVICE_02_RAND_TRNG;
	p_ISD->ptr.p_callbackfunc                = NULL;
	p_ISD->job_id                            = 0;
	p_ISD->prm.RAND_GENERATE.ptr.p_block_out = (uint32_t*)trng_output;
	p_ISD->prm.RAND_GENERATE.nb_blocks       = byte_to_block(buf_len);
	p_ISD->service_priority                  = R_ICUMIF_SERV_PRIORITY_NORMAL;
	p_ISD->req_nointerrupt                   = R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt                   = R_ICUMIF_REQRES_NOINTERRPUT;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}

	(void)memcpy((uint8_t*)buf, (uint8_t*)trng_output, buf_len);

out:
	return ret;
}

uint32_t fwss_sys_fw_init(void)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	/* Set parameter */
	p_ISD 					= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	p_ISD->service_id			= SERVICE_00_SYSTEM_INIT;
	p_ISD->vm_id				= 0U;
	p_ISD->req_res_status			= 0U;
	p_ISD->service_priority			= R_ICUMIF_SERV_PRIORITY_NORMAL;
	p_ISD->ptr.p_callbackfunc		= 0;
	p_ISD->job_id				= 0;
	p_ISD->req_nointerrupt			= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt			= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.SYSTEM_INIT.sys_init_id	= SYS_INIT_FW_INITIALIZATION;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
	}

	return ret;
}

uint32_t fwss_get_current_stage(uint32_t *stage)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;

	/* Check input data */
	if(!stage)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	/* Set parameter */
	p_ISD				= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	p_ISD->service_id		= SERVICE_00_GET_STAGE;
	p_ISD->ptr.p_callbackfunc	= NULL;
	p_ISD->req_nointerrupt		= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt		= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->job_id			= 0;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
	}

	/* Retrieve ICU-M current stage */
	*stage = p_ISD->prm.LIFE_CYCLE.current_stage;

	return ret;
}

uint32_t fwss_lc_set_stage(uint32_t stage)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;

	if(stage != LC_STAGE_LC1) {
		EMSG("Currently only support for switching to LC1 stage!\n");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	/* Set parameter */
	p_ISD = 				(r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	p_ISD->service_id			= SERVICE_00_STAGE_TRANSITION;
	p_ISD->ptr.p_callbackfunc		= NULL;
	p_ISD->job_id				= 0;
	p_ISD->prm.LIFE_CYCLE.current_stage	= (r_stage_type_t)0;
	p_ISD->prm.LIFE_CYCLE.cluster_id	= 0;
	p_ISD->prm.LIFE_CYCLE.cr_request	= LC_CR_NONE;
	p_ISD->prm.LIFE_CYCLE.ptr1.p_challenge	= BIG_BUFFER[0];
	p_ISD->prm.LIFE_CYCLE.ptr2.p_response	= BIG_BUFFER[1];
	p_ISD->req_nointerrupt			= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt			= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.LIFE_CYCLE.transition_dest	= stage;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
	}

out:
	return ret;
}

uint32_t check_icum_init(void)
{
	uint32_t res = FW_SERVICE_SUCCESS;
	uint32_t ret = TEE_SUCCESS;
	uint32_t stage;

	if(!is_init_icum) {
		/* Check ICU-M current stage */
		res = fwss_get_current_stage(&stage);
		if(res != FW_SERVICE_SUCCESS) {
			EMSG("fwss_get_current_stage() error");
			ret = TEE_ERROR_SECURITY;
			goto out;
		}

		if (stage == LC_STAGE_LC1) {
			is_init_icum = 1;
			goto out;
		}

		/* Init ICUM Firmware system */
		res = fwss_sys_fw_init();
		if(res != FW_SERVICE_SUCCESS) {
			EMSG("fwss_sys_fw_init() error");
			ret = TEE_ERROR_SECURITY;
			goto out;
		}

		/* Transfer to LC1 stage */
		res = fwss_lc_set_stage(LC_STAGE_LC1);
		if(res != FW_SERVICE_SUCCESS) {
			EMSG("fwss_lc_set_stage() error");
			ret = TEE_ERROR_SECURITY;
			goto out;
		}
		is_init_icum = 1;
	}

out:
	return ret;
}

uint32_t fwss_calculate_MP(void *key_buf, size_t key_len, const uint8_t* const_buf,
		size_t const_len, void* deriv_key_buf, size_t *deriv_key_len)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;
	CISD_API_TEST_t *p_prm;
	uint8_t *data1;
	uint8_t *data2;
	uint8_t *data3;

	/* Check input data */
	if(!key_buf || !key_len || !const_buf ||
		!const_len || !deriv_key_buf || !deriv_key_len) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if(ret != TEE_SUCCESS) {
		goto out;
	}

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	p_ISD		= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	data1		= (uint8_t *)p_ISD + NEXT_ADDR_ALIGN4(sizeof(r_icumif_isd_t));
	data2		= data1 + SHE_SINGLE_MESS_SIZE;
	data3		= data2 + SHE_SINGLE_MESS_SIZE;

	memcpy((uint8_t *)data1, (uint8_t *)key_buf, key_len);
	memcpy((uint8_t *)data2, (uint8_t *)const_buf, const_len);

	/* Set parameter */
	p_ISD->service_id		= (r_icumif_service_id_t)(16 * 16 + 9);
	p_ISD->ptr.p_callbackfunc	= NULL;
	p_ISD->job_id			= 0;
	p_ISD->vm_id			= 0;
	p_ISD->req_nointerrupt		= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt		= R_ICUMIF_REQRES_NOINTERRPUT;
	p_prm				= (CISD_API_TEST_t *)&(p_ISD->prm);
	p_prm->ptr1.p_data1		= (uint8_t *)data1;
	p_prm->ptr2.p_data2		= (uint8_t *)data2;
	p_prm->data01			= key_size_to_block_num(key_len);
	p_prm->ptr3.p_data3		= (uint8_t *)data3;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
	}

	*deriv_key_len = AES_KEY_LEN_128;
	memcpy((uint8_t *)deriv_key_buf, (uint8_t *)data3, *deriv_key_len);
out:
	return ret;
}

uint32_t fwss_aes_cipher(cipher_direction_t direction, cipher_modes_t mode,
	r_key_group_t group, r_key_index_t key_id, void *iv, void *input,
			uint8_t buf_len, void *output)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;
	uint32_t *aes_output;
	uint32_t *iv_share;
	uint32_t *input_share;

	/* Check input data */
	if(!iv || !input || !output || !buf_len) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if(ret != TEE_SUCCESS) {
		goto out;
	}

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	p_ISD 		= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	iv_share 	= (uint32_t *)p_ISD + NEXT_ADDR_ALIGN4(sizeof(r_icumif_isd_t));
	input_share 	= (uint32_t *)iv_share + buf_len;
	aes_output 	= (uint32_t *)input_share + buf_len;

	memcpy((uint8_t *)iv_share, (uint8_t *)iv, 32);
	memcpy((uint8_t *)input_share, (uint8_t *)input, 32);

	/* Set parameter */
	p_ISD->service_id			= SERVICE_01_AES_CIPHER;
	p_ISD->ptr.p_callbackfunc		= 0;
	p_ISD->job_id				= 0;
	p_ISD->req_nointerrupt			= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt			= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.AES_CIPHER.direction		= direction;
	p_ISD->prm.AES_CIPHER.cipher_mode	= mode;
	p_ISD->prm.AES_CIPHER.key_group		= group;
	p_ISD->prm.AES_CIPHER.key_id		= key_id;
	p_ISD->prm.AES_CIPHER.ptr1.p_iv		= (uint32_t *)iv_share;
	p_ISD->prm.AES_CIPHER.ptr2.p_block_in	= (uint32_t *)input_share;
	p_ISD->prm.AES_CIPHER.ptr3.p_block_out	= (uint32_t *)aes_output;
	p_ISD->prm.AES_CIPHER.size.nb_blocks	= byte_to_block(buf_len);
	p_ISD->prm.AES_CIPHER.job_slice		= 0;
	p_ISD->prm.AES_CIPHER.job_cycle		= JOB_ALL_AT_ONCE;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}

	(void)memcpy((uint8_t*)output, (uint8_t*)aes_output, buf_len);

out:
	return ret;
}

uint32_t fwss_plain_key_update(r_key_group_t group, uint8_t key_id, void *key_buf,
				                uint16_t key_len)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;
	uint8_t *input_key_share;

	/* Check input data */
	if(!key_buf || !key_len) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if(ret != TEE_SUCCESS) {
		goto out;
	}

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	p_ISD			= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	input_key_share		= (uint8_t *)p_ISD + NEXT_ADDR_ALIGN4(sizeof(r_icumif_isd_t));

	memcpy((uint8_t *)input_key_share, (uint8_t *)key_buf, key_len);

	/* Set parameter */
	p_ISD->service_id					= SERVICE_03_AES_KEY_UPDATE_PLAIN;
	p_ISD->ptr.p_callbackfunc				= 0;
	p_ISD->job_id						= 0;
	p_ISD->req_nointerrupt					= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt					= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.KEY_UPDATE_PLAIN.key_group			= group;
	p_ISD->prm.KEY_UPDATE_PLAIN.key_id			= key_id;
	p_ISD->prm.KEY_UPDATE_PLAIN.ptr.p_key_value		= (uint8_t *)input_key_share;
	p_ISD->prm.KEY_UPDATE_PLAIN.key_size_in_bytes		= key_len;
	p_ISD->prm.KEY_UPDATE_PLAIN.mem_cluster_verif		= 0;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.encryption		= 1;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.decryption		= 1;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.cmac_generation	= 1;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.cmac_verification	= 1;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.write_protected	= 0;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.disable_on_debug	= 0;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.no_wild_card		= 0;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
	}
out:
	return ret;
}

uint32_t fwss_aes_cmac(r_key_group_t group, r_key_index_t key_id, void *mess_buf,
		size_t mess_len, void *out_buf, size_t *out_len)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;
	uint32_t *p_mess_share;
	uint32_t *output_share;

	/* Check input data */
	if(!mess_buf || !mess_len || !out_buf || !out_len) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if(ret != TEE_SUCCESS) {
		goto out;
	}

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	p_ISD			= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	p_mess_share		= (uint32_t *)p_ISD + NEXT_ADDR_ALIGN4(sizeof(r_icumif_isd_t));
	output_share		= p_mess_share + mess_len;

	memcpy((uint8_t *)p_mess_share, (uint8_t *)mess_buf, mess_len);

	/* Set parameter */
	p_ISD->service_id			= SERVICE_01_AES_CMAC;
	p_ISD->ptr.p_callbackfunc		= 0;
	p_ISD->job_id				= 0;
	p_ISD->req_nointerrupt			= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt			= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->service_priority			= R_ICUMIF_SERV_PRIORITY_NORMAL;
	p_ISD->prm.AES_CMAC.key_group		= group;
	p_ISD->prm.AES_CMAC.key_id		= key_id;
	p_ISD->prm.AES_CMAC.cmac_operation	= CMAC_GENERATION;
	p_ISD->prm.AES_CMAC.ptr1.p_msg		= (uint32_t *)p_mess_share;
	p_ISD->prm.AES_CMAC.msg_size_in_bits	= mess_len * 8;
	p_ISD->prm.AES_CMAC.ptr2.p_cmac		= (uint32_t *)output_share;
	p_ISD->prm.AES_CMAC.cmac_size_in_bits	= 128;
	p_ISD->prm.AES_CMAC.job_slice		= 0;
	p_ISD->prm.AES_CMAC.job_cycle		= JOB_ALL_AT_ONCE;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}
	*out_len = AES_KEY_LEN_128;
	memcpy((uint8_t *)out_buf, (uint8_t *)output_share, *out_len);
out:
	return ret;
}

uint32_t fwss_she_key_update(uint8_t she_key_index, void *mess_buf, size_t mess_len)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;
	SHE_key_update_type *p_mess_share;
	uint8_t logical_index;
	uint8_t extended_key_id;

	/* Check input data */
	if(!mess_buf || !mess_len) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if(ret != TEE_SUCCESS) {
		goto out;
	}

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	p_ISD			= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	p_mess_share		= (SHE_key_update_type *)p_ISD + NEXT_ADDR_ALIGN4(sizeof(r_icumif_isd_t));

	memcpy((uint8_t *)p_mess_share, (uint8_t *)mess_buf, mess_len);

	/* Set parameter */
	p_ISD->service_id				= SERVICE_03_AES_KEY_UPDATE_SHE;
	p_ISD->ptr.p_callbackfunc			= 0;
	p_ISD->job_id					= 0;
	p_ISD->req_nointerrupt				= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt				= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.KEY_UPDATE_SHE.ptr1.p_M1		= (uint8_t *)p_mess_share->M1;
	p_ISD->prm.KEY_UPDATE_SHE.ptr2.p_M2		= (uint8_t *)p_mess_share->M2;
	p_ISD->prm.KEY_UPDATE_SHE.ptr3.p_M3		= (uint8_t *)p_mess_share->M3;
	p_ISD->prm.KEY_UPDATE_SHE.ptr4.p_M4		= (uint8_t *)p_mess_share->M4;
	p_ISD->prm.KEY_UPDATE_SHE.ptr5.p_M5		= (uint8_t *)p_mess_share->M5;
	logical_index					= she_key_to_logical_index(she_key_index);
	extended_key_id					= (logical_index - 1) / 10;
	p_ISD->prm.KEY_UPDATE_SHE.extended_key_id	= extended_key_id;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}
out:
	return ret;
}

uint32_t fwss_ext_flash_write(void)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if(ret != TEE_SUCCESS) {
		goto out;
	}

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	/* Set parameter */
	p_ISD				= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	p_ISD->service_id		= SERVICE_04_ICUMDF_WRITE;
	p_ISD->job_id			= 0;
	p_ISD->req_nointerrupt		= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt		= R_ICUMIF_REQRES_NOINTERRPUT;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}
out:
	return ret;
}

uint32_t fwss_auth_aes_cipher(cipher_direction_t direction, auth_cipher_modes_t mode,
		r_key_group_t group, r_key_index_t key_id, void *iv_buf, size_t iv_len,
		void *auth_buf, size_t auth_len, void *in_buf, size_t in_len,
		void *out_buf, void *tag_buf, size_t tag_len)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;
	uint32_t *iv_share;
	uint32_t *auth_share;
	uint32_t *input_share;
	uint32_t *output_share;
	uint32_t *tag_share;

	/* Check input data */
	if(!iv_buf || !auth_buf || !in_buf || !out_buf || !tag_buf)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if(ret != TEE_SUCCESS)
		goto out;

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	p_ISD		= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	iv_share	= (uint32_t *)p_ISD + NEXT_ADDR_ALIGN4(sizeof(r_icumif_isd_t));
	auth_share	= (uint32_t *)iv_share + iv_len;
	input_share	= (uint32_t *)auth_share + auth_len;
	output_share	= (uint32_t *)input_share + in_len;
	tag_share	= (uint32_t *)output_share + in_len;

	memcpy((uint8_t *)iv_share, (uint8_t *)iv_buf, iv_len);
	memcpy((uint8_t *)auth_share, (uint8_t *)auth_buf, auth_len);
	memcpy((uint8_t *)input_share, (uint8_t *)in_buf, in_len);

	/* Set parameter */
	p_ISD->service_id					= SERVICE_01_AES_AUTH_CIPHER;
	p_ISD->ptr.p_callbackfunc				= 0;
	p_ISD->job_id						= 0;
	p_ISD->req_nointerrupt					= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt					= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.AES_AUTH_CIPHER.direction			= direction;
	p_ISD->prm.AES_AUTH_CIPHER.cipher_mode			= mode;
	p_ISD->prm.AES_AUTH_CIPHER.key_group			= group;
	p_ISD->prm.AES_AUTH_CIPHER.key_id			= key_id;
	p_ISD->prm.AES_AUTH_CIPHER.ptr1.p_iv			= (uint32_t *)iv_share;
	p_ISD->prm.AES_AUTH_CIPHER.iv_size_in_bits		= iv_len * 8;
	p_ISD->prm.AES_AUTH_CIPHER.ptr2.p_auth_data		= (uint32_t *)auth_share;
	p_ISD->prm.AES_AUTH_CIPHER.auth_data_size_in_bits	= auth_len * 8;
	p_ISD->prm.AES_AUTH_CIPHER.ptr3.p_data_in		= (uint32_t *)input_share;
	p_ISD->prm.AES_AUTH_CIPHER.ptr4.p_data_out		= (uint32_t *)output_share;
	p_ISD->prm.AES_AUTH_CIPHER.data_size_in_bits		= in_len * 8;
	p_ISD->prm.AES_AUTH_CIPHER.ptr5.p_auth_tag		= (uint32_t *)tag_share;
	p_ISD->prm.AES_AUTH_CIPHER.auth_tag_size_in_bits	= tag_len * 8;
	p_ISD->prm.AES_AUTH_CIPHER.job_slice			= 0;
	p_ISD->prm.AES_AUTH_CIPHER.job_cycle			= JOB_ALL_AT_ONCE;
	p_ISD->prm.AES_AUTH_CIPHER.safety_mode			= 0;
	p_ISD->prm.AES_AUTH_CIPHER.ptr6.p_status_reg_auth_data	= 0;
	p_ISD->prm.AES_AUTH_CIPHER.ptr7.p_status_reg_data	= 0;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}

	(void)memcpy((uint8_t *)out_buf, (uint8_t *)output_share, in_len);
	(void)memcpy((uint8_t *)tag_buf, (uint8_t *)tag_share, tag_len);
out:
	return ret;
}

uint32_t fwss_get_id(void *uid_buf, size_t *uid_len) {
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;
	uint8_t *challenge_share;

	/* Check input data */
	if(!uid_buf || !uid_len)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if(ret != TEE_SUCCESS)
		goto out;

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	p_ISD		= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	challenge_share	= (uint8_t *)p_ISD + NEXT_ADDR_ALIGN4(sizeof(r_icumif_isd_t));

	memcpy((uint8_t *)challenge_share, (uint8_t *)CHALLENGE, 16);

	/* Set parameter */
	p_ISD->service_id			= SERVICE_00_GET_ID;
	p_ISD->ptr.p_callbackfunc		= 0;
	p_ISD->job_id				= 0;
	p_ISD->req_nointerrupt			= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt			= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.GET_ID.ptr1.p_challenge	= challenge_share;
	p_ISD->prm.GET_ID.UID[0]		= 0;
	p_ISD->prm.GET_ID.SREG			= 0;
	p_ISD->prm.GET_ID.ptr2.p_CMAC		= challenge_share + 32;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}
	*uid_len = SHE_UID_SIZE;
	memcpy((uint8_t *)uid_buf, (uint8_t *)p_ISD->prm.GET_ID.UID, *uid_len);
out:
	return ret;
}

uint32_t fwss_get_key_data(r_key_group_t group, r_key_index_t key_id,
		void *key_buf, size_t key_len)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;
	CISD_API_TEST_t *p_prm;
	r_aes_key_t *key_share;

	/* Check input data */
	if(!key_buf)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if(ret != TEE_SUCCESS)
		goto out;

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	p_ISD		= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	key_share 	= (r_aes_key_t *)p_ISD + NEXT_ADDR_ALIGN4(sizeof(r_icumif_isd_t));

	/* Set parameter */
	p_ISD->service_id		= (r_icumif_service_id_t)(16 * 16 + 5);
	p_ISD->ptr.p_callbackfunc	= 0;
	p_ISD->job_id			= 0;
	p_ISD->vm_id			= 0;
	p_ISD->req_nointerrupt		= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt		= R_ICUMIF_REQRES_NOINTERRPUT;
	p_prm			= (CISD_API_TEST_t *)&(p_ISD->prm);
	p_prm->data01		= group;
	p_prm->data02		= key_id;
	p_prm->ptr1.p_data1	= (uint8_t *)key_share;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = 2;
	}
	memcpy((uint8_t *)key_buf, (uint8_t *)key_share->key_value, key_len);
out:
	return ret;
}

uint32_t fwss_hmac_import(void *key_buf, size_t key_len, uint8_t hmac_key_id)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;
	uint8_t *key_share;

	/* Check input data */
	if(!key_buf)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if(ret != TEE_SUCCESS)
		goto out;

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	p_ISD			= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	key_share		= (uint8_t *)p_ISD + NEXT_ADDR_ALIGN4(sizeof(r_icumif_isd_t));

	memcpy((uint8_t *)key_share, (uint8_t *)key_buf, key_len);

	/* Set parameter */
	p_ISD->service_id				= SERVICE_03_HMAC_IMPORT;
	p_ISD->ptr.p_callbackfunc			= 0;
	p_ISD->job_id					= 0;
	p_ISD->req_nointerrupt				= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt				= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.HMAC_IMPORT.key_id			= hmac_key_id;
	p_ISD->prm.HMAC_IMPORT.ptr.p_key		= key_share;
	p_ISD->prm.HMAC_IMPORT.key_size_in_bytes	= key_len;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}
out:
	return ret;
}

uint32_t fwss_hmac_generation(uint8_t hmac_key_id, uint8_t hash_primitive, void *msg_buf,
		size_t msg_len, void *mac_buf, size_t mac_len, uint16_t job_slice)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = FW_SERVICE_SUCCESS;
	uint8_t *msg_share;
	uint8_t *mac_share;

	/* Check input data */
	if(!msg_buf || !mac_buf)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if(ret != TEE_SUCCESS)
		goto out;

	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	p_ISD			= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	msg_share		= (uint8_t *)p_ISD + NEXT_ADDR_ALIGN4(sizeof(r_icumif_isd_t));
	mac_share		= msg_share + msg_len;

	memcpy((uint8_t *)msg_share, (uint8_t *)msg_buf, msg_len);

	/* Set parameter */
	p_ISD->service_id		= SERVICE_01_HMAC;
	p_ISD->ptr.p_callbackfunc	= 0;
	p_ISD->job_id			= 0;
	p_ISD->req_nointerrupt		= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt		= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.HMAC.key_id			= hmac_key_id;
	p_ISD->prm.HMAC.hmac_operation		= HMAC_GENERATION;
	p_ISD->prm.HMAC.hash_primitive		= hash_primitive;
	p_ISD->prm.HMAC.ptr1.p_msg		= (uint8_t *)msg_share;
	p_ISD->prm.HMAC.msg_size_in_bytes	= msg_len;
	p_ISD->prm.HMAC.hmac_size_in_bytes	= mac_len;
	p_ISD->prm.HMAC.job_slice		= job_slice;
	p_ISD->prm.HMAC.ptr2.p_hmac		= (uint8_t *)mac_share;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}
	memcpy((uint8_t *)mac_buf, (uint8_t *)mac_share, mac_len);
out:
	return ret;
}
#endif

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
	} else {
		EMSG("res = 0x%x", res);
		ret = FW_SERVICE_FAILURE;
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
