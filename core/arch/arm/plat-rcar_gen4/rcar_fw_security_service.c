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
#include <kernel/misc.h>
#include <kernel/thread.h>
#include <tee_api_defines.h>
#include <stdbool.h>

static struct mutex fwss_mutex = MUTEX_INITIALIZER;
static uint8_t fw_pe_init[CFG_TEE_CORE_NB_CORE] __nex_bss;
static void *g_ISD_BUFFER __nex_data = NULL;
static void *g_LCS_BUFFER __nex_data = NULL;
static void *g_CMAC_BUFFER __nex_data = NULL;
static void *g_HASH_BUFFER __nex_data = NULL;
#if defined(RCAR_TRNG_BY_ICUMX_HWENGINE) || defined(RCAR_SECURE_STORAGE_BY_ICUMX_HWENGINE)
static void *g_ISD_SEC_SVC_BUFFER __nex_data = NULL;
bool is_icum_initialized = false;
#endif

#if defined(RCAR_TRNG_BY_ICUMX_HWENGINE) || defined(RCAR_SECURE_STORAGE_BY_ICUMX_HWENGINE)
/* Convert buffer length in bytes to number of word blocks */
inline uint32_t byte_to_block(uint32_t buf_len) {
	/* A block is equal to 4 bytes */
	return (buf_len + WORD_BLOCK_SIZE - 1) / WORD_BLOCK_SIZE;
}
#endif
static uint32_t fw_service_request(r_icumif_isd_t *p_ISD);

uint32_t fwss_service_init(void)
{
	int32_t res;
	volatile uint32_t *fw_status;
	uint32_t ret = FW_SERVICE_SUCCESS;

	if (g_ISD_BUFFER == NULL) {
#if defined(RCAR_TRNG_BY_ICUMX_HWENGINE) || defined(RCAR_SECURE_STORAGE_BY_ICUMX_HWENGINE)
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
		if ((*fw_status & ICUMIF_STATUS) != 0UL) {
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
	uint32_t fw_ret;

	mutex_lock(&fwss_mutex);
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
	fw_ret = p_ISD->prm.SECURE_BOOT_API.api_return_value;
	mutex_unlock(&fwss_mutex);

	if (ret == FW_SERVICE_SUCCESS) {
		if (fw_ret == BOOTROMAPI_OK) {
			*lcs_out = *p_lcs;
		} else {
			EMSG("SECURE_BOOT_API return_value = 0x%x", fw_ret);
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
	uint32_t fw_ret;

	mutex_lock(&fwss_mutex);
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
	fw_ret = p_ISD->prm.SECURE_BOOT_API.api_return_value;
	mutex_unlock(&fwss_mutex);

	if ((ret == FW_SERVICE_SUCCESS) &&
	    (fw_ret == BOOTROMAPI_OK)) {
		for (i = 0U; i < CMAC_COPY; i++) {
			cmac[i] = *p_cmac_buf;
			p_cmac_buf++;
		}
	} else if (ret != FW_SERVICE_SUCCESS){
		EMSG("ret = 0x%x", ret);
		fw_ret = FW_SERVICE_FAILURE;
	} else {
		EMSG("SECURE_BOOT_API return_value = 0x%x", fw_ret);
	}

	return fw_ret;
}

uint32_t fwss_secureboot_dec_and_comp(uint8_t *cnt_cert, uint32_t *cmac)
{
	uint32_t *p_cmac_buf;
	uint32_t *p_hash_buf;
	r_icumif_isd_t *p_ISD;
	uint32_t i;
	uint32_t ret;
	volatile uintptr_t p_cnt_cert;
	uint32_t fw_ret;

	mutex_lock(&fwss_mutex);
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
	fw_ret = p_ISD->prm.SECURE_BOOT_API.api_return_value;
	mutex_unlock(&fwss_mutex);

	if (ret != FW_SERVICE_SUCCESS) {
		EMSG("ret = 0x%x", ret);
		fw_ret = FW_SERVICE_FAILURE;
	} else if (fw_ret != BOOTROMAPI_OK) {
		EMSG("SECURE_BOOT_API return_value = 0x%x", fw_ret);
		fw_ret = FW_SERVICE_FAILURE;
	} else {
		/* no operation */
	}

	return fw_ret;
}

#if defined(RCAR_TRNG_BY_ICUMX_HWENGINE) || defined(RCAR_SECURE_STORAGE_BY_ICUMX_HWENGINE)
/****************************************************************************************
 * Function name : fwss_trng_generate
 * Description : This function generates a true random number using ICUMX Firmware.
 *
 * @param[out] buf		: Pointer to the destination buffer for the generated
 * 				  true random number.
 * @param[in] buf_len		: Size in bytes of the true random number generate.
 *
 * @return :	TEE_SUCCESS
 * 		TEE_ERROR_SECURITY
 ***************************************************************************************/
uint32_t fwss_trng_generate(void *buf, size_t buf_len)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = TEE_SUCCESS;
	uint32_t *trng_output;

	/* Init ICUM Firmware interface */
	res = fwss_service_init();
	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fwss_service_init() error");
		ret = TEE_ERROR_SECURITY;
	}

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if (ret != TEE_SUCCESS) {
		EMSG("Init ICUM system failed");
		goto out;
	}

	mutex_lock(&fwss_mutex);
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
	mutex_unlock(&fwss_mutex);

	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}

	(void)memcpy((uint8_t*)buf, (uint8_t*)trng_output, buf_len);

out:
	return ret;
}

/****************************************************************************************
 * Function name : fwss_sys_fw_init
 * Description : This function initializes ICU-M firmware.
 *
 * @return :	TEE_SUCCESS
 * 		TEE_ERROR_SECURITY
 ***************************************************************************************/
uint32_t fwss_sys_fw_init(void)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = TEE_SUCCESS;

	mutex_lock(&fwss_mutex);
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
	mutex_unlock(&fwss_mutex);

	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
	}

	return ret;
}

/****************************************************************************************
 * Function name : fwss_set_mono_ctr
 * Description : This function defines the number of NVM monotonic counters supported
 * 		 by ICUMX Firmware.
 *
 * @param[in] nb_monoctr_nv	: Number of NVM Monotonic Counters.
 *
 * @return :	TEE_SUCCESS
 * 		TEE_ERROR_SECURITY
 ***************************************************************************************/
uint32_t fwss_set_mono_ctr(uint8_t nb_monoctr_nv)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = TEE_SUCCESS;

	mutex_lock(&fwss_mutex);
	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	/* Set parameter */
	p_ISD					= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	p_ISD->service_id			= SERVICE_00_SYSTEM_CONFIG;
	p_ISD->ptr.p_callbackfunc		= NULL;
	p_ISD->job_id				= 0;
	p_ISD->req_nointerrupt			= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt			= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.SYSTEM_CONFIG.sys_cfg_id		= SET_MONOCTR_MAPPING;
	p_ISD->prm.SYSTEM_CONFIG.cfg.nb_monoctr_nv	= nb_monoctr_nv;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	mutex_unlock(&fwss_mutex);

	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
	}

	return ret;
}
/****************************************************************************************
 * Function name : fwss_init_mydata_set
 * Description : This function defines the number of mydata slots supported by ICUMX Firmware.
 *
 * @param[in] nb_items			: Number of mydata slots.
 * @param[in] item_size_in_bytes	: Size in bytes of each mydata item.
 *
 * @return :	TEE_SUCCESS
 * 		TEE_ERROR_SECURITY
 ***************************************************************************************/
uint32_t fwss_init_mydata_set(uint8_t nb_items, uint16_t item_size_in_bytes)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = TEE_SUCCESS;

	mutex_lock(&fwss_mutex);
	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	/* Set parameter */
	p_ISD					= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	p_ISD->service_id			= SERVICE_00_SYSTEM_CONFIG;
	p_ISD->ptr.p_callbackfunc		= NULL;
	p_ISD->job_id				= 0;
	p_ISD->req_nointerrupt			= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt			= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.SYSTEM_CONFIG.sys_cfg_id	= SET_MYDATA_MAPPING;
	p_ISD->prm.SYSTEM_CONFIG.cfg.mydata_set.nb_items		= nb_items;
	p_ISD->prm.SYSTEM_CONFIG.cfg.mydata_set.item_size_in_bytes	= item_size_in_bytes;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	mutex_unlock(&fwss_mutex);

	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
	}

	return ret;
}

/****************************************************************************************
 * Function name : fwss_get_current_stage
 * Description : This function retrieves the current Life Cycle Stage of ICUM Firmware.
 *
 * @param[out] current_stage		: The current Life Cycle Stage.
 * 					   Stage :	LC_STAGE_LC0
 * 							LC_STAGE_LC1
 * 							LC_STAGE_LC2
 * 							LC_STAGE_LC2S
 * 							LC_STAGE_TERMINATION
 *
 * @return :	TEE_SUCCESS
 * 		TEE_ERROR_SECURITY
 ***************************************************************************************/
uint32_t fwss_get_current_stage(uint32_t *current_stage)
{
	uint32_t res;
	uint32_t fw_stage;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = TEE_SUCCESS;

	/* Check input data */
	if (!current_stage)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&fwss_mutex);
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
	fw_stage = p_ISD->prm.LIFE_CYCLE.current_stage;
	mutex_unlock(&fwss_mutex);

	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
	}

	/* Retrieve ICU-M current stage */
	*current_stage = fw_stage;

	return ret;
}

/****************************************************************************************
 * Function name : fwss_lc_set_stage
 * Description : This function is used to make stage transitions of ICUM Firmware.
 *
 * @param[in] stage            : Transition destination Life Cycle Stage.
 * 					Stage : LC_STAGE_LC0
 * 						LC_STAGE_LC1
 *						LC_STAGE_LC2
 *						LC_STAGE_LC2S
 *						LC_STAGE_TERMINATION
 *
 * @return :	TEE_SUCCESS
 * 		TEE_ERROR_SECURITY
 ***************************************************************************************/
uint32_t fwss_lc_set_stage(uint32_t stage)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = TEE_SUCCESS;

	if (stage != LC_STAGE_LC1) {
		EMSG("Currently only support for switching to LC1 stage!\n");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}

	mutex_lock(&fwss_mutex);
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
	p_ISD->prm.LIFE_CYCLE.ptr1.p_challenge	= NULL;
	p_ISD->prm.LIFE_CYCLE.ptr2.p_response	= NULL;
	p_ISD->req_nointerrupt			= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt			= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.LIFE_CYCLE.transition_dest	= stage;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	mutex_unlock(&fwss_mutex);

	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
	}

out:
	return ret;
}

/****************************************************************************************
 * Function name : fwss_plain_key_update
 * Description : This function performs an AES plain key update supported by ICUMX Firmware.
 *
 * @param[in] key_group		: Key group of the AES key to be updated.
 * 					AES key group : KEY_GRP_AES
 * 							KEY_GRP_AES_RAM
 * 							KEY_GRP_AES_CR
 * @param[in] key_id		: Index of the key to be updated.
 * @param[in] key_buf		: Pointer to the buffer containing the AES key to be updated.
 * @param[in] key_len		: Size in bytes of the AES key.
 * @param[in] write_protected	: Restricts the update of keys.
 *
 * @return : 	TEE_SUCCESS
 *		TEE_ERROR_SECURITY
 ***************************************************************************************/
uint32_t fwss_plain_key_update(r_key_group_t key_group, uint8_t key_id,
		void *key_buf, uint16_t key_len, uint8_t write_protected)
{
	uint32_t res;
	uint32_t fw_result;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = TEE_SUCCESS;
	uint8_t *input_key_share;
	__attribute__((unused)) const char *key_grp_str = NULL;

	/* Check input data */
	if (!key_buf || !key_len) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if (ret != TEE_SUCCESS) {
		EMSG("Init ICUM system failed");
		goto out;
	}

	mutex_lock(&fwss_mutex);
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
	p_ISD->prm.KEY_UPDATE_PLAIN.key_group			= key_group;
	p_ISD->prm.KEY_UPDATE_PLAIN.key_id			= key_id;
	p_ISD->prm.KEY_UPDATE_PLAIN.ptr.p_key_value		= (uint8_t *)input_key_share;
	p_ISD->prm.KEY_UPDATE_PLAIN.key_size_in_bytes		= key_len;
	p_ISD->prm.KEY_UPDATE_PLAIN.mem_cluster_verif		= 0;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.encryption		= 1;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.decryption		= 1;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.cmac_generation	= 1;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.cmac_verification	= 1;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.write_protected	= write_protected;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.disable_on_debug	= 0;
	p_ISD->prm.KEY_UPDATE_PLAIN.flags.no_wild_card		= 0;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	fw_result = p_ISD->service_result;
	mutex_unlock(&fwss_mutex);

	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
	}

	/* Check service result */
	if (fw_result == SERV_KEY_WRITE_PROTECTED) {
		switch (key_group) {
			case KEY_GRP_AES:
				key_grp_str = KEY_GRP_AES_STR;
				break;
			case KEY_GRP_AES_RAM:
				key_grp_str = KEY_GRP_AES_RAM_STR;
				break;
			case KEY_GRP_AES_CR:
				key_grp_str = KEY_GRP_AES_CR_STR;
				break;
			default:
				key_grp_str = "UNKNOWN";
				break;
		}

		EMSG("The key id %d in group %s has been write-protected", key_id, key_grp_str);
		ret = TEE_ERROR_SECURITY;
	}
out:
	return ret;
}

/****************************************************************************************
 * Function name : fwss_aes_cmac
 * Description : This function processes a CMAC generation supported by ICUMX Firmware.
 *
 * @param[in] key_group		: Key group of the key to be used.
 * 					AES key group : KEY_GRP_AES
 * 							KEY_GRP_AES_RAM
 * 							KEY_GRP_AES_CR
 * @param[in] key_id		: Index of the key to be used.
 * @param[in] msg_buf		: Pointer to the message to process.
 * @param[in] msg_len		: Size in bytes of the message.
 * @param[out] out_buf		: Pointer to the destination buffer for the CMAC output result.
 *
 * @return : 	TEE_SUCCESS
 * 		TEE_ERROR_SECURITY
 ***************************************************************************************/
uint32_t fwss_aes_cmac(r_key_group_t key_group, r_key_index_t key_id, void *msg_buf,
					size_t msg_len, void *out_buf)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = TEE_SUCCESS;
	uint32_t *p_msg_share;
	uint32_t *output_share;

	/* Check input data */
	if (!msg_buf || !msg_len || !out_buf) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if (ret != TEE_SUCCESS) {
		EMSG("Init ICUM system failed");
		goto out;
	}

	mutex_lock(&fwss_mutex);
	/* Initialize the global buffer */
	(void)memset(g_ISD_SEC_SVC_BUFFER, 0, SIZE_OF_SEC_SRV);

	p_ISD			= (r_icumif_isd_t *)g_ISD_SEC_SVC_BUFFER;
	p_msg_share		= (uint32_t *)p_ISD + NEXT_ADDR_ALIGN4(sizeof(r_icumif_isd_t));
	output_share		= p_msg_share + msg_len;

	memcpy((uint8_t *)p_msg_share, (uint8_t *)msg_buf, msg_len);

	/* Set parameter */
	p_ISD->service_id			= SERVICE_01_AES_CMAC;
	p_ISD->ptr.p_callbackfunc		= 0;
	p_ISD->job_id				= 0;
	p_ISD->req_nointerrupt			= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt			= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->service_priority			= R_ICUMIF_SERV_PRIORITY_NORMAL;
	p_ISD->prm.AES_CMAC.key_group		= key_group;
	p_ISD->prm.AES_CMAC.key_id		= key_id;
	p_ISD->prm.AES_CMAC.cmac_operation	= CMAC_GENERATION;
	p_ISD->prm.AES_CMAC.ptr1.p_msg		= p_msg_share;
	p_ISD->prm.AES_CMAC.msg_size_in_bits	= msg_len * 8;
	p_ISD->prm.AES_CMAC.ptr2.p_cmac		= (uint32_t *)output_share;
	p_ISD->prm.AES_CMAC.cmac_size_in_bits	= 128;
	p_ISD->prm.AES_CMAC.job_slice		= 0;
	p_ISD->prm.AES_CMAC.job_cycle		= JOB_ALL_AT_ONCE;

	/* Run ICU FW Security services */
	res = fw_service_request(p_ISD);
	mutex_unlock(&fwss_mutex);

	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}
	memcpy((uint8_t *)out_buf, (uint8_t *)output_share, AES_KEY_LEN_128);
out:
	return ret;
}

/****************************************************************************************
 * Function name : fwss_ext_flash_write
 * Description : This function exports secure data (utilized by ICUM)
 * 		 to export area (utilized by Host).
 *
 * @return : 	TEE_SUCCESS
 * 		TEE_ERROR_SECURITY
 ***************************************************************************************/
uint32_t fwss_ext_flash_write(void)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = TEE_SUCCESS;

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if (ret != TEE_SUCCESS) {
		EMSG("Init ICUM system failed");
		goto out;
	}

	mutex_lock(&fwss_mutex);
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
	mutex_unlock(&fwss_mutex);

	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}
out:
	return ret;
}

/****************************************************************************************
 * Function name : fwss_auth_aes_cipher
 * Description : This function processes an AES authenticated ciphering operation
 * 		 supported by ICUMX Firmware.
 *
 * @param[in] direction			: Cipher direction.
 * @param[in] mode			: Authentication cipher mode to process.
 * @param[in] key_group			: Key group of the key to be used.
 * @param[in] key_id			: Index of the keyto be used.
 * @param[in] iv_buf			: Pointer to the initial vector.
 * @param[in] iv_len			: Size in bytes of the initial vector.
 * @param[in] auth_buf			: Pointer to the additional authentication data.
 * @param[in] auth_len			: Size in bytes of the additional authentication data.
 * @param[in] in_buf			: Pointer to the data to process.
 * @param[in] in_len			: Size in bytes of the data to process.
 * @param[in] out_buf			: Pointer to the data resulting from the ciphering operation.
 * @param[in/out] tag_buf		: Pointer to the calculated authentication tag.
 * @param[in] tag_len			: Size in bytes of the authentication tag.
 *
 * @return : 	TEE_SUCCESS
 * 		TEE_ERROR_SECURITY
 ****************************************************************************************/
uint32_t fwss_auth_aes_cipher(cipher_direction_t direction, auth_cipher_modes_t mode,
		r_key_group_t key_group, r_key_index_t key_id, void *iv_buf, size_t iv_len,
		void *auth_buf, size_t auth_len, void *in_buf, size_t in_len,
		void *out_buf, void *tag_buf, size_t tag_len)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = TEE_SUCCESS;
	uint32_t fw_result;
	uint32_t *iv_share;
	uint32_t *auth_share;
	uint32_t *input_share;
	uint32_t *output_share;
	uint32_t *tag_share;

	/* Check input data */
	if (!iv_buf || !auth_buf || !in_buf || !out_buf || !tag_buf)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if (ret != TEE_SUCCESS) {
		EMSG("Init ICUM system failed");
		goto out;
	}

	mutex_lock(&fwss_mutex);
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
	if (direction == CIPHER_DIR_DECRYPTION)
		memcpy((uint8_t *)tag_share, (uint8_t *)tag_buf, tag_len);

	/* Set parameter */
	p_ISD->service_id					= SERVICE_01_AES_AUTH_CIPHER;
	p_ISD->ptr.p_callbackfunc				= 0;
	p_ISD->job_id						= 0;
	p_ISD->req_nointerrupt					= R_ICUMIF_REQRES_INTERRPUT;
	p_ISD->res_nointerrupt					= R_ICUMIF_REQRES_NOINTERRPUT;
	p_ISD->prm.AES_AUTH_CIPHER.direction			= direction;
	p_ISD->prm.AES_AUTH_CIPHER.cipher_mode			= mode;
	p_ISD->prm.AES_AUTH_CIPHER.key_group			= key_group;
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
	fw_result = p_ISD->prm.AES_AUTH_CIPHER.verification_result;
	mutex_unlock(&fwss_mutex);

	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}

	(void)memcpy((uint8_t *)out_buf, (uint8_t *)output_share, in_len);
	if (direction == CIPHER_DIR_ENCRYPTION)
		(void)memcpy((uint8_t *)tag_buf, (uint8_t *)tag_share, tag_len);
	if (!fw_result) {
		EMSG("Verify MAC successfully!");
	} else {
		DMSG("Verify MAC failed!");
		ret = TEE_ERROR_MAC_INVALID;
	}
out:
	return ret;
}

/**************************************************************************************
 * Function name : fwss_hmac_import
 * Description : This function imports an HMAC key into the HMAC key slot in secure data
 * 		 supported by ICUMX Firmware.
 *
 * @param[in] key_buf		: Pointer to the HMAC key that needs to be imported.
 * @param[in] key_len		: Size in bytes of the HMAC key.
 * @param[in] hmac_key_id	: Index (within the key group KEY_GRP_HMAC)
 * 				  of the HMAC key to be stored.
 *
 * @return :	TEE_SUCCESS
 * 		TEE_ERROR_SECURITY
 ***************************************************************************************/
uint32_t fwss_hmac_import(void *key_buf, size_t key_len, uint8_t hmac_key_id)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = TEE_SUCCESS;
	uint8_t *key_share;

	/* Check input data */
	if (!key_buf)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if (ret != TEE_SUCCESS) {
		EMSG("Init ICUM system failed");
		goto out;
	}

	mutex_lock(&fwss_mutex);
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
	mutex_unlock(&fwss_mutex);

	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}
out:
	return ret;
}

/****************************************************************************************
 * Function name : fwss_hmac_generation
 * Description : This function processes an HMAC generation via
 * 		 the service id SERVICE_01_HMAC.
 *
 * @param[in] hmac_key_id		: Index (within the group KEY_GRP_HMAC) of the
 * 					  key to be used.
 * @param[in] hash_primitive		: The hash primitive used in the hashing operation.
 * @param[in] msg_buf			: Pointer to the message to process.
 * @param[in] msg_len			: Size in bytes of the message.
 * @param[in] mac_buf			: Pointer to the resulting HMAC.
 * @param[in] mac_len			: Size in bytes of the resulting HMAC.
 * @param[in] job_slice			: The maximum number of hash blocks processed in
 * 					  one job call.
 *
 * @return : 	TEE_SUCCESS
 * 		TEE_ERROR_SECURITY
 ***************************************************************************************/
uint32_t fwss_hmac_generation(uint8_t hmac_key_id, uint8_t hash_primitive, void *msg_buf,
		size_t msg_len, void *mac_buf, size_t mac_len, uint16_t job_slice)
{
	uint32_t res;
	r_icumif_isd_t *p_ISD;
	uint32_t ret = TEE_SUCCESS;
	uint8_t *msg_share;
	uint8_t *mac_share;

	/* Check input data */
	if (!msg_buf || !mac_buf)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if (ret != TEE_SUCCESS) {
		EMSG("Init ICUM system failed");
		goto out;
	}

	mutex_lock(&fwss_mutex);
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
	mutex_unlock(&fwss_mutex);

	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fw_service_request error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}
	memcpy((uint8_t *)mac_buf, (uint8_t *)mac_share, mac_len);
out:
	return ret;
}

/****************************************************************************************
 * Function name : check_icum_init
 * Description : This function checks the Life Cycle stage and performs system
 * 		 initialization if required.
 *		  - If Life Cycle Stage is LC0:
 *		    Performs initial system settings and transitions to LC1.
 *		  - If Life Cycle Stage is LC1, LC2, or LC2S:
 *		    No additional actions are taken, the function simply returns TEE_SUCCESS.
 *
 * @return : 	TEE_SUCCESS
 * 		TEE_ERROR_SECURITY
 ***************************************************************************************/
uint32_t check_icum_init(void)
{
	uint32_t ret = TEE_SUCCESS;
	uint32_t stage;

	if (!is_icum_initialized) {
		/* Check ICU-M current stage */
		ret = fwss_get_current_stage(&stage);
		if (ret != TEE_SUCCESS) {
			EMSG("fwss_get_current_stage() error");
			goto out;
		}

		if (stage == LC_STAGE_LC1 || stage == LC_STAGE_LC2 || stage == LC_STAGE_LC2S) {
			is_icum_initialized = true;
			goto out;
		}

		/* Init MyData service:
		 * - Number of MyData items: 10
		 * - Size of MyData item: 1064 bytes
		 */
		ret = fwss_init_mydata_set(10, 1064);
		if (ret != TEE_SUCCESS) {
			EMSG("fwss_init_mydata_set() error");
			goto out;
		}

		/* Init ICUM with 2 non-volatile monotonic counters */
		ret = fwss_set_mono_ctr(2);
		if (ret != TEE_SUCCESS) {
			EMSG("fwss_set_mono_ctr() error");
			goto out;
		}

		/* Init ICUM Firmware system */
		ret = fwss_sys_fw_init();
		if (ret != TEE_SUCCESS) {
			EMSG("fwss_sys_fw_init() error");
			goto out;
		}

		/* Transfer to LC1 stage */
		ret = fwss_lc_set_stage(LC_STAGE_LC1);
		if (ret != TEE_SUCCESS) {
			EMSG("fwss_lc_set_stage() error");
			goto out;
		}
		is_icum_initialized = true;
	}

out:
	return ret;
}
#endif

static uint32_t fw_service_request(r_icumif_isd_t *p_ISD)
{
	int32_t res;
	uint32_t exceptions;
	size_t pos;
	uint32_t ret = FW_SERVICE_SUCCESS;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	pos = get_core_pos();

	if (!fw_pe_init[pos]) {
		res = R_ICUMIF_Init((uint32_t *)((uintptr_t)ICU_FW_SHMEM_BASE));
		if (res != R_ICUMIF_ER_OK) {
			EMSG("R_ICUMIF_Init res = 0x%x", res);
			thread_unmask_exceptions(exceptions);
			ret = FW_SERVICE_FAILURE;
			goto out;
		}
		fw_pe_init[pos] = 1U;
	}

	res = R_ICUMIF_ServiceRequest(p_ISD);
	if (res == R_ICUMIF_ER_OK) {
		do {
			res = R_ICUMIF_IsServiceCompleted(p_ISD);
			if (res != R_ICUMIF_RTN_SERV_RUNNING) {
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

	thread_unmask_exceptions(exceptions);

	if (res != R_ICUMIF_ER_OK) {
		EMSG("res = 0x%x", res);
		ret = FW_SERVICE_FAILURE;
	} else if (p_ISD->service_result != SERV_OK) {
		EMSG("p_ISD->service_result = 0x%x", p_ISD->service_result);
		ret = FW_SERVICE_FAILURE;
	} else {
		/* no operation */
	}

out:
	return ret;
}
