// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Renesas Electronics Corporation
 */

#include "rcar_fw_security_service.h"
#include "drivers/comm_shared.h"
#include "drivers/comm.h"

uint32_t fwss_secureboot_get_lcs(uint32_t *lcs_out)
{
	uint32_t ret;
	generic_data_t *p_payload = (generic_data_t *)p_shared_data;

	/* Clear flag */
	p_shared_flag->flag = REQ_STATE_NONE;

	/* Set payload */
	p_payload->service_id = (uint8_t)SERVICE_ID_GET_LCS;
	/* R_ROM_GetLcs: [OUT] return value */
	p_payload->param[0uL] = BOOTROM_API_RETURN_SB_RET_ERR_INTERNAL_FAIL;
	/* R_ROM_GetLcs: [OUT] uint32_t *pLcs */
	p_payload->param[1uL] = 0uL;
	p_shared_payload->service_result = SERVICE_RESULT_OK;
	p_shared_payload->data_len = LCS_SIZE;
	p_shared_payload->p_data = (void *)p_payload;

	/* trigger communication */
	r_comm_trigger_secure(p_payload, p_shared_payload->data_len);

	/* Check the results */
	if (p_shared_payload->service_result != SERVICE_RESULT_OK) {
		EMSG("r_comm_trigger_secure() return 0x%x\r\n",
				p_shared_payload->service_result);
		ret = p_shared_payload->service_result;
	} else {
		ret = p_payload->param[0uL];
		*lcs_out = p_payload->param[1uL];
	}

	return ret;
}

uint32_t fwss_secureboot_verify(uint32_t key_cert_addr, uint32_t cnt_cert_addr,
		uint32_t extmac_addr, uint32_t *p_des_addr)
{
	uint32_t ret;
	generic_data_t *p_payload = (generic_data_t *)p_shared_data;

	/* Clear flag */
	p_shared_flag->flag = REQ_STATE_NONE;

	/* Set payload */
	p_payload->service_id = (uint8_t)SERVICE_ID_SECURE_BOOT_VERIFY;
	/* R_ROM_SecureBootVerify: [OUT] return value */
	p_payload->param[0uL] = BOOTROM_API_RETURN_SB_RET_ERR_INTERNAL_FAIL;
	/* R_ROM_SecureBootVerify: [IN]  uint32_t *pKeyCert */
	p_payload->param[1uL] = key_cert_addr;
	/* R_ROM_SecureBootVerify: [IN]  uint32_t *pContentCert */
	p_payload->param[2uL] = cnt_cert_addr;
	/* R_ROM_SecureBootVerify: [IN]  uint32_t *p_rekey */
	p_payload->param[3uL] = extmac_addr;
	/* R_ROM_SecureBootVerify: [OUT] uint32_t *dest_addr */
	p_payload->param[4uL] = 0uL;
	p_shared_payload->service_result = SERVICE_RESULT_OK;
	p_shared_payload->p_data = (void *)p_payload;

	/* trigger communication */
	r_comm_trigger_secure(p_payload, sizeof(generic_data_t));

	/* Check the results */
	if (p_shared_payload->service_result != SERVICE_RESULT_OK) {
		EMSG("r_comm_trigger_secure() return 0x%x\r\n",
				p_shared_payload->service_result);
		ret = p_shared_payload->service_result;
	} else {
		ret = p_payload->param[0uL];
		if (p_des_addr != NULL)
			p_des_addr = (uint32_t *)
				(uintptr_t)p_payload->param[4uL];
	}

	return ret;
}

uint32_t fwss_secureboot_decrypt(void)
{
	uint32_t ret;
	generic_data_t *p_payload = (generic_data_t *)p_shared_data;

	/* Clear flag */
	p_shared_flag->flag = REQ_STATE_NONE;

	/* Set payload */
	p_payload->service_id = (uint8_t)SERVICE_ID_SECURE_BOOT_DECRYPT;
	/* R_ROM_SecureBootDecrypt: [OUT] return value */
	p_payload->param[0uL] = BOOTROM_API_RETURN_SB_RET_ERR_INTERNAL_FAIL;
	p_shared_payload->service_result = SERVICE_RESULT_OK;
	p_shared_payload->p_data = (void *)p_payload;

	/* trigger communication */
	r_comm_trigger_secure(p_payload, sizeof(generic_data_t));

	/* Check the results */
	if (p_shared_payload->service_result != SERVICE_RESULT_OK) {
		EMSG("r_comm_trigger_secure() return 0x%x\r\n",
				p_shared_payload->service_result);
		ret = p_shared_payload->service_result;
	} else {
		ret = p_payload->param[0uL];
	}

	return ret;
}

uint32_t fwss_secureboot_compare(uint32_t *p_hash_cert, uint32_t *p_hash_cal,
		uint32_t hash_size)
{
	uint32_t ret;
	generic_data_t *p_payload = (generic_data_t *)p_shared_data;

	/* Clear flag */
	p_shared_flag->flag = REQ_STATE_NONE;

	/* Set payload */
	p_payload->service_id = (uint8_t)SERVICE_ID_SECURE_BOOT_COMPARE;
	/* R_ROM_SecureBootCompare: [OUT] return value */
	p_payload->param[0uL] = BOOTROM_API_RETURN_SB_RET_ERR_INTERNAL_FAIL;

	/* --------------------- Reserved -------------------- */
	p_payload->param[1uL] = NOT_USE;
	p_payload->param[2uL] = NOT_USE;
	p_payload->param[3uL] = NOT_USE;
	p_payload->param[4uL] = NOT_USE;
	p_payload->param[5uL] = NOT_USE;
	p_payload->param[6uL] = NOT_USE;
	p_payload->param[7uL] = NOT_USE;
	/* --------------------------------------------------- */

	/* R_ROM_SecureBootCompare: [OUT] uint32_t * hash_cert */
	p_payload->param[8uL] = 0uL;
	p_payload->param[9uL] = 0uL;
	p_payload->param[10uL] = 0uL;
	p_payload->param[11uL] = 0uL;
	p_payload->param[12uL] = 0uL;
	p_payload->param[13uL] = 0uL;
	p_payload->param[14uL] = 0uL;
	p_payload->param[15uL] = 0uL;
	/* --------------------------------------------------- */

	/* R_ROM_SecureBootCompare: [OUT] uint32_t * hash_calc */
	p_payload->param[16uL] = 0uL;
	p_payload->param[17uL] = 0uL;
	p_payload->param[18uL] = 0uL;
	p_payload->param[19uL] = 0uL;
	p_payload->param[20uL] = 0uL;
	p_payload->param[21uL] = 0uL;
	p_payload->param[22uL] = 0uL;
	p_payload->param[23uL] = 0uL;
	/* -------------------------------------------------- */

	/* R_ROM_SecureBootCompare: [IN]  uint32_t hash_size */
	p_payload->param[24uL] = hash_size;

	p_shared_payload->service_result = SERVICE_RESULT_OK;
	p_shared_payload->p_data = (void *)p_payload;

	/* trigger communication */
	r_comm_trigger_secure(p_payload, sizeof(generic_data_t));

	/* Check the results */
	if (p_shared_payload->service_result != SERVICE_RESULT_OK) {
		EMSG("r_comm_trigger_secure() return 0x%x\r\n",
				p_shared_payload->service_result);
		ret = p_shared_payload->service_result;
	} else {
		ret = p_payload->param[0uL];
		*p_hash_cert = p_payload->param[8uL];
		*p_hash_cal = p_payload->param[16uL];
	}

	return ret;
}
