// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2020, Renesas Electronics Corporation
 */

#include <string.h>
#include <io.h>
#include <trace.h>
#include <kernel/mutex.h>

#include "rcar_common.h"
#include "rcar_ta_auth.h"
#include "platform_config.h"
#include "rcar_mutex.h"
#include "rcar_fw_security_service.h"

/* Declaration of internal function */
static uint32_t get_key_cert_size(const uint32_t *cert_header);
static uint32_t get_content_cert_size(const uint32_t *cert_header);
static uint32_t get_object_size(const uint32_t *content_cert);
static uint64_t check_object_addr(const uint32_t *cert_header);
static uint32_t get_auth_mode(void);

static uint32_t get_key_cert_size(const uint32_t *cert_header)
{
	uint32_t cert_size = 0U;
	uint32_t hdr_tmp;
	uint32_t sig_size;



	hdr_tmp = (cert_header[CERT_IDX_FLAG] & 0x00600000U) >> 21U;
	sig_size = CERT_SIGNATURE_SIZE;

	if (hdr_tmp == 1U) {
		sig_size += CERT_SIGNATURE_SIZE / 2U;
	} else if (hdr_tmp == 2U) {
		sig_size += CERT_SIGNATURE_SIZE;
	} else {
		/* no operation */
	}

	if (hdr_tmp < 3U) {
		cert_size = ((cert_header[CERT_IDX_SIZE] & CERT_OFS_BIT_SIZE) *
			CERT_BLOCK_SIZE);
		cert_size += sig_size;
	}

	return cert_size;
}

static uint64_t check_object_addr(const uint32_t *cert_header)
{
	uint32_t cert_idx_mem_load_addr;
	uint32_t hdr_tmp;
	uint32_t sig_size;
	uint64_t obj_addr = 0U;

	hdr_tmp = (cert_header[CERT_IDX_FLAG] & 0x00600000U) >> 21U;
	sig_size = CERT_SIGNATURE_SIZE;

	if (hdr_tmp == 1U) {
		sig_size += CERT_SIGNATURE_SIZE / 2U;
	} else if (hdr_tmp == 2U) {
		sig_size += CERT_SIGNATURE_SIZE;
	} else {
		/* no operation */
	}

	if (hdr_tmp < 3U) {
		cert_idx_mem_load_addr = (CERT_IDX_MEM_LOAD_ADDR + sig_size)
					/ CERT_BLOCK_SIZE;

		obj_addr = (uint64_t)(cert_header[cert_idx_mem_load_addr + 1U]);
		obj_addr = obj_addr << 32U;
		obj_addr += (uint64_t)(cert_header[cert_idx_mem_load_addr]);
	}

	return obj_addr;
}

static uint32_t get_content_cert_size(const uint32_t *cert_header)
{
	uint32_t cert_size;

	cert_size = get_key_cert_size(cert_header);
	if (cert_size != 0U) {
		cert_size += CERT_ADD_DATA_SIZE;
	}

	return cert_size;
}

static uint32_t get_object_size(const uint32_t *content_cert)
{
	uint32_t obj_size = 0U;
	const uint32_t *cert_header;
	uint32_t offset;
	const uint32_t *obj_len;

	cert_header = content_cert;
	offset = get_key_cert_size(cert_header);
	if (offset != 0U) {
		offset += CERT_STORE_ADDR_SIZE;
		obj_len = content_cert + (offset / 4U);
		obj_size = *obj_len;

		if (obj_size > TA_OBJ_SIZE) {
			obj_size = 0U;
		} else {
			obj_size *= CERT_BLOCK_SIZE;
		}
	}
	return obj_size;
}

static uint32_t get_auth_mode(void)
{
	uint32_t lcs;
	uint32_t md;
	uint32_t auth_mode = NORMAL_BOOT_MODE;
	uint32_t ret;

	ret = fwss_secureboot_get_lcs(&lcs);

	if (ret == FW_SERVICE_SUCCESS) {
		if (lcs == LCS_SE) {
			/* LCS=SE + Secure boot */
			auth_mode = SECURE_BOOT_MODE;
		} else {
			md = (io_read32((vaddr_t)RST_MODEMR0) &
						RST_MODEMR0_MD5) >> 5U;
			if (md == 0U) {
				/* MD5=0 => LCS=CM/DM + Secure boot */
				auth_mode = SECURE_BOOT_MODE;
			} else {
				/* MD5=1 => LCS=CM/DM + Normal boot */
			}
		}
	} else {
		EMSG("fwss_secureboot_get_lcs() error");
	}

	return auth_mode;
}

TEE_Result rcar_auth_ta_certificate(const struct shdr *key_cert,
				struct shdr **secmem_ta)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t ret;
	uint32_t key_cert_size;
	uint32_t content_cert_size = 0U;
	uint32_t object_size = 0U;
	uint32_t auth_mode;
	const uint32_t *content_cert = NULL;
	struct shdr *fixed_ta = (struct shdr *)TA_VERIFICATION_BASE;
	uint8_t *fixed_base = (uint8_t *)TA_VERIFICATION_BASE;
	uint8_t *fixed_key_cert = (uint8_t *)TA_KEY_CERT_ADDR;
	uint8_t *fixed_content_cert = (uint8_t *)TA_CONTENT_CERT_ADDR;
	uint64_t object_addr;
	uint32_t cmac[4] = {0};

	key_cert_size = get_key_cert_size((const uint32_t *)key_cert);
	if ((key_cert_size == 0U) || (key_cert_size > TA_KEY_CERT_AREA_SIZE)) {
		res = TEE_ERROR_SECURITY;
		EMSG("key_cert_size error");
		goto out;
	}

	content_cert = (const uint32_t *)key_cert + (key_cert_size / 4U);
	content_cert_size = get_content_cert_size(content_cert);
	if ((content_cert_size == 0U) ||
		(content_cert_size > TA_CONTENT_CERT_AREA_SIZE)) {
		res = TEE_ERROR_SECURITY;
		EMSG("content_cert_size error");
		goto out;
	}

	object_size = get_object_size(content_cert);
	if (object_size == 0U) {
		res = TEE_ERROR_SECURITY;
		EMSG("object_size error");
		goto out;
	}

	DMSG("TA size: key_cert=0x%x content_cert=0x%x shdr+bin=0x%x",
		key_cert_size, content_cert_size, object_size);

	/* check the address of loading TA is the top of verification area */
	object_addr = check_object_addr(content_cert);
	if (object_addr != TA_VERIFICATION_BASE) {
		res = TEE_ERROR_SECURITY;
		EMSG("object_addr error. addrr=0x%x", res);
		goto out;
	}

	/*
	 *   Fixed memory map          | TotalSize=TA_VERIFICATION_SIZE
	 * ---------------------------------------------------------------
	 * | TA object data area       | TotalSize - [1] - [2] - [3]     |
	 * | (signed header + binary)  |                                 |
	 * ---------------------------------------------------------------
	 * | Key Certificate area      | [1]=TA_KEY_CERT_AREA_SIZE       |
	 * ---------------------------------------------------------------
	 * | Content Certificate area  | [2]=TA_CONTENT_CERT_AREA_SIZE   |
	 * ---------------------------------------------------------------
	 * | ICUM FW shared area       | [3]=ICUM_FW_SHARED_AREA_SIZE    |
	 * ---------------------------------------------------------------
	 */
	/* copy to fixed memory */
	(void)memcpy(fixed_base,
		(const uint8_t *)content_cert + content_cert_size,
		object_size);
	(void)memcpy(fixed_key_cert,
		(const uint8_t *)key_cert,
		key_cert_size);
	(void)memcpy(fixed_content_cert,
		(const uint8_t *)content_cert,
		content_cert_size);

	ret = fwss_service_init();
	if (ret != FW_SERVICE_SUCCESS) {
		EMSG("fwss_service_init() error");
		res = TEE_ERROR_SECURITY;
		goto out;
	}
	auth_mode = get_auth_mode();
	if (auth_mode == SECURE_BOOT_MODE) {
		ret = fwss_secureboot_verify(fixed_key_cert,
					fixed_content_cert, cmac);
		if (ret != BOOTROMAPI_OK) {
			res = TEE_ERROR_SECURITY;
			goto out;
		}
		ret = fwss_secureboot_dec_and_comp(fixed_content_cert, cmac);
		if (ret != BOOTROMAPI_OK) {
			res = TEE_ERROR_SECURITY;
			goto out;
		}
		DMSG("Secure boot success!");
		*secmem_ta = fixed_ta;
	} else {
		DMSG("Normal boot");
		*secmem_ta = fixed_ta;
	}
out:
	return res;
}
