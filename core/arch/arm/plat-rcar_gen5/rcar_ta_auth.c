// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2024, Renesas Electronics Corporation
 */

#include <string.h>
#include <io.h>
#include <trace.h>

#include "rcar_ta_auth.h"
#include "platform_config.h"
#include "rcar_fw_security_service.h"
#include "drivers/comm_shared.h"
#include "drivers/comm.h"

/* Declaration of internal function */
static uint32_t get_cert_size(uint8_t type, const uint32_t *cert_header);
static uint32_t get_object_size(const uint32_t *content_cert);
static uint64_t check_object_addr(const uint32_t *cert_header);
static uint32_t get_auth_mode(void);

static uint32_t get_cert_size(uint8_t type, const uint32_t *cert_header)
{
	sb_cert_t cert;
	uint32_t cert_size = 0;
	uint32_t header_size = 0;

	cert.base   = (const uint32_t *)cert_header;
	cert.tlv_length = (const uint32_t *)
		(cert.base +(CERT_HEADER_SIZE / 4));

	switch (type) {
	case TYPE_KEYCERT:
	     header_size =
		KC_MAGIC_NUMBER +
		KC_CERT_VERSION +
		KC_FLAGS +
		KC_RESERVED;
		break;
	case TYPE_CONTENTCERT:
	     header_size =
		CC_MAGIC_NUMBER +
		CC_CERT_VERSION +
		CC_FLAGS +
		CC_LOAD_ADDR +
		CC_DEST_ADDR +
		CC_IMAGE_SIZE +
		CC_CODE_VERSION;
		break;
	default:
		EMSG("Certificate is invalid!");
		break;
	}

	cert_size = *(cert.tlv_length);
	cert_size += header_size;
	cert_size += TLV_LENGTH;

	return cert_size;
}

static uint64_t check_object_addr(const uint32_t *cert_header)
{
	const uint32_t *p_cert_base = NULL;
	uint32_t obj_addr = 0U;

	p_cert_base = cert_header;
	p_cert_base += (CC_MAGIC_NUMBER / 4);
	p_cert_base += (CC_CERT_VERSION / 4);
	p_cert_base += (CC_FLAGS / 4);
	p_cert_base += (CC_LOAD_ADDR / 4);

	obj_addr = *p_cert_base;

	return obj_addr;
}

static uint32_t get_object_size(const uint32_t *content_cert)
{
	const uint32_t *p_cert_base;
	uint32_t obj_size = 0U;

	p_cert_base = content_cert;
	p_cert_base += (CC_MAGIC_NUMBER / 4);
	p_cert_base += (CC_CERT_VERSION / 4);
	p_cert_base += (CC_FLAGS / 4);
	p_cert_base += (CC_LOAD_ADDR / 4);
	p_cert_base += (CC_DEST_ADDR / 4);

	obj_size = *p_cert_base;

	return obj_size;
}

static uint32_t get_auth_mode(void)
{
	uint32_t lcs;
	uint32_t md;
	uint32_t auth_mode = NORMAL_BOOT_MODE;
	uint32_t ret;

	ret = fwss_secureboot_get_lcs(&lcs);
	if (ret == BOOTROM_API_RETURN_ROM_OK) {
		if (lcs == LCS_SE) {
			/* LCS=SE + Secure boot */
			auth_mode = SECURE_BOOT_MODE;
		} else {
			md = io_read32((vaddr_t)SYSSS_MAIN_REGION_0_MODE1)
						& MODE1_MD1_MASK;
			if (md == 0U) {
				/* MD01=0 => LCS=CM/DM + Secure boot */
				auth_mode = SECURE_BOOT_MODE;
			} else {
				/* MD01=1 => LCS=CM/DM + Normal boot */
			}
		}
	} else {
		EMSG("fwss_secureboot_get_lcs() error");
	}

	return auth_mode;
}

TEE_Result rcar_auth_ta_certificate(const struct shdr *key_cert,
			struct shdr **secmem_ta, size_t ta_size)
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
	size_t real_ta_size = 0U;

	uint8_t *p_rekey = NULL;
	uint32_t *p_hash_cert = NULL;
	uint32_t *p_hash_cal = NULL;

	/* Get SecureBoot KeyCertificate size */
	key_cert_size = get_cert_size(TYPE_KEYCERT, (const uint32_t *)key_cert);
	if ((key_cert_size == 0U) || (key_cert_size > TA_KEY_CERT_AREA_SIZE)) {
		res = TEE_ERROR_SECURITY;
		EMSG("key_cert_size error");
		goto out;
	}

	/* Get SecureBoot ContentCertificate size */
	content_cert = (const uint32_t *)key_cert + (key_cert_size / 4);
	content_cert_size = get_cert_size(TYPE_CONTENTCERT,
			(const uint32_t *)content_cert);
	if ((content_cert_size == 0U) ||
		(content_cert_size > TA_CONTENT_CERT_AREA_SIZE)) {
		res = TEE_ERROR_SECURITY;
		EMSG("content_cert_size error");
		goto out;
	}

	/* Get object size */
	object_size = get_object_size(content_cert);
	real_ta_size = ta_size - key_cert_size - content_cert_size;
	if (object_size == 0U || object_size != real_ta_size) {
		res = TEE_ERROR_SECURITY;
		EMSG("object_size error");
		goto out;
	}

	DMSG("Cert size: key_cert=0x%x content_cert=0x%x",
			key_cert_size, content_cert_size);
	DMSG("TA size: shdr+bin=0x%x real_ta=0x%lx",
			object_size, real_ta_size);

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
	 * | RSIP-M FW shared area     | [3]=RSIPM_FW_SHARED_AREA_SIZE   |
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

	/* Initialize shared buffer */
	IMSG("START: Initialize shared buffer: %lx\r\n",
			INTER_CORE_COMM_SHARED_MEM_ADDR);
	r_comm_main_init(INTER_CORE_COMM_SHARED_MEM_ADDR);
	IMSG("FINISHED: Initialize shared buffer: %lx\r\n",
			INTER_CORE_COMM_SHARED_MEM_ADDR);

	auth_mode = get_auth_mode();
	if (auth_mode == SECURE_BOOT_MODE) {
		p_rekey = (uint8_t *)calloc(REKEY_SIZE, sizeof(uint8_t));
		if (!p_rekey) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		ret = fwss_secureboot_verify((uintptr_t)fixed_key_cert,
				(uintptr_t)fixed_content_cert,
				(uintptr_t)p_rekey, 0);
		if (ret != BOOTROM_API_RETURN_ROM_OK) {
			res = TEE_ERROR_SECURITY;
			goto out;
		}

		ret = fwss_secureboot_decrypt();
		if (ret != BOOTROM_API_RETURN_ROM_OK &&
			ret != BOOTROM_API_RETURN_ROM_NO_NEED_DECRYPTION) {
			res = TEE_ERROR_SECURITY;
			goto out;
		}

		p_hash_cert = (uint32_t *)calloc(
			HASH_INTEGRITY_CHECK_HASH_SIZE / 4, sizeof(uint32_t));
		p_hash_cal = (uint32_t *)calloc(
			HASH_INTEGRITY_CHECK_HASH_SIZE / 4, sizeof(uint32_t));
		if (!p_hash_cert || !p_hash_cal) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		ret = fwss_secureboot_compare((uint32_t *)p_hash_cert,
				(uint32_t *)p_hash_cal,
					HASH_INTEGRITY_CHECK_HASH_SIZE);
		if (ret != BOOTROM_API_RETURN_ROM_OK) {
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
	if (p_rekey)
		free(p_rekey);
	if (p_hash_cert)
		free(p_hash_cert);
	if (p_hash_cal)
		free(p_hash_cal);

	return res;
}
