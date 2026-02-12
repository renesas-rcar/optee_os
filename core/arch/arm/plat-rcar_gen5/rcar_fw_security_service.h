/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Renesas Electronics Corporation
 */

#ifndef RCAR_FW_SECURITY_SERVICE_H
#define RCAR_FW_SECURITY_SERVICE_H

#include "rcar-common.h"

#define SYSSS_MAIN_REGION_0_MODE1       p2v_regadr(SYSSS_MAIN_REGION_0_BASE + \
						0x00001010, DEVICE0_SIZE)
#define MODE1_MD1_MASK                  (0x00000002uL)

#define SERVICE_ID_GET_LCS                      (0x02uL)
#define SERVICE_ID_SECURE_BOOT_VERIFY           (0x03uL)
#define SERVICE_ID_SECURE_BOOT_DECRYPT          (0x04uL)
#define SERVICE_ID_SECURE_BOOT_COMPARE          (0x05uL)

#define LCS_SIZE				(4uL)

/* Return value of Secure Boot AP */
#define BOOTROM_API_RETURN_ROM_OK	(0x5356F000uL)
#define BOOTROM_API_RETURN_ROM_NO_NEED_DECRYPTION	(0x53563C01uL)
#define BOOTROM_API_RETURN_ROM_ERR_PRIVILEGE_ERROR	(0xACA96901uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_INTERNAL_FAIL	(0xAAAA0000uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_INVALID_ARG	(0xAAAA0001uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_UNSUPPORTED_FUNCTION	(0xAAAA0002uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_MANI_INVALID_MAGIC	(0xAAAA0100uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_MANI_UNSUPPORTED_VERSION	(0xAAAA0101uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_MANI_OUT_OF_RANGE_LEN	(0xAAAA0102uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_MANI_TLV_FIELD_ERR	(0xAAAA0103uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_MANI_TLV_INVALID_LEN	(0xAAAA0104uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_MANI_INVALID_IMAGE_LEN	(0xAAAA0105uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_MANI_MISMATCH_SIGN_ALGORITHM \
	(0xAAAA0106uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_MANI_UNSUPPORTED_ALGORITHM \
	(0xAAAA0107uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_CRYPTO_FAIL	(0xAAAA0200uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_CRYPTO_AUTH_FAIL	(0xAAAA0201uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_CRYPTO_UNSUPPORTED_ALGORITHM \
	(0xAAAA0202uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_CRYPTO_PARAM_ERR		(0xAAAA0204uL)
#define BOOTROM_API_RETURN_SB_RET_ERR_IMAGE_COMPARE_HASH	(0xACA93C03uL)

#define SERVICE_RESULT_OK       (0x0uL)
#define NOT_USE                 (0x00000000uL)

/*******************************************************************************
 * Function & variable prototypes
 ******************************************************************************/

uint32_t fwss_secureboot_get_lcs(uint32_t *lcs_out);
uint32_t fwss_secureboot_verify(uint32_t key_cert_addr, uint32_t cnt_cert_addr,
		uint32_t extmac_addr, uint32_t *p_des_addr);
uint32_t fwss_secureboot_decrypt(void);
uint32_t fwss_secureboot_compare(uint32_t *p_hash_cert, uint32_t *p_hash_cal,
		uint32_t hash_size);

#endif /* RCAR_FW_SECURITY_SERVICE_H */
