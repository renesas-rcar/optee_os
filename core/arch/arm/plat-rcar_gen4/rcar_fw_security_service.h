// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Renesas Electronics Corporation
 */

#ifndef RCAR_FW_SECURITY_SERVICE_H
#define RCAR_FW_SECURITY_SERVICE_H

#define BOOTROMAPI_OK				(0U)
#define ROM_ERR_IMG_VERIFIER_NO_ENCRYPT_IMG	(0xF100001DU)

#define FW_SERVICE_SUCCESS			(0U)
#define FW_SERVICE_FAILURE			(1U)

#define SIZE_OF_LCS_BUFFER			(4U)
#define SIZE_OF_CMAC_BUFFER			(16U)
#define SIZE_OF_HASH_BUFFER			(64U)

#define RST_MODEMR0		p2v_regadr(RST_BASE)
#define RST_MODEMR0_MD5		(0x00000020U)

#define CMAC_COPY		(4U)
#define ICUMIF_STATUS		(0x1000F800UL)

#define BUF_OFS_LCS		SIZE_OF_ISD_BUFFER
#define BUF_OFS_CMAC		(BUF_OFS_LCS + 32U)
#define BUF_OFS_HASH		(BUF_OFS_CMAC + 32U)

/*******************************************************************************
 * Function & variable prototypes
 ******************************************************************************/
uint32_t fwss_service_init(void);
uint32_t fwss_secureboot_get_lcs(uint32_t *lcs_out);
uint32_t fwss_secureboot_verify(uint8_t *key_cert, uint8_t *cnt_cert,
				uint32_t *cmac);
uint32_t fwss_secureboot_dec_and_comp(uint8_t *cnt_cert, uint32_t *cmac);

#endif /* RCAR_FW_SECURITY_SERVICE_H */

