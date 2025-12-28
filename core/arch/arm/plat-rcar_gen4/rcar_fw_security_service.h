// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Renesas Electronics Corporation
 */

#ifndef RCAR_FW_SECURITY_SERVICE_H
#define RCAR_FW_SECURITY_SERVICE_H

#include "r_icumif_api.h"
#include <stdbool.h>
#include "platform_config.h"

#define BOOTROMAPI_OK				(0U)
#define ROM_ERR_IMG_VERIFIER_NO_ENCRYPT_IMG	(0xF100001DU)

#define FW_SERVICE_SUCCESS			(0U)
#define FW_SERVICE_FAILURE			(1U)

#define SIZE_OF_LCS_BUFFER			(4U)
#define SIZE_OF_CMAC_BUFFER			(16U)
#define SIZE_OF_HASH_BUFFER			(64U)

#define RST_MODEMR0		p2v_regadr(RST_BASE, DEVICE0_SIZE)
#define RST_MODEMR0_MD5		(0x00000020U)

#define CMAC_COPY		(4U)
#define ICUMIF_STATUS		(0x1000F800UL)

#define BUF_OFS_LCS		SIZE_OF_ISD_BUFFER
#define BUF_OFS_CMAC		(BUF_OFS_LCS + 32U)
#define BUF_OFS_HASH		(BUF_OFS_CMAC + 32U)

#if defined(RCAR_TRNG_BY_ICUMX_HWENGINE) || defined(RCAR_SECURE_STORAGE_BY_ICUMX_HWENGINE)
#define ICUM_FW_SHARED_AREA_SEC_SRV_ADDR	ADDR_ASSIGN_RGID(0x41D00480u, CFG_RCAR_RGID)
#define SIZE_OF_SEC_SRV				512

#define DEF_MAX_TRNG_BLOCKS	32
#define WORD_BLOCK_SIZE		4
#define NEXT_ADDR_ALIGN4(n)	(((n + 3) / 4) * 4)

#define AES_KEY_LEN_128		16u
#define AES_KEY_LEN_256		32u

#define ENABLE_KEY_WRITE_PROTECT	1u
#define DISABLE_KEY_WRITE_PROTECT	0u

#define KEY_GRP_AES_STR		"KEY_GRP_AES"
#define KEY_GRP_AES_RAM_STR	"KEY_GRP_AES_RAM"
#define KEY_GRP_AES_CR_STR	"KEY_GRP_AES_CR"
#endif

/*******************************************************************************
 * Function & variable prototypes
 ******************************************************************************/
uint32_t fwss_service_init(void);
uint32_t fwss_secureboot_get_lcs(uint32_t *lcs_out);
uint32_t fwss_secureboot_verify(uint8_t *key_cert, uint8_t *cnt_cert,
				uint32_t *cmac);
uint32_t fwss_secureboot_dec_and_comp(uint8_t *cnt_cert, uint32_t *cmac);
#if defined(RCAR_TRNG_BY_ICUMX_HWENGINE) || defined(RCAR_SECURE_STORAGE_BY_ICUMX_HWENGINE)
uint32_t fwss_trng_generate(void *buf, size_t buf_len);
uint32_t fwss_sys_fw_init(void);
uint32_t fwss_set_mono_ctr(uint8_t nb_monoctr_nv);
uint32_t fwss_init_mydata_set(uint8_t nb_items, uint16_t item_size_in_bytes);
uint32_t fwss_get_current_stage(uint32_t *current_stage);
uint32_t fwss_lc_set_stage(uint32_t stage);
uint32_t fwss_plain_key_update(r_key_group_t key_group, uint8_t key_id,
		void *key_buf, uint16_t key_len, uint8_t write_protected);
uint32_t fwss_aes_cmac(r_key_group_t group, r_key_index_t key_id, void *mess_buf,
		size_t mess_len, void *out_buf);
uint32_t fwss_ext_flash_write(void);
uint32_t fwss_auth_aes_cipher(cipher_direction_t direction, auth_cipher_modes_t mode,
		r_key_group_t key_group, r_key_index_t key_id, void *iv_buf, size_t iv_len,
		void *auth_buf, size_t auth_len, void *in_buf, size_t in_len,
		void *out_buf, void *tag_buf, size_t tag_len);
uint32_t fwss_hmac_import(void *key_buf, size_t key_len, uint8_t hmac_key_id);
uint32_t fwss_hmac_generation(uint8_t hmac_key_id, uint8_t hash_primitive, void *msg_buf,
		size_t msg_len, void *mac_buf, size_t mac_len, uint16_t job_slice);
uint32_t check_icum_init(void);
#endif
#endif /* RCAR_FW_SECURITY_SERVICE_H */

