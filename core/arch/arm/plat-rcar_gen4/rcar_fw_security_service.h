// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Renesas Electronics Corporation
 */

#ifndef RCAR_FW_SECURITY_SERVICE_H
#define RCAR_FW_SECURITY_SERVICE_H

#include "r_icumif_api.h"

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

#if defined(RCAR_TRNG_BY_ICUMX_HWENGINE) || defined(RCAR_STORAGE_KEY_BY_ICUMX_HWENGINE)
#define ICUM_FW_SHARED_AREA_SEC_SRV_ADDR	0x41C00480u
#define SIZE_OF_SEC_SRV				512

#define DEF_MAX_TRNG_BLOCKS	32
#define WORD_BLOCK_SIZE		4
#define NEXT_ADDR_ALIGN4(n)	(((n + 3) / 4) * 4)

#define AES_KEY_LEN_128		16u
#define AES_KEY_LEN_256		32u

#define SHE_SINGLE_MESS_SIZE	32u
#define TAG_LEN_128		128u
#define SHE_UID_SIZE		15u
#endif

/******************************************************************************
 *  * Typedefs & Enumerations
 *   ******************************************************************************/
typedef struct
{
	uint8_t M1[SHE_SINGLE_MESS_SIZE];
	uint8_t M2[SHE_SINGLE_MESS_SIZE];
	uint8_t M3[SHE_SINGLE_MESS_SIZE];
	uint8_t M4[SHE_SINGLE_MESS_SIZE];
	uint8_t M5[SHE_SINGLE_MESS_SIZE];
} SHE_key_update_type;

typedef struct __attribute__((__may_alias__))
{
	uint32_t     data01;
	uint32_t     data02;
	uint32_t     data03;
	uint32_t     data04;
	uint32_t     data05;
	uint32_t     data06;
	uint32_t     data07;
	uint32_t     data08;
	uint32_t     data09;
	uint32_t     data10;
	uint32_t     data11;
	uint32_t     data12;
	uint32_t     data13;
	uint32_t     data14;
	uint32_t     data15;

	union {
		uint8_t     *p_data1;
		uint64_t    padding_sys64;
	} ptr1;
	union {
		uint8_t     *p_data2;
		uint64_t    padding_sys64;
	} ptr2;
	union {
		uint8_t     *p_data3;
		uint64_t    padding_sys64;
	} ptr3;
	union {
		uint8_t     *p_data4;
		uint64_t    padding_sys64;
	} ptr4;
	union {
		uint8_t     *p_data5;
		uint64_t    padding_sys64;
	} ptr5;
} CISD_API_TEST_t;

/* aes flags */
typedef struct
{
	uint16_t                encryption:1;
	uint16_t                decryption:1;
	uint16_t                cmac_generation:1;
	uint16_t                cmac_verification:1;
	uint16_t                write_protected:1;
	uint16_t                disable_on_debug:1;
	uint16_t                no_wild_card:1;
} r_aes_flags_t;

/* aes key property */
typedef struct
{
	uint32_t                update_counter;
	uint16_t                key_size_in_bytes;
	r_mem_cluster_verif_t   mem_cluster_verif;
	r_aes_flags_t           flags;
} r_aes_key_prop_t;

/* aes key */
typedef struct
{
	r_key_group_t           key_group;
	r_key_index_t           key_id;
	uint8_t                 vm_id;
	r_aes_key_prop_t        properties;
	uint8_t                 key_value[AES_KEY_LEN_256];
} r_aes_key_t;

/*******************************************************************************
 * Function & variable prototypes
 ******************************************************************************/
uint32_t fwss_service_init(void);
uint32_t fwss_secureboot_get_lcs(uint32_t *lcs_out);
uint32_t fwss_secureboot_verify(uint8_t *key_cert, uint8_t *cnt_cert,
				uint32_t *cmac);
uint32_t fwss_secureboot_dec_and_comp(uint8_t *cnt_cert, uint32_t *cmac);
#if defined(RCAR_TRNG_BY_ICUMX_HWENGINE) || defined(RCAR_STORAGE_KEY_BY_ICUMX_HWENGINE)
extern uint8_t is_init_icum;

uint32_t fwss_trng_generate(void *buf, size_t buf_len);
uint32_t fwss_sys_fw_init(void);
uint32_t fwss_get_current_stage(uint32_t *stage);
uint32_t fwss_lc_set_stage(uint32_t stage);
uint32_t fwss_calculate_MP(void *key_buf, size_t key_len, const uint8_t* const_buf,
		size_t const_len, void* deriv_key_buf, size_t *deriv_key_len);
uint32_t fwss_aes_cipher(cipher_direction_t direction, cipher_modes_t mode,
		r_key_group_t group, r_key_index_t key_id, void *iv, void *input,
		uint8_t buf_len, void *output);
uint32_t fwss_plain_key_update(r_key_group_t group, uint8_t key_id, void *key_buf,
		uint16_t key_len);
uint32_t fwss_aes_cmac(r_key_group_t group, r_key_index_t key_id, void *mess_buf,
		size_t mess_len, void *out_buf, size_t *out_len);
uint32_t fwss_she_key_update(uint8_t she_key_index, void *mess_buf, size_t mess_len);
uint32_t fwss_ext_flash_write(void);
uint32_t fwss_auth_aes_cipher(cipher_direction_t direction, auth_cipher_modes_t mode,
		r_key_group_t group, r_key_index_t key_id, void *iv_buf, size_t iv_len,
		void *auth_buf, size_t auth_len, void *in_buf, size_t in_len,
		void *out_buf, void *tag_buf, size_t tag_len);
uint32_t fwss_get_id(void *uid_buf, size_t *uid_len);
uint32_t fwss_get_key_data(r_key_group_t group, r_key_index_t key_id,
		void *key_buf, size_t key_len);
uint32_t fwss_hmac_import(void *key_buf, size_t key_len, uint8_t hmac_key_id);
uint32_t fwss_hmac_generation(uint8_t hmac_key_id, uint8_t hash_primitive, void *msg_buf,
		size_t msg_len, void *mac_buf, size_t mac_len, uint16_t job_slice);
uint32_t check_icum_init(void);
uint8_t she_key_to_logical_index(uint8_t she_key_index);

static uint8_t __attribute__((unused)) CHALLENGE[16] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};
#endif
#endif /* RCAR_FW_SECURITY_SERVICE_H */

