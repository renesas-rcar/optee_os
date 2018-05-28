/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Renesas Electronics Corporation
 */

#ifndef TEE_STANDALONE_FS_KEY_MANAGER_H
#define TEE_STANDALONE_FS_KEY_MANAGER_H

#include <utee_defines.h>
#include <tee/tee_fs_key_manager.h>

#define SAFS_EK_SIZE		(16)		/* Encryption Key Size */
#define SAFS_IV_LEN		(16)		/* Initial Vector Length */
#define SAFS_TAG_LEN		(16)		/* MAC Length */

struct tee_sfkm_crypt_info {
	const uint8_t *data_in;
	size_t data_size;
	const uint8_t *iv;
	size_t iv_size;
	const uint8_t *key;
	size_t key_size;
};

TEE_Result tee_sfkm_init_key_manager(void);

TEE_Result tee_sfkm_generate_random(uint8_t *buf, uint8_t len);

TEE_Result tee_sfkm_encrypt_suk(struct tee_sfkm_crypt_info *c,
			uint8_t *data_out, uint8_t *tag,
			uint8_t *encrypted_iv);

TEE_Result tee_sfkm_encrypt(const struct tee_sfkm_crypt_info *c,
			uint8_t *data_out, uint8_t *tag);

TEE_Result tee_sfkm_decrypt_suk(struct tee_sfkm_crypt_info *c,
			const uint8_t *tag, uint8_t *data_out,
			uint8_t *decrypted_iv);

TEE_Result tee_sfkm_decrypt(const struct tee_sfkm_crypt_info *c,
			const uint8_t *tag, uint8_t *data_out);

TEE_Result tee_sfkm_generate_sha256(const uint8_t *data_in,
			size_t data_size, uint8_t *hash_out);

#endif /* TEE_STANDALONE_FS_KEY_MANAGER_H */
