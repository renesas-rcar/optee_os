/*
 * Copyright (c) 2016, Renesas Electronics Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
