// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2016-2018, Renesas Electronics Corporation
 */


/* Acronyms:
 *
 * SST - Secure Storage
 * SSK - Secure Storage Key
 * IV  - Initial vector
 * HUK - Hardware Unique Key
 * RNG - Random Number Generator
 *
 * SUK - Soc Unique encryption Key
 * IVEK- IV Encryption Key
 *
 */

#include <initcall.h>
#include <stdlib.h>
#include <string.h>
#include <kernel/tee_common_otp.h>
#include <tee/tee_cryp_utl.h>
#include <crypto/crypto.h>
#include <tee/tee_fs_key_manager.h>
#include <compiler.h>
#include <trace.h>
#include <util.h>

#include "tee_standalone_fs_key_manager.h"

static const uint8_t string_for_ssk_gen[] = "ONLY_FOR_tee_fs_ssk";
static uint8_t g_safs_suk[SAFS_EK_SIZE];
static uint8_t g_safs_ivek[TEE_SHA256_HASH_SIZE];

static TEE_Result generate_ssk(uint8_t *ssk, uint32_t ssk_size,
			uint8_t *huk, uint32_t huk_size,
			uint8_t *message, uint32_t message_size);
static TEE_Result crypt_aes(uint32_t algo, TEE_OperationMode mode,
			const struct tee_sfkm_crypt_info *c,
			uint8_t *data_out);
static TEE_Result generate_cmac(const uint8_t *data_in, size_t data_size,
			uint8_t *mac_out, const uint8_t *key, size_t key_size,
			const uint8_t *data2_in, size_t data2_size);

TEE_Result tee_sfkm_generate_random(uint8_t *buf, uint8_t len)
{
	return crypto_rng_read(buf, len);
}

static TEE_Result generate_ssk(uint8_t *ssk, uint32_t ssk_size,
			uint8_t *huk, uint32_t huk_size,
			uint8_t *message, uint32_t message_size)
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx = NULL;
	const uint32_t algo = TEE_FS_KM_HMAC_ALG;

	if ((ssk == NULL) || (huk == NULL) || (message == NULL)) {
		res = TEE_ERROR_BAD_PARAMETERS;
	}

	if (res == TEE_SUCCESS) {
		res = crypto_mac_alloc_ctx(&ctx, algo);
	}

	if (res == TEE_SUCCESS) {
		res = crypto_mac_init(ctx, algo, huk, huk_size);
	}

	if (res == TEE_SUCCESS) {
		res = crypto_mac_update(ctx, algo, message, message_size);
	}

	if (res == TEE_SUCCESS) {
		res = crypto_mac_final(ctx, algo, ssk, ssk_size);
	}

	if (ctx != NULL) {
		free(ctx);
	}

	return res;
}

TEE_Result tee_sfkm_init_key_manager(void)
{
	int res;
	struct tee_hw_unique_key huk;
	uint8_t chip_id[TEE_FS_KM_CHIP_ID_LENGTH];
	uint8_t message[sizeof(chip_id) + sizeof(string_for_ssk_gen)];
	uint8_t ssk[TEE_FS_KM_SSK_SIZE];

	/* Secure Storage Key Generation:
	 *
	 *     SSK = HMAC(HUK, message)
	 *     message := concatenate(chip_id, static string)
	 * */
	tee_otp_get_hw_unique_key(&huk);
	(void)tee_otp_get_die_id(chip_id, sizeof(chip_id));

	(void)memcpy(message, chip_id, sizeof(chip_id));
	(void)memcpy(message + sizeof(chip_id), string_for_ssk_gen,
			sizeof(string_for_ssk_gen));

	res = generate_ssk(ssk, sizeof(ssk),
			huk.data, sizeof(huk.data),
			message, sizeof(message));

	/* Soc Unique encryption Key Generation:
	 *
	 *     SUK = CMAC(SSK, chip_id)
	 */
	if (res == TEE_SUCCESS) {
		res = generate_cmac(chip_id, sizeof(chip_id),
				g_safs_suk, ssk, sizeof(ssk),
				NULL, 0U);
	}

	/* IV Encryption Key Generation:
	 *
	 *     IVEK = SHA-256(SUK)
	 */
	if (res == TEE_SUCCESS) {
		res = tee_sfkm_generate_sha256(g_safs_suk,
			sizeof(g_safs_suk), g_safs_ivek);
	}

	return res;
}

TEE_Result tee_sfkm_encrypt_suk(struct tee_sfkm_crypt_info *c,
			uint8_t *data_out, uint8_t *tag,
			uint8_t *encrypted_iv)
{
	TEE_Result res;
	struct tee_sfkm_crypt_info iv_enc_info;

	c->key = g_safs_suk;
	c->key_size = sizeof(g_safs_suk);

	res = tee_sfkm_encrypt(c, data_out, NULL);

	if (res == TEE_SUCCESS) {
		iv_enc_info.data_in	= c->iv;
		iv_enc_info.data_size	= c->key_size;
		iv_enc_info.iv		= NULL;
		iv_enc_info.iv_size	= 0U;
		iv_enc_info.key		= g_safs_ivek;
		iv_enc_info.key_size	= sizeof(g_safs_ivek);

		res = crypt_aes(TEE_ALG_AES_ECB_NOPAD, TEE_MODE_ENCRYPT,
				&iv_enc_info, encrypted_iv);
	}

	if (res == TEE_SUCCESS) {
		/* Encrypt-then-MAC */
		res = generate_cmac(data_out, c->data_size,
				tag, c->key, c->key_size,
				encrypted_iv, c->iv_size);
	}

	return res;
}

TEE_Result tee_sfkm_encrypt(const struct tee_sfkm_crypt_info *c,
			uint8_t *data_out, uint8_t *tag)
{
	TEE_Result res;

	res = crypt_aes(TEE_ALG_AES_CBC_NOPAD, TEE_MODE_ENCRYPT,
			c, data_out);

	if ((res == TEE_SUCCESS) && (tag != NULL)) {
		/* Encrypt-then-MAC */
		res = generate_cmac(data_out, c->data_size,
				tag, c->key, c->key_size,
				NULL, 0U);
	}

	return res;
}

TEE_Result tee_sfkm_decrypt_suk(struct tee_sfkm_crypt_info *c,
			const uint8_t *tag, uint8_t *data_out,
			uint8_t *decrypted_iv)
{
	TEE_Result res;
	uint8_t mac_buf[SAFS_TAG_LEN];
	struct tee_sfkm_crypt_info iv_dec_info;

	c->key = g_safs_suk;
	c->key_size = sizeof(g_safs_suk);

	/* Encrypt-then-MAC */
	res = generate_cmac(c->data_in, c->data_size,
			mac_buf, c->key, c->key_size,
			c->iv, c->iv_size);

	if (res == TEE_SUCCESS) {
		if (memcmp(mac_buf, tag, SAFS_TAG_LEN) != 0) {
			res = TEE_ERROR_MAC_INVALID;
			DMSG("MAC mismatched");
		}
	}

	if (res == TEE_SUCCESS) {
		iv_dec_info.data_in	= c->iv; /* Encrypted IV */
		iv_dec_info.data_size	= c->key_size;
		iv_dec_info.iv		= NULL;
		iv_dec_info.iv_size	= 0U;
		iv_dec_info.key		= g_safs_ivek;
		iv_dec_info.key_size	= sizeof(g_safs_ivek);

		res = crypt_aes(TEE_ALG_AES_ECB_NOPAD, TEE_MODE_DECRYPT,
				&iv_dec_info, decrypted_iv);

		if (res == TEE_SUCCESS) {
			c->iv = decrypted_iv;
			c->key = g_safs_suk;
			c->key_size = sizeof(g_safs_suk);

			res = crypt_aes(TEE_ALG_AES_CBC_NOPAD, TEE_MODE_DECRYPT,
					c, data_out);
		}
	}

	return res;
}

TEE_Result tee_sfkm_decrypt(const struct tee_sfkm_crypt_info *c,
			const uint8_t *tag, uint8_t *data_out)
{
	TEE_Result res;
	uint8_t mac_buf[SAFS_TAG_LEN];

	/* Encrypt-then-MAC */
	res = generate_cmac(c->data_in, c->data_size,
			mac_buf, c->key, c->key_size,
			NULL, 0U);

	if (res == TEE_SUCCESS) {
		if (memcmp(mac_buf, tag, SAFS_TAG_LEN) != 0) {
			res = TEE_ERROR_MAC_INVALID;
			DMSG("MAC mismatched");
		}
	}

	if (res == TEE_SUCCESS) {
		res = crypt_aes(TEE_ALG_AES_CBC_NOPAD, TEE_MODE_DECRYPT,
				c, data_out);
	}

	return res;
}

TEE_Result tee_sfkm_generate_sha256(const uint8_t *data_in, size_t data_size,
			uint8_t *hash_out)
{
	TEE_Result res;
	void *ctx = NULL;
	const uint32_t algo = TEE_ALG_SHA256;

	res = crypto_hash_alloc_ctx(&ctx, algo);

	if (res == TEE_SUCCESS) {
		res = crypto_hash_init(ctx, algo);
	}

	if (res == TEE_SUCCESS) {
		res = crypto_hash_update(ctx, algo, data_in, data_size);
	}

	if (res == TEE_SUCCESS) {
		res = crypto_hash_final(ctx, algo, hash_out,
				TEE_SHA256_HASH_SIZE);
	}

	if (ctx != NULL) {
		free(ctx);
	}

	if ((res != TEE_SUCCESS) && (res != TEE_ERROR_OUT_OF_MEMORY)) {
		EMSG("crypto_provider hash error. 0x%x", res);
		res = TEE_ERROR_SECURITY;
	}

	return res;
}

static TEE_Result crypt_aes(uint32_t algo, TEE_OperationMode mode,
			const struct tee_sfkm_crypt_info *c,
			uint8_t *data_out)
{
	TEE_Result res;
	void *ctx = NULL;

	res = crypto_cipher_alloc_ctx(&ctx, algo);

	if (res == TEE_SUCCESS) {
		res = crypto_cipher_init(ctx, algo, mode, c->key,
				c->key_size, NULL, 0, c->iv, c->iv_size);
	}

	if (res == TEE_SUCCESS) {
		res = crypto_cipher_update(ctx, algo, mode, true,
				c->data_in, c->data_size, data_out);
	}

	if (res == TEE_SUCCESS) {
		crypto_cipher_final(ctx, algo);
		res = TEE_SUCCESS;
	}

	if (ctx != NULL) {
		free(ctx);
	}

	if ((res != TEE_SUCCESS) && (res != TEE_ERROR_OUT_OF_MEMORY)) {
		EMSG("crypto_provider cipher error. 0x%x", res);
		res = TEE_ERROR_SECURITY;
	}

	return res;
}

static TEE_Result generate_cmac(const uint8_t *data_in, size_t data_size,
			uint8_t *mac_out, const uint8_t *key, size_t key_size,
			const uint8_t *data2_in, size_t data2_size)
{
	TEE_Result res;
	void *ctx = NULL;
	const uint32_t algo = TEE_ALG_AES_CMAC;
	const size_t mac_size = TEE_AES_BLOCK_SIZE;

	res = crypto_mac_alloc_ctx(&ctx, algo);

	if (res == TEE_SUCCESS) {
		res = crypto_mac_init(ctx, algo, key, key_size);
	}

	if (res == TEE_SUCCESS) {
		res = crypto_mac_update(ctx, algo, data_in, data_size);
	}

	if ((res == TEE_SUCCESS) && (data2_in != NULL)) {
		res = crypto_mac_update(ctx, algo, data2_in, data2_size);
	}

	if (res == TEE_SUCCESS) {
		res = crypto_mac_final(ctx, algo, mac_out, mac_size);
	}

	if (ctx != NULL) {
		free(ctx);
	}

	if ((res != TEE_SUCCESS) && (res != TEE_ERROR_OUT_OF_MEMORY)) {
		EMSG("crypto_provider mac error. 0x%x", res);
		res = TEE_ERROR_SECURITY;
	}

	return res;
}
