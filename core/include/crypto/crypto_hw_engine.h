/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Renesas Electronics Corporation
 */

#ifndef __CRYPTO_CRYPTO_HW_ENGINE_H
#define __CRYPTO_CRYPTO_HW_ENGINE_H

#include <tee_api_types.h>

/* This flag notice that it is an algorithm supported by SS6.3-Secure. */
#define SS_HW_NOT_SUPPORT_ALG 0U
/* This flag notice that it is not an algorithm supported by SS6.3-Secure. */
#define SS_HW_SUPPORT_ALG 1U

/*
 * brief: This function enables derivation of 128 bit customer keys
 *        by performing AES CMAC on customer input.
 *
 * param[in] keyType    - Input keyType 0:SESSION_KEY 1:KDR_KEY.
 * param[in] *in        - Input buffer address to make MAC.
 * param[in] inSize     - Size of Input buffer address.
 * param[in] out        - Output buffer address to get result.
 * param[in] outSize    - Size of Output buffer address.
 * return    TEE_Result - TEE internal API error code.
 */
TEE_Result crypto_hw_cmac_derivekey(uint32_t keyType, uint8_t *in,
		uint32_t inSize, uint8_t *out, uint32_t outSize);

/*
 * brief: This function gets RPMB key.
 * param[out] out         - Pointer to 32byte output, to be used as RPMB key.
 * param[out] outSize     - Size of Output buffer size.
 * return     TEE_Result  - TEE internal API error code.
 */
TEE_Result crypto_hw_rpmb_derivekey(uint8_t *out, uint32_t outSize);

/*
 * brief: This function gets RPMB sign frames.
 *
 * param[out] pListOfDataFrames - Pointer to a list of 284 Byte frame addresses.
 *                                The entire frame list will be signed.
 * param[out] listSize          - The number of 284 Byte frames in the list,
 *                                up to 65,535.
 * param[out] out               - Pointer to the output data (HMAC result).
 * param[out] outSize           - Size of Output buffer size.
 * return     TEE_Result        - TEE internal API error code.
 */
TEE_Result crypto_hw_rpmb_signframes(uint64_t *in, uint32_t listSize,
		uint8_t *out, uint32_t outSize);

/*
 * brief: This function provides AES unwrap for a user key or Krdp.
 *
 * param[in]     *srcData       - Input buffer address to make MAC.
 * param[in]     srcLen         - Size of Input buffer address.
 * param[in]     *keyData       - Key data address.
 * param[in]     keySize        - Key data size.
 * param[in]     isSecretKey    - Input keyType 0:User key 1:Krdp.
 * param[out]    *destData      - Output buffer address to get result.
 * param[in/out] *dstLen        - Size of Output buffer address.
 * return        TEE_Result     - TEE internal API error code.
 */
TEE_Result crypto_hw_cipher_unwrap(void *srcData, uint32_t srcLen,
		const void *keyData, uint32_t keySize, uint32_t isSecretKey,
		void *destData, uint32_t *dstLen);

/*
 * brief: This function provides generating Secure Key Package..
 *
 * param[in]  skeyParams      - Structure contains input parameters.
 * param[out] *skeyPackageBuf - Output buffer address to Secure Key Package.
 * return     TEE_Result      - TEE internal API error code.
 */
TEE_Result crypto_hw_gen_skey_package(RCAR_SkeyParams_t *skeyParams,
		uint8_t *skeyPackageBuf, uint32_t skeyPackageSize);

/*
 * brief: This function provides secure provisioning of OEM key.
 *
 * param[in]	 assetId        - Asset ID embedded in the asset package.
 * param[in]	 *pAssetPackage - The encrypted asset package.
 * param[in]	 assetPackagLen	- Package data size.
 * param[out]	 *pAssetData    - The decrypted asset data.
 * param[in/out] *pAssetDataLen - Size of Output buffer address.
 * param[out]	 *pUserData     - Optionally user data embedded in the package.
 * return	- TEE internal API error code.
 */
TEE_Result crypto_hw_asset_unpack(uint32_t assetId, uint8_t *pAssetPackage,
		uint32_t assetPackagLen, uint8_t *pAssetData,
		uint32_t *pAssetDataLen, uint32_t *pUserData);

/* Provide the function to get a context size for cryptographic processing */

/*
 * brief: Get context size to HASH algorithm.
 *
 * param[in]	algo       - Cryptographic algorithm.
 * param[out]	*size      - Size of context to HASH algorithm.
 * return	TEE_Result - TEE internal API error code.
 */
TEE_Result crypto_hw_hash_get_ctx_size(uint32_t algo, size_t *size);

/*
 * brief: Get context size to AES,DES algorithm.
 *
 * param[in]	algo       - Cryptographic algorithm.
 * param[out]	*size      - Size of context to AES,DES algorithm.
 * return	TEE_Result - TEE internal API error code.
 */
TEE_Result crypto_hw_cipher_get_ctx_size(uint32_t algo, size_t *size);

/*
 * brief: Get context size to HMAC,AES-MAC algorithm.
 *
 * param[in]	algo       - Cryptographic algorithm.
 * param[out]	*size      - Size of context to AES,DES algorithm.
 * return	TEE_Result - TEE internal API error code.
 */
TEE_Result crypto_hw_mac_get_ctx_size(uint32_t algo, size_t *size);

/*
 * brief: Check if SS6.3-Secure Driver supports a input HASH algorithm.
 *
 * param[in]	algo     - Cryptographic algorithm.
 * return	uint32_t - Return SS_NOT_SUPPORT_ALG in case of unsupporting
 *                         algorithm.
 *                         Return SS_SUPPORT_ALG in case of supporting
 *                         algorithm.
 */
uint32_t crypto_hw_hash_check_support(uint32_t algo);

/*
 * brief: Check if SS6.3-Secure Driver supports a input MAC algorithm.
 *
 * param[in]	algo     - Cryptographic algorithm.
 * return	uint32_t - Return SS_NOT_SUPPORT_ALG in case of unsupporting
 *                         algorithm.
 *                         Return SS_SUPPORT_ALG in case of supporting
 *                         algorithm.
 */
uint32_t crypto_hw_mac_check_support(uint32_t algo);

/*
 * brief: Check if SS6.3-Secure Driver supports a input cipher algorithm.
 *
 * param[in]	algo     - Cryptographic algorithm.
 * return	uint32_t - Return SS_NOT_SUPPORT_ALG in case of unsupporting
 *                         algorithm.
 *                         Return SS_SUPPORT_ALG in case of supporting
 *                         algorithm.
 */
uint32_t crypto_hw_cipher_check_support(uint32_t algo);

/*
 * brief: Check if SS6.3-Secure Driver supports a input RSA algorithm.
 *
 * param[in]	algo     - Cryptographic algorithm.
 * param[in]	modSize  - Modulus size.
 * return	uint32_t - Return SS_NOT_SUPPORT_ALG in case of unsupporting
 *                         algorithm.
 *                         Return SS_SUPPORT_ALG in case of supporting
 *                         algorithm.
 */
uint32_t crypto_hw_acipher_check_support(uint32_t algo, uint32_t modSize);

/*
 * brief: Check if SS6.3-Secure Driver supports a input RSA key size.
 *
 * param[in]	keySize  - RSA key size.
 * return	uint32_t - Return SS_NOT_SUPPORT_ALG in case of unsupporting
 *                         algorithm.
 *                         Return SS_SUPPORT_ALG in case of supporting
 *                         algorithm.
 */
uint32_t crypto_hw_acipher_check_support_key(uint32_t keySize);

/*
 * brief: Check if SS6.3-Secure Driver supports a ECDSA key size.
 *
 * param[in]	algo     - Cryptographic algorithm.
 * return	uint32_t - Return SS_NOT_SUPPORT_ALG in case of unsupporting
 *                         algorithm.
 *                         Return SS_SUPPORT_ALG in case of supporting
 *                         algorithm.
 */
uint32_t crypto_hw_acipher_ecc_check_support(uint32_t curve);

/*
 * brief: Check if SS6.3-Secure Driver supports a DH key size.
 *
 * param[in]	keySize  - DH key size.
 * return	uint32_t - Return SS_NOT_SUPPORT_ALG in case of unsupporting
 *                         algorithm.
 *                         Return SS_SUPPORT_ALG in case of supporting
 *                         algorithm.
 */
uint32_t crypto_hw_dh_check_support(uint32_t keySize);

/*
 * brief:	Initialize state of HASH algorithm.
 *
 * param[in]	*ctx		- Context to HASH algorithm.
 * param[in]	algo		- Cryptographic algorithm.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_hash_init(void *ctx, uint32_t algo);

/*
 * brief:	Block Data Update state of HASH algorithm.
 *
 * param[in]	*ctx		- Context to HASH algorithm.
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	data		- Pointer to input data buffer.
 * param[in]	len		- Size of the data to HASH algorithm.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_hash_update(void *ctx, uint32_t algo, const uint8_t *data,
		size_t len);

/*
 * brief:	Finalize state of HASH algorithm.
 *
 * param[in]	*ctx		- Context to HASH algorithm.
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	*digest		- Pointer to the output buffer.
 * param[in]	len		- Size of the output data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_hash_final(void *ctx, uint32_t algo, uint8_t *digest,
		size_t len);

/*
 * brief:	Initialize state of AES,DES algorithm.
 *
 * param[in]	*ctx		- Pointer to the AES contest.
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	mode		- Cipher Mode.
 * param[in]	*key1		- Pinter to the AES key.
 * param[in]	key1_len	- AES key size.
 * param[in]	*key2		- Pinter to the AES key(only AES-XST).
 * param[in]	key2_len	- AES key size(only AES-XST).
 * param[in]	*iv		- Pointer to the Initialize vector.
 * param[in]	iv_len		- Initialize vector size.
 * return	SSError_t	- SS provider error code.
 */
TEE_Result crypto_hw_cipher_init(void *ctx, uint32_t algo,
		TEE_OperationMode mode __maybe_unused, const uint8_t *key1,
		size_t key1_len, const uint8_t *iv __maybe_unused,
		size_t iv_len __maybe_unused);

/*
 * brief:	Block Data Update state of AES,DES algorithm.
 *
 * param[in]	*ctx		- Pointer to the AES,DES context.
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	last_block	- If source data is last chunk,
 *                                the value is true.
 * param[in]	*data		- Pointer to source data buffer.
 * param[in]	len		- Source data size.
 * param[in]	*dst		- Pointer to destination data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_cipher_update(void *ctx, uint32_t algo,
		TEE_OperationMode mode __unused,
		bool last_block __maybe_unused, const uint8_t *data, size_t len,
		uint8_t *dst);

/*
 * brief:	Finalize state of AES,DES algorithm.
 *
 * param[in]	*ctx		- Context to HASH algorithm.
 * param[in]	algo		- Cryptographic algorithm.
 * return	TEE_Result	- TEE internal API error code.
 */
void crypto_hw_cipher_final(void *ctx, uint32_t algo);

/*
 * brief:	Initialize state of HMAC,AES-MAC algorithm.
 *
 * param[in]	*ctx		- Pointer to the HASH contest.
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	*key		- Pinter to the Random key.
 * param[in]	len		- Random key size.
 * return	SSError_t	- SS provider error code.
 */
TEE_Result crypto_hw_mac_init(void *ctx, uint32_t algo, const uint8_t *key,
		size_t len);

/*
 * brief:	Block Data Update state of HMAC,AES-MAC algorithm.
 *
 * param[in]	*ctx		- Pointer to the HMAC,AES-MAC context.
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	*data		- Pointer to source data buffer.
 * param[in]	len		- Source data size.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_mac_update(void *ctx, uint32_t algo, const uint8_t *data,
		size_t len);

/*
 * brief:	Finalize state of HMAC,AES-MAC algorithm.
 *
 * param[in]	*ctx		- Context to HMAC,AES-MAC algorithm.
 * param[in]	algo		- Cryptographic algorithm.
 * param[out]	*digest		- Pointer to the digest(MAC) data.
 * param[out]	digest_len	- Digest(MAC) data size.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_mac_final(void *ctx, uint32_t algo, uint8_t *digest,
		size_t digest_len);

/*
 * brief:	Encryption by the RSA primitive (PKCS #1)
 *
 * param[in]	*key		- Pointer to the struct data of RSA key pair.
 * param[in]	*src		- Pointer to the source data.
 * param[in]	src_len		- Size of source data.
 * param[out]	*dst		- Pointer to the destination of the encrypt
 *                                data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_rsanopad_encrypt(struct rsa_public_key *key,
		const uint8_t *src, size_t src_len, uint8_t *dst,
		size_t *dst_len);

/*
 * brief:	Decryption by the RSA primitive (PKCS #1)
 *
 * param[in]	*key		- Pointer to the struct data of RSA key pair.
 * param[in]	*src		- Pointer to the source data.
 * param[in]	src_len		- Size of source data.
 * param[out]	*dst		- Pointer to the destination of the decrypt
 *                                data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_rsanopad_decrypt(struct rsa_keypair *key,
		const uint8_t *src, size_t src_len, uint8_t *dst,
		size_t *dst_len);

/*
 * brief:	Encryption by the RSA(PKCS1 v1.5,OAEP) FIPS 180-4(SHA-1,SHA-2)
 *
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	*key		- Pointer to the struct of the RSA public key.
 * param[in]	*label		- Pointer to the the label data.
 * param[in]	label_len	- Size of the label data.
 * param[in]	*src		- Pointer to the source data buffer.
 * param[in]	*src_len	- Size of source data buffer.
 * param[out]	dst		- Pointer to the destination data buffer.
 * param[out]	*dst_len	- Size of destination data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_rsaes_encrypt(uint32_t algo,
		struct rsa_public_key *key, const uint8_t *label,
		size_t label_len, const uint8_t *src, size_t src_len,
		uint8_t *dst, size_t *dst_len);

/*
 * brief:	Decryption by the RSA(PKCS1 v1.5,OAEP) FIPS 180-4(SHA-1,SHA-2)
 *
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	*key		- Pointer to the struct of the RSA key pair.
 * param[in]	*label		- Pointer to the the label data.
 * param[in]	label_len	- Size of the label data.
 * param[in]	*src		- Pointer to the source data buffer.
 * param[in]	*src_len	- Size of source data buffer.
 * param[out]	dst		- Pointer to the destination data buffer.
 * param[out]	*dst_len	- Size of destination data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_rsaes_decrypt(uint32_t algo,
		struct rsa_keypair *key, const uint8_t *label, size_t label_len,
		const uint8_t *src, size_t src_len, uint8_t *dst,
		size_t *dst_len);

/*
 * brief:	Sign by the RSA (PKCS1 v1.5, PSS) FIPS 180-4 (SHA-1, SHA-2)
 *
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	*key		- Pointer to the struct of the RSA key pair.
 * param[in]	*salt_len	- Pointer to the the salt data.
 * param[in]	*msg		- Pointer to the message data buffer.
 * param[in]	msg_len		- Size of message data buffer.
 * param[out]	*sig		- Pointer to the signature data buffer.
 * param[out]	*sig_len	- Size of signature data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_rsassa_sign(uint32_t algo, struct rsa_keypair *key,
		int salt_len, const uint8_t *msg, size_t msg_len, uint8_t *sig,
		size_t *sig_len);

/*
 * brief:	Verify by the RSA (PKCS1 v1.5, PSS) FIPS 180-4 (SHA-1, SHA-2)
 *
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	*key		- Pointer to the struct of the RSA key pair.
 * param[in]	*salt_len	- Pointer to the the salt data.
 * param[in]	*msg		- Pointer to the message data buffer.
 * param[in]	msg_len		- Size of message data buffer.
 * param[in]	*sig		- Pointer to the signature data buffer.
 * param[in]	*sig_len	- Size of signature data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_rsassa_verify(uint32_t algo,
		struct rsa_public_key *key, int salt_len, const uint8_t *msg,
		size_t msg_len, const uint8_t *sig);

/*
 * brief:	Generate RSA key pair.
 *
 * param[out]	*key		- Pointer to the struct data of RSA key pair.
 * param[in]	key_sizse	- Size of RSA key pair.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_gen_rsa_key(struct rsa_keypair *key,
		size_t key_size);

/*
 * brief:	Generate ECC key pair.
 *
 * param[in/out] *key		- Pointer to the struct data of ECC key pair.
 * return	 TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_gen_ecc_key(struct ecc_keypair *key);

/*
 * brief:	Generate DH key pair.
 *
 * param[in/out] *key		- Pointer to the struct data of DH key pair.
 * param[in]	 *q		- Pointer to the bignum data of q(SUBPRIME).
 * param[in]	 *xbits		- Pointer to the bignum data of x bits.
 * return	 TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_gen_dh_key(struct dh_keypair *key,
		struct bignum *q, size_t xbits);

/*
 * brief:	Generate secret key.
 *
 * param[in/out] *private_key	- Pointer to the struct data of DH client
 *                                private key.
 * param[in]	 *public_key	- Pointer to the bignum data of DH server
 *                                public key.
 * param[in]	 *secret	- Pointer to the bignum data of secret key.
 * return	 TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_dh_shared_secret(struct dh_keypair *private_key,
		struct bignum *public_key, struct bignum *secret);

/*
 * brief:	Initialize the random number generato.
 *
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_rng_init(void);

/*
 * brief:	Wrap CRYS_RND_GenerateVector() to output more than 64KB of data.
 *
 * param[in]	*outPtr		- Pointer of output buffer.
 * param[in]	outSize		- Byte size of the output data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_rng_read(void *outPtr, size_t outSize);

/*
 * brief:	Add entropy for PRNG.
 *
 * param[in]	*inbuf		- Pointer to the entropy data buffer.
 * param[in]	len		- Size of entropy data.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_rng_add_entropy(const uint8_t *inbuf, size_t len);

/*
 * brief:	Generate SHA256 from input data and compare it with input digest.
 *
 * param[in]	hash		- HASH data generated from input data.
 * param[in]	data		- Input data address.
 * param[in]    data_size       - Size of input data
 * return	TEE_Result      - TEE Internal API error code.
 */
TEE_Result crypto_hw_hash_sha256_check(const uint8_t *hash, const uint8_t *data,
		size_t data_size);

/*
 * brief:	Sign by the ECC (FIPS 186-4 ANSI X9.62)
 *
 * param[in]	*key		- Pointer to the struct of the ECC key pair.
 * param[in]	*msg		- Pointer to the message data buffer.
 * param[in]	msg_len		- Size of message data buffer.
 * param[out]	*sig		- Pointer to the signature data buffer.
 * param[out]	*sig_len	- Size of signature data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_ecc_sign(struct ecc_keypair *key,
		const uint8_t *msg, size_t msg_len, uint8_t *sig,
		size_t *sig_len);

/*
 * brief:	Verify by the ECC (FIPS 186-4 ANSI X9.62)
 *
 * param[in]	*key		- Pointer to the struct of the ECC key pair.
 * param[in]	*msg		- Pointer to the message data buffer.
 * param[in]	msg_len		- Size of message data buffer.
 * param[in]	*sig		- Pointer to the signature data buffer.
 * param[in]	*sig_len	- Size of signature data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_ecc_verify(struct ecc_public_key *key,
		const uint8_t *msg, size_t msg_len, const uint8_t *sig,
		size_t sig_len);

/*
 * brief:	Generate secret key by the ECC.
 *
 * param[in]	*private_key	- Pointer to the struct data of ECC private key.
 * param[in]	*public_key	- Pointer to the struct data of ECC public key.
 * param[out]	*secret		- Pointer to the secret key data buffer.
 * param[out]	*secret_len	- Pointer to the secret key Size.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_ecc_shared_secret(struct ecc_keypair *private_key,
		struct ecc_public_key *public_key, void *secret,
		unsigned long *secret_len);

/*
 * brief:	Allocate a context for AESCCM algorithm.
 *
 * param[in]	ctx		- Pointer to the AESCCM context.
 * return	TEE_Result	- TEE Internal API error code.
 */
TEE_Result crypto_hw_aes_ccm_alloc_ctx(void **ctx);

/*
 * brief:	Copy a context for AESCCM algorithm.
 *
 * param[in]	dst_ctx		- Pointer to a destination context.
 * param[in]	src_ctx		- Pointer to a source context.
 * return	void
 */
void crypto_hw_aes_ccm_copy_state(void *dst_ctx, const void *src_ctx);

/*
 * brief:	Initialize state of AESCCM algorithm.
 *
 * param[in]	*ctx		- Pointer to the AESCCM contest.
 * param[in]	mode		- Operation Mode (Encrypt or Decrypt).
 * param[in]	*key		- Pinter to the AES key.
 * param[in]	key_len		- AES key size.
 * param[in]	*nonce		- Pinter to the nonce data.
 * param[in]	nonce_len	- nonce data size.
 * param[in]	tag_len		- Tag data size.
 * param[in]	aad_len		- Add data size.
 * param[in]	payload_len	- Payload data size.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_aes_ccm_init(void *ctx, TEE_OperationMode mode,
		const uint8_t *key, size_t key_len, const uint8_t *nonce,
		size_t nonce_len, size_t tag_len, size_t aad_len,
		size_t payload_len);

/*
 * brief:	Block Add Data Update state of AESCCM algorithm.
 *
 * param[in]	*ctx		- Pointer to the AESCCM context.
 * param[in]	*data		- Pointer to source data buffer.
 * param[in]	len		- Source data size.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_aes_ccm_update_aad(void *ctx, const uint8_t *data,
		size_t len);

/*
 * brief:	Block payload data update state of AESCCM algorithm.
 *
 * param[in]	*ctx		- Pointer to the AESCCM context.
 * param[in]	*src_data	- Pointer to source data buffer.
 * param[in]	len		- Source and destination data size.
 * param[in]	*dst_data	- Pointer to destination data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_aes_ccm_update_payload(void *ctx, const uint8_t *src_data,
		size_t len, uint8_t *dst_data);

/*
 * brief:	Finalize state (Encrypt) of AESCCM algorithm.
 *
 * param[in]	*ctx		- Pointer to the AESCCM context.
 * param[in]	*src_data	- Pointer to source data buffer.
 * param[in]	len		- Source and destination data size.
 * param[out]	*dst_data	- Pointer to destination data buffer.
 * param[out]	*dst_tag	- Pointer to tag data buffer.
 * param[out]	dst_tag_len	- Tag data size.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_aes_ccm_enc_final(void *ctx, const uint8_t *src_data,
		size_t len, uint8_t *dst_data, uint8_t *dst_tag,
		size_t *dst_tag_len);

/*
 * brief:	Finalize state (Decrypt) of AESCCM algorithm.
 *
 * param[in]	*ctx		- Pointer to the AESCCM context.
 * param[in]	*src_data	- Pointer to source data buffer.
 * param[in]	len		- Source data size.
 * param[out]	*dst_data	- Pointer to destination data buffer.
 * param[in]	*tag		- Pointer to tag data buffer.
 * param[in]	tag_len		- Tag data size.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_aes_ccm_dec_final(void *ctx, const uint8_t *src_data,
		size_t len, uint8_t *dst_data, const uint8_t *tag,
		size_t tag_len);

/*
 * brief:	In case of SS provider, this function do nothing.
 * return	void
 */
void crypto_hw_aes_ccm_final(void);


#endif /* __CRYPTO_CRYPTO_HW_ENGINE_H */
