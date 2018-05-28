// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2018, Renesas Electronics Corporation
 */

#include <initcall.h>
#include <platform_config.h>
#include <kernel/panic.h>
#include <rcar_suspend_to_ram.h>
#include <crypto/crypto.h>
#include <crypto/aes-ccm.h>
#include "tee_provider_common.h"
#include "include_secure/crys.h"
#include "include_secure/crys_rsa_types.h"
#include "include_secure/crys_rsa_error.h"
#include "include_secure/crys_aes_error.h"
#include "include_secure/crys_des_error.h"
#include "include_secure/crys_hash_error.h"
#include "include_secure/crys_hmac_error.h"
#include "include_secure/crys_aesccm_error.h"
#include "include_secure/crys_rnd_error.h"
#include "include_secure/crys_dh_error.h"
#include "include_secure/crys_ecpki_build.h"
#include "include_secure/dx_cclib.h"
#include "include_secure/dx_util.h"
#include "include_secure/dx_util_error.h"
#include "include_secure/dx_util_rpmb.h"
#include "include_secure/crys_aes_unwrap_rcar.h"
#include "include_secure/crys_suspend_to_ram.h"
#include "include_secure/secure_key_gen.h"


#ifdef CFG_CRYPT_ENABLE_CEPKA
#include "include_pka/crys_pka_suspend_to_ram.h"
#include "tee_pka_provider.h"
#endif

typedef struct {
	CRYS_AESCCM_UserContext_t crys_ctx;
	CRYSError_t crys_error;
	uint8_t restBuf[16U];
	uint32_t restBufSize;
	uint32_t blockSize;
	uint32_t tagSize;
} SS_AESCCM_Context_t;

typedef struct {
	CRYS_AESUserContext_t crys_ctx;
	CRYSError_t crys_error;
	uint8_t restBuf[32U];
	uint32_t restBufSize;
	uint32_t blockSize;
	TEE_OperationMode mode;
} SS_AES_Context_t;

typedef struct {
	CRYS_DESUserContext_t crys_ctx;
	CRYSError_t crys_error;
	uint8_t restBuf[8U];
	uint32_t restBufSize;
	uint32_t blockSize;
} SS_DES_Context_t;

typedef struct {
	CRYS_HASHUserContext_t crys_ctx;
	CRYSError_t crys_error;
	uint8_t restBuf[128U];
	uint32_t restBufSize;
	uint32_t blockSize;
} SS_HASH_Context_t;

typedef struct {
	CRYS_HMACUserContext_t crys_ctx;
	CRYSError_t crys_error;
	uint8_t restBuf[128U];
	uint32_t restBufSize;
	uint32_t blockSize;
} SS_HMAC_Context_t;

typedef enum {
	SS_ALG_AES,
	SS_ALG_DES,
	SS_ALG_HASH,
	SS_ALG_HMAC,
	SS_ALG_AESCCM
}ss_crys_algo;

#define MAX_DATAIN_SIZE (64U*1024U)
#define MAX_DATAIN_CCM_SIZE (512U*1024U)
#define MAX_RSA_KEY_SIZE (512U)

#define CONV_HASHMODE_TO_OAEP(hashMode) \
do { \
	switch (hashMode) { \
	case CRYS_RSA_After_SHA1_mode: \
		(hashMode) = CRYS_RSA_HASH_SHA1_mode; \
		break; \
	case CRYS_RSA_After_SHA224_mode: \
		(hashMode) = CRYS_RSA_HASH_SHA224_mode; \
		break; \
	case CRYS_RSA_After_SHA256_mode: \
		(hashMode) = CRYS_RSA_HASH_SHA256_mode; \
		break; \
	case CRYS_RSA_After_SHA384_mode: \
		(hashMode) = CRYS_RSA_HASH_SHA384_mode; \
		break; \
	case CRYS_RSA_After_SHA512_mode: \
		(hashMode) = CRYS_RSA_HASH_SHA512_mode; \
		break; \
	default: \
		break; \
	} \
}while (0)

#define CHECK_CONTEXT(res,ss_ctx,type,ctx) \
do{ \
	if ((ctx) != NULL) { \
		(ss_ctx) = (type *)(ctx); \
		if ((ss_ctx)->crys_error != (SSError_t)CRYS_OK) { \
			(res) = SS_ERROR_BAD_STATE; \
			PROV_EMSG("BAD_STATE crys_error=0x%08x\n", \
					(ss_ctx)->crys_error); \
		} \
	} else { \
		(res) = SS_ERROR_BAD_PARAMETERS; \
		PROV_EMSG("BAD_PARAMETERS(ctx=NULL)\n"); \
	} \
} while(0)

#define NULL_CHECK_RSA_KEYPAIR(ptr,res) \
do { \
	if(NULL == (ptr)){ \
		(res) = SS_ERROR_BAD_PARAMETERS; \
		PROV_EMSG("BAD_PARAMETERS key is NULL\n"); \
	} else { \
		if((NULL == (ptr)->e) || \
		   (NULL == (ptr)->d) || \
		   (NULL == (ptr)->n) || \
		   (NULL == (ptr)->p) || \
		   (NULL == (ptr)->q) || \
		   (NULL == (ptr)->qp) || \
		   (NULL == (ptr)->dp) || \
		   (NULL == (ptr)->dq)) { \
			(res) = SS_ERROR_BAD_PARAMETERS; \
			PROV_EMSG("BAD_PARAMETERS key menbers are NULL\n"); \
		} \
	} \
}while (0)

#define NULL_CHECK_RSA_PUBLIC_KEY(ptr,res) \
do { \
	if(NULL == (ptr)){ \
		(res) = SS_ERROR_BAD_PARAMETERS; \
		PROV_EMSG("BAD_PARAMETERS key is NULL\n"); \
	} else { \
		if((NULL == (ptr)->e) || \
		   (NULL == (ptr)->n)) { \
			(res) = SS_ERROR_BAD_PARAMETERS; \
			PROV_EMSG("BAD_PARAMETERS key menbers are NULL\n"); \
		} \
	} \
}while (0)

#define NULL_CHECK_DH_KEYPAIR(ptr,res) \
do { \
	if(NULL == (ptr)){ \
		(res) = SS_ERROR_BAD_PARAMETERS; \
		PROV_EMSG("BAD_PARAMETERS key is NULL\n"); \
	} else { \
		if((NULL == (ptr)->g) || \
		   (NULL == (ptr)->p) || \
		   (NULL == (ptr)->x) || \
		   (NULL == (ptr)->y) || \
		   (NULL == (ptr)->q)) { \
			(res) = SS_ERROR_BAD_PARAMETERS; \
			PROV_EMSG("BAD_PARAMETERS key menbers are NULL\n"); \
		} \
	} \
}while (0)

#define NULL_CHECK_ECC_PUBLIC_KEY(ptr,res) \
do { \
	if(NULL == (ptr)){ \
		(res) = SS_ERROR_BAD_PARAMETERS; \
		PROV_EMSG("BAD_PARAMETERS key is NULL\n"); \
	} else { \
		if((NULL == (ptr)->x) || \
		   (NULL == (ptr)->y)) { \
			(res) = SS_ERROR_BAD_PARAMETERS; \
			PROV_EMSG("BAD_PARAMETERS key menbers are NULL\n"); \
		} \
	} \
}while (0)

#define NULL_CHECK_ECC_KEYPAIR(ptr,res) \
do { \
	if(NULL == (ptr)){ \
		(res) = SS_ERROR_BAD_PARAMETERS; \
		PROV_EMSG("BAD_PARAMETERS key is NULL\n"); \
	} else { \
		if((NULL == (ptr)->d) || \
		   (NULL == (ptr)->x) || \
		   (NULL == (ptr)->y)) { \
			(res) = SS_ERROR_BAD_PARAMETERS; \
			PROV_EMSG("BAD_PARAMETERS key menbers are NULL\n"); \
		} \
	} \
}while (0)

#define CHECK_CRYS_ERROR_AESCCM_BASE		(CRYS_AESCCM_MODULE_ERROR_BASE >> 8U)
#define CHECK_CRYS_ERROR_AES_BASE		(CRYS_AES_MODULE_ERROR_BASE >> 8U)

/*************** declaration statement ***************/
/* Provide SS6.3-Secure Driver specific functions */
#if defined(CFG_CRYPTO_ECC)
static SSError_t ss_get_ecc_keysize(uint32_t curve,
		CRYS_ECPKI_DomainID_t *domain_id, uint32_t *key_size_bytes);

#endif
static SSError_t ss_get_rsa_hash(uint32_t algo,
		CRYS_RSA_HASH_OpMode_t *rsa_hashmode, size_t *hashSize,
		CRYS_PKCS1_MGF_t *mgf, CRYS_PKCS1_version *version);
static SSError_t ss_build_pub_key(CRYS_RSAUserPubKey_t **userPubKey,
		struct rsa_public_key *key);
static SSError_t ss_build_priv_key(CRYS_RSAUserPrivKey_t **userPrivKey,
		struct rsa_keypair *key);
static SSError_t ss_aes_init(void *ctx, uint32_t algo, TEE_OperationMode mode,
		const uint8_t *key1, size_t key1_len, const uint8_t *iv,
		size_t iv_len);
static SSError_t ss_des_init(void *ctx, uint32_t algo, TEE_OperationMode mode,
		const uint8_t *key1, size_t key1_len, const uint8_t *iv,
		size_t iv_len);
static SSError_t ss_swap_cts_block(uint32_t algo, uint8_t *dstPtr,
		uint32_t dstSize, uint32_t blockSize);
static SSError_t ss_aes_update(void *ctx, uint32_t algo, bool last_block, const uint8_t *data,
		size_t len, uint8_t *dst);
static SSError_t ss_des_update(void *ctx, uint32_t algo, const uint8_t *data, size_t len,
		uint8_t *dst);
static void ss_aes_final(void *ctx, uint32_t algo);
static void ss_des_final(void *ctx, uint32_t algo);
static SSError_t ss_aesmac_init(void *ctx, uint32_t algo, const uint8_t *key,
		size_t len);
static SSError_t ss_hmac_init(void *ctx, uint32_t algo, const uint8_t *key,
		size_t len);
static SSError_t ss_hmac_update(void *ctx, uint32_t algo, const uint8_t *data, size_t len);
static SSError_t ss_aesmac_update(void *ctx, uint32_t algo, const uint8_t *data,
		size_t len);
static SSError_t ss_hmac_final(void *ctx, uint32_t algo, uint8_t *digest,
		size_t digest_len);
static SSError_t ss_aesmac_final(void *ctx, uint32_t algo, uint8_t *digest, size_t digest_len);
static SSError_t ss_translate_error_crys2ss_init(DX_CclibRetCode_t err);
static SSError_t ss_translate_error_crys2ss_rsa(CRYSError_t err);
static SSError_t ss_translate_error_crys2ss_dh(CRYSError_t err);
static SSError_t ss_translate_error_crys2ss_aes(CRYSError_t err);
static SSError_t ss_translate_error_crys2ss_des(CRYSError_t err);
static SSError_t ss_translate_error_crys2ss_hash(CRYSError_t err);
static SSError_t ss_translate_error_crys2ss_hmac(CRYSError_t err);
static SSError_t ss_translate_error_crys2ss_ccm(CRYSError_t err);
static SSError_t ss_translate_error_crys2ss_rnd(CRYSError_t err);
static SSError_t ss_translate_error_crys2ss_util(DxUTILError_t err);
static SSError_t ss_get_ecc_digest(uint32_t msg_len,
		CRYS_ECPKI_HASH_OpMode_t *hash);
#ifndef CFG_CRYPT_ENABLE_CEPKA
static SSError_t ss_ecc_verify_secure(struct ecc_public_key *key,
		const uint8_t *msg, size_t msg_len, const uint8_t *sig,
		size_t sig_len);
#endif

static SSError_t ss_buffer_update(void *ctx, uint32_t algo,
		const uint8_t *srcData, uint32_t srcLen, uint8_t **dstData);

static SSError_t ss_crys_aes_update(void *ctx, uint8_t *dataIn_ptr,
		uint32_t dataInSize, uint8_t *dataOut_ptr, CRYSError_t *crysRes);
static SSError_t ss_crys_des_update(void *ctx, uint8_t *dataIn_ptr,
		uint32_t dataInSize, uint8_t *dataOut_ptr, CRYSError_t *crysRes);
static SSError_t ss_crys_hash_update(void *ctx, uint8_t *dataIn_ptr,
		uint32_t dataInSize, uint8_t *dataOut_ptr, CRYSError_t *crysRes);
static SSError_t ss_crys_hmac_update(void *ctx, uint8_t *dataIn_ptr,
		uint32_t dataInSize, uint8_t *dataOut_ptr, CRYSError_t *crysRes);
static SSError_t ss_crys_aesccm_update(void *ctx, uint8_t *dataIn_ptr,
		uint32_t dataInSize, uint8_t *dataOut_ptr, CRYSError_t *crysRes);
static void ss_backup_cb(enum suspend_to_ram_state state, uint32_t cpu_id);
static TEE_Result crypto_hw_init_crypto_engine(void);

static SSError_t ss_crys_aes_update(void *ctx, uint8_t *dataIn_ptr,
		uint32_t dataInSize, uint8_t *dataOut_ptr, CRYSError_t *crysRes)
{
	SSError_t res;
	PROV_DMSG("ctx=%p dataIn_prt=%p\n", ctx, dataIn_ptr);
	PROV_DMSG("dataInSize=%d dataOut_ptr=%p\n", dataInSize, dataOut_ptr);
	*crysRes = CRYS_AES_Block((CRYS_AESUserContext_t *)ctx, dataIn_ptr,
			dataInSize, dataOut_ptr);
	res = ss_translate_error_crys2ss_aes(*crysRes);
	PROV_DMSG("crysRes=0x%08x -> res=0x%08x\n", *crysRes, res);
	return res;
}
static SSError_t ss_crys_des_update(void *ctx, uint8_t *dataIn_ptr,
		uint32_t dataInSize, uint8_t *dataOut_ptr, CRYSError_t *crysRes)
{
	SSError_t res;
	PROV_DMSG("ctx=%p dataIn_prt=%p\n", ctx, dataIn_ptr);
	PROV_DMSG("dataInSize=%d dataOut_ptr=%p\n", dataInSize, dataOut_ptr);
	*crysRes = CRYS_DES_Block((CRYS_DESUserContext_t *)ctx, dataIn_ptr,
			dataInSize, dataOut_ptr);
	res = ss_translate_error_crys2ss_des(*crysRes);
	PROV_DMSG("crysRes=0x%08x -> res=0x%08x\n", *crysRes, res);
	return res;
}
static SSError_t ss_crys_hash_update(void *ctx, uint8_t *dataIn_ptr,
		uint32_t dataInSize, uint8_t *dataOut_ptr __unused,
		CRYSError_t *crysRes)
{
	SSError_t res;
	PROV_DMSG("ctx=%p dataIn_prt=%p\n", ctx, dataIn_ptr);
	PROV_DMSG("dataInSize=%d dataOut_ptr=%p\n", dataInSize, dataOut_ptr);
	*crysRes = CRYS_HASH_Update((CRYS_HASHUserContext_t *)ctx, dataIn_ptr,
			dataInSize);
	res = ss_translate_error_crys2ss_hash(*crysRes);
	PROV_DMSG("crysRes=0x%08x -> res=0x%08x\n", *crysRes, res);
	return res;
}
static SSError_t ss_crys_hmac_update(void *ctx, uint8_t *dataIn_ptr,
		uint32_t dataInSize, uint8_t *dataOut_ptr __unused,
		CRYSError_t *crysRes)
{
	SSError_t res;
	PROV_DMSG("ctx=%p dataIn_prt=%p\n", ctx, dataIn_ptr);
	PROV_DMSG("dataInSize=%d dataOut_ptr=%p\n", dataInSize, dataOut_ptr);
	*crysRes = CRYS_HMAC_Update((CRYS_HMACUserContext_t *)ctx, dataIn_ptr,
			dataInSize);
	res = ss_translate_error_crys2ss_hmac(*crysRes);
	PROV_DMSG("crysRes=0x%08x -> res=0x%08x\n", *crysRes, res);
	return res;
}
static SSError_t ss_crys_aesccm_update(void *ctx, uint8_t *dataIn_ptr,
		uint32_t dataInSize, uint8_t *dataOut_ptr, CRYSError_t *crysRes)
{
	SSError_t res;
	PROV_DMSG("ctx=%p dataIn_prt=%p\n", ctx, dataIn_ptr);
	PROV_DMSG("dataInSize=%d dataOut_ptr=%p\n", dataInSize, dataOut_ptr);
	*crysRes = CRYS_AESCCM_BlockTextData((CRYS_AESCCM_UserContext_t *)ctx,
			dataIn_ptr, dataInSize, dataOut_ptr);
	res = ss_translate_error_crys2ss_ccm(*crysRes);
	PROV_DMSG("crysRes=0x%08x -> res=0x%08x\n", *crysRes, res);
	return res;
}

/*****************************************************/

/*
 * brief:	Translate  CRYS API initialize error into SS provider error.
 *
 * param[in]	err		- CRYS API initialize error code
 * return	TEE_Result
 */
static SSError_t ss_translate_error_crys2ss_init(DX_CclibRetCode_t err)
{
	SSError_t res;

	PROV_INMSG("err = 0x%08x\n", err);

	switch (err) {
	case DX_CCLIB_RET_OK:
		PROV_DMSG("res = SS_SUCCESS\n");
		res = SS_SUCCESS;
		break;
	case DX_CCLIB_RET_ENOTSUP:
		PROV_DMSG("res = SS_ERROR_NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	case DX_CCLIB_RET_ENOPERM:
		PROV_DMSG("res = SS_ERROR_BAD_PARAMETERS\n");
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	default:
		PROV_DMSG("res = SS_ERROR_GENERIC\n");
		res = SS_ERROR_GENERIC;
		break;
	}

	PROV_OUTMSG("return res = 0x%08x\n", res);
	return res;
}

/*
 * brief:	Translate  CRYS API RSA error into SS provider error.
 *
 * param[in]	err		- CRYS API RSA error code
 * return	TEE_Result
 */
static SSError_t ss_translate_error_crys2ss_rsa(CRYSError_t err)
{
	SSError_t  res;

	PROV_INMSG("CRYSError_t = 0x%08x\n", err);

	switch ((ulong32)err) {
	case (CRYSError_t)CRYS_OK:
		PROV_DMSG("res = SS_SUCCESS\n");
		res = SS_SUCCESS;
		break;
	case DX_FAIL:
	case CRYS_FATAL_ERROR:
	case CRYS_OUT_OF_RESOURCE_ERROR:
		PROV_DMSG("res = SS_ERROR_GENERIC\n");
		res = SS_ERROR_GENERIC;
		break;
	case CRYS_RSA_BASE_OAEP_DECODE_PARAMETER_STRING_TOO_LONG:
	case CRYS_RSA_BASE_OAEP_ENCODE_MESSAGE_TOO_LONG:
		PROV_DMSG("res = SS_ERROR_SHORT_BUFFER\n");
		res = SS_ERROR_SHORT_BUFFER;
		break;
	case CRYS_RSA_ERROR_VER15_INCONSISTENT_VERIFY:
		PROV_DMSG("res = SS_ERROR_SIGNATURE_INVALID");
		res= SS_ERROR_SIGNATURE_INVALID;
		break;
	case CRYS_RSA_KEY_GEN_CONDITIONAL_TEST_FAIL_ERROR:
	case CRYS_RSA_CAN_NOT_GENERATE_RAND_IN_RANGE:
	case CRYS_RSA_FIPS_MODE_FAIL_ERROR:
	case CRYS_RSA_FIPS_MODE_SF_NOT_PERFORMED_ERROR:
	case CRYS_RSA_INVALID_INPUT_BUFFER_SIZE_ERROR:
		PROV_DMSG("res = SS_ERROR_GENERIC\n");
		res = SS_ERROR_GENERIC;
		break;
	default:
		PROV_DMSG("res = SS_ERROR_BAD_PARAMETERS\n");
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	}

	PROV_OUTMSG("return res = 0x%08x\n", res);
	return res;
}

/*
 * brief:	Translate  CRYS API DH error into SS provider error.
 *
 * param[in]	err		- CRYS API DH error code
 * return	TEE_Result
 */
static SSError_t ss_translate_error_crys2ss_dh(CRYSError_t err)
{
	SSError_t res;

	PROV_INMSG("CRYSError_t = 0x%08x\n", err);

	switch ((ulong32)err) {
	case (CRYSError_t)CRYS_OK:
		PROV_DMSG("res = SS_SUCCESS\n");
		res = SS_SUCCESS;
		break;
	case DX_FAIL:
	case CRYS_FATAL_ERROR:
	case CRYS_OUT_OF_RESOURCE_ERROR:
		PROV_DMSG("res = SS_ERROR_GENERIC\n");
		res = SS_ERROR_GENERIC;
		break;
	case CRYS_DH_IS_NOT_SUPPORTED:
		PROV_DMSG("res = SS_ERROR_NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	default:
		PROV_DMSG("res = SS_ERROR_BAD_PARAMETERS\n");
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	}

	PROV_OUTMSG("return res = 0x%08x\n", res);
	return res;
}

/*
 * brief:	Translate  CRYS API AES error into SS provider error.
 *
 * param[in]	err		- CRYS API AES error code
 * return	TEE_Result
 */
static SSError_t ss_translate_error_crys2ss_aes(CRYSError_t err)
{
	SSError_t res;

	PROV_INMSG("CRYSError_t = 0x%08x\n", err);

	switch ((ulong32)err) {
	case (CRYSError_t)CRYS_OK:
		PROV_DMSG("res = SS_SUCCESS\n");
		res = SS_SUCCESS;
		break;
	case DX_FAIL:
	case CRYS_FATAL_ERROR:
	case CRYS_OUT_OF_RESOURCE_ERROR:
		PROV_DMSG("res = SS_ERROR_GENERIC\n");
		res = SS_ERROR_GENERIC;
		break;
	case CRYS_AES_DECRYPT_MODE_NOT_ALLOWED_ON_CTR_MODE:
	case CRYS_AES_XTS_IS_NOT_SUPPORTED_ON_HW_ERROR:
	case CRYS_AES_DECRYPTION_NOT_ALLOWED_ON_THIS_MODE:
	case CRYS_AES_NOT_ALLOWED_KEY_TYPE_ON_THIS_MODE:
	case CRYS_AES_ILLEGAL_SECRET_KEY_MODE:
	case CRYS_AES_ADDITIONAL_BLOCK_NOT_PERMITTED_ERROR:
	case CRYS_AES_XTS_IS_NOT_SUPPORTED_ERROR:
	case CRYS_AES_IS_NOT_SUPPORTED:
		PROV_DMSG("res = SS_ERROR_NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	case CRYS_AES_UNWRAP_LCS_CHECK_ERROR:
		PROV_DMSG("res = SS_ERROR_LCS_CHECK\n");
		res = SS_ERROR_LCS_CHECK;
		break;
	default:
		PROV_DMSG("res = SS_ERROR_BAD_PARAMETERS\n");
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	}

	PROV_OUTMSG("return res = 0x%08x\n", res);
	return res;
}

/*
 * brief:	Translate  CRYS DES DES error into SS provider error.
 *
 * param[in]	err		- CRYS API DES error code
 * return	TEE_Result
 */
static SSError_t ss_translate_error_crys2ss_des(CRYSError_t err)
{
	SSError_t res;

	PROV_INMSG("CRYSError_t = 0x%08x\n", err);

	switch ((ulong32)err) {
	case (CRYSError_t)CRYS_OK:
		PROV_DMSG("res = SS_SUCCESS\n");
		res = SS_SUCCESS;
		break;
	case DX_FAIL:
	case CRYS_FATAL_ERROR:
	case CRYS_OUT_OF_RESOURCE_ERROR:
		PROV_DMSG("res = SS_ERROR_GENERIC\n");
		res = SS_ERROR_GENERIC;
		break;
	case CRYS_DES_IS_NOT_SUPPORTED:
		PROV_DMSG("res = SS_ERROR_NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	default:
		PROV_DMSG("res = SS_ERROR_BAD_PARAMETERS\n");
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	}

	PROV_OUTMSG("return res = 0x%08x\n", res);
	return res;
}

/*
 * brief:	Translate  CRYS API HASH error into SS provider error.
 *
 * param[in]	err		- CRYS API HASH error code
 * return	TEE_Result
 */
static SSError_t ss_translate_error_crys2ss_hash(CRYSError_t err)
{
	SSError_t res;

	PROV_INMSG("CRYSError_t = 0x%08x\n", err);

	switch ((ulong32)err) {
	case (CRYSError_t)CRYS_OK:
		PROV_DMSG("res = SS_SUCCESS\n");
		res = SS_SUCCESS;
		break;
	case DX_FAIL:
	case CRYS_FATAL_ERROR:
	case CRYS_OUT_OF_RESOURCE_ERROR:
		PROV_DMSG("res = SS_ERROR_GENERIC\n");
		res = SS_ERROR_GENERIC;
		break;
	case CRYS_HASH_LAST_BLOCK_ALREADY_PROCESSED_ERROR:
		PROV_DMSG("res = SS_ERROR_BAD_STATE\n");
		res = SS_ERROR_BAD_STATE;
		break;
	case CRYS_HASH_IS_NOT_SUPPORTED:
		PROV_DMSG("res = SS_ERROR_NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	default:
		PROV_DMSG("res = SS_ERROR_BAD_PARAMETERS\n");
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	}

	PROV_OUTMSG("return res = 0x%08x\n", res);
	return res;
}

/*
 * brief:	Translate  CRYS API HMAC error into SS provider error.
 *
 * param[in]	err		- CRYS API HMAC error code
 * return	TEE_Result
 */
static SSError_t ss_translate_error_crys2ss_hmac(CRYSError_t err)
{
	SSError_t res;

	PROV_INMSG("CRYSError_t = 0x%08x\n", err);

	switch ((ulong32)err) {
	case (CRYSError_t)CRYS_OK:
		PROV_DMSG("res = SS_SUCCESS\n");
		res = SS_SUCCESS;
		break;
	case DX_FAIL:
	case CRYS_FATAL_ERROR:
	case CRYS_OUT_OF_RESOURCE_ERROR:
		PROV_DMSG("res = SS_ERROR_GENERIC\n");
		res = SS_ERROR_GENERIC;
		break;
	case CRYS_HMAC_LAST_BLOCK_ALREADY_PROCESSED_ERROR:
		PROV_DMSG("res = SS_ERROR_BAD_STATE\n");
		res = SS_ERROR_BAD_STATE;
		break;
	case CRYS_HMAC_IS_NOT_SUPPORTED:
		PROV_DMSG("res = SS_ERROR_NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	default:
		PROV_DMSG("res = SS_ERROR_BAD_PARAMETERS\n");
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	}

	PROV_OUTMSG("return res = 0x%08x\n", res);
	return res;
}

/*
 * brief:	Translate  CRYS API AESCCM error into SS provider error.
 *
 * param[in]	err		- CRYS API AESCCM error code
 * return	TEE_Result
 */
static SSError_t ss_translate_error_crys2ss_ccm(CRYSError_t err)
{
	SSError_t res;

	PROV_INMSG("CRYSError_t = 0x%08x\n", err);

	switch ((ulong32)err) {
	case (CRYSError_t)CRYS_OK:
		PROV_DMSG("res = SS_SUCCESS\n");
		res = SS_SUCCESS;
		break;
	case DX_FAIL:
	case CRYS_FATAL_ERROR:
	case CRYS_OUT_OF_RESOURCE_ERROR:
		PROV_DMSG("res = SS_ERROR_GENERIC\n");
		res = SS_ERROR_GENERIC;
		break;
	case CRYS_AESCCM_NOT_ALL_ADATA_WAS_PROCESSED_ERROR:
	case CRYS_AESCCM_NOT_ALL_DATA_WAS_PROCESSED_ERROR:
	case CRYS_AESCCM_ADATA_WAS_PROCESSED_ERROR:
		PROV_DMSG("res = SS_ERROR_BAD_STATE\n");
		res = SS_ERROR_BAD_STATE;
		break;
	case CRYS_AESCCM_ILLEGAL_DMA_BUFF_TYPE_ERROR:
		PROV_DMSG("res = SS_ERROR_GENERIC\n");
		res = SS_ERROR_GENERIC;
		break;
	case CRYS_AESCCM_ADDITIONAL_BLOCK_NOT_PERMITTED_ERROR:
	case CRYS_AESCCM_IS_NOT_SUPPORTED:
		PROV_DMSG("res = SS_ERROR_NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	case CRYS_AESCCM_CCM_MAC_INVALID_ERROR:
		res = SS_ERROR_MAC_INVALID;
		break;
	default:
		PROV_DMSG("res = SS_ERROR_BAD_PARAMETERS\n");
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	}

	PROV_OUTMSG("return res = 0x%08x\n", res);
	return res;
}

/*
 * brief:	Translate  CRYS API RND error into SS provider error.
 *
 * param[in]	err		- CRYS API RND error code
 * return	TEE_Result
 */
static SSError_t ss_translate_error_crys2ss_rnd(CRYSError_t err)
{
	SSError_t res;

	PROV_INMSG("CRYSError_t = 0x%08x\n", err);

	switch ((ulong32)err) {
	case (CRYSError_t)CRYS_OK:
		PROV_DMSG("res = SS_SUCCESS\n");
		res = SS_SUCCESS;
		break;
	case DX_FAIL:
	case CRYS_FATAL_ERROR:
	case CRYS_OUT_OF_RESOURCE_ERROR:
		PROV_DMSG("res = SS_ERROR_GENERIC\n");
		res = SS_ERROR_GENERIC;
		break;
	case CRYS_RND_INSTANTIATION_NOT_DONE_ERROR:
	case CRYS_RND_TRNG_TIME_EXCEED_ERROR:
	case CRYS_RND_TRNG_LOSS_SAMPLES_AND_TIME_EXCEED_ERROR:
		PROV_DMSG("res = SS_ERROR_BAD_STATE\n");
		res = SS_ERROR_BAD_STATE;
		break;
	case CRYS_RND_IS_KAT_MODE_ERROR:
	case CRYS_RND_GEN_A_ERROR:
	case CRYS_RND_GEN_B_ERROR:
	case CRYS_RND_GEN_C_ERROR:
	case CRYS_RND_ILLEGAL_AES_KEY_SIZE_ERROR:
	case CRYS_RND_TRNG_ERRORS_ERROR:
		PROV_DMSG("res = SS_ERROR_GENERIC\n");
		res = SS_ERROR_GENERIC;
		break;
	case CRYS_RND_IS_NOT_SUPPORTED:
		PROV_DMSG("res = SS_ERROR_NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	default:
		PROV_DMSG("res = SS_ERROR_BAD_PARAMETERS\n");
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	}

	PROV_OUTMSG("return res = 0x%08x\n", res);
	return res;
}

/*
 * brief:	Translate  CRYS API ECC error into SS provider error.
 *
 * param[in]	err		- CRYS API ECC error code
 * return	TEE_Result
 */
SSError_t ss_translate_error_crys2ss_ecc(CRYSError_t err)
{
	SSError_t res;

	PROV_INMSG("CRYSError_t = 0x%08x\n", err);

	switch ((ulong32)err) {
	case (CRYSError_t)CRYS_OK:
		PROV_DMSG("res = SS_SUCCESS\n");
		res = SS_SUCCESS;
		break;
	case DX_FAIL:
	case CRYS_FATAL_ERROR:
	case CRYS_OUT_OF_RESOURCE_ERROR:
		PROV_DMSG("res = SS_ERROR_GENERIC\n");
		res = SS_ERROR_GENERIC;
		break;
	case CRYS_ECPKI_GEN_KEY_THIS_D0MAIN_IS_NOT_SUPPORTED_ERROR:
	case CRYS_ECPKI_IS_NOT_SUPPORTED:
		PROV_DMSG("res = SS_ERROR_NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	default:
		PROV_DMSG("res = SS_ERROR_BAD_PARAMETERS\n");
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	}

	PROV_OUTMSG("return res = 0x%08x\n", res);
	return res;
}


/*
 * brief:	Translate  CRYS API RND error into SS provider error.
 *
 * param[in]	err		- CRYS API Util error code
 * return	TEE_Result
 */
static SSError_t ss_translate_error_crys2ss_util(DxUTILError_t err)
{
	SSError_t res;
	PROV_INMSG("CRYSError_t = 0x%08x\n", err);

	switch ((ulong32)err) {
	case DX_UTIL_OK:
		res = SS_SUCCESS;
		break;
	case DX_UTIL_INVALID_KEY_TYPE:
	case DX_UTIL_DATA_IN_POINTER_INVALID_ERROR:
	case DX_UTIL_DATA_IN_SIZE_INVALID_ERROR:
	case DX_UTIL_DATA_OUT_POINTER_INVALID_ERROR:
	case DX_UTIL_DATA_OUT_SIZE_INVALID_ERROR:
	case DX_UTIL_ILLEGAL_PARAMS_ERROR:
	case DX_UTIL_BAD_ADDR_ERROR:
	case DX_UTIL_EK_DOMAIN_INVALID_ERROR:
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	case DX_UTIL_FATAL_ERROR:
	case DX_UTIL_KDR_INVALID_ERROR:
	case DX_UTIL_LCS_INVALID_ERROR:
	default:
		res = SS_ERROR_GENERIC;
		break;
	}
	return res;
}

static SSError_t ss_buffer_update(void *ctx, uint32_t algo,
		const uint8_t *srcData, uint32_t srcLen, uint8_t **dstData)
{
	SSError_t res = SS_SUCCESS;
	CRYSError_t *crysRes;
	ss_crys_algo crysAlgo;
	SS_AES_Context_t *aesCtx;
	SS_DES_Context_t *desCtx;
	SS_HASH_Context_t *hashCtx;
	SS_HMAC_Context_t *hmacCtx;
	SS_AESCCM_Context_t *ccmCtx;
	void * context;
	uint8_t *restBuffer;
	uint32_t *restBufferSize;
	uint32_t updateBlockSize;
	uint32_t copySize;
	uint32_t maxDataInSize = MAX_DATAIN_SIZE;
	uint8_t *srcUpdateData = (uint8_t *)srcData;

	static CRYSError_t (*ss_update[5])(void *ctx, uint8_t *dataIn_ptr,
			uint32_t dataInSize, uint8_t *dataOut_ptr,
			CRYSError_t *crysRes) = {
				[SS_ALG_AES] = &ss_crys_aes_update,
				[SS_ALG_DES] = &ss_crys_des_update,
				[SS_ALG_HASH] = &ss_crys_hash_update,
				[SS_ALG_HMAC] = &ss_crys_hmac_update,
				[SS_ALG_AESCCM] = &ss_crys_aesccm_update
	};

	PROV_INMSG("ctx=%p algo=%d srcData=%p srcLen=%d dstData=%p", ctx, algo,
			srcData, srcLen, dstData);

	switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_AES)
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
#endif
#if defined(CFG_CRYPTO_XCBC_MAC)
	case TEE_ALG_AES_XCBC_MAC:
#endif
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
#endif
#if defined(CFG_CRYPTO_OFB)
	case TEE_ALG_AES_OFB:
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
#endif
		PROV_DMSG("algo=AES (no CCM)\n");
		crysAlgo = SS_ALG_AES;
		aesCtx = (SS_AES_Context_t *)ctx;
		context = (void *)&aesCtx->crys_ctx;
		crysRes = &aesCtx->crys_error;
		restBuffer = aesCtx->restBuf;
		restBufferSize = &aesCtx->restBufSize;
		updateBlockSize = aesCtx->blockSize;
		break;
#if defined(CFG_CRYPTO_CCM)
	case TEE_ALG_AES_CCM:
		PROV_DMSG("algo=AES CCM\n");
		crysAlgo = SS_ALG_AESCCM;
		ccmCtx = (SS_AESCCM_Context_t *)ctx;
		context = (void *)&ccmCtx->crys_ctx;
		crysRes = &ccmCtx->crys_error;
		restBuffer = ccmCtx->restBuf;
		restBufferSize = &ccmCtx->restBufSize;
		updateBlockSize = ccmCtx->blockSize;
		maxDataInSize = MAX_DATAIN_CCM_SIZE;
		break;
#endif
#endif
#if defined(CFG_CRYPTO_DES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
#endif
		PROV_DMSG("algo=DES\n");
		crysAlgo = SS_ALG_DES;
		desCtx = (SS_DES_Context_t *)ctx;
		context = (void *)&desCtx->crys_ctx;
		crysRes = &desCtx->crys_error;
		restBuffer = desCtx->restBuf;
		restBufferSize = &desCtx->restBufSize;
		updateBlockSize = desCtx->blockSize;
		break;
#endif
#if defined(_CFG_CRYPTO_WITH_HASH)
#if defined(CFG_CRYPTO_MD5)
	case TEE_ALG_MD5:
#endif
#if defined(CFG_CRYPTO_SHA1)
	case TEE_ALG_SHA1:
#endif
#if defined(CFG_CRYPTO_SHA224)
	case TEE_ALG_SHA224:
#endif
#if defined(CFG_CRYPTO_SHA256)
	case TEE_ALG_SHA256:
#endif
#if defined(CFG_CRYPTO_SHA384)
	case TEE_ALG_SHA384:
#endif
#if defined(CFG_CRYPTO_SHA512)
	case TEE_ALG_SHA512:
		PROV_DMSG("algo=HASH\n");
		crysAlgo = SS_ALG_HASH;
		hashCtx = (SS_HASH_Context_t *)ctx;
		context = (void *)&hashCtx->crys_ctx;
		crysRes = &hashCtx->crys_error;
		restBuffer = hashCtx->restBuf;
		restBufferSize = &hashCtx->restBufSize;
		updateBlockSize = hashCtx->blockSize;
		break;
#endif
#endif
#if defined(CFG_CRYPTO_HMAC)
#if defined(CFG_CRYPTO_MD5)
	case TEE_ALG_HMAC_MD5:
#endif
#if defined(CFG_CRYPTO_SHA1)
	case TEE_ALG_HMAC_SHA1:
#endif
#if defined(CFG_CRYPTO_SHA224)
	case TEE_ALG_HMAC_SHA224:
#endif
#if defined(CFG_CRYPTO_SHA256)
	case TEE_ALG_HMAC_SHA256:
#endif
#if defined(CFG_CRYPTO_SHA384)
	case TEE_ALG_HMAC_SHA384:
#endif
#if defined(CFG_CRYPTO_SHA512)
	case TEE_ALG_HMAC_SHA512:
#endif
		PROV_DMSG("algo=HMAC\n");
		crysAlgo = SS_ALG_HMAC;
		hmacCtx = (SS_HMAC_Context_t *)ctx;
		context = (void *)&hmacCtx->crys_ctx;
		crysRes = &hmacCtx->crys_error;
		restBuffer = hmacCtx->restBuf;
		restBufferSize = &hmacCtx->restBufSize;
		updateBlockSize = hmacCtx->blockSize;
		break;
#endif
	default:
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	}

	if (res == SS_SUCCESS) {
		if (((*restBufferSize + srcLen) > updateBlockSize)
				&& (*restBufferSize != 0U)) {
			/* There is not yet input data in context. */
			copySize = updateBlockSize - *restBufferSize;
			(void)memcpy(restBuffer + *restBufferSize,
					srcUpdateData, copySize);
			PROV_DMSG("CALL CRYS Update [algo=%d]\n", crysAlgo);
			PROV_DMSG("context=%p restBuffer=%p\n", context,
					restBuffer);
			PROV_DMSG("updateBlockSize=%d dstData=%p\n",
					updateBlockSize, *dstData);
			res = ss_update[crysAlgo](context, restBuffer,
					updateBlockSize, *dstData, crysRes);
			PROV_DMSG("Result : 0x%08x\n", res);
			*restBufferSize = 0U;
			srcUpdateData += copySize;
			srcLen -= copySize;
			if (*dstData != NULL) {
				*dstData += updateBlockSize;
			}
		}
	}

	if (res == SS_SUCCESS) {
		/* There is not yet input data in srcData. */
		while (srcLen >= updateBlockSize) {
			copySize = MIN(ROUNDDOWN(srcLen, updateBlockSize),
					maxDataInSize);
			PROV_DMSG("CALL CRYS Update [algo=%d]\n", crysAlgo);
			PROV_DMSG("context=%p restBuffer=%p\n", context,
					restBuffer);
			PROV_DMSG("updateBlockSize=%d dstData=%p\n",
					updateBlockSize, *dstData);
			res = ss_update[crysAlgo](context, srcUpdateData,
					copySize, *dstData, crysRes);
			PROV_DMSG("Result : 0x%08x\n", res);
			if (res != SS_SUCCESS) {
				break;
			}
			srcUpdateData += copySize;
			srcLen -= copySize;
			if (*dstData != NULL) {
				*dstData += copySize;
			}
		}
		/* Rest data exists ? */
		if ((res == SS_SUCCESS) && (srcLen > 0U)) {
			PROV_DMSG("%d byte data can't input to CRYS API.\n",
					srcLen);
			(void)memcpy((restBuffer + *restBufferSize),
					srcUpdateData, srcLen);
			*restBufferSize += srcLen;
			PROV_DMSG("restBufferSize%d.\n", *restBufferSize);
		}
	}

	PROV_OUTMSG("Return : 0x%08x\n", res);
	return res;
}

/*
 * brief: Check if SS6.3-Secure Driver supports a input HASH algorithm.
 *
 * param[in]	algo     - Cryptographic algorithm.
 * return	uint32_t - Return SS_NOT_SUPPORT_ALG in case of unsupporting
 *                         algorithm.
 *                         Return SS_SUPPORT_ALG in case of supporting
 *                         algorithm.
 */
uint32_t crypto_hw_hash_check_support(uint32_t algo)
{
	uint32_t ret;

	switch ((int32_t)algo) {
	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		ret = SS_HW_SUPPORT_ALG;
		break;
	default:
		ret = SS_HW_NOT_SUPPORT_ALG;
		break;
	}
	PROV_DMSG("ret=%d\n", ret);
	return ret;
}

/*
 * brief: Check if SS6.3-Secure Driver supports a input MAC algorithm.
 *
 * param[in]	algo     - Cryptographic algorithm.
 * return	uint32_t - Return SS_NOT_SUPPORT_ALG in case of unsupporting
 *                         algorithm.
 *                         Return SS_SUPPORT_ALG in case of supporting
 *                         algorithm.
 */
uint32_t crypto_hw_mac_check_support(uint32_t algo)
{
	uint32_t ret;

	switch ((int32_t)algo) {
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		ret = SS_HW_NOT_SUPPORT_ALG;
		break;
	default:
		ret = SS_HW_SUPPORT_ALG;
		break;
	}
	PROV_DMSG("ret=%d\n", ret);
	return ret;
}


/*
 * brief: Check if SS6.3-Secure Driver supports a input cipher algorithm.
 *
 * param[in]	algo     - Cryptographic algorithm.
 * return	uint32_t - Return SS_NOT_SUPPORT_ALG in case of unsupporting
 *                         algorithm.
 *                         Return SS_SUPPORT_ALG in case of supporting
 *                         algorithm.
 */
uint32_t crypto_hw_cipher_check_support(uint32_t algo)
{
	uint32_t ret;
	switch ((int32_t)algo) {
	case TEE_ALG_AES_XTS:
		ret = SS_HW_NOT_SUPPORT_ALG;
		break;
	default:
		ret = SS_HW_SUPPORT_ALG;
		break;
	}
	PROV_DMSG("ret=%d\n", ret);
	return ret;
}

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
uint32_t crypto_hw_acipher_check_support(uint32_t algo, uint32_t modSize)
{
	uint32_t ret;

	ret = crypto_hw_acipher_check_support_key(modSize);

	switch ((int32_t)algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		ret = SS_HW_NOT_SUPPORT_ALG;
		break;
	default:
		break;
	}
	PROV_DMSG("ret=%d\n", ret);
	return ret;
}

/*
 * brief: Check if SS6.3-Secure Driver supports a input RSA key size.
 *
 * param[in]	keySize  - RSA key size.
 * return	uint32_t - Return SS_NOT_SUPPORT_ALG in case of unsupporting
 *                         algorithm.
 *                         Return SS_SUPPORT_ALG in case of supporting
 *                         algorithm.
 */
uint32_t crypto_hw_acipher_check_support_key(uint32_t keySize)
{
	uint32_t ret;

	switch (keySize) {
	case 512U:
	case 1024U:
	case 2048U:
	case 3072U:
	case 4096U:
		ret = SS_HW_SUPPORT_ALG;
		break;
	default:
		ret = SS_HW_NOT_SUPPORT_ALG;
		break;
	}
	PROV_DMSG("ret=%d\n", ret);
	return ret;
}

/*
 * brief: Check if SS6.3-Secure Driver supports ECC.
 *
 * param[in]	curve    - Elliptic Curve Cryptography
 * return	uint32_t - Return SS_NOT_SUPPORT_ALG in case of unsupporting
 *                         algorithm.
 *                         Return SS_SUPPORT_ALG in case of supporting
 *                         algorithm.
 */
uint32_t crypto_hw_acipher_ecc_check_support(uint32_t curve)
{
	uint32_t ret;

	switch ((int32_t)curve) {
	case TEE_ECC_CURVE_NIST_P192:
	case TEE_ECC_CURVE_NIST_P224:
	case TEE_ECC_CURVE_NIST_P256:
	case TEE_ECC_CURVE_NIST_P384:
	case TEE_ECC_CURVE_NIST_P521:
		ret = SS_HW_SUPPORT_ALG;
		break;
	default:
		ret = SS_HW_NOT_SUPPORT_ALG;
		break;
	}
	PROV_DMSG("ret=%d\n", ret);
	return ret;
}

/*
 * brief: Check if SS6.3-Secure Driver supports a DH key size.
 *
 * param[in]	keySize  - DH key size.
 * return	uint32_t - Return SS_NOT_SUPPORT_ALG in case of unsupporting
 *                         algorithm.
 *                         Return SS_SUPPORT_ALG in case of supporting
 *                         algorithm.
 */
uint32_t crypto_hw_dh_check_support(uint32_t keySize)
{
	uint32_t ret;

	switch (keySize) {
	case 1024U:
	case 2048U:
		ret = SS_HW_SUPPORT_ALG;
		break;
	default:
		ret = SS_HW_NOT_SUPPORT_ALG;
		break;
	}
	PROV_DMSG("ret=%d\n", ret);
	return ret;
}


/******************************************************************************
 * Message digest functions
 ******************************************************************************/

/*
 * brief:	Get context size to HASH algorithm.
 *
 * param[in]	algo		- Cryptographic algorithm.
 * param[out]	*size		- Size of context to HASH algorithm.
 * return	TEE_Result	- TEE internal API error code.
 */
#ifdef _CFG_CRYPTO_WITH_HASH
TEE_Result crypto_hw_hash_get_ctx_size(uint32_t algo, size_t *size)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;

	PROV_INMSG("algo=%d, *size=%p\n",algo,size);

	switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_MD5)
	case TEE_ALG_MD5:
#endif
#if defined(CFG_CRYPTO_SHA1)
	case TEE_ALG_SHA1:
#endif
#if defined(CFG_CRYPTO_SHA224)
	case TEE_ALG_SHA224:
#endif
#if defined(CFG_CRYPTO_SHA256)
	case TEE_ALG_SHA256:
#endif
#if defined(CFG_CRYPTO_SHA384)
	case TEE_ALG_SHA384:
#endif
#if defined(CFG_CRYPTO_SHA512)
	case TEE_ALG_SHA512:
#endif
		PROV_DMSG("size = sizeof(SS_HASH_Context_t)\n");
		*size = sizeof(SS_HASH_Context_t);
		break;
	default:
		PROV_EMSG("NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	}
	PROV_DMSG("size=%ld byte\n",*size);
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}


/*
 * brief:	Initialize state of HASH algorithm.
 *
 * param[in]	*ctx		- Context to HASH algorithm.
 * param[in]	algo		- Cryptographic algorithm.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_hash_init(void *ctx, uint32_t algo)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	SS_HASH_Context_t *ss_ctx;
	CRYS_HASHUserContext_t *contextID_ptr;
	CRYS_HASH_OperationMode_t hash_mode;

	PROV_INMSG("*ctx=%p, algo=%d\n",ctx,algo);

	if (ctx != NULL) {
		ss_ctx = (SS_HASH_Context_t *)ctx;
		ss_ctx->crys_error = SS_SUCCESS;
		ss_ctx->restBufSize = 0U;
		ss_ctx->blockSize = 64U;
		contextID_ptr = &ss_ctx->crys_ctx;
	} else {
		res = SS_ERROR_BAD_PARAMETERS;
		PROV_EMSG("BAD_PARAMETERS ctx=%p\n",ctx);
	}
	if (res == SS_SUCCESS) {
		switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_MD5)
		case TEE_ALG_MD5:
			PROV_DMSG("algo = TEE_ALG_MD5\n");
			hash_mode = CRYS_HASH_MD5_mode;
			break;
#endif
#if defined(CFG_CRYPTO_SHA1)
		case TEE_ALG_SHA1:
			PROV_DMSG("algo = TEE_ALG_SHA1\n");
			hash_mode = CRYS_HASH_SHA1_mode;
			break;
#endif
#if defined(CFG_CRYPTO_SHA224)
		case TEE_ALG_SHA224:
			PROV_DMSG("algo = TEE_ALG_SHA224\n");
			hash_mode = CRYS_HASH_SHA224_mode;
			break;
#endif
#if defined(CFG_CRYPTO_SHA256)
		case TEE_ALG_SHA256:
			PROV_DMSG("algo = TEE_ALG_SHA256\n");
			hash_mode = CRYS_HASH_SHA256_mode;
			break;
#endif
#if defined(CFG_CRYPTO_SHA384)
		case TEE_ALG_SHA384:
			PROV_DMSG("algo = TEE_ALG_SHA384\n");
			hash_mode = CRYS_HASH_SHA384_mode;
			ss_ctx->blockSize = 128U;
			break;
#endif
#if defined(CFG_CRYPTO_SHA512)
		case TEE_ALG_SHA512:
			PROV_DMSG("algo = TEE_ALG_SHA512\n");
			hash_mode = CRYS_HASH_SHA512_mode;
			ss_ctx->blockSize = 128U;
			break;
#endif
		default:
			PROV_EMSG("NOT_SUPPORTED\n");
			hash_mode = CRYS_HASH_OperationModeLast;
			res = SS_ERROR_NOT_SUPPORTED;
			break;
		}
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL:CRYS_HASH_Init(%p,0x%08x)\n",contextID_ptr, hash_mode);
		crys_res = CRYS_HASH_Init(contextID_ptr, hash_mode);
		ss_ctx->crys_error = crys_res;
		res = ss_translate_error_crys2ss_hash(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

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
		size_t len)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	SS_HASH_Context_t *ss_ctx;
	uint8_t *nullBuf = NULL;

	PROV_INMSG("*ctx=%p, algo=%d, *data=%p, len=%ld\n", ctx, algo, data,
			len);

	CHECK_CONTEXT(res, ss_ctx, SS_HASH_Context_t, ctx);

	if(SS_SUCCESS == res){
		res = ss_buffer_update(ctx, algo, data, len, &nullBuf);
	}

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

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
		size_t len)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;

	SS_HASH_Context_t *ss_ctx;
	CRYS_HASHUserContext_t *contextID_ptr = NULL;
	CRYS_HASH_Result_t hashResultBuff;

	PROV_INMSG("*ctx=%p, algo=%d, *digest=%p, len=%ld\n",ctx,algo,digest,len);

	if (ctx != NULL) {
		ss_ctx = (SS_HASH_Context_t *)ctx;
		contextID_ptr = &ss_ctx->crys_ctx;
		if (ss_ctx->crys_error != (SSError_t)CRYS_OK) {
			res = SS_ERROR_BAD_STATE;
			PROV_EMSG("BAD_STATE ss_ctx->crys_error=0x%08x\n",ss_ctx->crys_error);
		}
	} else {
		res = SS_ERROR_BAD_PARAMETERS;
		PROV_EMSG("BAD_PARAMETERS(ctx=%p)\n",ctx);
	}

	if (res == SS_SUCCESS) {
		if (NULL == digest) {
			res = SS_ERROR_BAD_PARAMETERS;
			PROV_EMSG("BAD_PARAMETERS(digest=%p)\n", digest);
		}
	}

	if (res == SS_SUCCESS) {
		switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_MD5)
		case TEE_ALG_MD5:
#endif
#if defined(CFG_CRYPTO_SHA1)
		case TEE_ALG_SHA1:
#endif
#if defined(CFG_CRYPTO_SHA224)
		case TEE_ALG_SHA224:
#endif
#if defined(CFG_CRYPTO_SHA256)
		case TEE_ALG_SHA256:
#endif
#if defined(CFG_CRYPTO_SHA384)
		case TEE_ALG_SHA384:
#endif
#if defined(CFG_CRYPTO_SHA512)
		case TEE_ALG_SHA512:
#endif
			PROV_DMSG("algo = 0x%08x\n", algo);
			break;
		default:
			PROV_EMSG("NOT_SUPPORTED\n");
			res = SS_ERROR_NOT_SUPPORTED;
			break;
		}
	}

	if ((res == SS_SUCCESS) && (ss_ctx->restBufSize != 0U)) {
		PROV_DMSG("CALL:  CRYS_HASH_Update(%p,%p,%d)\n",
				contextID_ptr, ss_ctx->restBuf, ss_ctx->restBufSize);
		crys_res = CRYS_HASH_Update(contextID_ptr,
				ss_ctx->restBuf,ss_ctx->restBufSize);
		ss_ctx->crys_error = crys_res;
		res = ss_translate_error_crys2ss_hash(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL:  CRYS_HASH_Finish(%p,%p)\n",contextID_ptr, hashResultBuff);
		crys_res = CRYS_HASH_Finish(contextID_ptr, hashResultBuff);
		ss_ctx->crys_error = crys_res;
		res = ss_translate_error_crys2ss_hash(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
		if (res == SS_SUCCESS) {
			(void)memcpy(digest, hashResultBuff, len);
		}
	}

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}
#endif

/******************************************************************************
 * Asymmetric algorithms
 ******************************************************************************/
#if defined(_CFG_CRYPTO_WITH_ACIPHER)
#if defined(CFG_CRYPTO_RSA)
/*
 * brief:	Generate RSA key pair.
 *
 * param[out]	*key		- Pointer to the struct data of RSA key pair.
 * param[in]	key_sizse	- Size of RSA key pair.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_gen_rsa_key(struct rsa_keypair *key,
		size_t key_size)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	int32_t mpa_res;
	uint8_t *pubExp_ptr = NULL;
	uint16_t pubExpSizeInBytes = 0U;
	CRYS_RSAUserPrivKey_t *pCcUserPrivKey = NULL;
	CRYS_RSAUserPubKey_t *pCcUserPubKey = NULL;
	CRYS_RSAKGData_t *keyGenData = NULL;
	CRYSRSAPrivKey_t *pCcPrivKey = NULL;
	CRYSRSAPubKey_t *pCcPublKey;
	CRYS_RSAConvertKeyToCrtBuffers_t *crt_buffer = NULL;
	void *tmp1 = NULL;
	void *tmp2 = NULL;

	PROV_INMSG("*key=%p, key_size=%ld\n",key,key_size);
	NULL_CHECK_RSA_PUBLIC_KEY(key,res);
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_copy_bn2bin_uint16(%p,%p,%d)\n", key->e,
				&pubExp_ptr, pubExpSizeInBytes);
		res = ss_copy_bn2bin_uint16(key->e, &pubExp_ptr,
				&pubExpSizeInBytes);
		PROV_DMSG("Result: res=0x%08x\n", res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_malloc(%ld,0x%08x)\n",sizeof(CRYS_RSAUserPrivKey_t), res);
		pCcUserPrivKey = (CRYS_RSAUserPrivKey_t *)ss_malloc(
				sizeof(CRYS_RSAUserPrivKey_t), &res);
		PROV_DMSG("Result: res=0x%08x\n",res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_malloc(%ld,0x%08x)\n",sizeof(CRYS_RSAUserPrivKey_t), res);
		pCcUserPubKey = (CRYS_RSAUserPubKey_t *)ss_malloc(
				sizeof(CRYS_RSAUserPubKey_t), &res);
		PROV_DMSG("Result: res=0x%08x\n",res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_malloc(%ld,0x%08x)\n",sizeof(CRYS_RSAUserPrivKey_t), res);
		keyGenData = (CRYS_RSAKGData_t *)ss_malloc(
				sizeof(CRYS_RSAKGData_t), &res);
		PROV_DMSG("Result: res=0x%08x\n",res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_malloc(%ld,0x%08x)\n",sizeof(CRYS_RSAUserPrivKey_t), res);
		crt_buffer = (CRYS_RSAConvertKeyToCrtBuffers_t *)ss_malloc(
				sizeof(CRYS_RSAConvertKeyToCrtBuffers_t), &res);
		PROV_DMSG("Result: res=0x%08x\n",res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: CRYS_RSA_KG_GenerateKeyPairCRT() pubExp_ptr=%p pubExpSizeInBytes=0x%08x\n",
				(void *)pubExp_ptr, pubExpSizeInBytes);
		PROV_DMSG("key_size=%ld, pCcUserPrivKey=%p, pCcUserPubKey=%p, keyGenData=%p\n",
				 key_size, pCcUserPrivKey, pCcUserPubKey, keyGenData);
		crys_res = CRYS_RSA_KG_GenerateKeyPairCRT(pubExp_ptr,
				pubExpSizeInBytes, key_size, pCcUserPrivKey,
				pCcUserPubKey, keyGenData);
		res = ss_translate_error_crys2ss_rsa(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}
	if (res == SS_SUCCESS) {
		pCcPrivKey = (CRYSRSAPrivKey_t *)pCcUserPrivKey->PrivateKeyDbBuff;
		pCcPublKey = (CRYSRSAPubKey_t *)pCcUserPubKey->PublicKeyDbBuff;
		PROV_DMSG("CALL: ss_bn_bin2bn(key->e)\n");
		res = ss_bn_bin2bn((uint8_t *)pCcPublKey->e,
			(ROUNDUP(pCcPublKey->eSizeInBits, 8U) / 8U), key->e);
		PROV_DMSG("Result: res=0x%08x\n",res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_bn_bin2bn(key->n)\n");
		res = ss_bn_bin2bn((uint8_t *)pCcPrivKey->n,
			(ROUNDUP(pCcPrivKey->nSizeInBits, 8U) / 8U), key->n);
		PROV_DMSG("Result: res=0x%08x\n",res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_bn_bin2bn(key->p)\n");
		res = ss_bn_bin2bn((uint8_t *)pCcPrivKey->PriveKeyDb.Crt.P,
			(ROUNDUP(pCcPrivKey->PriveKeyDb.Crt.PSizeInBits, 8U) / 8U),
				key->p);
		PROV_DMSG("Result: res=0x%08x\n",res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_bn_bin2bn(key->q)\n");
		res = ss_bn_bin2bn((uint8_t *)pCcPrivKey->PriveKeyDb.Crt.Q,
			(ROUNDUP(pCcPrivKey->PriveKeyDb.Crt.QSizeInBits, 8U) / 8U),
				key->q);
		PROV_DMSG("Result: res=0x%08x\n",res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_bn_bin2bn(key->qp)\n");
		res = ss_bn_bin2bn((uint8_t *)pCcPrivKey->PriveKeyDb.Crt.qInv,
			(ROUNDUP(pCcPrivKey->PriveKeyDb.Crt.qInvSizeInBits, 8U) / 8U),
				key->qp);
		PROV_DMSG("Result: res=0x%08x\n",res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_bn_bin2bn(key->dp)\n");
		res = ss_bn_bin2bn((uint8_t *)pCcPrivKey->PriveKeyDb.Crt.dP,
			(ROUNDUP(pCcPrivKey->PriveKeyDb.Crt.dPSizeInBits, 8U) / 8U),
				key->dp);
		PROV_DMSG("Result: res=0x%08x\n",res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_bn_bin2bn(key->dq)\n");
		res = ss_bn_bin2bn((uint8_t *)pCcPrivKey->PriveKeyDb.Crt.dQ,
			(ROUNDUP(pCcPrivKey->PriveKeyDb.Crt.dQSizeInBits, 8U) / 8U),
				key->dq);
		PROV_DMSG("Result: res=0x%08x\n",res);
	}
	/* Calculation private exponents (key->d) */
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: bn_alloc_max(&tmp1)\n");
		if(CRYPT_OK != mp_init_multi(&tmp1,&tmp2,NULL)){
			res = SS_ERROR_OUT_OF_MEMORY;
			PROV_DMSG("Result: res=0x%08x\n",res);
		}
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: mp_sub_d(%p,1,%p)\n",key->p,tmp1);
		mpa_res = mp_sub_d(key->p, 1U, tmp2);
		PROV_DMSG("Result: mpa_res=0x%08x\n",mpa_res);

		if (mpa_res == CRYPT_OK) {
			PROV_DMSG("CALL: mp_sub_d(%p,1,%p)\n",key->q,tmp2);
			mpa_res = mp_sub_d(key->q, 1U, tmp1);
			PROV_DMSG("Result: mpa_res=0x%08x\n",mpa_res);
		}
		if (mpa_res == CRYPT_OK) {
			PROV_DMSG("CALL: mp_mul(%p,%p,%p)\n",tmp1,tmp2,tmp1);
			mpa_res = mp_lcm(tmp1, tmp2, tmp1);
			PROV_DMSG("Result: mpa_res=0x%08x\n",mpa_res);
		}
		if (mpa_res == CRYPT_OK) {
			PROV_DMSG("CALL: mp_mul(%p,%p,%p)\n",key->e, tmp1, key->d);
			mpa_res = mp_invmod(key->e, tmp1, key->d);
			PROV_DMSG("Result: mpa_res=0x%08x\n",mpa_res);
		}
		if (mpa_res != CRYPT_OK) {
			res = SS_ERROR_GENERIC;
			PROV_DMSG("Calc [key->d] failed res=0x%08x\n",res);
		}
	}

	mp_clear_multi(tmp1,tmp2,NULL);
	ss_free((void*)pubExp_ptr);
	ss_free((void*)pCcUserPrivKey);
	ss_free((void*)pCcUserPubKey);
	ss_free((void*)keyGenData);
	ss_free((void*)crt_buffer);

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

/*
 * brief:	Build RSA private key.
 *
 * param[out]	**userPrivKey	- RSA private key of Sansa format.
 * param[in]	*key		- RSA private key of TEE internal API format.
 * return	SSError_t	- SS provider error code.
 */
static SSError_t ss_build_priv_key(CRYS_RSAUserPrivKey_t **userPrivKey,
		struct rsa_keypair *key)
{
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	CRYS_RSAUserPrivKey_t *privKey_ptr = NULL;
	uint8_t *e_ptr = NULL;
	uint16_t eSize = 0U;
	uint8_t *d_ptr = NULL;
	uint16_t dSize = 0U;
	uint8_t *n_ptr = NULL;
	uint16_t nSize = 0U;
	uint8_t *dp_ptr = NULL;
	uint16_t dpSize = 0U;
	uint8_t *p_ptr = NULL;
	uint16_t pSize = 0U;
	uint8_t *q_ptr = NULL;
	uint16_t qSize = 0U;
	uint8_t *dq_ptr = NULL;
	uint16_t dqSize = 0U;
	uint8_t *qInv_ptr = NULL;
	uint16_t qInvSize = 0U;

	PROV_INMSG("**userPrivKey=%p, key=%p\n",*userPrivKey,key);
	NULL_CHECK_RSA_KEYPAIR(key,res);
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_malloc(CRYS_RSAUserPrivKey_t)\n");
		privKey_ptr = (CRYS_RSAUserPrivKey_t *)ss_malloc(
				sizeof(CRYS_RSAUserPrivKey_t), &res);
	}
	if (res == SS_SUCCESS) {
		if ((bn_num_bytes(key->p) == 0U)
				|| ((bn_num_bytes(key->n) >= MAX_RSA_KEY_SIZE))) {
			PROV_DMSG("key->e=%p\n", key->e);
			res = ss_copy_bn2bin_uint16(key->e, &e_ptr, &eSize);
			if (res == SS_SUCCESS) {
				PROV_DMSG("key->d=%p\n", key->d);
				res = ss_copy_bn2bin_uint16(key->d, &d_ptr,
						&dSize);
			}
			if (res == SS_SUCCESS) {
				PROV_DMSG("key->n=%p\n", key->n);
				res = ss_copy_bn2bin_uint16(key->n, &n_ptr,
						&nSize);
			}
			if (res == SS_SUCCESS) {
				PROV_DMSG("CALL: CRYS_RSA_Build_PrivKey()\n");
				PROV_DMSG("privKey_ptr=%p\n", privKey_ptr);
				PROV_DMSG("d_ptr=%p dSize=%d\n", d_ptr, dSize);
				PROV_DMSG("e_ptr=%p eSize=%d\n", e_ptr, eSize);
				PROV_DMSG("n_ptr=%p nSize=%d\n", n_ptr, nSize);
				crys_res = CRYS_RSA_Build_PrivKey(privKey_ptr,
						d_ptr, dSize, e_ptr, eSize,
						n_ptr, nSize);
				res = ss_translate_error_crys2ss_rsa(crys_res);
				PROV_DMSG("crys_res=0x%08x -> res=0x%08x\n",
						crys_res, res);
			}
		} else {
			PROV_DMSG("key->p=%p\n", key->p);
			res = ss_copy_bn2bin_uint16(key->p, &p_ptr, &pSize);
			if (res == SS_SUCCESS) {
				PROV_DMSG("key->q=%p\n", key->q);
				res = ss_copy_bn2bin_uint16(key->q, &q_ptr,
						&qSize);
			}
			if (res == SS_SUCCESS) {
				PROV_DMSG("key->dp=%p\n", key->dp);
				res = ss_copy_bn2bin_uint16(key->dp, &dp_ptr,
						&dpSize);
			}
			if (res == SS_SUCCESS) {
				PROV_DMSG("key->dq=%p\n", key->dq);
				res = ss_copy_bn2bin_uint16(key->dq, &dq_ptr,
						&dqSize);
			}
			if (res == SS_SUCCESS) {
				PROV_DMSG("key->qp=%p\n", key->qp);
				res = ss_copy_bn2bin_uint16(key->qp, &qInv_ptr,
						&qInvSize);
			}
			if (res == SS_SUCCESS) {
				PROV_DMSG("CRYS_RSA_Build_PrivKeyCRT()\n");
				PROV_DMSG("privKey_ptr=%p\n", privKey_ptr);
				PROV_DMSG("p_ptr=%p pSize=%d\n", p_ptr, pSize);
				PROV_DMSG("q_ptr=%p qSize=%d\n", q_ptr, qSize);
				PROV_DMSG("dp_ptr=%p nSize=%d\n", dp_ptr,
						dqSize);
				PROV_DMSG("dq_ptr=%p dSize=%d\n", dp_ptr,
						dqSize);
				PROV_DMSG("qInv_ptr=%p qInvSize=%d\n", e_ptr,
						eSize);
				crys_res = CRYS_RSA_Build_PrivKeyCRT(
						privKey_ptr, p_ptr, pSize,
						q_ptr, qSize, dp_ptr, dpSize,
						dq_ptr, dqSize, qInv_ptr,
						qInvSize);
				res = ss_translate_error_crys2ss_rsa(crys_res);
				PROV_DMSG("crys_res=0x%08x -> res=0x%08x\n",
						crys_res, res);
			}
		}
	}
	if (res == SS_SUCCESS) {
		*userPrivKey = privKey_ptr;
	} else {
		ss_free((void*)privKey_ptr);
		PROV_EMSG("ss_build_priv_key\n");
	}

	ss_free((void*)e_ptr);
	ss_free((void*)d_ptr);
	ss_free((void*)n_ptr);
	ss_free((void*)p_ptr);
	ss_free((void*)q_ptr);
	ss_free((void*)dp_ptr);
	ss_free((void*)dq_ptr);
	ss_free((void*)qInv_ptr);
	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}

/*
 * brief:	Build RSA public key.
 *
 * param[out]	**userPubKey	- Double pointer to RSA public key of Sansa format.
 * param[in]	*key		- Pointer to RSA private key of TEE internal API format.
 * return	SSError_t	- SS provider error code.
 */
static SSError_t ss_build_pub_key(CRYS_RSAUserPubKey_t **userPubKey,
		struct rsa_public_key *key)
{
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	CRYS_RSAUserPubKey_t *pubKey_ptr = NULL;
	uint8_t *modulus_ptr = NULL;
	uint8_t *exponent_ptr = NULL;
	uint16_t modulusSize = 0U;
	uint16_t exponentSize = 0U;

	PROV_INMSG("**userPubKey=%p, *key=%p\n",*userPubKey,key);
	NULL_CHECK_RSA_PUBLIC_KEY(key,res);
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_malloc(CRYS_RSAUserPubKey_t)\n");
		pubKey_ptr = (CRYS_RSAUserPubKey_t *)ss_malloc(
				sizeof(CRYS_RSAUserPubKey_t), &res);
	}
	if (res == SS_SUCCESS) {
		res = ss_copy_bn2bin_uint16(key->e,&exponent_ptr,&exponentSize);
	}
	if (res == SS_SUCCESS) {
		res = ss_copy_bn2bin_uint16(key->n,&modulus_ptr,&modulusSize);
	}

	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: CRYS_RSA_Build_PubKey()\n");
		((mpanum)key->n)->d[bn_num_bytes(key->n)-1U] |= 0x1U;
		crys_res = CRYS_RSA_Build_PubKey(pubKey_ptr,
				exponent_ptr,
				exponentSize,
				modulus_ptr,
				modulusSize);
		res = ss_translate_error_crys2ss_rsa(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}
	if (res == SS_SUCCESS) {
		*userPubKey = pubKey_ptr;
	} else {
		ss_free((void*)pubKey_ptr);
		PROV_EMSG("ss_build_publ_key\n");
	}

	ss_free(exponent_ptr);
	ss_free(modulus_ptr);
	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}

/*
 * brief:	Encryption by the RSA primitive (PKCS #1)
 *
 * param[in]	*key		- Pointer to the struct data of RSA key pair.
 * param[in]	*src		- Pointer to the source data.
 * param[in]	src_len		- Size of source data.
 * param[out]	*dst		- Pointer to the destination of the encrypt data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_rsanopad_encrypt(struct rsa_public_key *key,
		const uint8_t *src, size_t src_len, uint8_t *dst,
		size_t *dst_len)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	CRYS_RSAUserPubKey_t *userPubKey_ptr = NULL;
	CRYS_RSAPrimeData_t * primeData_ptr = NULL;
	uint8_t *data_ptr = NULL;
	uint16_t data_len = 0U;
	uint8_t *in_ptr = NULL;
	uint8_t *out_ptr = NULL;
	size_t in_len;
	size_t out_len = 0U;
	size_t offset =0U;

	PROV_INMSG("*key=%p, *src=%p, src_len=%ld, *dst=%p, *dst_len=%p\n",key,src,src_len,dst,dst_len);

	in_len = bn_num_bytes(key->n);

	if(src_len > in_len) {
		res = SS_ERROR_BAD_PARAMETERS;
	} else if (src_len == in_len) {
		data_ptr = (uint8_t *)src;
		data_len = (uint16_t)src_len;
	} else {
		in_ptr = (uint8_t *)ss_calloc(1U, in_len, &res);
		if(res == SS_SUCCESS){
			(void)memcpy(in_ptr, src, src_len);
		}
		data_ptr = in_ptr;
		data_len = (uint16_t)src_len;
	}

	if (res == SS_SUCCESS) {
		out_len = in_len;
		out_ptr = (uint8_t *)ss_calloc(1U,out_len, &res);
	}


	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_malloc(CRYS_RSAPrimeData_t)\n");
		primeData_ptr = (CRYS_RSAPrimeData_t *)ss_malloc(
				sizeof(CRYS_RSAPrimeData_t), &res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_build_pub_key()\n");
		res = ss_build_pub_key(&userPubKey_ptr, key);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: CRYS_RSA_PRIM_Encrypt()\n");
		crys_res = CRYS_RSA_PRIM_Encrypt(userPubKey_ptr, primeData_ptr,
				data_ptr, data_len, out_ptr);
		res = ss_translate_error_crys2ss_rsa(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	/* Remove the zero-padding (leave one zero if buff is all zeroes) */
	if (res == SS_SUCCESS) {
		while ((offset < (out_len - 1U)) && (*(out_ptr + offset) == 0U)) {
			offset++;
		}

		if (*dst_len < (out_len - offset)) {
			*dst_len = out_len - offset;
			res = SS_ERROR_SHORT_BUFFER;
		}
	}

	if (res == SS_SUCCESS) {
		*dst_len = out_len - offset;
		(void)memcpy(dst, (uint8_t *)out_ptr + offset, *dst_len);
	}

	ss_free((void *)in_ptr);
	ss_free((void *)out_ptr);
	ss_free((void *)userPubKey_ptr);
	ss_free((void *)primeData_ptr);

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

/*
 * brief:	Decryption by the RSA primitive (PKCS #1)
 *
 * param[in]	*key		- Pointer to the struct data of RSA key pair.
 * param[in]	*src		- Pointer to the source data.
 * param[in]	src_len		- Size of source data.
 * param[out]	*dst		- Pointer to the destination of the decrypt data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_rsanopad_decrypt(struct rsa_keypair *key,
		const uint8_t *src, size_t src_len, uint8_t *dst,
		size_t *dst_len)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	CRYS_RSAUserPrivKey_t *userPrivKey_ptr = NULL;
	CRYS_RSAPrimeData_t * primeData_ptr = NULL;
	uint8_t *rsaData_ptr;
	uint16_t rsaDataSize;
	uint8_t *outBuf;
	size_t blen;
	size_t offset =0U;

	PROV_INMSG("*key=%p, *src=%p, src_len=%ld, *dst=%p, *dst_len=%p\n",key,src,src_len,dst,dst_len);

	rsaData_ptr = (uint8_t *) src;
	rsaDataSize = (uint16_t) src_len;

	blen = bn_num_bytes(key->n);
	outBuf = (uint8_t *)ss_malloc(blen, &res);

	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_malloc(CRYS_RSAPrimeData_t)\n");
		primeData_ptr = (CRYS_RSAPrimeData_t *)ss_malloc(
				sizeof(CRYS_RSAPrimeData_t), &res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: ss_build_priv_key()\n");
		res = ss_build_priv_key(&userPrivKey_ptr, key);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: CRYS_RSA_PRIM_Decrypt()\n");
		crys_res = CRYS_RSA_PRIM_Decrypt(userPrivKey_ptr, primeData_ptr,
				rsaData_ptr, rsaDataSize, outBuf);
		res = ss_translate_error_crys2ss_rsa(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	/* Remove the zero-padding (leave one zero if buff is all zeroes) */
	if (res == SS_SUCCESS) {
		while ((offset < (blen - 1U)) && (*(outBuf + offset) == 0U)) {
			offset++;
		}
		if (*dst_len < (blen - offset)) {
			*dst_len = blen - offset;
			res = SS_ERROR_SHORT_BUFFER;
		}
	}

	if (res == SS_SUCCESS) {
		*dst_len = blen - offset;
		(void)memcpy(dst, (uint8_t *)outBuf + offset, *dst_len);
	}

	ss_free((void *)userPrivKey_ptr);
	ss_free((void *)primeData_ptr);
	ss_free((void *)outBuf);
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

/*
 * brief:	Decryption by the RSA primitive (PKCS #1)
 *
 * param[in]	algo		- Cryptographic algorithm.
 * param[out]	*rsa_hashmode	- Pointer to the hash mode of the RSA key.
 * param[out]	*hashSize	- Pointer to the size of hash data.
 * param[out]	*mgf		- Pointer to the mask generation functions (MGF).
 * param[out]	*version	- Pointer to the version of the RSA key.
 * return	TEE_Result	- TEE internal API error code.
 */
static SSError_t ss_get_rsa_hash(uint32_t algo,
		CRYS_RSA_HASH_OpMode_t *rsa_hashmode, size_t *hashSize,
		CRYS_PKCS1_MGF_t *mgf, CRYS_PKCS1_version *version)
{
	SSError_t res = SS_SUCCESS;
	PROV_INMSG("algo = 0x%08x\n",algo);
	switch ((int32_t)algo) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
		PROV_DMSG("algo=TEE_ALG_RSAES_PKCS1_V1_5");
		*rsa_hashmode = CRYS_RSA_HASH_NO_HASH_mode;
		*hashSize = 0U;
		*mgf = CRYS_PKCS1_NO_MGF;
		*version = CRYS_PKCS1_VER15;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
		PROV_DMSG("algo=TEE_ALG_RSASSA_PKCS1_V1_5_SHA1");
		*rsa_hashmode = CRYS_RSA_After_SHA1_mode;
		*hashSize = 20U;
		*mgf = CRYS_PKCS1_NO_MGF;
		*version = CRYS_PKCS1_VER15;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
		PROV_DMSG("algo=TEE_ALG_RSASSA_PKCS1_V1_5_SHA224");
		*rsa_hashmode = CRYS_RSA_After_SHA224_mode;
		*hashSize = 28U;
		*mgf = CRYS_PKCS1_NO_MGF;
		*version = CRYS_PKCS1_VER15;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
		PROV_DMSG("algo=TEE_ALG_RSASSA_PKCS1_V1_5_SHA256");
		*rsa_hashmode = CRYS_RSA_After_SHA256_mode;
		*hashSize = 32U;
		*mgf = CRYS_PKCS1_NO_MGF;
		*version = CRYS_PKCS1_VER15;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
		PROV_DMSG("algo=TEE_ALG_RSASSA_PKCS1_V1_5_SHA384");
		*rsa_hashmode = CRYS_RSA_After_SHA384_mode;
		*hashSize = 48U;
		*mgf = CRYS_PKCS1_NO_MGF;
		*version = CRYS_PKCS1_VER15;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		PROV_DMSG("algo=TEE_ALG_RSASSA_PKCS1_V1_5_SHA512");
		*rsa_hashmode = CRYS_RSA_After_SHA512_mode;
		*mgf = CRYS_PKCS1_NO_MGF;
		*hashSize = 64U;
		*version = CRYS_PKCS1_VER15;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		PROV_DMSG("algo=TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1");
		*rsa_hashmode = CRYS_RSA_After_SHA1_mode;
		*hashSize = 20U;
		*mgf = CRYS_PKCS1_MGF1;
		*version = CRYS_PKCS1_VER21;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		PROV_DMSG("algo=TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224");
		*rsa_hashmode = CRYS_RSA_After_SHA224_mode;
		*hashSize = 28U;
		*mgf = CRYS_PKCS1_MGF1;
		*version = CRYS_PKCS1_VER21;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		PROV_DMSG("algo=TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256");
		*rsa_hashmode = CRYS_RSA_After_SHA256_mode;
		*hashSize = 32U;
		*mgf = CRYS_PKCS1_MGF1;
		*version = CRYS_PKCS1_VER21;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		PROV_DMSG("algo=TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384");
		*rsa_hashmode = CRYS_RSA_After_SHA384_mode;
		*hashSize = 48U;
		*mgf = CRYS_PKCS1_MGF1;
		*version = CRYS_PKCS1_VER21;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		PROV_DMSG("algo=TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512");
		*rsa_hashmode = CRYS_RSA_After_SHA512_mode;
		*hashSize = 64U;
		*mgf = CRYS_PKCS1_MGF1;
		*version = CRYS_PKCS1_VER21;
		break;
	default:
		PROV_EMSG("NOT_SUPPORTED\n");
		*rsa_hashmode = CRYS_RSA_HASH_OpModeLast;
		*hashSize = 0U;
		*mgf = CRYS_PKCS1_MGFLast;
		*version = CRYS_PKCS1_versionLast;
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	}
	PROV_DMSG("*rsa_hashmode=0x%08x, *hashSize=0x%08lx,*mgf=0x%08x,*version=0x%08x\n",
			*rsa_hashmode, *hashSize,*mgf,*version);

	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}

/*
 * brief:	Encryption by the RSA (PKCS1 v1.5, OAEP) FIPS 180-4 (SHA-1, SHA-2)
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
		uint8_t *dst, size_t *dst_len)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	CRYS_RSAUserPubKey_t *userPubKey_ptr = NULL;
	CRYS_RSAPrimeData_t *primeData_ptr = NULL;
	CRYS_RSA_HASH_OpMode_t hashFunc;
	CRYS_PKCS1_MGF_t mgf;
	uint8_t *l;
	uint16_t llen;
	uint8_t *dataIn_ptr;
	uint16_t dataInSize;
	uint8_t *output_ptr;
	CRYS_PKCS1_version version;
	size_t modulas_size;
	size_t hashSize;

	PROV_INMSG("algo=%d, *key=%p, *label=%p, label_len=%ld\n",algo,key,label,label_len);
	PROV_INMSG("*src=%p, src_len=%ld, *dst=%p, dst_len=%p\n",src,src_len,dst,dst_len);


	PROV_DMSG("Input key->e\n");
	PROV_DHEXDUMP(key->e,bn_num_bytes(key->e));
	PROV_DMSG("Input key->n\n");
	PROV_DHEXDUMP(key->n,bn_num_bytes(key->n));
	PROV_DMSG("Input label\n");
	PROV_DHEXDUMP(label,label_len);
	PROV_DMSG("Input src  src_len=%ld\n",src_len);
	PROV_DHEXDUMP(src,src_len);

	output_ptr = dst;
	l = (uint8_t *)label;
	llen = (uint16_t)label_len;
	dataIn_ptr = (uint8_t *)src;
	dataInSize = (uint16_t)src_len;

	NULL_CHECK_RSA_PUBLIC_KEY(key,res);
	if (res == SS_SUCCESS) {
		modulas_size = bn_num_bytes(key->n);
		if (NULL == dst_len) {
			res = SS_ERROR_BAD_PARAMETERS;
			PROV_EMSG("BAD_PARAMETERS(key=%p)\n", key);
		} else {
			if (*dst_len < modulas_size) {
				res = SS_ERROR_SHORT_BUFFER;
			}
			*dst_len = modulas_size;
			PROV_DMSG("dst_len=%ld\n",*dst_len);
		}
	}
	if (res == SS_SUCCESS) {
		primeData_ptr = (CRYS_RSAPrimeData_t *)ss_malloc(
				sizeof(CRYS_RSAPrimeData_t), &res);
	}
	if (res == SS_SUCCESS) {
		res = ss_build_pub_key(&userPubKey_ptr, key);
	}
	if (res == SS_SUCCESS) {
		res = ss_get_rsa_hash((const uint32_t)algo, &hashFunc,
				&hashSize, &mgf, &version);
	}
	if (res == SS_SUCCESS) {
		if (version == CRYS_PKCS1_VER15) {
			PROV_DMSG("CALL:  CRYS_RSA_PKCS1v15_Encrypt()\n");
			crys_res = CRYS_RSA_PKCS1v15_Encrypt(userPubKey_ptr,
					primeData_ptr, dataIn_ptr, dataInSize,
					output_ptr);
		} else {
			CONV_HASHMODE_TO_OAEP(hashFunc);
			PROV_DMSG("CALL:  CRYS_RSA_OAEP_Encrypt()\n");
			crys_res = CRYS_RSA_OAEP_Encrypt(userPubKey_ptr,
					primeData_ptr, hashFunc, l, llen, mgf,
					dataIn_ptr, dataInSize, output_ptr);
		}
		res = ss_translate_error_crys2ss_rsa(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	ss_free((void *)userPubKey_ptr);
	ss_free((void *)primeData_ptr);
	PROV_DHEXDUMP(dst,*dst_len);
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}


/*
 * brief:	Decryption by the RSA (PKCS1 v1.5, OAEP) FIPS 180-4 (SHA-1, SHA-2)
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
TEE_Result crypto_hw_acipher_rsaes_decrypt(uint32_t algo, struct rsa_keypair *key,
		const uint8_t *label, size_t label_len, const uint8_t *src,
		size_t src_len, uint8_t *dst, size_t *dst_len)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;

	/* CRYS_*_Decrypt */
	CRYS_RSAUserPrivKey_t *userPrivKey_ptr = NULL;
	CRYS_RSAPrimeData_t *primeData_ptr = NULL;
	CRYS_RSA_HASH_OpMode_t rsa_hashMode;
	CRYS_PKCS1_MGF_t mgf;
	CRYS_PKCS1_version version;
	uint8_t *l;
	uint16_t llen = 0U;
	uint16_t dataInSize = 0U;
	uint16_t outputSize;
	uint8_t *dataIn_ptr;
	uint8_t *output_ptr;
	size_t modulas_size;
	size_t hashSize;

	PROV_INMSG("algo=%d, *key=%p, *label=%p, label_len=%ld\n",algo,key,label,label_len);
	PROV_INMSG("*src=%p, src_len=%ld, *dst=%p, *dst_len=%p\n",src,src_len,dst,dst_len);

	PROV_DMSG("Input key->e\n");
	PROV_DHEXDUMP(key->e,bn_num_bytes(key->e));
	PROV_DMSG("Input key->d\n");
	PROV_DHEXDUMP(key->d,bn_num_bytes(key->d));
	PROV_DMSG("Input key->n\n");
	PROV_DHEXDUMP(key->n,bn_num_bytes(key->n));
	PROV_DMSG("Input key->p\n");
	PROV_DHEXDUMP(key->p,bn_num_bytes(key->p));
	PROV_DMSG("Input key->q\n");
	PROV_DHEXDUMP(key->q,bn_num_bytes(key->q));
	PROV_DMSG("Input key->qp\n");
	PROV_DHEXDUMP(key->qp,bn_num_bytes(key->qp));
	PROV_DMSG("Input key->dp\n");
	PROV_DHEXDUMP(key->dp,bn_num_bytes(key->dp));
	PROV_DMSG("Input key->dq\n");
	PROV_DHEXDUMP(key->dq,bn_num_bytes(key->dq));
	PROV_DMSG("Input label\n");
	PROV_DHEXDUMP(label,label_len);
	PROV_DMSG("Input src  src_len=%ld\n",src_len);
	PROV_DHEXDUMP(src,src_len);

	l = (uint8_t *)label;
	dataIn_ptr = (uint8_t *)src;
	output_ptr = (uint8_t *)dst;

	NULL_CHECK_RSA_KEYPAIR(key,res);
	if (res == SS_SUCCESS){
		modulas_size = bn_num_bytes(key->n);
		if (src_len < 0xFFFFU) {
			dataInSize = (uint16_t)src_len;
		} else {
			res = SS_ERROR_OVERFLOW;
			PROV_EMSG("OVERFLOW(src_len)\n");
		}
	}
	if (res == SS_SUCCESS){
		if(dst_len == NULL){
			res = SS_ERROR_BAD_PARAMETERS;
			PROV_EMSG("BAD_PARAMETERS(dst_len=%p)\n", key);
		} else {
			if (*dst_len < 0xFFFFU) {
				outputSize = (uint16_t)*dst_len;
			} else {
				outputSize = 0xFFFFU;
			}
		}
	}
	if (res == SS_SUCCESS) {
		if (label_len < 0xFFFFU) {
			llen = (uint16_t)label_len;
		} else {
			res = SS_ERROR_OVERFLOW;
			PROV_EMSG("OVERFLOW(label_len)\n");
		}
	}
	if (res == SS_SUCCESS) {
		primeData_ptr = (CRYS_RSAPrimeData_t *)ss_malloc(
				sizeof(CRYS_RSAPrimeData_t), &res);
	}
	if (res == SS_SUCCESS) {
		res = ss_build_priv_key(&userPrivKey_ptr, key);
	}
	if (res == SS_SUCCESS) {
		res = ss_get_rsa_hash((const uint32_t)algo, &rsa_hashMode,
				&hashSize, &mgf, &version);
	}
	if (res == SS_SUCCESS) {
		if (version == CRYS_PKCS1_VER15) {
			if (outputSize >= (modulas_size - 11U)) {
				PROV_DMSG("CALL: CRYS_RSA_PKCS1v15_Decrypt()\n");
				crys_res = CRYS_RSA_PKCS1v15_Decrypt(
						userPrivKey_ptr, primeData_ptr,
						dataIn_ptr, dataInSize,
						output_ptr, &outputSize);
				res = ss_translate_error_crys2ss_rsa(crys_res);
				PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
			} else {
				*dst_len = modulas_size;
				res = SS_ERROR_SHORT_BUFFER;
				PROV_EMSG("SHORT_BUFFER(PKCS)\n");
			}
		} else {
			if (outputSize >= (modulas_size - (2U * hashSize) - 2U)) {
				CONV_HASHMODE_TO_OAEP(rsa_hashMode);
				PROV_DMSG("CALL: CRYS_RSA_OAEP_Decrypt()\n");
				crys_res = CRYS_RSA_OAEP_Decrypt(
						userPrivKey_ptr, primeData_ptr,
						rsa_hashMode, l, llen, mgf,
						dataIn_ptr, dataInSize,
						output_ptr, &outputSize);
				res = ss_translate_error_crys2ss_rsa(crys_res);
				PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
			} else {
				*dst_len = modulas_size;
				res = SS_ERROR_SHORT_BUFFER;
				PROV_EMSG("SHORT_BUFFER(OAEP)\n");
			}
		}

	}
	if (res == SS_SUCCESS) {
		*dst_len = (size_t)outputSize;
		PROV_DMSG("Output dst   dst_len=%ld\n",*dst_len);
	}

	ss_free((void *)userPrivKey_ptr);
	ss_free((void *)primeData_ptr);
	tee_res = ss_translate_error_ss2tee(res);
	PROV_DHEXDUMP(dst,*dst_len);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

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
		size_t *sig_len)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	CRYS_RSAPrivUserContext_t *userContext_ptr = NULL;
	CRYS_RSAUserPrivKey_t *userPrivKey_ptr = NULL;
	CRYS_RSA_HASH_OpMode_t rsaHashMode;
	CRYS_PKCS1_MGF_t mgf;
	uint16_t saltLen = 0U;
	uint8_t *dataIn_ptr;
	uint32_t dataInSize = 0U;
	uint8_t *output_ptr;
	uint16_t outputSize;
	CRYS_PKCS1_version version;
	size_t modulas_size;
	size_t hashSize;

	PROV_INMSG("algo=%d, *key=%p, salt_len=%d, *msg=%p",algo,key,salt_len, msg);
	PROV_INMSG("msg_len=%ld, *sig=%p, sig_len=%p\n",msg_len,sig,sig_len);

	dataIn_ptr = (uint8_t *)msg;
	output_ptr = (uint8_t *)sig;

	NULL_CHECK_RSA_KEYPAIR(key,res);
	if (res == SS_SUCCESS) {
		modulas_size = bn_num_bytes(key->n);
		if ( NULL == sig_len) {
			res = SS_ERROR_BAD_PARAMETERS;
			PROV_EMSG("BAD_PARAMETERS(key=%p)\n", key);
		} else {
			if (*sig_len < modulas_size) {
				res = SS_ERROR_SHORT_BUFFER;
				PROV_EMSG("SHORT_BUFFER(sig_len=%ld)\n",
						*sig_len);
			}
		}
		if (res == SS_SUCCESS) {
			if (*sig_len <= 0xFFFFU) {
				outputSize = (uint16_t)*sig_len;
			} else {
				outputSize = 0xFFFFU;
			}
		}
	}
	if (res == SS_SUCCESS) {
		if (salt_len < 0xFFFF) {
			saltLen = (uint16_t)salt_len;
		} else {
			res = SS_ERROR_OVERFLOW;
			PROV_EMSG("OVERFLOW(salt_len)\n");
		}
	}
	if (res == SS_SUCCESS) {
		if (msg_len < 0xFFFFU) {
			dataInSize = (uint16_t)msg_len;
		} else {
			res = SS_ERROR_OVERFLOW;
			PROV_EMSG("OVERFLOW(msg_len)\n");
		}
	}
	if (res == SS_SUCCESS) {
		res = ss_build_priv_key(&userPrivKey_ptr, key);
	}
	if (res == SS_SUCCESS) {
		userContext_ptr = (CRYS_RSAPrivUserContext_t *)ss_malloc(
				sizeof(CRYS_RSAPrivUserContext_t), &res);
	}
	if (res == SS_SUCCESS) {
		res = ss_get_rsa_hash((const uint32_t)algo, &rsaHashMode,
				&hashSize, &mgf, &version);
	}
	if (res == SS_SUCCESS) {
		if (version == CRYS_PKCS1_VER15) {
			PROV_DMSG("CALL:  CRYS_RSA_PKCS1v15_Sign()\n");
			crys_res = CRYS_RSA_PKCS1v15_Sign(userContext_ptr,
					userPrivKey_ptr, rsaHashMode,
					dataIn_ptr, dataInSize, output_ptr,
					&outputSize);
		} else {
			PROV_DMSG("CALL:  CRYS_RSA_PSS_Sign()\n");
			crys_res = CRYS_RSA_PSS_Sign(userContext_ptr,
					userPrivKey_ptr, rsaHashMode, mgf,
					saltLen, dataIn_ptr, dataInSize,
					output_ptr, &outputSize);
		}
		res = ss_translate_error_crys2ss_rsa(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	if (res == SS_SUCCESS) {
		*sig_len = (size_t)outputSize;
		PROV_DMSG("sig=%p, *sig_len=%ld\n",sig,*sig_len);
	}

	ss_free((void *)userContext_ptr);
	ss_free((void *)userPrivKey_ptr);
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

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
		size_t msg_len, const uint8_t *sig)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;

	CRYS_RSAPubUserContext_t *userContext_ptr = NULL;
	CRYS_RSAUserPubKey_t *userPubKey_ptr = NULL;
	CRYS_RSA_HASH_OpMode_t rsaHashMode;
	CRYS_PKCS1_MGF_t mgf;
	uint16_t saltLen = 0U;
	uint8_t *dataIn_ptr;
	uint32_t dataInSize = 0U;
	uint8_t *sig_ptr;
	CRYS_PKCS1_version version;
	size_t hashSize;

	PROV_INMSG("algo=%d, *key=%p, salt_len=%d, *msg=%p",algo,key,salt_len, msg);
	PROV_INMSG("msg_len=%ld, *sig=%p\n",msg_len,sig);

	dataIn_ptr = (uint8_t *)msg;
	sig_ptr = (uint8_t *)sig;
	NULL_CHECK_RSA_PUBLIC_KEY(key,res);

	if (res == SS_SUCCESS) {
		if (salt_len < 0xFFFF) {
			saltLen = (uint16_t)salt_len;
		} else {
			res = SS_ERROR_OVERFLOW;
			PROV_EMSG("OVERFLOW(salt_len)\n");
		}
	}
	if (res == SS_SUCCESS) {
		if (msg_len < 0xFFFFU) {
			dataInSize = (uint16_t)msg_len;
		} else {
			res = SS_ERROR_OVERFLOW;
			PROV_EMSG("OVERFLOW(msg_len)\n");
		}
	}
	if (res == SS_SUCCESS) {
		userContext_ptr = (CRYS_RSAPubUserContext_t *)ss_malloc(
				sizeof(CRYS_RSAPubUserContext_t), &res);
	}
	if (res == SS_SUCCESS) {
		res = ss_build_pub_key(&userPubKey_ptr, key);
	}
	if (res == SS_SUCCESS) {
		res = ss_get_rsa_hash((const uint32_t)algo, &rsaHashMode,
				&hashSize, &mgf, &version);
	}
	if (res == SS_SUCCESS) {
		if (version == CRYS_PKCS1_VER15) {
			PROV_DMSG("CALL:  CRYS_RSA_PKCS1v15_Verify()\n");
			crys_res = CRYS_RSA_PKCS1v15_Verify(userContext_ptr,
					userPubKey_ptr, rsaHashMode, dataIn_ptr,
					dataInSize, sig_ptr);
		} else {
			PROV_DMSG("CALL:  CRYS_RSA_PSS_Verify()\n");
			crys_res = CRYS_RSA_PSS_Verify(userContext_ptr,
					userPubKey_ptr, rsaHashMode, mgf,
					saltLen, dataIn_ptr, dataInSize,
					sig_ptr);
		}
		res = ss_translate_error_crys2ss_rsa(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	ss_free((void *)userContext_ptr);
	ss_free((void *)userPubKey_ptr);

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

#endif /* CFG_CRYPTO_RSA */

#if defined(CFG_CRYPTO_DH)
/*
 * brief:	Generate DH key pair.
 *
 * param[in/out] *key		- Pointer to the struct data of DH key pair.
 * param[in]	 *q		- Pointer to the bignum data of q(SUBPRIME).
 * param[in]	 *xbits		- Pointer to the bignum data of x bits.
 * return	 TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_gen_dh_key(struct dh_keypair *key, struct bignum *q,
		size_t xbits)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	uint32_t modulusSize;
	uint8_t *generator_ptr = NULL;
	uint16_t generatorSize;
	uint8_t *prime_ptr = NULL;
	uint16_t primeSize;
	uint16_t l;
	uint8_t *q_ptr = NULL;
	uint16_t qSize;
	CRYS_DHUserPubKey_t *tmpPubKey = NULL;
	CRYS_DHPrimeData_t *tmpPrimeData = NULL;
	uint8_t *clientPrvKey_ptr = NULL;
	uint16_t clientPrvKeySize = 0U;
	uint8_t *clientPubKey_ptr = NULL;
	uint16_t clientPubKeySize = 0U;

	PROV_INMSG("*key=%p, *q=%p, xbits=%ld\n",key,q,xbits);

	NULL_CHECK_DH_KEYPAIR(key,res);
	if (res == SS_SUCCESS) {
		modulusSize = bn_num_bytes(key->p);
		if (0xFFFFU < xbits) {
			res = SS_ERROR_OVERFLOW;
			PROV_EMSG("OVERFLOW(xbits)\n");
		} else {
			l = (uint16_t)xbits;
		}
	}
	if (res == SS_SUCCESS) {
		tmpPubKey = (CRYS_DHUserPubKey_t *)ss_malloc(
				sizeof(CRYS_DHUserPubKey_t), &res);
	}
	if (res == SS_SUCCESS) {
		tmpPrimeData = (CRYS_DHPrimeData_t *)ss_malloc(
				sizeof(CRYS_DHPrimeData_t), &res);
	}

	if (res == SS_SUCCESS) {
		if (0U != l) {
			clientPrvKeySize = l / 8U;
		} else {
			clientPrvKeySize = (uint16_t)modulusSize;
		}
		clientPrvKey_ptr = (uint8_t *)ss_malloc(
				(uint32_t)clientPrvKeySize, &res);
	}
	if (res == SS_SUCCESS) {
		clientPubKeySize = (uint16_t)modulusSize;
		clientPubKey_ptr = (uint8_t *)ss_malloc(
				(uint32_t)clientPubKeySize, &res);
	}
	/* convert from bignum to binary */
	if (res == SS_SUCCESS) {
		res = ss_copy_bn2bin_uint16(key->g, &generator_ptr,
				&generatorSize);
	}
	if (res == SS_SUCCESS) {
		res = ss_copy_bn2bin_uint16(key->p, &prime_ptr, &primeSize);
	}
	if (res == SS_SUCCESS) {
		if (q == NULL) {
			PROV_DMSG("CALL: CRYS_DH_PKCS3_GeneratePubPrv()\n");
			crys_res = CRYS_DH_PKCS3_GeneratePubPrv(
					generator_ptr, generatorSize,
					prime_ptr, primeSize, l,
					tmpPubKey, tmpPrimeData,
					clientPrvKey_ptr,
					&clientPrvKeySize,
					clientPubKey_ptr,
					&clientPubKeySize);
			res = ss_translate_error_crys2ss_dh(crys_res);
			PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
		} else {
			/* q */
			res = ss_copy_bn2bin_uint16(q, &q_ptr, &qSize);
			if (res == SS_SUCCESS) {
				crypto_bignum_copy(q, key->q);
				PROV_DMSG("CALL: CRYS_DH_ANSI_X942_GeneratePubPrv()\n");
				crys_res = CRYS_DH_ANSI_X942_GeneratePubPrv(
						generator_ptr, generatorSize,
						prime_ptr, primeSize, q_ptr,
						qSize, tmpPubKey, tmpPrimeData,
						clientPrvKey_ptr,
						&clientPrvKeySize,
						clientPubKey_ptr,
						&clientPubKeySize);
				res = ss_translate_error_crys2ss_dh(crys_res);
				PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);

			}
		}
	}

	/* convert bin -> bignum */
	if (res == SS_SUCCESS) {
		res = ss_bn_bin2bn(clientPrvKey_ptr, (size_t)clientPrvKeySize,
				key->x);
	}
	if (res == SS_SUCCESS) {
		res = ss_bn_bin2bn(clientPubKey_ptr, (size_t)clientPubKeySize,
				key->y);
	}

	ss_free((void *)generator_ptr);
	ss_free((void *)prime_ptr);
	ss_free((void *)tmpPrimeData);
	ss_free((void *)tmpPubKey);
	ss_free((void *)clientPrvKey_ptr);
	ss_free((void *)clientPubKey_ptr);
	ss_free((void *)q_ptr);

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

/*
 * brief:	Generate secret key.
 *
 * param[in/out] *private_key	- Pointer to the struct data of DH client private key.
 * param[in]	 *public_key	- Pointer to the bignum data of DH server public key.
 * param[in]	 *secret	- Pointer to the bignum data of secret key.
 * return	 TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_dh_shared_secret(struct dh_keypair *private_key,
		struct bignum *public_key, struct bignum *secret)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	uint8_t *clientPrvKey_ptr = NULL;
	uint16_t clientPrvKeySize = 0U;
	uint8_t *serverPubKey_ptr = NULL;
	uint16_t serverPubKeySize = 0U;
	uint8_t *prime_ptr = NULL;
	uint16_t primeSize = 0U;
	CRYS_DHUserPubKey_t *tmpPubKey = NULL;
	CRYS_DHPrimeData_t *tmpPrimeData = NULL;
	uint8_t *secretKey_ptr = NULL;
	uint16_t secretKeySize;

	PROV_INMSG("*private_key=%p, *public_key=%p, *secret=%p\n",private_key,public_key,secret);

	NULL_CHECK_DH_KEYPAIR(private_key,res);
	if (res == SS_SUCCESS) {
		tmpPubKey = (CRYS_DHUserPubKey_t *)ss_malloc(
				sizeof(CRYS_DHUserPubKey_t), &res);
	}
	if (res == SS_SUCCESS) {
		tmpPrimeData = (CRYS_DHPrimeData_t *) ss_malloc(
				sizeof(CRYS_DHPrimeData_t), &res);
	}

	/* client private key */
	if (res == SS_SUCCESS) {
		res = ss_copy_bn2bin_uint16(private_key->x, &clientPrvKey_ptr,
				&clientPrvKeySize);
	}
	/* client public key */
	if (res == SS_SUCCESS) {
		res = ss_copy_bn2bin_uint16(public_key, &serverPubKey_ptr,
				&serverPubKeySize);
	}
	/* prime */
	if (res == SS_SUCCESS) {
		res = ss_copy_bn2bin_uint16(private_key->p, &prime_ptr,
				&primeSize);
	}

	if (res == SS_SUCCESS) {
		secretKeySize = primeSize;
		secretKey_ptr = (uint8_t *)ss_malloc((size_t)secretKeySize, &res);
	}


	if (res == SS_SUCCESS) {
		secretKeySize = primeSize;
		PROV_DMSG("CALL: CRYS_DH_GetSecretKey()\n");
		crys_res = CRYS_DH_GetSecretKey(clientPrvKey_ptr,
				clientPrvKeySize, serverPubKey_ptr,
				serverPubKeySize, prime_ptr, primeSize,
				tmpPubKey, tmpPrimeData, secretKey_ptr,
				&secretKeySize);
		res = ss_translate_error_crys2ss_dh(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	if (res == SS_SUCCESS) {
		res = crypto_bignum_bin2bn(secretKey_ptr,(size_t)secretKeySize, secret);
	}

	ss_free((void *)tmpPubKey);
	ss_free((void *)tmpPrimeData);
	ss_free((void *)clientPrvKey_ptr);
	ss_free((void *)serverPubKey_ptr);
	ss_free((void *)prime_ptr);
	ss_free((void *)secretKey_ptr);

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

#endif /* CFG_CRYPTO_DH */

#if defined(CFG_CRYPTO_ECC)
/*
 * brief:	Get a digest algorithm used in ECDSA.
 *
 * param[in]	msg_len			- Input message size.
 * param[out]	*hash			- Digest algorithm.
 * return	SSError_t		- SS provider error code.
 */
static SSError_t ss_get_ecc_digest(uint32_t msg_len,
		CRYS_ECPKI_HASH_OpMode_t *hash)
{
	SSError_t res = SS_SUCCESS;

	switch ((int32_t)msg_len) {
	case CRYS_HASH_SHA1_DIGEST_SIZE_IN_BYTES:
		PROV_DMSG("TEE_ALG_ECDSA_WITH_SHA1\n");
		*hash = CRYS_ECPKI_AFTER_HASH_SHA1_mode;
		break;
	case CRYS_HASH_SHA224_DIGEST_SIZE_IN_BYTES:
		PROV_DMSG("TEE_ALG_ECDSA_WITH_SHA224\n");
		*hash = CRYS_ECPKI_AFTER_HASH_SHA224_mode;
		break;
	case CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES:
		PROV_DMSG("TEE_ALG_ECDSA_WITH_SHA256\n");
		*hash = CRYS_ECPKI_AFTER_HASH_SHA256_mode;
		break;
	case CRYS_HASH_SHA384_DIGEST_SIZE_IN_BYTES:
		PROV_DMSG("TEE_ALG_ECDSA_WITH_SHA384\n");
		*hash = CRYS_ECPKI_AFTER_HASH_SHA384_mode;
		break;
	case CRYS_HASH_SHA512_DIGEST_SIZE_IN_BYTES:
		PROV_DMSG("TEE_ALG_ECDSA_WITH_SHA512\n");
		*hash = CRYS_ECPKI_AFTER_HASH_SHA512_mode;
		break;
	default:
		PROV_EMSG("NOT SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	}

	PROV_OUTMSG("return res=0x%08x", res);
	return res;
}

/*
 * brief:	Get ECC key size by the domain ID of TEE internal API.
 *
 * param[in]	curve			- Domain ID of TEE internal API.
 * param[out]	*domain_id		- Domain ID of CRYS API.
 * return	SSError_t		- SS provider error code.
 */
static SSError_t ss_get_ecc_keysize(uint32_t curve,
		CRYS_ECPKI_DomainID_t *domain_id, uint32_t *key_size_bytes)
{
	SSError_t res = SS_SUCCESS;

	PROV_INMSG("curve=%d\n", curve);

	switch ((int32_t)curve) {
	case TEE_ECC_CURVE_NIST_P192:
		PROV_DMSG("curve=TEE_ECC_CURVE_NIST_P192\n");
		*domain_id = CRYS_ECPKI_DomainID_secp192r1;
		*key_size_bytes = 24U;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		PROV_DMSG("curve=TEE_ECC_CURVE_NIST_P224\n");
		*domain_id = CRYS_ECPKI_DomainID_secp224r1;
		*key_size_bytes = 28U;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		PROV_DMSG("curve=TEE_ECC_CURVE_NIST_P256\n");
		*domain_id = CRYS_ECPKI_DomainID_secp256r1;
		*key_size_bytes = 32U;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		PROV_DMSG("curve=TEE_ECC_CURVE_NIST_P384\n");
		*domain_id = CRYS_ECPKI_DomainID_secp384r1;
		*key_size_bytes = 48U;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		PROV_DMSG("curve=TEE_ECC_CURVE_NIST_P521\n");
		*domain_id = CRYS_ECPKI_DomainID_secp521r1;
		*key_size_bytes = 66U;
		break;
	default:
		PROV_DMSG("ERROR: NOT SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	}

	PROV_OUTMSG("return res=0x%08x", res);
	return res;
}

/*
 * brief:	Generate ECC key pair.
 *
 * param[in/out] *key		- Pointer to the struct data of ECC key pair.
 * return	 TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_acipher_gen_ecc_key(struct ecc_keypair *key)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	CRYS_ECPKI_DomainID_t domain_id;
	CRYS_ECPKI_UserPrivKey_t *userpriv_key = NULL;
	CRYS_ECPKI_UserPublKey_t *userpubl_key = NULL;
	CRYS_ECPKI_KG_TempData_t *temp_buff = NULL;
	CRYS_ECPKI_PrivKey_t *privKey_ptr;
	CRYS_ECPKI_PublKey_t *publKey_ptr = NULL;
	uint32_t key_size_bytes;

	PROV_INMSG("*key=%p\n",key);

	NULL_CHECK_ECC_KEYPAIR(key,res);
	if (res == SS_SUCCESS) {
		userpriv_key = (CRYS_ECPKI_UserPrivKey_t *)ss_malloc(
				sizeof(CRYS_ECPKI_UserPrivKey_t), &res);
	}
	if (res == SS_SUCCESS) {
		userpubl_key = (CRYS_ECPKI_UserPublKey_t *)ss_malloc(
				sizeof(CRYS_ECPKI_UserPublKey_t), &res);
	}
	if (res == SS_SUCCESS) {
		temp_buff = (CRYS_ECPKI_KG_TempData_t *)ss_malloc(
				sizeof(CRYS_ECPKI_KG_TempData_t), &res);
	}
	if (res == SS_SUCCESS) {
		res = ss_get_ecc_keysize(key->curve, &domain_id, &key_size_bytes);
	}
	/* Generate the ECC key */
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL:  CRYS_ECPKI_GenKeyPair()\n");
		crys_res = CRYS_ECPKI_GenKeyPair(domain_id, userpriv_key,
				userpubl_key, temp_buff);
		res = ss_translate_error_crys2ss_ecc(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}
	if (res == SS_SUCCESS) {
		privKey_ptr = (CRYS_ECPKI_PrivKey_t *)userpriv_key->PrivKeyDbBuff;
		publKey_ptr = (CRYS_ECPKI_PublKey_t *)userpubl_key->PublKeyDbBuff;
		res = ss_bn_bin2bn((uint8_t *)&privKey_ptr->PrivKey[0], key_size_bytes, key->d);
	}
	if (res == SS_SUCCESS) {
		res = ss_bn_bin2bn((uint8_t *)&publKey_ptr->PublKeyX[0], key_size_bytes, key->x);
	}
	if (res == SS_SUCCESS) {
		res = ss_bn_bin2bn((uint8_t *)&publKey_ptr->PublKeyY[0], key_size_bytes, key->y);
	}

	ss_free((void *)userpriv_key);
	ss_free((void *)userpubl_key);
	ss_free((void *)temp_buff);
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

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
		size_t *sig_len)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	CRYS_ECPKI_DomainID_t domain_id;
	CRYS_ECDSA_SignUserContext_t *signUserContext_ptr = NULL;
	CRYS_ECPKI_UserPrivKey_t *signerPrivKey_ptr = NULL;
	CRYS_ECPKI_HASH_OpMode_t eccHashMode;
	uint8_t *privKeySizeIn_ptr = NULL;
	size_t privKeySizeInBytes;
	uint8_t *messageDataIn_ptr;
	uint32_t messageSizeInBytes;
	uint8_t *signatureOut_ptr;
	uint32_t *signatureOutSize_ptr;
	uint32_t modulusbytes;

	PROV_INMSG("*key=%p, *msg=%p\n", key, msg);
	PROV_INMSG("msg_len=0x%08lx, *sig=%p, *sig_len=0x%08lx\n", msg_len, sig,
			*sig_len);

	NULL_CHECK_ECC_KEYPAIR(key,res);
	messageDataIn_ptr = (uint8_t *)msg;
	messageSizeInBytes = (uint32_t)msg_len;
	signatureOut_ptr = (uint8_t *)sig;
	signatureOutSize_ptr = (uint32_t *)sig_len;

	if (res == SS_SUCCESS){
		signUserContext_ptr = (CRYS_ECDSA_SignUserContext_t *)ss_malloc(
				sizeof(CRYS_ECDSA_SignUserContext_t), &res);
	}
	if (res == SS_SUCCESS) {
		signerPrivKey_ptr = (CRYS_ECPKI_UserPrivKey_t *)ss_malloc(
				sizeof(CRYS_ECPKI_UserPrivKey_t), &res);
	}
	if (res == SS_SUCCESS) {
		res = ss_get_ecc_keysize(key->curve, &domain_id, &modulusbytes);
	}

	if (res == SS_SUCCESS) {
		res = ss_copy_bn2bin(key->d, &privKeySizeIn_ptr,
				&privKeySizeInBytes);
	}

	if (res == SS_SUCCESS) {
		res = ss_get_ecc_digest(messageSizeInBytes, &eccHashMode);
	}

	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL:  CRYS_ECPKI_BuildPrivKey()\n");
		crys_res = CRYS_ECPKI_BuildPrivKey(domain_id, privKeySizeIn_ptr,
				(uint32_t)privKeySizeInBytes, signerPrivKey_ptr);
		PROV_DMSG("Result: crys_res=0x%08x\n", crys_res);
		if (crys_res == (CRYSError_t) CRYS_OK) {
			PROV_DMSG("CALL:  CRYS_ECDSA_Sign()\n");
			crys_res = CRYS_ECDSA_Sign(signUserContext_ptr,
					signerPrivKey_ptr,
					eccHashMode,
					messageDataIn_ptr, messageSizeInBytes,
					signatureOut_ptr, signatureOutSize_ptr);
			PROV_DMSG("Result: crys_res=0x%08x\n", crys_res);
		}
		res = ss_translate_error_crys2ss_ecc(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	ss_free((void *)signUserContext_ptr);
	ss_free((void *)privKeySizeIn_ptr);
	ss_free((void *)signerPrivKey_ptr);

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}


#ifndef CFG_CRYPT_ENABLE_CEPKA
/*
 * brief:	Verify by the ECC using PKA engines (FIPS 186-4 ANSI X9.62)
 *
 * param[in]	*key		- Pointer to the struct of the ECC key pair.
 * param[in]	*msg		- Pointer to the message data buffer.
 * param[in]	msg_len		- Size of message data buffer.
 * param[in]	*sig		- Pointer to the signature data buffer.
 * param[in]	*sig_len	- Size of signature data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
static SSError_t ss_ecc_verify_secure(struct ecc_public_key *key,
		const uint8_t *msg, size_t msg_len, const uint8_t *sig,
		size_t sig_len)
{
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;

	CRYS_ECPKI_UserPublKey_t *userPublKey_ptr = NULL;
	CRYS_ECDSA_VerifyUserContext_t *verifyUserContext_ptr = NULL;
	CRYS_ECPKI_HASH_OpMode_t eccHashMode;
	uint8_t *messageDataIn_ptr;
	uint32_t messageSizeInBytes;
	uint8_t *signatureOut_ptr;
	uint32_t signatureOutSize;
	CRYS_ECPKI_DomainID_t domain_id;
	uint8_t *publKeyIn_ptr = NULL;
	uint32_t publKeySizeInBytes = 0U;
	size_t publKeySizeXBytes;
	size_t publKeySizeYBytes;
	uint8_t *publKeyX_ptr = NULL;
	uint8_t *publKeyY_ptr = NULL;
	uint32_t modulusbytes = 0U;

	PROV_INMSG("*key=%p, *msg=%p, msg_len=%ld\n", key, msg, msg_len);
	PROV_INMSG("*sig=%p, sig_len=%ld\n", sig, sig_len);

	messageDataIn_ptr = (uint8_t *)msg;
	messageSizeInBytes = (uint32_t)msg_len;
	signatureOut_ptr = (uint8_t *)sig;
	signatureOutSize = (uint32_t)sig_len;

	NULL_CHECK_ECC_PUBLIC_KEY(key,res);
	if( res == SS_SUCCESS){
		res = ss_get_ecc_keysize(key->curve, &domain_id, &modulusbytes);
	}

	if (res == SS_SUCCESS) {
		userPublKey_ptr = (CRYS_ECPKI_UserPublKey_t *)ss_malloc(
				sizeof(CRYS_ECPKI_UserPublKey_t), &res);
	}
	if (res == SS_SUCCESS) {
		verifyUserContext_ptr =
				(CRYS_ECDSA_VerifyUserContext_t *)ss_malloc(
						sizeof(CRYS_ECDSA_VerifyUserContext_t),
						&res);
	}

	if (res == SS_SUCCESS) {
		/* malloc public key size */
		res = ss_copy_bn2bin(key->x, &publKeyX_ptr, &publKeySizeXBytes);
	}
	if (res == SS_SUCCESS) {
		res = ss_copy_bn2bin(key->y, &publKeyY_ptr, &publKeySizeYBytes);
	}
	if (res == SS_SUCCESS) {
		publKeySizeInBytes = sizeof(uint8_t) + (modulusbytes * 2U);

		publKeyIn_ptr = (uint8_t *)ss_calloc(1U, publKeySizeInBytes, &res);
	}

	if (res == SS_SUCCESS) {
		res = ss_get_ecc_digest(messageSizeInBytes, &eccHashMode);
	}

	if (res == SS_SUCCESS) {
		/* build public key */
		*publKeyIn_ptr = (uint8_t)CRYS_EC_PointUncompressed;
		(void)memcpy((publKeyIn_ptr + 1U + modulusbytes) - publKeySizeXBytes,
				publKeyX_ptr, publKeySizeXBytes);
		(void)memcpy((publKeyIn_ptr + 1U + (modulusbytes * 2U)) - publKeySizeYBytes,
				publKeyY_ptr, publKeySizeYBytes);
		PROV_DMSG("CALL:  CRYS_ECDSA_Verify()\n");
		crys_res = CRYS_ECPKI_BuildPublKey(domain_id, publKeyIn_ptr,
				publKeySizeInBytes, userPublKey_ptr);
		res = ss_translate_error_crys2ss_ecc(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n", crys_res,
				res);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL:  CRYS_ECDSA_Verify()\n");
		crys_res = CRYS_ECDSA_Verify(verifyUserContext_ptr,
				userPublKey_ptr, eccHashMode, signatureOut_ptr,
				signatureOutSize, messageDataIn_ptr,
				messageSizeInBytes);
		res = ss_translate_error_crys2ss_ecc(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n", crys_res,
				res);
	}

	ss_free((void *)publKeyX_ptr);
	ss_free((void *)publKeyY_ptr);
	ss_free((void *)publKeyIn_ptr);
	ss_free((void *)verifyUserContext_ptr);
	ss_free((void *)userPublKey_ptr);

	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}
#endif

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
		size_t sig_len)
{
	TEE_Result tee_res;
	SSError_t res;
	PROV_INMSG("*key=%p, *msg=%p, msg_len=%ld\n",key,msg,msg_len);
	PROV_INMSG("*sig=%p, sig_len=%ld\n",sig,sig_len);

#ifdef CFG_CRYPT_ENABLE_CEPKA
	PROV_DMSG("USE Crypto Engine PKA\n");
	res = ss_ecc_verify_pka(key, msg, msg_len, sig, sig_len);
#else
	PROV_DMSG("USE Crypto Engine Secure\n");
	res = ss_ecc_verify_secure(key,msg,msg_len,sig,sig_len);
#endif

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

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
		unsigned long *secret_len)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	CRYS_ECPKI_DomainID_t domain_id;
	CRYS_ECPKI_UserPrivKey_t *userpriv_key = NULL;
	CRYS_ECPKI_UserPublKey_t *userpubl_key = NULL;
	CRYS_ECDH_TempData_t *tempBuff_ptr = NULL;
	uint8_t *privKeyIn_ptr = NULL;
	size_t privKeySizeInBytes = 0U;
	uint8_t *publKeyIn_ptr = NULL;
	uint32_t publkeysize_bytes = 0U;
	uint8_t *publKeyX_ptr = NULL;
	size_t publKeySizeXBytes = 0U;
	uint8_t *publKeyY_ptr = NULL;
	size_t publKeySizeYBytes = 0U;
	uint8_t *sharedSecretValue_ptr;
	uint32_t *sharedSecrValSize_ptr;
	uint32_t modulusbytes = 0U;

	PROV_INMSG("*private_key=%p, *public_key=%p\n",private_key,public_key);
	PROV_INMSG("*secret=%p, *secret_len=%p\n",secret,secret_len);

	sharedSecretValue_ptr = (uint8_t *)secret;
	sharedSecrValSize_ptr = (uint32_t *)secret_len;

	NULL_CHECK_ECC_KEYPAIR(private_key,res);
	NULL_CHECK_ECC_PUBLIC_KEY(public_key,res);
	if (res == SS_SUCCESS) {
		if (private_key->curve != public_key->curve) {
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}
	if (res == SS_SUCCESS) {
		tempBuff_ptr = (CRYS_ECDH_TempData_t *)ss_malloc(
				sizeof(CRYS_ECDH_TempData_t), &res);
	}
	if (res == SS_SUCCESS) {
		userpriv_key = (CRYS_ECPKI_UserPrivKey_t *)ss_malloc(
				sizeof(CRYS_ECPKI_UserPrivKey_t), &res);
	}
	if (res == SS_SUCCESS) {
		userpubl_key = (CRYS_ECPKI_UserPublKey_t *)ss_malloc(
				sizeof(CRYS_ECPKI_UserPublKey_t), &res);
	}

	/* Check the curves are the same */
	if (res == SS_SUCCESS) {
		res = ss_get_ecc_keysize(public_key->curve, &domain_id, &modulusbytes);
	}
	/* build public key */
	if (res == SS_SUCCESS) {
		res = ss_copy_bn2bin(public_key->x, &publKeyX_ptr,
				&publKeySizeXBytes);
	}

	if (res == SS_SUCCESS) {
		res = ss_copy_bn2bin(public_key->y, &publKeyY_ptr,
				&publKeySizeYBytes);
	}
	if (res == SS_SUCCESS) {
		publkeysize_bytes = sizeof(uint8_t) + (modulusbytes * 2U);
		publKeyIn_ptr = (uint8_t *)ss_calloc(1,publkeysize_bytes, &res);
	}
	if (res == SS_SUCCESS) {
		*publKeyIn_ptr = (uint8_t)CRYS_EC_PointUncompressed;
		(void)memcpy((((publKeyIn_ptr + 1U) + modulusbytes) - publKeySizeXBytes),
				publKeyX_ptr, publKeySizeXBytes);
		(void)memcpy(((((publKeyIn_ptr) + 1U) + (modulusbytes * 2U)) - publKeySizeYBytes),
				publKeyY_ptr, publKeySizeYBytes);
		PROV_DMSG("CALL:  CRYS_ECPKI_BuildPublKey()\n");
		crys_res = CRYS_ECPKI_BuildPublKey(domain_id, publKeyIn_ptr,
				publkeysize_bytes, userpubl_key);
		res = ss_translate_error_crys2ss_ecc(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}
	if (res == SS_SUCCESS) {
		res = ss_copy_bn2bin(private_key->d, &privKeyIn_ptr,
				&privKeySizeInBytes);
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL:  CRYS_ECPKI_BuildPrivKey()\n");
		crys_res = CRYS_ECPKI_BuildPrivKey(domain_id, privKeyIn_ptr,
				privKeySizeInBytes, userpriv_key);
		PROV_DMSG("Result: crys_res=0x%08x\n", crys_res);
		if (crys_res == (CRYSError_t) CRYS_OK) {
			PROV_DMSG("CALL:  CRYS_ECDH_SVDP_DH()\n");
			crys_res = CRYS_ECDH_SVDP_DH(userpubl_key, userpriv_key,
					sharedSecretValue_ptr,
					sharedSecrValSize_ptr, tempBuff_ptr);
			PROV_DMSG("Result: crys_res=0x%08x\n", crys_res);
		}
		res = ss_translate_error_crys2ss_ecc(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	ss_free((void *)tempBuff_ptr);
	ss_free((void *)userpriv_key);
	ss_free((void *)userpubl_key);
	ss_free((void *)publKeyX_ptr);
	ss_free((void *)publKeyY_ptr);
	ss_free((void *)publKeyIn_ptr);
	ss_free((void *)privKeyIn_ptr);

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

#endif /* CFG_CRYPTO_ECC */

#endif /* _CFG_CRYPTO_WITH_ACIPHER */

/******************************************************************************
 * Symmetric ciphers
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_CIPHER)
/*
 * brief:	Get context size to AES,DES algorithm.
 *
 * param[in]	algo		- Cryptographic algorithm.
 * param[out]	*size		- Size of context to AES,DES algorithm.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_cipher_get_ctx_size(uint32_t algo, size_t *size)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	PROV_INMSG("START cipher_get_ctx_size\n");
	switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_AES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
#endif
#if defined(CFG_CRYPTO_OFB)
	case TEE_ALG_AES_OFB:
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
#endif
		PROV_DMSG("ctx size = sizeof(SS_AES_Context_t)\n");
		*size = sizeof(SS_AES_Context_t);
		break;
#endif
#if defined(CFG_CRYPTO_DES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
#endif
		PROV_DMSG("ctx size = sizeof(SS_DES_Context_t)\n");
		*size = sizeof(SS_DES_Context_t);
		break;
#endif
	default:
		PROV_EMSG("ERROR SS_ERROR_NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	}

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

/*
 * brief:	Initialize state of AES algorithm.
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
static SSError_t ss_aes_init(void *ctx, uint32_t algo, TEE_OperationMode mode,
		const uint8_t *key1, size_t key1_len, const uint8_t *iv,
		size_t iv_len)
{
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;

	SS_AES_Context_t *ss_ctx;
	CRYS_AESUserContext_t *contextID_ptr;
	CRYS_AES_IvCounter_t *ivCounter_ptr = NULL;
	CRYS_AES_Key_t aesKey;
	CRYS_AES_KeySize_t aesKeySize = CRYS_AES_KeySizeLast;
	CRYS_AES_EncryptMode_t encDecFlag = CRYS_AES_EncryptModeLast;
	CRYS_AES_OperationMode_t opeMode = CRYS_AES_OperationModeLast;

	PROV_INMSG("START ss_aes_init\n");

	if ( ctx != NULL) {
		ss_ctx = (SS_AES_Context_t *)ctx;
		ss_ctx->crys_error = SS_SUCCESS;
		ss_ctx->blockSize = 16U;
		ss_ctx->restBufSize = 0U;
		ss_ctx->mode = mode;
		contextID_ptr = &ss_ctx->crys_ctx;
		(void)memset(contextID_ptr, 0, sizeof(CRYS_AESUserContext_t));
	} else {
		PROV_DMSG("ERROR:BAD_PARAMETERS(ctx)\n");
		res = SS_ERROR_BAD_PARAMETERS;
	}

	if (res == SS_SUCCESS) {
		if (iv == NULL) {
			PROV_DMSG("iv = NULL\n");
			ivCounter_ptr = NULL;
		} else {
			PROV_DMSG("iv = NOT NULL\n");
			ivCounter_ptr = (CRYS_AES_IvCounter_t *)ss_malloc_and_copy(
					sizeof(CRYS_AES_IvCounter_t), (const void *)iv,
					iv_len, &res);
		}
	}

	if (res == SS_SUCCESS) {
		PROV_DMSG("Copy AES key (non XTS)\n");
		if (key1 != NULL) {
			switch (key1_len) {
			case 16U:
				PROV_DMSG("KeySize=128Bit\n");
				aesKeySize = CRYS_AES_Key128BitSize;
				break;
			case 24U:
				PROV_DMSG("KeySize=192Bit\n");
				aesKeySize = CRYS_AES_Key192BitSize;
				break;
			case 32U:
				PROV_DMSG("KeySize=256Bit\n");
				aesKeySize = CRYS_AES_Key256BitSize;
				break;
			default:
				PROV_DMSG("ERROR:BAD_PARAMETERS key_len=%ld\n",
						key1_len);
				res = SS_ERROR_BAD_PARAMETERS;
				break;
			}
			if (res == SS_SUCCESS) {
				(void)memcpy(aesKey, key1, key1_len);
				PROV_DMSG("AES key ...%x%x sizse_num=%d\n",
						aesKey[1], aesKey[0],
						aesKeySize);
			}
		} else {
			PROV_DMSG("ERROR:BAD_PARAMETERS(key_ptr)\n");
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}
	if (res == SS_SUCCESS) {
		switch (mode) {
		case TEE_MODE_ENCRYPT:
			PROV_DMSG("encDecFlag=CRYS_AES_Encrypt\n");
			encDecFlag = CRYS_AES_Encrypt;
			break;
		case TEE_MODE_DECRYPT:
			PROV_DMSG("encDecFlag=CRYS_AES_Decrypt\n");
			encDecFlag = CRYS_AES_Decrypt;
			break;
		default:
			PROV_DMSG("ERROR:BAD_PARAMETERS(mode)\n");
			res = SS_ERROR_BAD_PARAMETERS;
			break;
		}
	}
	if (res == SS_SUCCESS) {
		switch ((int32_t)algo) {
		case TEE_ALG_AES_ECB_NOPAD:
			PROV_DMSG("opeMode=CRYS_AES_ECB_mode\n");
			opeMode = CRYS_AES_ECB_mode;
			break;
		case TEE_ALG_AES_CBC_NOPAD:
			PROV_DMSG("opeMode=CRYS_AES_CBC_mode\n");
			opeMode = CRYS_AES_CBC_mode;
			break;
		case TEE_ALG_AES_CTR:
			PROV_DMSG("opeMode=CRYS_AES_CTR_mode\n");
			opeMode = CRYS_AES_CTR_mode;
			break;
		case TEE_ALG_AES_OFB:
			PROV_DMSG("opeMode=CRYS_AES_OFB_mode\n");
			opeMode = CRYS_AES_OFB_mode;
			break;
		case TEE_ALG_AES_CTS:
			PROV_DMSG("opeMode=CRYS_AES_CBC_CTS_mode\n");
			opeMode = CRYS_AES_CBC_CTS_mode;
			break;
		default:
			PROV_DMSG("ERROR:BAD_PARAMETERS(algo)\n");
			res = SS_ERROR_NOT_SUPPORTED;
			break;
		}
	}

	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: CRYS_AES_Init\n");
		crys_res = CRYS_AES_Init(
				contextID_ptr,
				*ivCounter_ptr,
				aesKey,
				aesKeySize, encDecFlag, opeMode);
		ss_ctx->crys_error = crys_res;
		res = ss_translate_error_crys2ss_aes(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	ss_free((void *)ivCounter_ptr);
	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}


/*
 * brief:	Initialize state of DES algorithm.
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
#define DESKEY_SIZE_BYTE 8U
static SSError_t ss_des_init(void *ctx, uint32_t algo, TEE_OperationMode mode,
		const uint8_t *key1, size_t key1_len, const uint8_t *iv,
		size_t iv_len)
{

	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;

	SS_DES_Context_t *ss_ctx;
	CRYS_DESUserContext_t *contextID_ptr;
	CRYS_DES_Iv_t *ivConter_ptr = NULL;
	CRYS_DES_Key_t *desKey = NULL;
	CRYS_DES_NumOfKeys_t numOfKeys = CRYS_DES_NumOfKeysLast;
	CRYS_DES_EncryptMode_t encDecFlag = CRYS_DES_EncryptModeLast;
	CRYS_DES_OperationMode_t opeMode = CRYS_DES_OperationModeLast;

	PROV_INMSG("START ss_des_init\n");

	if (ctx != NULL) {
		ss_ctx = (SS_DES_Context_t *)ctx;
		ss_ctx->crys_error = SS_SUCCESS;
		ss_ctx->blockSize = 8U;
		ss_ctx->restBufSize= 0U;
		contextID_ptr = &ss_ctx->crys_ctx;
		(void)memset(contextID_ptr, 0, sizeof(CRYS_DESUserContext_t));
	} else {
		res = SS_ERROR_BAD_PARAMETERS;
	}

	if (res == SS_SUCCESS) {
		if (iv != NULL) {
			ivConter_ptr = (CRYS_DES_Iv_t *)ss_malloc_and_copy(
					sizeof(CRYS_DES_Iv_t), (const void *)iv, iv_len,
					&res);
		}
	}

	if (res == SS_SUCCESS) {
		desKey = (CRYS_DES_Key_t *)ss_malloc(sizeof(CRYS_DES_Key_t),
				&res);

	}

	if (res == SS_SUCCESS) {
		if (key1 == NULL) {
			PROV_DMSG("ERROR: BAD_PARAMETERS(key1)\n");
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}

	if (res == SS_SUCCESS) {
		switch ((int32_t)algo) {
		case TEE_ALG_DES_ECB_NOPAD:
		case TEE_ALG_DES_CBC_NOPAD:
			PROV_DMSG("algo = DES   ");
			switch (key1_len) {
			case (DESKEY_SIZE_BYTE):
				(void)memcpy(desKey->key1, key1,
						DESKEY_SIZE_BYTE);
				numOfKeys = CRYS_DES_1_KeyInUse;
				PROV_DMSG("numOfKeys = 1\n");
				break;
			default:
				PROV_DMSG("ERROR: BAD_PARAMETERS(key1_len)\n");
				res = SS_ERROR_BAD_PARAMETERS;
				break;
			}
			break;
		case TEE_ALG_DES3_ECB_NOPAD:
		case TEE_ALG_DES3_CBC_NOPAD:
			PROV_DMSG("algo = DES3   ");
			switch (key1_len) {
			case (DESKEY_SIZE_BYTE*2U):
				(void)memcpy(desKey->key1, key1,
						DESKEY_SIZE_BYTE);
				(void)memcpy(desKey->key2,
						key1 + DESKEY_SIZE_BYTE,
						DESKEY_SIZE_BYTE);
				numOfKeys = CRYS_DES_2_KeysInUse;
				PROV_DMSG("numOfKeys = 2\n");
				break;
			case (DESKEY_SIZE_BYTE*3U):
				(void)memcpy(desKey->key1, key1,
						DESKEY_SIZE_BYTE);
				(void)memcpy(desKey->key2,
						key1 + DESKEY_SIZE_BYTE,
						DESKEY_SIZE_BYTE);
				(void)memcpy(desKey->key3,
						key1 + (DESKEY_SIZE_BYTE * 2U),
						DESKEY_SIZE_BYTE);
				numOfKeys = CRYS_DES_3_KeysInUse;
				PROV_DMSG("numOfKeys = 3\n");
				break;
			default:
				PROV_DMSG("ERROR: BAD_PARAMETERS(key1_len)\n");
				res = SS_ERROR_NOT_SUPPORTED;
				break;
			}
			break;
		default:
			PROV_DMSG("ERROR: BAD_PARAMETERS(algo)\n");
			res = SS_ERROR_BAD_PARAMETERS;
			break;
		}

	}
	if (res == SS_SUCCESS) {
		switch (mode) {
		case TEE_MODE_ENCRYPT:
			PROV_DMSG("numOfKeys = 3\n");
			encDecFlag = CRYS_DES_Encrypt;
			break;
		case TEE_MODE_DECRYPT:
			PROV_DMSG("numOfKeys = 3\n");
			encDecFlag = CRYS_DES_Decrypt;
			break;
		default:
			PROV_DMSG("ERROR: BAD_PARAMETERS(mode)\n");
			res = SS_ERROR_BAD_PARAMETERS;
			break;
		}
	}
	if (res == SS_SUCCESS) {
		switch ((int32_t)algo) {
		case TEE_ALG_DES_ECB_NOPAD:
		case TEE_ALG_DES3_ECB_NOPAD:
			PROV_DMSG("numOfKeys = 2\n");
			opeMode = CRYS_DES_ECB_mode;
			break;
		case TEE_ALG_DES_CBC_NOPAD:
		case TEE_ALG_DES3_CBC_NOPAD:
			PROV_DMSG("numOfKeys = 3\n");
			opeMode = CRYS_DES_CBC_mode;
			break;
		default:
			PROV_EMSG("NOT_SUPPORTED\n");
			res = SS_ERROR_NOT_SUPPORTED;
			break;
		}
	}
	if (res == SS_SUCCESS) {
		crys_res = CRYS_DES_Init(
				contextID_ptr,
				*ivConter_ptr,
				desKey,
				numOfKeys, encDecFlag, opeMode);
		ss_ctx->crys_error = crys_res;
		res = ss_translate_error_crys2ss_des(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	ss_free((void *)ivConter_ptr);
	ss_free((void *)desKey);
	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}

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
		size_t iv_len __maybe_unused)
{
	SSError_t res;
	PROV_INMSG("*ctx=%p, algo=%d, mode=%d, *key1=%p, key1_len=%ld\n",ctx,algo,mode,key1,key1_len);
	PROV_INMSG("*key2=%p, key2_len=%ld, *iv=%p, *iv_len=%ld\n",key2,key2_len,iv,iv_len);

	PROV_DMSG("Input key1\n");
	PROV_DHEXDUMP(key1,key1_len);
	PROV_DMSG("Input key2\n");
	PROV_DHEXDUMP(key2,key2_len);
	PROV_DMSG("Input iv\n");
	PROV_DHEXDUMP(iv,iv_len);

	switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_AES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
#endif
#if defined(CFG_CRYPTO_OFB)
	case TEE_ALG_AES_OFB:
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
#endif
		PROV_DMSG("Input ctx\n");
		PROV_DHEXDUMP(ctx,sizeof(SS_AES_Context_t));
		PROV_DMSG("CALL: ss_aes_init\n");
		res = ss_aes_init(ctx, algo, mode, key1, key1_len, iv, iv_len);
		PROV_DMSG("Result: 0x%08x\n",res);
		break;
#endif
#if defined(CFG_CRYPTO_DES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
#endif
		PROV_DMSG("CALL: ss_aes_init\n");
		res = ss_des_init(ctx, algo, mode, key1, key1_len, iv, iv_len);
		PROV_DMSG("Result: 0x%08x\n",res);
		break;
#endif
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	case TEE_ALG_AES_GCM:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_XCBC_MAC:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CMAC:
	default:
		PROV_DMSG("ERROR:SS_ERROR_NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	}

	PROV_OUTMSG("return res=0x%08x\n", res);
	return ss_translate_error_ss2tee(res);
}

/*
 * brief:	Block Data Update state of AES algorithm.
 *
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	*dstPtr		- Pointer to destination data buffer.
 * param[in]	dstSize		- destination data size.
 * param[in]	blockSize	- block data size.
 * return	SSError_t	- Internal error code of this provider.
 */
static SSError_t ss_swap_cts_block(uint32_t algo, uint8_t *dstPtr,
		uint32_t dstSize, uint32_t blockSize)
{
	SSError_t res = SS_SUCCESS;
	uint8_t *swapPtr;
	PROV_DMSG("algo=0x%08x dstPtr=%p\n", algo, dstPtr);
	PROV_DMSG("dInSize=%d blkSize=%d\n", dstSize, blockSize);
	if ((0U == (dstSize % blockSize)) && (TEE_ALG_AES_CTS == (int32_t)algo)) {
		swapPtr = (uint8_t *)ss_malloc(dstSize, &res);
		if (SS_SUCCESS == res) {
			(void)memcpy(swapPtr, dstPtr + blockSize, blockSize);
			(void)memcpy(swapPtr + blockSize, dstPtr, blockSize);
			(void)memcpy(dstPtr, swapPtr, dstSize);
			ss_free(swapPtr);
		}
	}
	return res;
}

#define CTS_OFFSET 17U
/*
 * brief:	Block Data Update state of AES algorithm.
 *
 * param[in]	*ctx		- Pointer to the AES,DES context.
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	last_block	- If source data is last chunk, the value is true.
 * param[in]	*data		- Pointer to source data buffer.
 * param[in]	len		- Source data size.
 * param[in]	*dst		- Pointer to destination data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
static SSError_t ss_aes_update(void *ctx, uint32_t algo, bool last_block,
		const uint8_t *data, size_t len, uint8_t *dst)
{
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	SS_AES_Context_t *ss_ctx = NULL;
	CRYS_AESUserContext_t  *ContextID_ptr;
	uint8_t *dataIn_ptr = NULL;
	uint32_t dataInSize;
	uint8_t *dataOut_ptr = NULL;
	uint8_t *ctsData = NULL;

	PROV_INMSG("START ss_aes_update\n");

	CHECK_CONTEXT(res, ss_ctx, SS_AES_Context_t, ctx);

	if (SS_SUCCESS == res) {
		if (NULL != dst) {
			dataOut_ptr = dst;
		} else {
			res = SS_ERROR_BAD_PARAMETERS;
			PROV_EMSG("BAD_PARAMETERS(dst)\n");
		}
	}

	if (SS_SUCCESS == res) {
		if (((uint32_t)TEE_ALG_AES_CTS == algo) && (true == last_block)) {
			if (CTS_OFFSET <= len) {
				len -= CTS_OFFSET;
			} else {
				res = SS_ERROR_BAD_PARAMETERS;
			}
		}
	}

	if (SS_SUCCESS == res) {
		res = ss_buffer_update(ss_ctx, algo, data, len, &dataOut_ptr);
	}

	if ((SS_SUCCESS == res) && (true == last_block)) {
		if ((uint32_t)TEE_ALG_AES_CTS == algo) {
			dataInSize = ss_ctx->restBufSize + CTS_OFFSET;
			ctsData = (uint8_t *)ss_malloc(dataInSize, &res);
			if (SS_SUCCESS == res) {
				(void)memcpy(ctsData, ss_ctx->restBuf,
						ss_ctx->restBufSize);
				(void)memcpy((ctsData + ss_ctx->restBufSize),
						(data + len), CTS_OFFSET);
				dataIn_ptr = ctsData;
				if (TEE_MODE_DECRYPT == ss_ctx->mode) {
					PROV_DMSG("algo=0x%08x dstData=%p\n",
							algo, ctsData);
					PROV_DMSG("dstSize=%d blkSize=%d\n",
							dataInSize,
							ss_ctx->blockSize);
					res = ss_swap_cts_block(algo, ctsData,
							dataInSize,
							ss_ctx->blockSize);
				}

			}
		} else {
			dataInSize = ss_ctx->restBufSize;
			dataIn_ptr = ss_ctx->restBuf;
		}
		if (SS_SUCCESS == res) {
			ContextID_ptr = &ss_ctx->crys_ctx;
			crys_res = CRYS_AES_Finish(ContextID_ptr, dataIn_ptr,
					dataInSize, dataOut_ptr);
			ss_ctx->crys_error = crys_res;
			res = ss_translate_error_crys2ss_aes(crys_res);
			PROV_DMSG("crys_res=0x%08x -> res=0x%08x\n", crys_res, res);
		}
		if ((SS_SUCCESS == res) && (TEE_MODE_ENCRYPT == ss_ctx->mode)) {
			PROV_DMSG("algo=0x%08x dstData=%p\n", algo,
					dataOut_ptr);
			PROV_DMSG("dstSize=%d blkSize=%d\n", dataInSize,
					ss_ctx->blockSize);
			res = ss_swap_cts_block(algo, dataOut_ptr, dataInSize,
					ss_ctx->blockSize);
		}
		ss_free(ctsData);
	}

	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;

}

/*
 * brief:	Block Data Update state of DES algorithm.
 *
 * param[in]	*ctx		- Pointer to the AES,DES context.
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	*data		- Pointer to source data buffer.
 * param[in]	len		- Source data size.
 * param[in]	*dst		- Pointer to destination data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
static SSError_t ss_des_update(void *ctx, uint32_t algo, const uint8_t *data,
		size_t len, uint8_t *dst)
{
	SSError_t res = SS_SUCCESS;
	SS_DES_Context_t *ss_ctx = NULL;
	uint8_t *dataOut_ptr = NULL;

	PROV_INMSG("START cipher_init\n");

	CHECK_CONTEXT(res, ss_ctx, SS_DES_Context_t, ctx);

	if (SS_SUCCESS == res) {
		if (NULL != dst) {
			dataOut_ptr = dst;
		} else {
			res = SS_ERROR_BAD_PARAMETERS;
			PROV_EMSG("BAD_PARAMETERS(dst)\n");
		}
	}

	if (SS_SUCCESS == res) {
		res = ss_buffer_update(ss_ctx, algo, data, len,
				&dataOut_ptr);
	}

	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}

/*
 * brief:	Block Data Update state of AES,DES algorithm.
 *
 * param[in]	*ctx		- Pointer to the AES,DES context.
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	last_block	- If source data is last chunk, the value is true.
 * param[in]	*data		- Pointer to source data buffer.
 * param[in]	len		- Source data size.
 * param[in]	*dst		- Pointer to destination data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_cipher_update(void *ctx, uint32_t algo,
		TEE_OperationMode mode __unused,
		bool last_block __maybe_unused, const uint8_t *data, size_t len,
		uint8_t *dst)
{
	TEE_Result tee_res;
	SSError_t res;

	PROV_INMSG("*ctx=%p, algo=%d, mode=%d, last_block=%d\n",ctx,algo,mode,last_block);
	PROV_INMSG("*data=%p, len=%ld, *dst=%p\n",data,len,dst);

	PROV_DMSG("Input src data\n");
	PROV_DHEXDUMP(data,len);
	PROV_DMSG("Input dst data\n");
	PROV_DHEXDUMP(dst,len);

	switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_AES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
#endif
#if defined(CFG_CRYPTO_OFB)
	case TEE_ALG_AES_OFB:
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
#endif
		PROV_DMSG("CALL: ss_aes_update\n");
		PROV_DMSG("Input ctx\n");
		PROV_DHEXDUMP(ctx,sizeof(SS_AES_Context_t));
		res = ss_aes_update(ctx, algo,last_block, data, len, dst);
		PROV_DMSG("Result: 0x%08x\n",res);
		break;
#endif
#if defined(CFG_CRYPTO_DES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
#endif
		PROV_DMSG("CALL: ss_des_update\n");
		PROV_DMSG("Input ctx\n");
		PROV_DHEXDUMP(ctx,sizeof(SS_DES_Context_t));
		res = ss_des_update(ctx, algo, data, len, dst);
		PROV_DMSG("Result: 0x%08x\n",res);
		break;
#endif
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	case TEE_ALG_AES_GCM:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_XCBC_MAC:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CMAC:
	default:
		PROV_DMSG("ERROR:SS_ERROR_NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	}

	tee_res = ss_translate_error_ss2tee(res);
	PROV_DMSG("Output dst data\n");
	PROV_DHEXDUMP(dst,len);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

/*
 * brief:	Finalize state of AES algorithm.
 *
 * param[in]	*ctx		- Context to HASH algorithm.
 * param[in]	algo		- Cryptographic algorithm.
 * return	TEE_Result	- TEE internal API error code.
 */
static void ss_aes_final(void *ctx, uint32_t algo)
{
	TEE_Result res = SS_SUCCESS;
	CRYSError_t crys_res;
	SS_AES_Context_t *ss_ctx;
	CRYS_AESUserContext_t *contextID_ptr;

	PROV_DMSG("*ctx=%p, algo=%d\n",ctx,algo);

	if (ctx != NULL) {
		ss_ctx = (SS_AES_Context_t *)ctx;
	} else {
		PROV_EMSG("ERROR:BAD_PARAMETERS algo=0x%08x\n",algo);
		res = SS_ERROR_BAD_PARAMETERS;
	}

	if (res == SS_SUCCESS) {
		contextID_ptr = &ss_ctx->crys_ctx;
		switch ((int32_t) algo) {
#if defined(CFG_CRYPTO_AES)
#if defined(CFG_CRYPTO_ECB)
		case TEE_ALG_AES_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_CBC)
		case TEE_ALG_AES_CBC_NOPAD:
#endif
#if defined(CFG_CRYPTO_CTR)
		case TEE_ALG_AES_CTR:
#endif
#if defined(CFG_CRYPTO_OFB)
		case TEE_ALG_AES_OFB:
#endif
#if defined(CFG_CRYPTO_CTS)
		case TEE_ALG_AES_CTS:
#endif
			PROV_DMSG("CALL: CRYS_AES_Finish\n");
			crys_res = CRYS_AES_Finish(contextID_ptr, NULL, 0U,
					NULL);
			ss_ctx->crys_error = crys_res;
			PROV_DMSG("Result: crys_res=0x%08x\n", crys_res);
			break;
#endif
		case TEE_ALG_AES_GCM:
		case TEE_ALG_AES_CCM:
		case TEE_ALG_AES_CBC_MAC_NOPAD:
		case TEE_ALG_AES_CBC_MAC_PKCS5:
		case TEE_ALG_AES_XCBC_MAC:
		case TEE_ALG_AES_CMAC:
		default:
			break;
		}
	}
	return;
}


/*
 * brief:	Finalize state of AES,DES algorithm.
 *
 * param[in]	*ctx		- Context to HASH algorithm.
 * param[in]	algo		- Cryptographic algorithm.
 * return	TEE_Result	- TEE internal API error code.
 */
static void ss_des_final(void *ctx, uint32_t algo)
{
	TEE_Result res = SS_SUCCESS;
	CRYSError_t crys_res;
	SS_DES_Context_t *ss_ctx;
	CRYS_DESUserContext_t *contextID_ptr;

	PROV_DMSG("*ctx=%p, algo=%d\n",ctx,algo);

	if (ctx != NULL) {
		ss_ctx = (SS_DES_Context_t *)ctx;
	} else {
		PROV_EMSG("ERROR:BAD_PARAMETERS algo=0x%08x\n",algo);
		res = SS_ERROR_BAD_PARAMETERS;
	}

	if (res == SS_SUCCESS) {
		contextID_ptr = &ss_ctx->crys_ctx;

		switch ((int32_t) algo) {
#if defined(CFG_CRYPTO_DES)
#if defined(CFG_CRYPTO_ECB)
		case TEE_ALG_DES_ECB_NOPAD:
		case TEE_ALG_DES3_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_ECB)
		case TEE_ALG_DES_CBC_NOPAD:
		case TEE_ALG_DES3_CBC_NOPAD:
#endif
			PROV_DMSG("CALL: CRYS_DES_Free\n");
			crys_res = CRYS_DES_Free(contextID_ptr);
			ss_ctx->crys_error = crys_res;
			PROV_DMSG("Result: crys_res=0x%08x\n", crys_res);
			break;
		case TEE_ALG_DES3_CBC_MAC_NOPAD:
		case TEE_ALG_DES3_CBC_MAC_PKCS5:
		case TEE_ALG_DES_CBC_MAC_NOPAD:
		case TEE_ALG_DES_CBC_MAC_PKCS5:
#endif
		default:
			break;
		}
	}
	return;
}

/*
 * brief:	Finalize state of AES,DES algorithm.
 *
 * param[in]	*ctx		- Context to HASH algorithm.
 * param[in]	algo		- Cryptographic algorithm.
 * return	TEE_Result	- TEE internal API error code.
 */
void crypto_hw_cipher_final(void *ctx, uint32_t algo)
{
	PROV_INMSG("*ctx=%p, algo=%d\n",ctx,algo);

	switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_AES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
#endif
#if defined(CFG_CRYPTO_OFB)
	case TEE_ALG_AES_OFB:
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
#endif
		PROV_DMSG("CALL: ss_aes_final\n");
		PROV_DMSG("Input ctx\n");
		PROV_DHEXDUMP(ctx,sizeof(SS_AES_Context_t));
		ss_aes_final(ctx, algo);
		break;
#endif
#if defined(CFG_CRYPTO_DES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
#endif
		PROV_DMSG("CALL: ss_des_final\n");
		PROV_DMSG("Input ctx\n");
		PROV_DHEXDUMP(ctx,sizeof(SS_DES_Context_t));
		ss_des_final(ctx, algo);
		break;
#endif
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	case TEE_ALG_AES_GCM:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CMAC:
	case TEE_ALG_AES_XCBC_MAC:
	default:
		break;
	}
	return;
}

#endif /* _CFG_CRYPTO_WITH_CIPHER */

/*****************************************************************************
 * Message Authentication Code functions
 *****************************************************************************/

#if defined(_CFG_CRYPTO_WITH_MAC)
/*
 * brief:	Get context size to HMAC,AES-MAC algorithm.
 *
 * param[in]	algo		- Cryptographic algorithm.
 * param[out]	*size		- Size of context to AES,DES algorithm.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_mac_get_ctx_size(uint32_t algo, size_t *size)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;

	PROV_INMSG("START: mac_get_ctx_size\n");

	switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_HMAC)
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		PROV_DMSG("ctx size = sizeof(SS_HMAC_Context_t)\n");
		*size = sizeof(SS_HMAC_Context_t);
		break;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
		PROV_DMSG("ctx size = sizeof(SS_AES_Context_t)\n");
		*size = sizeof(SS_AES_Context_t);
		break;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		PROV_DMSG("ctx size = sizeof(SS_AES_Context_t)\n");
		*size = sizeof(SS_AES_Context_t);
		break;
#endif
#if defined(CFG_CRYPTO_XCBC_MAC)
	case TEE_ALG_AES_XCBC_MAC:
		PROV_DMSG("ctx size = sizeof(SS_AES_Context_t)\n");
		*size = sizeof(SS_AES_Context_t);
		break;
#endif
	default:

		PROV_EMSG("NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	}

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}


/*
 * brief:	Initialize state of AES-MAC algorithm.
 *
 * param[in]	*ctx		- Pointer to the AES contest.
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	*key		- Pinter to the AES key.
 * param[in]	len		- AES key size.
 * return	SSError_t	- SS provider error code.
 */
static SSError_t ss_aesmac_init(void *ctx, uint32_t algo __unused,
		const uint8_t *key, size_t len)
{
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	SS_AES_Context_t *ss_ctx;
	CRYS_AESUserContext_t *contextID_ptr;
	CRYS_AES_IvCounter_t ivCounter_ptr = {0U};
	CRYS_AES_OperationMode_t aesMode;
	CRYS_AES_Key_t aesKey = {0U};
	CRYS_AES_KeySize_t aeskeySize;

	PROV_INMSG("START: ss_aesmac_init\n");

	if (ctx != NULL) {
		ss_ctx = (SS_AES_Context_t *)ctx;
		(void)memset(ss_ctx,0,sizeof(SS_AES_Context_t));
		ss_ctx->crys_error = SS_SUCCESS;
		ss_ctx->blockSize = 16U;
		ss_ctx->restBufSize = 0U;
		contextID_ptr = &ss_ctx->crys_ctx;
	} else {
		PROV_EMSG("BAD_PARAMETERS(ctx)\n");
		res = SS_ERROR_BAD_PARAMETERS;
	}

	if (res == SS_SUCCESS) {
		switch (len) {
		case 16U:
			PROV_DMSG("key_len = 128bit\n");
			aeskeySize = CRYS_AES_Key128BitSize;
			break;
		case 24U:
			PROV_DMSG("key_len = 192bit\n");
			aeskeySize = CRYS_AES_Key192BitSize;
			break;
		case 32U:
			PROV_DMSG("key_len = 256bit\n");
			aeskeySize = CRYS_AES_Key256BitSize;
			break;
		default:
			PROV_EMSG("BAD_PARAMETERS(len)\n");
			aeskeySize = CRYS_AES_KeySizeLast;
			res = SS_ERROR_BAD_PARAMETERS;
			break;
		}
	}

	if (res == SS_SUCCESS) {
		if (key == NULL) {
			PROV_EMSG("BAD_PARAMETERS(key)\n");
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}
	if (res == SS_SUCCESS) {
		switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_CBC_MAC)
		case TEE_ALG_AES_CBC_MAC_NOPAD:
		case TEE_ALG_AES_CBC_MAC_PKCS5:
			PROV_DMSG("algo = AES MAC\n");
			aesMode = CRYS_AES_MAC_mode;
			break;
#endif
#if defined(CFG_CRYPTO_CMAC)
		case TEE_ALG_AES_CMAC:
			PROV_DMSG("algo = CMAC\n");
			aesMode = CRYS_AES_CMAC_mode;
			break;
#endif
#if defined(CFG_CRYPTO_XCBC_MAC)
		case TEE_ALG_AES_XCBC_MAC:
			PROV_DMSG("algo = XCBC MAC\n");
			aesMode = CRYS_AES_XCBC_MAC_mode;
			break;
#endif
		default:
			PROV_EMSG("NOT_SUPPORTED\n");
			res = SS_ERROR_NOT_SUPPORTED;
			break;
		}
	}
	if (res == SS_SUCCESS) {
		(void)memcpy(aesKey, key, len);
		PROV_DMSG("CALL:  CRYS_AES_Init()\n");
		crys_res = CRYS_AES_Init(contextID_ptr, ivCounter_ptr, aesKey,
				aeskeySize, CRYS_AES_Encrypt, aesMode);
		ss_ctx->crys_error = crys_res;
		res = ss_translate_error_crys2ss_aes(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}

/*
 * brief:	Initialize state of HMAC algorithm.
 *
 * param[in]	*ctx		- Pointer to the HASH contest.
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	*key		- Pinter to the Random key.
 * param[in]	len		- Random key size.
 * return	SSError_t	- SS provider error code.
 */
static SSError_t ss_hmac_init(void *ctx, uint32_t algo, const uint8_t *key,
		size_t len)
{
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	SS_HMAC_Context_t *ss_ctx;
	CRYS_HMACUserContext_t *contextID_ptr;
	uint8_t *hashKey_ptr;
	uint16_t hashKeySize;
	CRYS_HASH_OperationMode_t opeMode;

	PROV_INMSG("START: ss_hmac_init\n");

	if (ctx != NULL) {
		ss_ctx = (SS_HMAC_Context_t *)ctx;
		(void)memset(ss_ctx,0,sizeof(SS_HMAC_Context_t));
		ss_ctx->crys_error = SS_SUCCESS;
		ss_ctx->restBufSize = 0U;
		contextID_ptr = &ss_ctx->crys_ctx;
		hashKey_ptr = (uint8_t *)key;
		hashKeySize = (uint16_t)len;
		ss_ctx->blockSize = 64U;
	} else {
		PROV_EMSG("BAD_PARAMETERS(ctx)\n");
		res = SS_ERROR_BAD_PARAMETERS;
	}

	if (res == SS_SUCCESS) {
		switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_MD5)
		case TEE_ALG_HMAC_MD5:
			PROV_DMSG("algo = TEE_ALG_HMAC_MD5\n");
			opeMode = CRYS_HASH_MD5_mode;
			break;
#endif
#if defined(CFG_CRYPTO_SHA1)
		case TEE_ALG_HMAC_SHA1:
			PROV_DMSG("algo = TEE_ALG_HMAC_SHA1\n");
			opeMode = CRYS_HASH_SHA1_mode;
			break;
#endif
#if defined(CFG_CRYPTO_SHA224)
		case TEE_ALG_HMAC_SHA224:
			PROV_DMSG("algo = TEE_ALG_HMAC_SHA224\n");
			opeMode = CRYS_HASH_SHA224_mode;
			break;
#endif
#if defined(CFG_CRYPTO_SHA256)
		case TEE_ALG_HMAC_SHA256:
			PROV_DMSG("algo = TEE_ALG_HMAC_SHA256\n");
			opeMode = CRYS_HASH_SHA256_mode;
			break;
#endif
#if defined(CFG_CRYPTO_SHA384)
		case TEE_ALG_HMAC_SHA384:
			PROV_DMSG("algo = TEE_ALG_HMAC_SHA384\n");
			opeMode = CRYS_HASH_SHA384_mode;
			ss_ctx->blockSize = 128U;
			break;
#endif
#if defined(CFG_CRYPTO_SHA512)
		case TEE_ALG_HMAC_SHA512:
			PROV_DMSG("algo = TEE_ALG_HMAC_SHA512\n");
			opeMode = CRYS_HASH_SHA512_mode;
			ss_ctx->blockSize = 128U;
			break;
#endif
		default:
			PROV_EMSG("NOT_SUPPORTED\n");
			opeMode = CRYS_HASH_OperationModeLast;
			res = SS_ERROR_NOT_SUPPORTED;
			break;
		}
	}

	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL:  CRYS_HMAC_Init()\n");
		crys_res = CRYS_HMAC_Init(contextID_ptr, opeMode, hashKey_ptr,
				hashKeySize);
		ss_ctx->crys_error = crys_res;
		res = ss_translate_error_crys2ss_hmac(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}

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
		size_t len)
{
	TEE_Result tee_res;
	SSError_t res;

	PROV_INMSG("START: mac_init\n");
	PROV_DMSG("algo = 0x%08x\n",algo);
	switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_HMAC)
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		PROV_DMSG("CALL:  ss_hmac_init()\n");
		res = ss_hmac_init(ctx, algo, key, len);
		break;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
		PROV_DMSG("CALL:  ss_aesmac_init()\n");
		res = ss_aesmac_init(ctx, algo, key, len);
		break;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		PROV_DMSG("CALL:  ss_aesmac_init()\n");
		res = ss_aesmac_init(ctx, algo, key, len);
		break;
#endif
#if defined(CFG_CRYPTO_XCBC_MAC)
	case TEE_ALG_AES_XCBC_MAC:
		PROV_DMSG("CALL:  ss_aesmac_init()\n");
		res = ss_aesmac_init(ctx, algo, key, len);
		break;
#endif
	default:
		PROV_EMSG("NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	}

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

/*
 * brief:	Block Data Update state of HMAC algorithm.
 *
 * param[in]	*ctx		- Pointer to the HMAC context.
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	*data		- Pointer to source data buffer.
 * param[in]	len		- Source data size.
 * return	TEE_Result	- TEE internal API error code.
 */
static SSError_t ss_hmac_update(void *ctx, uint32_t algo, const uint8_t *data, size_t len)
{
	SSError_t res = SS_SUCCESS;
	SS_HMAC_Context_t *ss_ctx;
	uint8_t *nullBuf = NULL;

	PROV_INMSG("START: ss_hmac_update\n");

	CHECK_CONTEXT(res, ss_ctx, SS_HMAC_Context_t, ctx);

	if(SS_SUCCESS == res){
		res = ss_buffer_update(ctx, algo, data, len, &nullBuf);
	}

	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}

/*
 * brief:	Block Data Update state of AES-MAC algorithm.
 *
 * param[in]	*ctx		- Pointer to the AES-MAC context.
 * param[in]	algo		- Cryptographic algorithm.
 * param[in]	*data		- Pointer to source data buffer.
 * param[in]	len		- Source data size.
 * return	TEE_Result	- TEE internal API error code.
 */
static SSError_t ss_aesmac_update(void *ctx, uint32_t algo, const uint8_t *data,
		size_t len)
{
	SSError_t res = SS_SUCCESS;
	SS_AES_Context_t *ss_ctx;
	uint8_t *nullBuf = NULL;

	PROV_INMSG("START: ss_aesmac_update\n");

	CHECK_CONTEXT(res, ss_ctx, SS_AES_Context_t, ctx);

	if(SS_SUCCESS == res){
		res = ss_buffer_update(ctx, algo, data, len, &nullBuf);
	}

	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}

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
		size_t len)
{
	TEE_Result tee_res;
	SSError_t res;

	PROV_INMSG("START: mac_update\n");

	switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_HMAC)
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		PROV_DMSG("CALL: ss_hmac_update()\n");
		res = ss_hmac_update(ctx, algo, data, len);
		break;
#endif
#if defined(CFG_CRYPTO_AES)
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
#endif
#if defined(CFG_CRYPTO_XCBC_MAC)
	case TEE_ALG_AES_XCBC_MAC:
#endif
		PROV_DMSG("CALL: ss_aesmac_update() algo=CMAC\n");
		res = ss_aesmac_update(ctx, algo, data, len);
		break;
#endif
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	default:
		PROV_EMSG("NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	}

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

/*
 * brief:	Finalize state of HMAC algorithm.
 *
 * param[in]	*ctx		- Context to HMAC,AES-MAC algorithm.
 * param[in]	algo		- Cryptographic algorithm.
 * param[out]	*digest		- Pointer to the digest(MAC) data.
 * param[out]	digest_len	- Digest(MAC) data size.
 * return	TEE_Result	- TEE internal API error code.
 */
static SSError_t ss_hmac_final(void *ctx, uint32_t algo, uint8_t *digest,
		size_t digest_len)
{
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	SS_HMAC_Context_t *ss_ctx;
	CRYS_HMACUserContext_t *contextID_ptr;
	CRYS_HASH_Result_t hmacResultBuff;
	uint32_t hmacResultLen = 0U;

	PROV_INMSG("START: ss_hmac_final\n");

	if (ctx != NULL) {
		ss_ctx = (SS_HMAC_Context_t *)ctx;
	} else {
		PROV_EMSG("BAD_PARAMETERS(ctx)\n");
		res = SS_ERROR_BAD_PARAMETERS;
	}

	if (res == SS_SUCCESS) {
		if (ss_ctx->crys_error != SS_SUCCESS) {
			PROV_EMSG("BAD_STATE\n");
			res = SS_ERROR_BAD_STATE;
		} else {
			contextID_ptr = &ss_ctx->crys_ctx;

			switch ((int32_t)algo) {
			case TEE_ALG_HMAC_MD5:
				PROV_DMSG("algo=TEE_ALG_HMAC_MD5\n");
				hmacResultLen = 16U;
				break;
			case TEE_ALG_HMAC_SHA1:
				PROV_DMSG("algo=TEE_ALG_HMAC_SHA1\n");
				hmacResultLen = 20U;
				break;
			case TEE_ALG_HMAC_SHA224:
				PROV_DMSG("algo=TEE_ALG_HMAC_SHA224\n");
				hmacResultLen = 28U;
				break;
			case TEE_ALG_HMAC_SHA256:
				PROV_DMSG("algo=TEE_ALG_HMAC_SHA256\n");
				hmacResultLen = 32U;
				break;
			case TEE_ALG_HMAC_SHA384:
				PROV_DMSG("algo=TEE_ALG_HMAC_SHA384\n");
				hmacResultLen = 48U;
				break;
			case TEE_ALG_HMAC_SHA512:
				PROV_DMSG("algo=TEE_ALG_HMAC_SHA512\n");
				hmacResultLen = 64U;
				break;
			default:
				PROV_EMSG("NOT_SUPPORTED\n");
				res = SS_ERROR_NOT_SUPPORTED;
				break;
			}
		}
	}

	if (res == SS_SUCCESS) {
		if (digest == NULL) {
			PROV_EMSG("BAD_PARAMETERS(digest)\n");
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}

	if (res == SS_SUCCESS) {
		if (digest_len < (size_t)hmacResultLen) {
			PROV_EMSG("SHORT_BUFFER(hmacResultLen)\n");
			res = SS_ERROR_SHORT_BUFFER;
		}
	}

	if (res == SS_SUCCESS) {
		if(ss_ctx->restBufSize != 0U){
			crys_res = CRYS_HMAC_Update(contextID_ptr,
					ss_ctx->restBuf, ss_ctx->restBufSize);
			ss_ctx->crys_error = crys_res;
			res = ss_translate_error_crys2ss_hmac(crys_res);
		}
	}

	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: CRYS_HMAC_Finish()\n");
		crys_res = CRYS_HMAC_Finish(contextID_ptr, hmacResultBuff);
		ss_ctx->crys_error = crys_res;
		res = ss_translate_error_crys2ss_hmac(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}
	if (res == SS_SUCCESS) {
		(void)memcpy(digest, hmacResultBuff, hmacResultLen);
	}

	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}

/*
 * brief:	Finalize state of AES-MAC algorithm.
 *
 * param[in]	*ctx		- Context to HMAC,AES-MAC algorithm.
 * param[in]	algo		- Cryptographic algorithm.
 * param[out]	*digest		- Pointer to the digest(MAC) data.
 * param[out]	digest_len	- Digest(MAC) data size.
 * return	TEE_Result	- TEE internal API error code.
 */
static SSError_t ss_aesmac_final(void *ctx, uint32_t algo, uint8_t *digest, size_t digest_len)
{
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	SS_AES_Context_t *ss_ctx;
	CRYS_AESUserContext_t *contextID_ptr;
	uint8_t *dataIn_ptr;
        uint32_t dataInSize;

	PROV_INMSG("START: ss_aesmac_final\n");

	if (ctx != NULL) {
		ss_ctx = (SS_AES_Context_t *)ctx;
	} else {
		PROV_EMSG("BAD_PARAMETERS(ctx)\n");
		res = SS_ERROR_BAD_PARAMETERS;
	}
	if (res == SS_SUCCESS) {
		if(digest_len < 16U) {
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}
	if (res == SS_SUCCESS) {
		if (ss_ctx->crys_error != SS_SUCCESS) {
			PROV_EMSG("BAD_STATE\n");
			res = SS_ERROR_BAD_STATE;
		}
	}

	if (res == SS_SUCCESS) {
		contextID_ptr = &ss_ctx->crys_ctx;
		PROV_DMSG("CALL: CRYS_AES_Finish()\n");
		if ((int32_t)algo == TEE_ALG_AES_CBC_MAC_PKCS5) {
			(void)memset(ss_ctx->restBuf + ss_ctx->restBufSize,
					(int32_t)ss_ctx->blockSize - (int32_t)ss_ctx->restBufSize,
					ss_ctx->blockSize - ss_ctx->restBufSize);
			dataIn_ptr = ss_ctx->restBuf;
			dataInSize = ss_ctx->blockSize;
		} else {
			if(ss_ctx->restBufSize != 0U){
				dataIn_ptr = ss_ctx->restBuf;
				dataInSize = ss_ctx->restBufSize;
			} else {
				dataIn_ptr = NULL;
				dataInSize = 0U;
			}
		}
		crys_res = CRYS_AES_Finish(contextID_ptr, dataIn_ptr, dataInSize, digest);
		ss_ctx->crys_error = crys_res;
		res = ss_translate_error_crys2ss_aes(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}
	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}

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
		size_t digest_len)
{
	TEE_Result tee_res;
	SSError_t res;

	PROV_INMSG("START: mac_final\n");

	switch ((int32_t)algo) {
#if defined(CFG_CRYPTO_HMAC)
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		PROV_DMSG("CALL: ss_hmac_final()\n");
		res = ss_hmac_final(ctx, algo, digest, digest_len);
		break;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
		PROV_DMSG("CALL: ss_aesmac_final() algo=AES_MAC\n");
		res = ss_aesmac_final(ctx, algo, digest, digest_len);
		break;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		PROV_DMSG("CALL: ss_aesmac_final() algo=CMAC\n");
		res = ss_aesmac_final(ctx, algo, digest, digest_len);
		break;
#endif
#if defined(CFG_CRYPTO_XCBC_MAC)
	case TEE_ALG_AES_XCBC_MAC:
		PROV_DMSG("CALL: ss_aesmac_final() algo=CMAC\n");
		res = ss_aesmac_final(ctx, algo, digest, digest_len);
		break;
#endif
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	default:
		PROV_EMSG("NOT_SUPPORTED\n");
		res = SS_ERROR_NOT_SUPPORTED;
		break;
	}
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}
#endif /* _CFG_CRYPTO_WITH_MAC */

/******************************************************************************
 * Authenticated encryption
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_AUTHENC)
#define TEE_CCM_NONCE_MAX_LENGTH	13U
#define TEE_CCM_NONCE_MIN_LENGTH	7U
#define TEE_CCM_TAG_MAX_LENGTH		16U
#define TEE_CCM_TAG_MIN_LENGTH		4U

#if defined(CFG_CRYPTO_CCM)
/*
 * brief:	Allocate a context for AESCCM algorithm.
 *
 * param[in]	ctx		- Pointer to the AESCCM context.
 * return	TEE_Result	- TEE Internal API error code.
 */
TEE_Result crypto_hw_aes_ccm_alloc_ctx(void **ctx)
{
	TEE_Result tee_ret;
	SSError_t ret = SS_SUCCESS;
	SS_AESCCM_Context_t *ss_ctx;

	ss_ctx = (SS_AESCCM_Context_t *)ss_calloc(1U,
			sizeof(SS_AESCCM_Context_t), &ret);
	if (ret == SS_SUCCESS) {
		*ctx = ss_ctx;
	}
	tee_ret = ss_translate_error_ss2tee(ret);

	return tee_ret;
}

/*
 * brief:	Copy a context for AESCCM algorithm.
 *
 * param[in]	dst_ctx		- Pointer to a destination context.
 * param[in]	src_ctx		- Pointer to a source context.
 * return	void
 */
void crypto_hw_aes_ccm_copy_state(void *dst_ctx, const void *src_ctx)
{
	(void)memcpy(dst_ctx, src_ctx, sizeof(SS_AESCCM_Context_t));
}

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
		size_t payload_len)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	SS_AESCCM_Context_t *ss_ctx;
	CRYS_AESCCM_UserContext_t *contextID_ptr;
	CRYS_AES_EncryptMode_t encrDecrMode;
	CRYS_AESCCM_Key_t ccmkey;
	CRYS_AESCCM_KeySize_t ccmkeySize;
	uint32_t ddataSize;
	uint32_t textSize;
	uint8_t *n_ptr;
	uint8_t sizeOfN;
	uint8_t sizeOfT;

	PROV_INMSG("START: crypto_aes_ccm_init\n");

	if (ctx != NULL) {
		ss_ctx = (SS_AESCCM_Context_t *)ctx;
		(void)memset(ss_ctx,0,sizeof(SS_AESCCM_Context_t));
		ss_ctx->crys_error = SS_SUCCESS;
		ss_ctx->blockSize = 16U;
		ss_ctx->restBufSize = 0U;
		ss_ctx->tagSize = tag_len;
		contextID_ptr = &ss_ctx->crys_ctx;
	} else {
		PROV_EMSG("BAD_PARAMETERS(ctx)\n");
		res = SS_ERROR_BAD_PARAMETERS;
	}

	if (res == SS_SUCCESS) {
		contextID_ptr = &ss_ctx->crys_ctx;
		ddataSize = (uint32_t)aad_len;
		textSize = (uint32_t)payload_len;
		n_ptr = (uint8_t *)nonce;
		sizeOfN = (uint8_t)nonce_len;
		sizeOfT = (uint8_t)tag_len;

		switch (mode) {
		case TEE_MODE_ENCRYPT:
			PROV_DMSG("mode=TEE_MODE_ENCRYPT\n");
			encrDecrMode = CRYS_AES_Encrypt;
			break;
		case TEE_MODE_DECRYPT:
			PROV_DMSG("mode=TEE_MODE_DECRYPT\n");
			encrDecrMode = CRYS_AES_Decrypt;
			break;
		default:
			PROV_EMSG("BAD_PARAMETERS(mode)\n");
			encrDecrMode = CRYS_AES_EncryptModeLast;
			res = SS_ERROR_BAD_PARAMETERS;
			break;
		}
	}

	if ((res == SS_SUCCESS) && (key == NULL)) {
		PROV_EMSG("BAD_PARAMETERS(key)\n");
		res = SS_ERROR_BAD_PARAMETERS;
	}

	if (res == SS_SUCCESS) {
		switch (key_len) {
		case 16U:
			PROV_DMSG("key_len=128 bit\n");
			ccmkeySize = CRYS_AES_Key128BitSize;
			break;
		case 24U:
			PROV_DMSG("key_len=192 bit\n");
			ccmkeySize = CRYS_AES_Key192BitSize;
			break;
		case 32U:
			PROV_DMSG("key_len=256 bit\n");
			ccmkeySize = CRYS_AES_Key256BitSize;
			break;
		default:
			PROV_EMSG("BAD_PARAMETERS(key_len)\n");
			ccmkeySize = CRYS_AES_KeySizeLast;
			res = SS_ERROR_BAD_PARAMETERS;
			break;
		}
	}

	if (res == SS_SUCCESS) {
		(void)memcpy(ccmkey, key, key_len);
		if ((nonce_len > TEE_CCM_NONCE_MAX_LENGTH)
				|| (nonce_len < TEE_CCM_NONCE_MIN_LENGTH)) {
			PROV_EMSG("BAD_PARAMETERS(nonce_len)\n");
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}

	if (res == SS_SUCCESS) {
		if ((sizeOfT > TEE_CCM_TAG_MAX_LENGTH)
				|| (sizeOfT < TEE_CCM_TAG_MIN_LENGTH)) {
			PROV_EMSG("BAD_PARAMETERS(sizeOfT) size\n");
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}

	if (res == SS_SUCCESS) {
		if ((sizeOfT & 0x01U) == 1U) {
			PROV_EMSG("BAD_PARAMETERS(sizeOfT) value\n");
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}

	if (res == SS_SUCCESS) {
			PROV_DMSG("CALL: CRYS_AESCCM_Init()\n");
			crys_res = CRYS_AESCCM_Init(contextID_ptr, encrDecrMode,
					ccmkey, ccmkeySize, ddataSize, textSize,
					n_ptr, sizeOfN, sizeOfT);
			ss_ctx->crys_error = crys_res;
			res = ss_translate_error_crys2ss_ccm(crys_res);
			PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",
					crys_res, res);
	}

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

/*
 * brief:	Block Add Data Update state of AESCCM algorithm.
 *
 * param[in]	*ctx		- Pointer to the AESCCM context.
 * param[in]	*data		- Pointer to source data buffer.
 * param[in]	len		- Source data size.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_aes_ccm_update_aad(void *ctx, const uint8_t *data,
		size_t len)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	SS_AESCCM_Context_t *ss_ctx;
	CRYS_AESCCM_UserContext_t *contextID_ptr;
	uint8_t *dataIn_ptr;
	uint32_t dataInSize;

	PROV_INMSG("START: crypto_aes_ccm_update_aad\n");

	if (ctx != NULL) {
		ss_ctx = (SS_AESCCM_Context_t *)ctx;
	} else {
		PROV_EMSG("BAD_PARAMETERS(ctx)\n");
		res = SS_ERROR_BAD_PARAMETERS;
	}

	if (res == SS_SUCCESS) {
		if (ss_ctx->crys_error != SS_SUCCESS) {
			PROV_EMSG("BAD_STATE\n");
			res = SS_ERROR_BAD_STATE;
		} else {
			contextID_ptr = &ss_ctx->crys_ctx;
			dataIn_ptr = (uint8_t *)data;
			dataInSize = (uint32_t)len;
			PROV_DMSG("CALL: CRYS_AESCCM_BlockAdata()\n");
			crys_res = CRYS_AESCCM_BlockAdata(contextID_ptr,
					dataIn_ptr, dataInSize);
			ss_ctx->crys_error = crys_res;
			res = ss_translate_error_crys2ss_ccm(crys_res);
			PROV_DMSG("Result: crys_res=0x%08x\n", crys_res);
		}
	}

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

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
		size_t len, uint8_t *dst_data)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	SS_AESCCM_Context_t *ss_ctx;

	PROV_INMSG("START: crypto_aes_ccm_update_payload\n");

	CHECK_CONTEXT(res, ss_ctx, SS_AESCCM_Context_t, ctx);

	if (SS_SUCCESS == res) {
		if ((MAX_DATAIN_CCM_SIZE < len)
				|| ((len % 16U) != 0U)) {
			res = SS_ERROR_BAD_PARAMETERS;
			PROV_EMSG("BAD_PARAMETERS len=%ld\n", len);
		}

	}

	if (SS_SUCCESS == res) {
		PROV_DMSG("ctx=%p\n", ctx);
		PROV_DMSG("src_data=%p len=%ld dst_data=%p\n",
				src_data, len, dst_data);
		res = ss_buffer_update(ctx, TEE_ALG_AES_CCM, src_data,
				len, &dst_data);
	}

	/* dst_len not used for SS provider*/
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

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
		size_t *dst_tag_len)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;

	SS_AESCCM_Context_t *ss_ctx;
	CRYS_AESCCM_UserContext_t *contextID_ptr;
	uint8_t *dataIn_ptr;
	uint32_t dataInSize;
	uint8_t *dataOut_ptr;
	CRYS_AESCCM_Mac_Res_t macRes = {0U};
	uint8_t sizeOfT;

	PROV_INMSG("START: authenc_enc_final\n");

	if (ctx != NULL) {
		ss_ctx = (SS_AESCCM_Context_t *)ctx;
	} else {
		PROV_EMSG("BAD_PARAMETERS(ctx)\n");
		res = SS_ERROR_BAD_PARAMETERS;
	}

	if (res == SS_SUCCESS) {
		if (ss_ctx->crys_error != SS_SUCCESS) {
			res = SS_ERROR_BAD_STATE;
			PROV_EMSG("BAD_STATE\n");
		} else {
			contextID_ptr = &ss_ctx->crys_ctx;
			dataIn_ptr = (uint8_t *)src_data;
			dataInSize = (uint32_t)len;
			dataOut_ptr = (uint8_t *)dst_data;
			sizeOfT = (uint8_t)*dst_tag_len;
			/* Check the tag length */
			if (sizeOfT < ss_ctx->tagSize) {
				*dst_tag_len = ss_ctx->tagSize;
				res = SS_ERROR_SHORT_BUFFER;
				PROV_EMSG("ERROR:SHORT_BUFFER(sizeOfT)\n");
			}
		}
	}
	if (res == SS_SUCCESS) {
		/* Compute the tag */
		PROV_DMSG("CALL: CRYS_AESCCM_Finish()\n");
		crys_res = CRYS_AESCCM_Finish(contextID_ptr, dataIn_ptr,
				dataInSize, dataOut_ptr, macRes,
				&sizeOfT);
		ss_ctx->crys_error = crys_res;
		res = ss_translate_error_crys2ss_ccm(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	if (res == SS_SUCCESS) {
		*dst_tag_len = sizeOfT;
		(void)memcpy(dst_tag, macRes, (size_t)sizeOfT);
	}

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

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
		size_t tag_len)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;

	SS_AESCCM_Context_t *ss_ctx;
	CRYS_AESCCM_UserContext_t *contextID_ptr;
	uint8_t *dataIn_ptr;
	uint32_t dataInSize;
	uint8_t *dataOut_ptr;
	CRYS_AESCCM_Mac_Res_t macRes = {0U};
	uint8_t sizeOfT;

	PROV_INMSG("START: authenc_dec_final\n");

	if (ctx != NULL) {
		ss_ctx = (SS_AESCCM_Context_t *)ctx;
	} else {
		res = SS_ERROR_BAD_PARAMETERS;
		PROV_EMSG("BAD_PARAMETERS(ctx)\n");
	}

	if (res == SS_SUCCESS) {
		if (ss_ctx->crys_error != SS_SUCCESS) {
			res = SS_ERROR_BAD_STATE;
			PROV_EMSG("BAD_STATE\n");

		} else {
			contextID_ptr = &ss_ctx->crys_ctx;
			dataIn_ptr = (uint8_t *)src_data;
			dataInSize = (uint32_t)len;
			dataOut_ptr = (uint8_t *)dst_data;
			sizeOfT = (uint8_t)tag_len;
			if (sizeOfT == 0U) {
				res = SS_ERROR_SHORT_BUFFER;
				PROV_EMSG("ERROR:SHORT_BUFFER(sizeOfT)\n");
			}
		}
	}
	if (res == SS_SUCCESS) {
		if (sizeOfT > (uint8_t) TEE_CCM_TAG_MAX_LENGTH) {
			res = SS_ERROR_BAD_PARAMETERS;
			PROV_EMSG("BAD_PARAMETERS(sizeOfT)\n");
		} else {
			(void)memcpy(macRes, tag, sizeOfT);
		}
	}
	if (res == SS_SUCCESS) {
		crys_res = CRYS_AESCCM_Finish(contextID_ptr, dataIn_ptr,
				dataInSize, dataOut_ptr, macRes,
				&sizeOfT);
		ss_ctx->crys_error = crys_res;
		res = ss_translate_error_crys2ss_ccm(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",crys_res,res);
	}

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);
	return tee_res;
}

/*
 * brief:	In case of SS provider, this function do nothing.
 * return	void
 */
void crypto_hw_aes_ccm_final(void)
{
	PROV_INMSG("START: authenc_final (do nothing)\n");
	return;
}
#endif /* CFG_CRYPTO_CCM */
#endif /* _CFG_CRYPTO_WITH_AUTHENC */

/******************************************************************************
 * Pseudo Random Number Generator
 ******************************************************************************/

/*
 * brief:	Wrap CRYS_RND_GenerateVector() to output more than 64KB of data.
 *
 * param[in]	*outPtr		- Pointer of output buffer.
 * param[in]	outSize		- Byte size of the output data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_rng_read(void *outPtr, size_t outSize)
{
	SSError_t res;
	CRYSError_t crys_res = (CRYSError_t)CRYS_OK;
	size_t remain = outSize;
	uint16_t crysOutSize;
	uint8_t *compOutPtr = (uint8_t *)outPtr;

	PROV_DMSG("crysOutSize=%ld  outPtr=%p\n", outSize, outPtr);

	while ((remain != 0U) && (crys_res == (CRYSError_t)CRYS_OK)) {
		if (remain > 0xFFC0U) {
			crysOutSize = 0xFFC0U;
		} else {
			crysOutSize = (uint16_t)remain;
		}
		PROV_DMSG("CALL: CRYS_RND_GenerateVector()\n");
		PROV_DMSG("crysOutSize=%d  outPtr=%p\n", crysOutSize, outPtr);
		crys_res = CRYS_RND_GenerateVector(crysOutSize, compOutPtr);
		compOutPtr += crysOutSize;
		remain -= crysOutSize;
	}

	res = ss_translate_error_crys2ss_rnd(crys_res);
	PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n", crys_res, res);
	return res;
}

/*
 * brief:	Add entropy for PRNG.
 *
 * param[in]	*inbuf		- Pointer to the entropy data buffer.
 * param[in]	len		- Size of entropy data.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_rng_add_entropy(const uint8_t *inbuf, size_t len)
{
	TEE_Result tee_res;
	SSError_t res;
	CRYSError_t crys_res;
	uint8_t addInput[(uint32_t)CRYS_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS
			* sizeof(uint32_t)] = {0};
	size_t addInputSizeBytes;

	PROV_INMSG("START: prng_add_entropy\n");

	if (NULL == inbuf) {
		PROV_EMSG("Input Buffer is NULL\n");
		res = SS_ERROR_BAD_PARAMETERS;
	} else {
		if (sizeof(addInput) < len) {
			addInputSizeBytes = sizeof(addInput);
		} else {
			addInputSizeBytes = len;
		}
		(void)memcpy(addInput, inbuf, addInputSizeBytes);

		PROV_DMSG("CALL: CRYS_RND_AddAdditionalInput()\n");
		crys_res = CRYS_RND_AddAdditionalInput((uint8_t *)&addInput[0],
				(uint16_t)sizeof(addInput));

		res = ss_translate_error_crys2ss_rnd(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n", crys_res,
				res);
		if (SS_SUCCESS != res) {
			PROV_EMSG("res=0x%08x\n", res);
		}
	}
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n", res, tee_res);
	return tee_res;
}

/*
 * brief:	Initialize the random number generato.
 *
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_rng_init(void)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	CRYS_RND_WorkBuff_t *rndWorkBuff;

	PROV_INMSG("START: prng_init\n");

	rndWorkBuff = (CRYS_RND_WorkBuff_t *)ss_malloc(
			sizeof(CRYS_RND_WorkBuff_t), &res);

	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL: CRYS_RND_Instantiation()\n");
		crys_res = CRYS_RND_Instantiation(rndWorkBuff);
		res = ss_translate_error_crys2ss_rnd(crys_res);
		PROV_DMSG("Result: crys_res=0x%08x -> res=0x%08x\n",
				crys_res, 	res);
	}
	ss_free(rndWorkBuff);
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",
			res, tee_res);
	return tee_res;
}

/*
 * brief:	This function enables derivation of 128 bit customer keys
 * 		by performing AES CMAC on customer input.
 *
 * param[in]	keyType		- Input keyType 0:SESSION_KEY 1:KDR_KEY.
 * param[in]	*in		- Input buffer address to make MAC.
 * param[in]	inSize		- Size of Input buffer address.
 * param[in]	out		- Output buffer address to get result.
 * param[in]	outSize		- Size of Output buffer address.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_cmac_derivekey(uint32_t keyType, uint8_t *in,
		uint32_t inSize, uint8_t *out, uint32_t outSize)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	DxUTILError_t util_res;
	DX_UTIL_KeyType_t aesKeyType;
	uint8_t *pDataIn;
	uint32_t dataInSize;
	DX_UTIL_AES_CmacResult_t pCmacResult;

	pDataIn = in;
	dataInSize = inSize;

	switch (keyType) {
	case 0U:
		aesKeyType = DX_UTIL_SESSION_KEY;
		break;
	case 1U:
		aesKeyType = DX_UTIL_KDR_KEY;
		break;
	default:
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	}

	if (res == SS_SUCCESS) {
		if (out == NULL) {
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}
	if (res == SS_SUCCESS) {
		if (outSize < 16U) {
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}
	if (res == SS_SUCCESS) {
		util_res = DX_UTIL_CmacDeriveKey(aesKeyType, pDataIn,
				dataInSize, pCmacResult);
		res = ss_translate_error_crys2ss_util(util_res);
	}
	if (res == SS_SUCCESS) {
		(void)memcpy(out, pCmacResult,
				sizeof(DX_UTIL_AES_CmacResult_t));
	}
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n", res, tee_res);
	return tee_res;
}

/*
 * brief:	This function gets RPMB key.
 * param[out]	out		- Pointer to 32byte output, to be used as RPMB key.
 * param[out]	outSize		- Size of Output buffer size.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_rpmb_derivekey(uint8_t *out, uint32_t outSize)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	DxUTILError_t util_res;
	DxUtilRpmbKey_t pCmacResult;
	uint32_t rpmbKeySize;

	rpmbKeySize = sizeof(DxUtilRpmbKey_t);
	if (out == NULL) {
		PROV_EMSG("But Parameters out=%p",out);
		res = SS_ERROR_BAD_PARAMETERS;
	}
	if (res == SS_SUCCESS) {
		if (outSize < rpmbKeySize) {
			PROV_EMSG("Short Buffer outSize=%d rpmbKeySize=%d",
					outSize, rpmbKeySize);
			res = SS_ERROR_SHORT_BUFFER;
		}
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("DX_UTIL_SignRPMBFrames() pCmacResult=%p\n",pCmacResult);
		util_res = DX_UTIL_DeriveRPMBKey(pCmacResult);
		PROV_DHEXDUMP(pCmacResult, sizeof(DxUtilRpmbKey_t));
		res = ss_translate_error_crys2ss_util(util_res);
		PROV_DMSG("return util_res=0x%08x -> res=0x%08x\n", util_res,
				res);
	}
	if (res == SS_SUCCESS) {
		(void)memcpy(out, pCmacResult, rpmbKeySize);
		PROV_DHEXDUMP(out, rpmbKeySize);
	}
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n", res, tee_res);
	return tee_res;
}

/*
 * brief:	This function gets RPMB sign frames.
 * param[out]	pListOfDataFrames		- Pointer to a list of 284 Byte frame addresses.
 *                        The entire frame list will be signed.
 * param[out]	listSize		- The number of 284 Byte frames in the list, up to 65,535.
 * param[out]	out		- Pointer to the output data (HMAC result).
 * param[out]	outSize		- Size of Output buffer size.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_rpmb_signframes(uint64_t *in, uint32_t listSize, uint8_t *out,
		uint32_t outSize)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	DxUTILError_t util_res;
	DxUtilHmacResult_t pHmacResult;
	uint32_t hmacSize;

	PROV_INMSG("in=%p listSize=%d out=%p outSize=%d\n", in, listSize, out,
			outSize);
	hmacSize = (uint32_t)DX_UTIL_HMAC_SHA256_DIGEST_SIZE_IN_WORDS
			* sizeof(uint32_t);
	if (in == NULL) {
		PROV_EMSG("But Parameters in=%p",in);
		res = SS_ERROR_BAD_PARAMETERS;
	}
	if (res == SS_SUCCESS) {
		if (out == NULL) {
			PROV_EMSG("But Parameters out=%p",out);
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}
	if (res == SS_SUCCESS) {
		if (outSize < hmacSize) {
			PROV_EMSG("Short Buffer outSize=%d hmacSize=%d",
					outSize, hmacSize);
			res = SS_ERROR_SHORT_BUFFER;
		}
	}
	if (res == SS_SUCCESS) {
		PROV_DMSG("DX_UTIL_SignRPMBFrames()\n");
		PROV_DMSG("in=%p listSize=%d pHmacResult=%p\n", in, listSize,
				pHmacResult);
		util_res = DX_UTIL_SignRPMBFrames((unsigned long *)in, listSize,
				pHmacResult);
		PROV_DHEXDUMP(pHmacResult, hmacSize);
		res = ss_translate_error_crys2ss_util(util_res);
		PROV_DMSG("return util_res=0x%08x -> res=0x%08x\n", util_res,
				res);
	}
	if (res == SS_SUCCESS) {
		(void)memcpy(out, pHmacResult, hmacSize);
		PROV_DHEXDUMP(out, hmacSize);
	}
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n", res, tee_res);
	return tee_res;
}

/*
 * brief:	This function provides AES unwrap for a user key or Krdp.
 *
 * param[in]	 *srcData	- Input buffer address to make MAC.
 * param[in]	 srcLen		- Size of Input buffer address.
 * param[in]	 *keyData	- Key data address.
 * param[in]	 keySize	- Key data size.
 * param[in]	 isSecretKey	- Input keyType 0:User key 1:Krdp.
 * param[out]	 *destData	- Output buffer address to get result.
 * param[in/out] *dstLen	- Size of Output buffer address.
 * return	 TEE_Result	- TEE internal API error code.
 */
TEE_Result crypto_hw_cipher_unwrap(void *srcData, uint32_t srcLen,
		const void *keyData, uint32_t keySize, uint32_t isSecretKey,
		void *destData, uint32_t *dstLen)
{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	CRYS_AES_Key_t unwrapKey;
	CRYS_AES_KeySize_t keySizeNum = CRYS_AES_KeySizeLast;
	uint32_t dataOutLen;


	if (0U == isSecretKey) {
		switch (keySize) {
		case 16U:
			PROV_DMSG("KeySize=128Bit\n");
			keySizeNum = CRYS_AES_Key128BitSize;
			break;
		case 24U:
			PROV_DMSG("KeySize=192Bit\n");
			keySizeNum = CRYS_AES_Key192BitSize;
			break;
		case 32U:
			PROV_DMSG("KeySize=256Bit\n");
			keySizeNum = CRYS_AES_Key256BitSize;
			break;
		default:
			PROV_EMSG("Error keySize=%d\n", keySize);
			res = SS_ERROR_BAD_PARAMETERS;
			break;
		}
		if (SS_SUCCESS == res) {
			if (NULL != keyData) {
				(void)memcpy(unwrapKey, keyData, keySize);
			}
		}
	}
	if (SS_SUCCESS == res) {
		if (dstLen == NULL) {
			PROV_EMSG("But Parameters dstLen=%p",dstLen);
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}
	if (SS_SUCCESS == res) {
		dataOutLen = *dstLen;
		PROV_DMSG("Call CRYS_AESUNWRAP() dataOutLen=%d\n", dataOutLen);
		crys_res = CRYS_AESUNWRAP((uint8_t *)srcData, srcLen, unwrapKey,
				keySizeNum, isSecretKey, (uint8_t *)destData,
				&dataOutLen);
		PROV_DMSG("End  CRYS_AESUNWRAP() dataOutLen=%d\n", dataOutLen);
		PROV_DMSG("crys_res=0x%08x res=0x%08x\n", crys_res, res);
		res = ss_translate_error_crys2ss_aes(crys_res);
	}
	if (SS_SUCCESS == res) {
		*dstLen = dataOutLen;
	}
	tee_res = ss_translate_error_ss2tee(res);
	PROV_DMSG("tee_res=0x%08x res=0x%08x\n", tee_res, res);
	return tee_res;
}

/*
 * brief:	This function provides generating Secure Key Package..
 *
 * param[in]	 skeyParams	 - Structure contains input parameters.
 * param[out]	 *skeyPackageBuf - Output buffer address to Secure Key Package.
 * return	 TEE_Result	 - TEE internal API error code.
 */
TEE_Result crypto_hw_gen_skey_package(RCAR_SkeyParams_t *skeyParams,
		uint8_t *skeyPackageBuf, uint32_t skeyPackageSize)
{
	SSError_t res = SS_SUCCESS;
	TEE_Result tee_res;
	uint32_t util_res;
	enum secure_key_direction skeyDirection;
	enum secure_key_cipher_mode skeyMode;
	enum secure_key_type skeyType;
	struct DX_UTIL_NonceCtrProtParams_t skeyProtParams;
	skeyPackageBuf_t OutPackageBuf;

	switch (skeyParams->direction) {
	case TEE_MODE_ENCRYPT:
		skeyDirection = DX_SECURE_KEY_DIRECTION_ENCRYPT;
		break;
	case TEE_MODE_DECRYPT:
		skeyDirection = DX_SECURE_KEY_DIRECTION_DECRYPT;
		break;
	default:
		PROV_EMSG("Direction=%d", skeyParams->direction);
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	}

	if (SS_SUCCESS == res) {
		switch (skeyParams->mode) {
		case TEE_SKEY_CIPHER_CBC:
			skeyMode = DX_SECURE_KEY_CIPHER_CBC;
			break;
		case TEE_SKEY_CIPHER_CTR:
			skeyMode = DX_SECURE_KEY_CIPHER_CTR;
			break;
		case TEE_SKEY_CIPHER_OFB:
			skeyMode = DX_SECURE_KEY_CIPHER_OFB;
			break;
		case TEE_SKEY_CIPHER_CBC_CTS:
			skeyMode = DX_SECURE_KEY_CIPHER_CBC_CTS;
			break;
		case TEE_SKEY_CIPHER_CTR_NONCE_PROT:
			skeyMode = DX_SECURE_KEY_CIPHER_CTR_NONCE_PROT;
			break;
		case TEE_SKEY_CIPHER_CTR_NONCE_PROT_NSP:
			skeyMode = DX_SECURE_KEY_CIPHER_CTR_NONCE_CTR_PROT_NSP;
			break;
		default:
			PROV_EMSG("Mode=%d", skeyParams->mode);
			res = SS_ERROR_NOT_SUPPORTED;
			break;
		}
	}

	if (SS_SUCCESS == res) {
		switch (skeyParams->keyType) {
		case TEE_SKEY_AES_KEY128:
			skeyType = DX_SECURE_KEY_AES_KEY128;
			break;
		case TEE_SKEY_AES_KEY256:
			skeyType = DX_SECURE_KEY_AES_KEY256;
			break;
		case TEE_SKEY_MULTI2:
			skeyType = DX_SECURE_KEY_MULTI2;
			break;
		case TEE_SKEY_BYPASS:
			skeyType = DX_SECURE_KEY_BYPASS;
			break;
		default:
			PROV_EMSG("KeyType=%d", skeyParams->keyType);
			res = SS_ERROR_BAD_PARAMETERS;
			break;
		}
	}

	if (SS_SUCCESS == res) {
		skeyProtParams.nonceCtrBuff = &skeyParams->nonceCtrBuff[0];
		skeyProtParams.nonceLen = skeyParams->nonceLen;
		skeyProtParams.ctrLen = skeyParams->ctrLen;
		skeyProtParams.dataRange = skeyParams->dataRange;
		skeyProtParams.isNonSecPathOp = skeyParams->isNonSecPathOp;

		util_res = DX_UTIL_GenerateSecureKeyPackage(skeyDirection,
				skeyMode, skeyParams->lowerBound,
				skeyParams->upperBound, skeyParams->nonceBuf,
				skeyParams->keyBuf, skeyType,
				skeyParams->keyNumRounds, &skeyProtParams,
				OutPackageBuf);

		res = ss_translate_error_crys2ss_util(util_res);
		PROV_DMSG("util_res=0x%08x -> res=0x%08x\n", util_res, res);
	}

	if (SS_SUCCESS == res) {
		if (NULL == skeyPackageBuf) {
			PROV_EMSG("skeyPackageBuf is NULL");
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}

	if (SS_SUCCESS == res) {
		if (sizeof(skeyPackageBuf_t) <= skeyPackageSize) {
			(void)memcpy(skeyPackageBuf, OutPackageBuf,
				sizeof(skeyPackageBuf_t));
		} else {
			PROV_EMSG("skeyPackageSize=%d", skeyPackageSize);
			res = SS_ERROR_BAD_PARAMETERS;
		}
	}

	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n", res, tee_res);
	return tee_res;
}
/*
 * brief:	This function provides secure provisioning of OEM key.
 *
 * param[in]	 assetId		- Asset ID embedded in the asset package.
 * param[in]	 *pAssetPackage		- The encrypted asset package.
 * param[in]	 assetPackagLen		- Package data size.
 * param[out]	 *pAssetData		- The decrypted asset data.
 * param[in/out] *pAssetDataLen		- Size of Output buffer address.
 * param[out]	 *pUserData		- Optionally user data embedded in the package.
 * return	- TEE internal API error code.
 */
TEE_Result crypto_hw_asset_unpack(uint32_t assetId,
		uint8_t *pAssetPackage, uint32_t assetPackagLen,
		uint8_t *pAssetData, uint32_t *pAssetDataLen,
		uint32_t *pUserData)

{
	TEE_Result tee_res;
	SSError_t res = SS_SUCCESS;
	CRYSError_t crys_res;
	uint32_t dataOutLen;
	uint32_t check_crys_res;

	PROV_INMSG("START: do_asset_unpack\n");
	if ((pAssetPackage == NULL) || (pAssetData == NULL) || 
		(pAssetDataLen  == NULL)) {
		PROV_EMSG("But Parameters in=%p out=%p outlen_ptr=%p",
			pAssetPackage, pAssetData, pAssetDataLen);
		res = SS_ERROR_BAD_PARAMETERS;
	}
	
	if (SS_SUCCESS == res) {
		dataOutLen = *pAssetDataLen;
		crys_res = CRYS_ASSET_UNPACK(assetId, pAssetPackage,
				assetPackagLen, pAssetData, &dataOutLen,
				pUserData);
		PROV_DMSG("crys_res=0x%08x dataOutLen=%d\n", crys_res, dataOutLen);
		check_crys_res = crys_res >> 8U;
		if (check_crys_res == CHECK_CRYS_ERROR_AES_BASE) {
			res = ss_translate_error_crys2ss_aes(crys_res);
		} else if (check_crys_res == CHECK_CRYS_ERROR_AESCCM_BASE) {
			res = ss_translate_error_crys2ss_ccm(crys_res);
		} else {
			res = ss_translate_error_crys2ss_util(crys_res);
		}
		PROV_DMSG("crys_res=0x%08x -> res=0x%08x\n", crys_res, res);
	}
	if (SS_SUCCESS == res) {
		*pAssetDataLen = dataOutLen;
	}
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("res=0x%08x -> tee_res=0x%08x\n",res, tee_res);
	return tee_res;
}

/*
 * brief:	Callback function to use Suspend To RAM.
 *
 * param[in]	state		- State of Suspend To RAM.
 * param[in]	cpu_id		- ID of using CPU.
 * return	void
 */
static void ss_backup_cb(enum suspend_to_ram_state state,
		uint32_t cpu_id __unused)
{
	if (state == SUS2RAM_STATE_SUSPEND) {
		CRYS_Core_Suspend();
#if defined(CFG_CRYPT_ENABLE_CEPKA)
		CRYS_PKA_Suspend();
#endif
	} else {
		CRYS_Core_Resume();
#if defined(CFG_CRYPT_ENABLE_CEPKA)
		CRYS_PKA_Resume();
#endif
	}
	return;
}
suspend_to_ram_cbfunc(ss_backup_cb);

#if defined(CFG_CRYPTO_SHA256)
/*
 * brief:	Generate SHA256 from input data and compare it with input digest.
 *
 * param[in]	hash		- HASH data generated from input data.
 * param[in]	data		- Input data address.
 * param[in]    data_size       - Size of input data
 * return	TEE_Result      - TEE Internal API error code.
 */
TEE_Result crypto_hw_hash_sha256_check(const uint8_t *hash, const uint8_t *data,
		size_t data_size)
{
	TEE_Result ret;
	uint8_t gen_hash[TEE_SHA256_HASH_SIZE];
	int32_t mem_ret;

	CRYS_HASHUserContext_t ctx;

	ret = crypto_hw_hash_init(&ctx, TEE_ALG_SHA256);

	if (ret == (TEE_Result)TEE_SUCCESS) {
		ret = crypto_hw_hash_update(&ctx, TEE_ALG_SHA256, data,
				data_size);
	}

	if (ret == (TEE_Result)TEE_SUCCESS) {
		ret = crypto_hw_hash_final(&ctx, TEE_ALG_SHA256, gen_hash,
				(size_t)TEE_SHA256_HASH_SIZE);
	}

	if (ret == (TEE_Result)TEE_SUCCESS) {
		mem_ret = memcmp(gen_hash, hash, (size_t)TEE_SHA256_HASH_SIZE);
		if (mem_ret != 0) {
			ret = (TEE_Result)TEE_ERROR_SECURITY;
		}
	}

	return ret;
}
#endif /* CFG_CRYPTO_SHA256 */

/*
 * brief:	Initialize of Crypto Engine Secure and PKA engines.
 *
 * return	TEE_Result	- TEE internal API error code.
 */
static TEE_Result crypto_hw_init_crypto_engine(void)
{
	TEE_Result tee_res;
	SSError_t res;
	DX_CclibRetCode_t crys_res;
	DxUTILError_t util_res;
	PROV_INMSG("START %s\n", __func__);
	crys_res = DX_CclibInit();
	res = ss_translate_error_crys2ss_init(crys_res);
	PROV_DMSG("crys_res=0x%08x -> res=0x%08x \n",crys_res,res);
	if (res == SS_SUCCESS) {
		util_res = DX_UTIL_SetSessionKey();
		res = ss_translate_error_crys2ss_util(util_res);
	}
#if defined(CFG_CRYPT_ENABLE_CEPKA)
	if (res == SS_SUCCESS) {
		res = pka_verify_init();
	}
#endif
	tee_res = ss_translate_error_ss2tee(res);
	PROV_OUTMSG("return res=0x%08x -> tee_res=0x%08x\n",res,tee_res);

	return tee_res;
}

service_init(crypto_hw_init_crypto_engine);
