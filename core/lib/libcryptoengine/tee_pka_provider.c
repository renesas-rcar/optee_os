// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2018, Renesas Electronics Corporation
 */

#include "include_pka/crys_error.h"
#include "include_pka/sa_pkadrvlib.h"
#include "tee_provider_common.h"
#include "tee_pka_provider.h"

/******************************************************************************/
/* Static Function Prototypes                                                 */
/******************************************************************************/
static SSError_t pka_translate_error_pka2ss_ecc(SA_PkadrvlibRetCode_t err);
static SSError_t pka_get_ecc_digest(uint32_t msg_len,
		CRYS_ECPKI_HASH_OpMode_t *hash);
static SSError_t pka_get_ecc_keysize(uint32_t curve,
		CRYS_ECPKI_DomainID_t *domain_id,
		uint32_t *key_size_bytes);
static void userProcessCompletedFunc(CRYSError_t opStatus __unused,
		void* pVerifContext __unused);

/*
 * brief:	Translate  CRYS API AES error into SS provider error.
 *
 * param[in]	err		- CRYS API AES error code
 * return	TEE_Result
 */
static SSError_t pka_translate_error_pka2ss_ecc(SA_PkadrvlibRetCode_t err)
{
	SSError_t res;

	PROV_INMSG("SA_PkadrvlibRetCode_t err=0x%08x\n", err);

	switch (err) {
	case SA_PKADRVLIB_RET_OK:
	case SA_PKADRVLIB_RET_EINPROGRESS:
		PROV_DMSG("res = SS_SUCCESS\n");
		res = SS_SUCCESS;
		break;
	case SA_PKADRVLIB_RET_MUTEX_LOCK_ERROR:
	case SA_PKADRVLIB_RET_MUTEX_UNLOCK_ERROR:
	case SA_PKADRVLIB_RET_MUTEX_INIT_ERROR:
	case SA_PKADRVLIB_RET_MUTEX_TERMINATE_ERROR:
		PROV_EMSG("res = SS_ERROR_BAD_STATE\n");
		res = SS_ERROR_BAD_STATE;
		break;
	default:
		PROV_EMSG("res = SS_ERROR_BAD_PARAMETERS\n");
		res = SS_ERROR_BAD_PARAMETERS;
		break;
	}

	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}

/*
 * brief:	Get a digest algorithm used in ECDSA.
 *
 * param[in]	msg_len			- Input message size.
 * param[out]	*hash			- Digest algorithm.
 * return	SSError_t		- SS provider error code.
 */
static SSError_t pka_get_ecc_digest(uint32_t msg_len,
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
static SSError_t pka_get_ecc_keysize(uint32_t curve,
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

	PROV_OUTMSG("return res=0x%08x\n", res);
	return res;
}

/*
 * brief:	Callback for signalign "engine available" events,
 *              in case all engines ware busy.
 * 		But in case of Gen3, unusing callback function.
 *
 * return	TEE_Result	- TEE internal API error code.
 */
static void userProcessCompletedFunc(CRYSError_t opStatus __unused,
		void* pVerifContext __unused)
{
	return;
}

/*
 * brief:	Verify by the ECC using CRYS API (FIPS 186-4 ANSI X9.62)
 *
 * param[in]	*key		- Pointer to the struct of the ECC key pair.
 * param[in]	*msg		- Pointer to the message data buffer.
 * param[in]	msg_len		- Size of message data buffer.
 * param[in]	*sig		- Pointer to the signature data buffer.
 * param[in]	*sig_len	- Size of signature data buffer.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result ss_ecc_verify_pka(struct ecc_public_key *key, const uint8_t *msg,
		size_t msg_len, const uint8_t *sig, size_t sig_len)
{
	TEE_Result tee_res;
	CRYSError_t crys_res;
	SSError_t res = SS_SUCCESS;
	SA_PkadrvlibRetCode_t pka_res;
	CRYS_ECPKI_UserPublKey_t *pUserPublKey = NULL;
	CRYS_ECPKI_HASH_OpMode_t eccHash;
	uint8_t *pSignatureIn;
	uint32_t signatureSizeBytes;
	uint8_t *pMessageDataIn;
	uint32_t messageSizeInBytes;
	CRYS_ECPKI_DomainID_t domain_id;
	CRYS_ECPKI_Domain_t *ecc_domain;
	uint8_t *publKeyIn_ptr = NULL;
	uint32_t publKeySizeInBytes;
	size_t publKeySizeXBytes;
	size_t publKeySizeYBytes;
	uint32_t modulusbytes;
	uint8_t *publKeyX_ptr = NULL;
	uint8_t *publKeyY_ptr = NULL;

	PROV_INMSG("*key=%p, *msg=%p, msg_len=%ld\n", (void * )key, msg,
			msg_len);
	PROV_INMSG("*sig=%p, sig_len=%ld\n", sig, sig_len);

	pSignatureIn = (uint8_t *)sig;
	signatureSizeBytes = (uint32_t)sig_len;
	pMessageDataIn = (uint8_t *)msg;
	messageSizeInBytes = (uint32_t)msg_len;

	if (key == NULL) {
		res = SS_ERROR_BAD_PARAMETERS;
		PROV_DMSG("BAD_PARAMETERS(key)\n");
	}

	if (res == SS_SUCCESS) {
		pUserPublKey = (CRYS_ECPKI_UserPublKey_t *)ss_malloc(
				sizeof(CRYS_ECPKI_UserPublKey_t), &res);
	}

	if (res == SS_SUCCESS) {
		res = pka_get_ecc_keysize(key->curve, &domain_id, &modulusbytes);
	}

	if (res == SS_SUCCESS) {
		crys_res = CRYS_ECPKI_GetEcDomain(domain_id, &ecc_domain);
		res = ss_translate_error_crys2ss_ecc(crys_res);
		PROV_DMSG("Result: res=0x%08x\n", res);
	}

	if (res == SS_SUCCESS) {
		/* malloc public key size */
		res = ss_copy_bn2bin(key->x, &publKeyX_ptr, &publKeySizeXBytes);
	}
	if (res == SS_SUCCESS) {
		res = ss_copy_bn2bin(key->y, &publKeyY_ptr, &publKeySizeYBytes);
	}
	if (res == SS_SUCCESS) {
		publKeySizeInBytes = (sizeof(uint8_t) + (modulusbytes * 2U));
		publKeyIn_ptr = (uint8_t *)ss_calloc(1U, publKeySizeInBytes, &res);
	}

	if (res == SS_SUCCESS) {
		res = pka_get_ecc_digest(messageSizeInBytes, &eccHash);
	}

	if (res == SS_SUCCESS) {
		/* build public key */
		*publKeyIn_ptr = (uint8_t)CRYS_EC_PointUncompressed;
		(void)memcpy(((publKeyIn_ptr + 1U + modulusbytes)
						- publKeySizeXBytes),
				publKeyX_ptr, publKeySizeXBytes);
		(void)memcpy(((publKeyIn_ptr + 1U + (modulusbytes * 2U))
						- publKeySizeYBytes),
				publKeyY_ptr, publKeySizeYBytes);
		PROV_DMSG("CALL:  CRYS_ECPKI_BuildPublKey()\n");
		PROV_DMSG("ecc_domain=%p publkeyIn_ptr=%p\n", (void *)ecc_domain,
				(void *)publKeyIn_ptr);
		PROV_DMSG("publKeySizeInBytes=%d pUserPublKey=%p\n",
				publKeySizeInBytes, (void *)pUserPublKey);
		pka_res = SA_PKADRV_EcdsaBuildPublKey(ecc_domain, publKeyIn_ptr,
				publKeySizeInBytes, pUserPublKey);
		res = pka_translate_error_pka2ss_ecc(pka_res);
		PROV_DMSG("Result: res=0x%08x\n", res);
	}

	if (res == SS_SUCCESS) {
		PROV_DMSG("CALL:  SA_PKADRV_EcdsaVerifyMessage()\n");
		PROV_DMSG("pUserPublKey=%p eccHash=%d\n",
				(void *)pUserPublKey, eccHash);
		PROV_DMSG("pSignatureIn=%p signatureSizeBytes=%d\n",
				(void *)pSignatureIn, signatureSizeBytes);
		PROV_DMSG("pMessageDataIn=%p messageSizeInBytes=%d\n",
				(void *)pMessageDataIn, messageSizeInBytes);
		pka_res = SA_PKADRV_EcdsaVerifyMessage(
		NULL, &userProcessCompletedFunc, pUserPublKey, eccHash,
				pSignatureIn, signatureSizeBytes,
				pMessageDataIn, messageSizeInBytes);
		res = pka_translate_error_pka2ss_ecc(pka_res);
		PROV_DMSG("Result: res=0x%08x\n", res);
	}

	ss_free((void *)publKeyX_ptr);
	ss_free((void *)publKeyY_ptr);
	ss_free((void *)publKeyIn_ptr);
	ss_free((void *)pUserPublKey);

	OUTMSG("END do_ecc_verify_pka res=0x%08x\n", res);
	tee_res = ss_translate_error_ss2tee(res);
	return tee_res;
}

/*
 * brief:	Initialize the Crypto Engine PKA.
 *
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result pka_verify_init(void)
{

	TEE_Result res;
	SA_PkadrvlibRetCode_t pka_res;

	PROV_INMSG("SA_PKADRV_Init()\n");
	pka_res = SA_PKADRV_Init(NULL, NULL);
	res = pka_translate_error_pka2ss_ecc(pka_res);

	return res;
}
