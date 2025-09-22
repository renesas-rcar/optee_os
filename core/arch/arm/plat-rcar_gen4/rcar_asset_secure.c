#include <stdint.h>
#include <tee_api_defines.h>
#include "tee_api_types.h"
#include "trace.h"

#include "rcar_asset_secure.h"

TEE_Result icum_asset_unpack(uint32_t assetId,
		uint8_t *pAssetPackage, uint32_t assetPackageLen,
		uint8_t *pAssetData, uint32_t *pAssetDataLen,
		uint32_t *pUserData);

TEE_Result icum_asset_unpack(uint32_t assetId,
		uint8_t *pAssetPackage, uint32_t assetPackageLen,
		uint8_t *pAssetData, uint32_t *pAssetDataLen,
		uint32_t *pUserData)
{
	uint32_t res;
	uint32_t ret = TEE_SUCCESS;
	uint8_t keyProv[ASSET_PKG_AES_CMAC_RESULT_SIZE_IN_BYTES] = {0};
	uint8_t dataIn[ASSET_DATA_IN_CMAC_LENGTH] = {0};
	uint8_t i = 0;
	uint32_t enAssetDataSize = 0;
	uint32_t assetMacOffset = 0;
	uint32_t tmpWord;

	if (0 == assetId) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* make sure asster data buffer length allocated by user is big enough */
	CONVERT_BYTE_ARR_TO_WORD(&pAssetPackage[ASSET_PKG_EN_DATA_SIZE_OFFSET], enAssetDataSize);
	if ((assetPackageLen < ASSET_PKG_NONE_ASSET_DATA_SIZE+enAssetDataSize) ||
			(*pAssetDataLen < enAssetDataSize)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* check Token and Version */
	CONVERT_BYTE_ARR_TO_WORD(&pAssetPackage[ASSET_PKG_TOKEN_OFFSET], tmpWord);
	if ((unsigned int)ASSET_PACK_TOKEN != tmpWord) {
		return TEE_ERROR_BAD_PARAMETERS;
	}
	CONVERT_BYTE_ARR_TO_WORD(&pAssetPackage[ASSET_PKG_VERSION_SIZE], tmpWord);
	if ((unsigned int)ASSET_VERSION != tmpWord) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* 1. derive a specific key KPROV = AES-CMAC (KUT, 0x01 || 0x50 || 0x00 || asset_id || 0x80)*/
	i = 0;
	dataIn[i++] = KUT_DATA_IN_PREFIX_DATA0;
	dataIn[i++] = KUT_DATA_IN_PREFIX_DATA1;
	dataIn[i++] = KUT_DATA_IN_PREFIX_DATA2;
	/* add asset ID */
	CONVERT_WORD_TO_BYTE_ARR(assetId, (unsigned char *)&dataIn[i]);
	i += sizeof(uint32_t);
	dataIn[i] = KUT_DATA_IN_SUFIX_DATA;

	 /* Init ICUM Firmware interface */
	res = fwss_service_init();
	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fwss_service_init() error");
		ret = TEE_ERROR_SECURITY;
	}

	/* Derive and update K_PROV from Transport Key */
	ret = fwss_aes_cmac(KEY_GRP_AES, 11, dataIn, sizeof(dataIn), &keyProv[0]);
	if (ret != TEE_SUCCESS) {
		EMSG("Failed to derive K_PROV !");
		goto out;
	}

	ret = fwss_plain_key_update(KEY_GRP_AES_RAM, 4, (uint8_t *)keyProv,
			AES_BLOCK_SIZE_IN_BYTES, DISABLE_KEY_WRITE_PROTECT);
	if (ret != TEE_SUCCESS) {
		EMSG("Failed to install K_PROV !");
		goto out;
	}

	/* Decrypt the Asset data within asset buffer using AES-CCM  */
	assetMacOffset = ASSET_PKG_EN_DATA_OFFSET+enAssetDataSize;
	ret = fwss_auth_aes_cipher(CIPHER_DIR_DECRYPTION, AUTH_CIPHER_MOD_CCM,
			KEY_GRP_AES_RAM, 4,
			&(pAssetPackage[ASSET_PKG_CCM_NONCE_OFFSET]),
			ASSET_PKG_CCM_NONCE_SIZE,
			&(pAssetPackage[ASSET_PKG_CCM_ADDITIONAL_DATA_OFFSET]),
			ASSET_PKG_CCM_ADDITIONAL_DATA_SIZE,
			&(pAssetPackage[ASSET_PKG_EN_DATA_OFFSET]),
			enAssetDataSize,
			pAssetData,
			&(pAssetPackage[assetMacOffset]),
			ASSET_PKG_MAC_SIZE);
	if (ret != TEE_SUCCESS) {
		EMSG("Failed to decrypt asset package !");
		goto out;
	}

	if (pUserData != NULL) {
		CONVERT_BYTE_ARR_TO_WORD(&pAssetPackage[ASSET_PKG_USER_DATA_OFFSET], *pUserData);
	}
	*pAssetDataLen = enAssetDataSize;
out:
	return ret;
}

TEE_Result rcar_asset_unpack(uint32_t assetId,
		uint8_t *pAssetPackage, uint32_t assetPackageLen,
		uint8_t *pAssetData, uint32_t *pAssetDataLen,
		uint32_t *pUserData)
{
	uint32_t ret = TEE_SUCCESS;
	uint32_t dataOutLen;

	IMSG("START: do_asset_unpack\n");
	if ((pAssetPackage == NULL) || (pAssetData == NULL) ||
		(pAssetDataLen == NULL)) {
		EMSG("But Parameters in=%p out=%p outlen_ptr=%p",
			pAssetPackage, pAssetData, pAssetDataLen);
		ret = TEE_ERROR_BAD_PARAMETERS;
	}

	if (TEE_SUCCESS == ret) {
		dataOutLen = *pAssetDataLen;
		ret = icum_asset_unpack(assetId, pAssetPackage,
			assetPackageLen, pAssetData, &dataOutLen,
			pUserData);
		DMSG("res=0x%08x dataOutLen=%d\n", ret, dataOutLen);
	}
	if (TEE_SUCCESS == ret) {
		*pAssetDataLen = dataOutLen;
	}

	return ret;
}
