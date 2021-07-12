/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2016-2021, Renesas Electronics Corporation
 */

#ifndef TEE_API_H
#define TEE_API_H

#include <tee_internal_api.h>

TEE_Result RCAR_AesUnwrap(void *srcData, uint32_t srcLen, void *keyData,
	uint32_t keySize, uint32_t isSecretKey, void *destData, uint32_t *dstLen);

TEE_Result RCAR_GenSkeyPackage(RCAR_SkeyParams_t *skeyParams,
		uint8_t *skeyPackageBuf, uint32_t skeyPackageSize);

TEE_Result RCAR_AssetUnpack(uint32_t assetId,
		uint8_t *pAssetPackage, uint32_t assetPackagLen,
		uint8_t *pAssetData, uint32_t *pAssetDataLen,
		uint32_t *pUserData);
#endif /* TEE_API_H */
