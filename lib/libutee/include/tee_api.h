/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef TEE_API_H
#define TEE_API_H

#include <tee_internal_api.h>

#ifdef PLATFORM_rcar_gen4
TEE_Result RCAR_AssetUnpack(uint32_t assetId,
		uint8_t *pAssetPackage, uint32_t assetPackagLen,
		uint8_t *pAssetData, uint32_t *pAssetDataLen,
		uint32_t *pUserData);
#endif

#endif /* TEE_API_H */
