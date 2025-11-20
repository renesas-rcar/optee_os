#ifndef RCAR_ASSET_SECURE_H
#define RCAR_ASSET_SECURE_H
#include <stdint.h>
#include <tee_api_defines.h>
#include "tee_api_types.h"
#include "rcar_fw_security_service.h"

/* asset package offsets and sizes definitions */
/* field desc(byte size):    token(4)     version(4)  user data(4)    encrypted asset size(4)    nonce(8)     encrypted data(max 512)      mac(8) */
/* bytes offset         :    0..3          4..7        8..11           12..15                     16..23         24....max 536         ..max 544*/
#define ASSET_PKG_TOKEN_OFFSET			0
#define ASSET_PKG_TOKEN_SIZE			4
#define ASSET_PKG_VERSION_OFFSET		(ASSET_PKG_TOKEN_OFFSET+ASSET_PKG_TOKEN_SIZE)
#define ASSET_PKG_VERSION_SIZE			4
#define ASSET_PKG_USER_DATA_OFFSET		(ASSET_PKG_VERSION_OFFSET+ASSET_PKG_VERSION_SIZE)
#define ASSET_PKG_USER_DATA_SIZE		4
#define ASSET_PKG_EN_DATA_SIZE_OFFSET		(ASSET_PKG_USER_DATA_OFFSET+ASSET_PKG_USER_DATA_SIZE)
#define ASSET_PKG_EN_DATA_SIZE_SIZE		4
#define ASSET_PKG_CCM_ADDITIONAL_DATA_OFFSET	0
#define ASSET_PKG_CCM_ADDITIONAL_DATA_SIZE  	(ASSET_PKG_TOKEN_SIZE+ASSET_PKG_VERSION_SIZE+ASSET_PKG_USER_DATA_SIZE+ASSET_PKG_EN_DATA_SIZE_SIZE)

#define ASSET_PKG_CCM_NONCE_OFFSET 		(ASSET_PKG_EN_DATA_SIZE_OFFSET+ASSET_PKG_EN_DATA_SIZE_SIZE)
#define ASSET_PKG_CCM_NONCE_SIZE		8
#define ASSET_PKG_EN_DATA_OFFSET 		(ASSET_PKG_CCM_NONCE_OFFSET+ASSET_PKG_CCM_NONCE_SIZE)
#define ASSET_PKG_MAC_SIZE			8
#define ASSET_PKG_NONE_ASSET_DATA_SIZE		(ASSET_PKG_CCM_ADDITIONAL_DATA_SIZE+ASSET_PKG_CCM_NONCE_SIZE+ASSET_PKG_MAC_SIZE)

#define ASSET_PKG_AES_CMAC_RESULT_SIZE_IN_BYTES		16  //DX_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES
#define KUT_SIZE_IN_BYTES				ASSET_PKG_AES_CMAC_RESULT_SIZE_IN_BYTES
#define ASSET_DATA_MAX_SIZE_IN_BYTES			512
#define ASSET_PACKAGE_MAX_SIZE_IN_BYTES			(OEM_ASSET_DATA_MAX_SIZE_IN_BYTES+ASSET_PKG_NONE_ASSET_DATA_SIZE)

#define ASSET_DATA_IN_CMAC_LENGTH			(4+sizeof(int))

/* definitions for input buffer for AES_CMAC User Transported Key derivation*/
#define KUT_DATA_IN_PREFIX_DATA0  0x01
#define KUT_DATA_IN_PREFIX_DATA1  0x50
#define KUT_DATA_IN_PREFIX_DATA2  0x00
#define KUT_DATA_IN_SUFIX_DATA    0x80

#define ASSET_MUL_16_BYTES_MASK (0x10-0x1)

#define  ASSET_PACK_TOKEN   0x20052001
#define  ASSET_VERSION      0x00000001

#define CONVERT_WORD_TO_BYTE_ARR(inWord, outPtr) {\
	*outPtr     = (inWord>>24) & 0xFF;\
	*(outPtr+1) = (inWord>>16) & 0xFF;\
	*(outPtr+2) = (inWord>>8) & 0xFF;\
	*(outPtr+3) = (inWord) & 0xFF;\
}

#define CONVERT_BYTE_ARR_TO_WORD(inPtr, outWord) {\
	outWord = (*inPtr<<24) | (*(inPtr+1)<<16) | (*(inPtr+2)<<8) | (*(inPtr+3)); \
}

#define KEY_DERIVATION_4_RPMB	0x01,0x52,0x50,0x4D,0x42,0x20,0x4B,0x45,0x59,0x00,0x01,0x00
#define RPMB_KEY_SIZE		32u

/*******************************************************************************
 * Function & variable prototypes
 ******************************************************************************/
TEE_Result rcar_asset_unpack(uint32_t assetId,
		uint8_t *pAssetPackage, uint32_t assetPackagLen,
		uint8_t *pAssetData, uint32_t *pAssetDataLen,
		uint32_t *pUserData);
TEE_Result rcar_icum_rpmb_derivekey(uint8_t *out, uint32_t outSize);
#endif /* RCAR_ASSET_SECURE_H */
