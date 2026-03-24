/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2024 Renesas Electronics Corporation
 */

#ifndef RCAR_TA_AUTH_H
#define RCAR_TA_AUTH_H

#include <signed_hdr.h>
#include "tee_api_types.h"

#define TA_KEY_CERT_AREA_SIZE		(4096U)
#define TA_CONTENT_CERT_AREA_SIZE	(4096U)
#define TA_CONTENT_CERT_ADDR		(TA_VERIFICATION_BASE + \
					TA_VERIFICATION_SIZE - \
					TA_CONTENT_CERT_AREA_SIZE)
#define TA_KEY_CERT_ADDR		(TA_CONTENT_CERT_ADDR - \
					TA_KEY_CERT_AREA_SIZE)

#define SECURE_BOOT_MODE		(0U)
#define NORMAL_BOOT_MODE		(1U)

#define LCS_SE				(0xA55AAF50u)

#define HASH_INTEGRITY_CHECK_HASH_SIZE	(0x00000020u)

#define CERT_HEADER_SIZE		(32U)
#define REKEY_SIZE			(20U)
#define TLV_LENGTH			(4U)

/* Define header KC */
#define KC_MAGIC_NUMBER			(4U)
#define KC_CERT_VERSION			(4U)
#define KC_FLAGS			(4U)
#define KC_RESERVED			(20U)

/* Define header CC */
#define CC_MAGIC_NUMBER			(4U)
#define CC_CERT_VERSION			(4U)
#define CC_FLAGS			(4U)
#define CC_LOAD_ADDR			(4U)
#define CC_DEST_ADDR			(4U)
#define CC_IMAGE_SIZE			(4U)
#define CC_CODE_VERSION			(8U)

#define TYPE_KEYCERT			(0U)
#define TYPE_CONTENTCERT		(1U)

/******************************************************************************
 * Typedefs & Enumerations
 *****************************************************************************/
typedef struct {
	const uint32_t *base;
	const uint32_t *header;     /* Header field (32 bytes) */
	const uint32_t *tlv_length; /* TLV Length field */
} sb_cert_t;

TEE_Result rcar_auth_ta_certificate(const struct shdr *key_cert,
				struct shdr **secmem_ta, size_t ta_size);

#endif /* RCAR_TA_AUTH_H */
