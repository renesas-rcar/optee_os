/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2020 Renesas Electronics Corporation
 */

#ifndef RCAR_TA_AUTH_H
#define RCAR_TA_AUTH_H

#include <stdint.h>
#include <signed_hdr.h>
#include "tee_api_types.h"

#define TA_KEY_CERT_AREA_SIZE		(4096U)
#define TA_CONTENT_CERT_AREA_SIZE	(4096U)
#define TA_NONCACHE_STACK_AREA_SIZE	(4096U)
#define TA_NONCACHE_STACK_ADDR		(TA_VERIFICATION_BASE + \
					TA_VERIFICATION_SIZE)
#define TA_CONTENT_CERT_ADDR		(TA_NONCACHE_STACK_ADDR - \
					TA_NONCACHE_STACK_AREA_SIZE - \
					TA_CONTENT_CERT_AREA_SIZE)
#define TA_KEY_CERT_ADDR		(TA_CONTENT_CERT_ADDR - \
					TA_KEY_CERT_AREA_SIZE)
#define NONCACHE_STACK_AREA_SIZE	(4096U)
#define NONCACHE_STACK_AREA_ADDR 	TA_KEY_CERT_ADDR
#define CERT_SIGNATURE_SIZE		(256U)
#define CERT_STORE_ADDR_SIZE		(8U)
#define CERT_REC_LEN_SIZE		(4U)
#define CERT_ADD_DATA_SIZE		(CERT_STORE_ADDR_SIZE + \
					CERT_REC_LEN_SIZE)
#define CERT_OFS_BIT_SIZE		(0xffffU)
#define CERT_BLOCK_SIZE			(4U)
#define CERT_IDX_SIZE			(2)
#define CERT_IDX_FLAG			(3)
#define RST_MODEMR	(p2v_ioadr(RST_BASE, DEVICE0_PA_END - RST_BASE) + 0x0060U)
#define MFIS_SOFTMDR	(p2v_ioadr(MFIS_BASE, DEVICE0_PA_END - MFIS_BASE) \
						+ 0x0600U)
#define LCS_SE				(0x5U)
#define SECURE_BOOT_MODE		(0U)
#define NORMAL_BOOT_MODE		(1U)
#define CERT_IDX_MEM_LOAD_ADDR	(84U)
#define TA_OBJ_SIZE			((TA_KEY_CERT_ADDR - \
					NONCACHE_STACK_AREA_SIZE -  \
					TA_VERIFICATION_BASE) / CERT_BLOCK_SIZE)

TEE_Result rcar_auth_ta_certificate(const struct shdr *key_cert,
				struct shdr **secmem_ta, size_t ta_size);

#endif /* RCAR_TA_AUTH_H */
