/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2018, Renesas Electronics Corporation
 */

#ifndef TEE_PROVIDER_COMMON_H
#define TEE_PROVIDER_COMMON_H

#include <crypto/crypto.h>
#include <tee/tee_cryp_utl.h>
#include <mpalib.h>
#include <stdlib.h>
#include <string.h>
#include <utee_defines.h>
#include <trace.h>
#include <tee_api_types.h>
#include <string_ext.h>
#include <util.h>
#include <tomcrypt_mpa.h>
#include <tomcrypt_macros.h>
#include "include_secure/crys_error.h"
/******************************************************************************/
/* Defines                                                                    */
/******************************************************************************/
/* Debug */
#define PROV_INMSG(...)		do{}while(0)
#define PROV_OUTMSG(...)	do{}while(0)
#define PROV_EMSG(...)		EMSG(__VA_ARGS__)
#define PROV_IMSG(...)		do{}while(0)
#define PROV_DMSG(...)		do{}while(0)
#define PROV_FMSG(...)		do{}while(0)
#define PROV_DHEXDUMP(...)	do{}while(0)

/* Provider error codes */
#define SS_SUCCESS			  0x0000000000U
#define SS_ERROR_CORRUPT_OBJECT		  0x0000000001U
#define SS_ERROR_CORRUPT_OBJECT_2	  0x0000000002U
#define SS_ERROR_STORAGE_NOT_AVAILABLE	  0x0000000003U
#define SS_ERROR_STORAGE_NOT_AVAILABLE_2  0x0000000004U
#define SS_ERROR_GENERIC		  0x0000000005U
#define SS_ERROR_ACCESS_DENIED		  0x0000000006U
#define SS_ERROR_CANCEL			  0x0000000007U
#define SS_ERROR_ACCESS_CONFLICT	  0x0000000008U
#define SS_ERROR_EXCESS_DATA		  0x0000000009U
#define SS_ERROR_BAD_FORMAT		  0x000000000AU
#define SS_ERROR_BAD_PARAMETERS		  0x000000000BU
#define SS_ERROR_BAD_STATE		  0x000000000CU
#define SS_ERROR_ITEM_NOT_FOUND		  0x000000000DU
#define SS_ERROR_NOT_IMPLEMENTED	  0x000000000EU
#define SS_ERROR_NOT_SUPPORTED		  0x000000000FU
#define SS_ERROR_NO_DATA		  0x0000000010U
#define SS_ERROR_OUT_OF_MEMORY		  0x0000000011U
#define SS_ERROR_BUSY			  0x0000000012U
#define SS_ERROR_COMMUNICATION		  0x0000000013U
#define SS_ERROR_SECURITY		  0x0000000014U
#define SS_ERROR_SHORT_BUFFER		  0x0000000015U
#define SS_ERROR_EXTERNAL_CANCEL	  0x0000000016U
#define SS_ERROR_OVERFLOW		  0x0000000017U
#define SS_ERROR_TARGET_DEAD		  0x0000000018U
#define SS_ERROR_STORAGE_NO_SPACE	  0x0000000019U
#define SS_ERROR_MAC_INVALID		  0x000000001AU
#define SS_ERROR_SIGNATURE_INVALID	  0x000000001BU
#define SS_ERROR_TIME_NOT_SET		  0x000000001CU
#define SS_ERROR_TIME_NEEDS_RESET	  0x000000001DU
#define SS_ERROR_LCS_CHECK		  0x000000001EU
#define SS_ERROR_LAST_NUM		  0x0000000020U

/******************************************************************************/
/* Typedefs                                                                   */
/******************************************************************************/
typedef uint32_t SSError_t;

typedef struct {
	SSError_t ss_error;
	TEE_Result tee_result;
}ErrorTable_t;

/******************************************************************************/
/* Global Variables                                                           */
/******************************************************************************/
extern const ErrorTable_t error_tbl[SS_ERROR_LAST_NUM];

/******************************************************************************/
/* Public Function Prototypes                                                 */
/******************************************************************************/
size_t bn_num_bytes(struct bignum *a);
SSError_t ss_bn_bin2bn(const uint8_t *from, size_t fromsize,
		struct bignum *to);
SSError_t ss_copy_bn2bin(struct bignum *src_bn, uint8_t **dest_ptr,
		size_t *dest_size);
void *ss_malloc_and_copy(size_t malloc_size, const void* src,
		size_t src_len, SSError_t *err);

void *ss_malloc(size_t malloc_size, SSError_t *err);
void *ss_calloc(size_t n, size_t calloc_size, SSError_t *err);
void ss_free(void *free_ptr);
SSError_t ss_copy_bn2bin_uint16(struct bignum *src_bn,
		uint8_t **dest_ptr, uint16_t *dest_size);
TEE_Result ss_translate_error_ss2tee(SSError_t err);
SSError_t ss_translate_error_crys2ss_ecc(CRYSError_t err);
/*****************************************************/

#endif
