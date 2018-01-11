/*
 * Copyright (c) 2015-2018, Renesas Electronics Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY
 */
#ifndef TEE_PROVIDER_COMMON_H
#define TEE_PROVIDER_COMMON_H

#include <tee/tee_cryp_provider.h>
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
size_t bn_num_bits(struct bignum *a);
int32_t bn_compare(struct bignum *a, struct bignum *b);
void bn_bn2bin(const struct bignum *from, uint8_t *to);
TEE_Result bn_bin2bn(const uint8_t *from, size_t fromsize,
		struct bignum *to);
SSError_t ss_bn_bin2bn(const uint8_t *from, size_t fromsize,
		struct bignum *to);
struct bignum *bn_allocate(size_t size_bits);
void bn_free(struct bignum *s);
void bn_clear(struct bignum *s);
SSError_t bn_alloc_max(struct bignum **s);
void bn_copy(struct bignum *to, const struct bignum *from);
SSError_t ss_copy_bn2bin(struct bignum *src_bn, uint8_t **dest_ptr,
		size_t *dest_size);
void *ss_malloc_and_copy(size_t malloc_size, const void* src,
		size_t src_len, SSError_t *err);

void *ss_malloc(size_t malloc_size, SSError_t *err);
void *ss_calloc(size_t n, size_t calloc_size, SSError_t *err);
void ss_free(void *free_ptr);
SSError_t ss_copy_bn2bin_uint16(struct bignum *src_bn,
		uint8_t **dest_ptr, uint16_t *dest_size);
SSError_t ss_translate_error_tee2ss(TEE_Result err);
TEE_Result ss_translate_error_ss2tee(SSError_t err);
SSError_t ss_translate_error_crys2ss_ecc(CRYSError_t err);
/*****************************************************/

#endif
