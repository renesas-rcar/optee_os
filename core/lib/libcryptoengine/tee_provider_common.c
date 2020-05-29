// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2018, Renesas Electronics Corporation
 */

#include "tee_provider_common.h"

const ErrorTable_t error_tbl[SS_ERROR_LAST_NUM] = {
	{SS_SUCCESS,			  (TEE_Result)TEE_SUCCESS	   },
	{SS_ERROR_CORRUPT_OBJECT,	  TEE_ERROR_CORRUPT_OBJECT	   },
	{SS_ERROR_CORRUPT_OBJECT_2,	  TEE_ERROR_CORRUPT_OBJECT_2	   },
	{SS_ERROR_STORAGE_NOT_AVAILABLE,  TEE_ERROR_STORAGE_NOT_AVAILABLE  },
	{SS_ERROR_STORAGE_NOT_AVAILABLE_2,TEE_ERROR_STORAGE_NOT_AVAILABLE_2},
	{SS_ERROR_GENERIC,		  TEE_ERROR_GENERIC		   },
	{SS_ERROR_ACCESS_DENIED,	  TEE_ERROR_ACCESS_DENIED	   },
	{SS_ERROR_CANCEL,		  TEE_ERROR_CANCEL		   },
	{SS_ERROR_ACCESS_CONFLICT,	  TEE_ERROR_ACCESS_CONFLICT	   },
	{SS_ERROR_EXCESS_DATA,		  TEE_ERROR_EXCESS_DATA		   },
	{SS_ERROR_BAD_FORMAT,		  TEE_ERROR_BAD_FORMAT		   },
	{SS_ERROR_BAD_PARAMETERS,	  TEE_ERROR_BAD_PARAMETERS	   },
	{SS_ERROR_BAD_STATE,		  TEE_ERROR_BAD_STATE		   },
	{SS_ERROR_ITEM_NOT_FOUND,	  TEE_ERROR_ITEM_NOT_FOUND	   },
	{SS_ERROR_NOT_IMPLEMENTED,	  TEE_ERROR_NOT_IMPLEMENTED	   },
	{SS_ERROR_NOT_SUPPORTED,	  TEE_ERROR_NOT_SUPPORTED	   },
	{SS_ERROR_NO_DATA,		  TEE_ERROR_NO_DATA		   },
	{SS_ERROR_OUT_OF_MEMORY,	  TEE_ERROR_OUT_OF_MEMORY	   },
	{SS_ERROR_BUSY,			  TEE_ERROR_BUSY		   },
	{SS_ERROR_COMMUNICATION,	  TEE_ERROR_COMMUNICATION	   },
	{SS_ERROR_SECURITY,		  TEE_ERROR_SECURITY		   },
	{SS_ERROR_SHORT_BUFFER,		  TEE_ERROR_SHORT_BUFFER	   },
	{SS_ERROR_EXTERNAL_CANCEL,	  TEE_ERROR_EXTERNAL_CANCEL	   },
	{SS_ERROR_OVERFLOW,		  TEE_ERROR_OVERFLOW		   },
	{SS_ERROR_TARGET_DEAD,		  TEE_ERROR_TARGET_DEAD		   },
	{SS_ERROR_STORAGE_NO_SPACE,	  TEE_ERROR_STORAGE_NO_SPACE	   },
	{SS_ERROR_MAC_INVALID,		  TEE_ERROR_MAC_INVALID		   },
	{SS_ERROR_SIGNATURE_INVALID,	  TEE_ERROR_SIGNATURE_INVALID	   },
	{SS_ERROR_TIME_NOT_SET,		  TEE_ERROR_TIME_NOT_SET	   },
	{SS_ERROR_TIME_NEEDS_RESET,	  TEE_ERROR_TIME_NEEDS_RESET	   },
	{SS_ERROR_LCS_CHECK,	  	  TEE_ERROR_LCS_CHECK		   },
	{SS_ERROR_LAST_NUM, 		  0U}
};




/*
 * brief:	Allocate memory block with malloc.
 *
 * param[in]	malloc_size	- Allocate memory size.
 * param[out]	*err		- SS provider error code.
 * return	*void		- Pointer to the memory block allocated.
 */
void *ss_malloc(size_t malloc_size, SSError_t *err)
{
	void *res = NULL;

	PROV_INMSG("malloc_size=%ld err=0x%08x\n",malloc_size, *err);


	if (0U == malloc_size) {
		*err = SS_ERROR_BAD_PARAMETERS;
		PROV_EMSG("BAD_PARAMETERS malloc_size=%ld\n",
				malloc_size);
	}

	if (SS_SUCCESS == *err) {
		res = malloc(malloc_size);
		if (NULL == res) {
			*err = SS_ERROR_OUT_OF_MEMORY;
			PROV_EMSG("OUT_OF_MEMORY \n");
		} else {
			*err = SS_SUCCESS;
		}
	}

	PROV_OUTMSG("res=%p err = 0x%08x\n",res,*err);
	return res;
}

/*
 * brief:	Allocate memory block with calloc.
 *
 * param[in]	n		- Number of elements to allocate.
 * param[in]	calloc_size	- Allocate memory size.
 * param[out]	*err		- SS provider error code.
 * return	*void		- Pointer to the memory block allocated.
 */
void *ss_calloc(size_t n, size_t calloc_size, SSError_t *err)
{
	void *res = NULL;

	PROV_INMSG("n=%ld calloc_size=%ld err=0x%08x\n",n,calloc_size, *err);

	if (n == 0U) {
		*err = SS_ERROR_BAD_PARAMETERS;
		PROV_EMSG("BAD_PARAMETER n=%ld\n", n);
	}
	if (*err == SS_SUCCESS) {
		if (calloc_size == 0U) {
			*err = SS_ERROR_BAD_PARAMETERS;
			PROV_EMSG("BAD_PARAMETER calloc_size=%ld\n",calloc_size);
		}
	}
	if (*err == SS_SUCCESS) {
		res = calloc(n, calloc_size);
		if (res == NULL) {
			*err = SS_ERROR_OUT_OF_MEMORY;
			PROV_EMSG("OUT_OF_MEMORY res=NULL\n");
		} else {
			*err = SS_SUCCESS;
			PROV_IMSG("SUCCESS calloc\n");
		}
	}

	PROV_OUTMSG("res=%p err=0x%08x\n",res, *err);
	return res;
}

/*
 * brief:	Deallocate memory block.
 *
 * param[in]	*free_ptr	- Pointer to a memory block previously allocated.
 * return	void
 */
void ss_free(void *free_ptr)
{
	if (free_ptr != NULL) {
		free(free_ptr);
	} else {
		PROV_IMSG("Input address is NULL");
	}
}

/*
 * brief:	Allocate memory block and copy data buffer.
 *
 * param[in]	malloc_size	- Size of a memory block to allocate.
 * param[in]	*src		- Pointer to a memory block previously allocated.
 * param[in]	src_len		- Allocate memory size.
 * param[in]	*err		- SS provider error code.
 * return	void		- Pointer to a memory block allocated.
 */
void *ss_malloc_and_copy(size_t malloc_size, const void *src, size_t src_len,
		SSError_t *err)
{
	void* res = NULL;
	PROV_INMSG("malloc_size=%ld src=%p src_len=0x%08lx err=0x%08x\n",
			malloc_size, src, src_len, *err);

	if(src == NULL){
		*err = SS_ERROR_BAD_PARAMETERS;
		PROV_EMSG("ERROR(src) SS_ERROR_BAD_PARAMETERS\n");
	}
	if(src_len == 0U){
		*err = SS_ERROR_BAD_PARAMETERS;
		PROV_EMSG("ERROR(src_len) SS_ERROR_BAD_PARAMETERS\n");
	}
	if (*err == SS_SUCCESS) {
		res = ss_malloc(malloc_size, err);
	}
	if (*err == SS_SUCCESS) {
		PROV_IMSG("memcpy\n");
		(void)memcpy(res, src, src_len);
	}

	PROV_OUTMSG("res=%p err=0x%08x\n",res, *err);
	return res;
}

/*
 * brief:	Calculate the bignum size (byte).
 *
 * param[in]	*a		- Pointer to bignum data.
 * return	size_t		- Size of bignum represented in byte.
 */
size_t bn_num_bytes(struct bignum *a)
{
	size_t ret;
	PROV_INMSG("a=%p\n", (void *)a);
	ret = crypto_bignum_num_bytes(a);
	return ret;
}

/*
 * brief:	Convert bignum into binary.
 *
 * param[in]	*from		- Pointer to the binary data buffer.
 * param[in]	fromsize	- Size of the binary data buffer.
 * param[out]	*to		- Pointer to the output data of bignum.
 * return	Always return SS_SUCCESS of SS provider error code.
 */
SSError_t ss_bn_bin2bn(const uint8_t *from, size_t fromsize,
		struct bignum *to)
{
	PROV_INMSG("*from=%p, fromsize=%ld, *to=%p\n",from,fromsize,(void *)to);

	((mpanum)(to))->size = (ROUNDUP(fromsize, 4U) >> 2U);
	(void)memcpy((((mpanum)(to))->d), from, fromsize);

	return SS_SUCCESS;
}

/*
 * brief:	Copy and convert bignum into binary.
 *
 * param[in]	*src_bin	- Pointer to the bignum data buffer.
 * param[out]	**dest_ptr	- Pointer to the binary data address.
 * param[out]	*dest_size	- Pointer to the binary data size.
 * return	SSError_t	- SS provider error code.
 */
SSError_t ss_copy_bn2bin(struct bignum *src_bn, uint8_t **dest_ptr,
		size_t *dest_size)
{
	SSError_t res = SS_SUCCESS;
	PROV_INMSG("*src_bin=%p, dest_ptr=%p, dest_size=%ld\n",(void *)src_bn, *dest_ptr,*dest_size);

	if (src_bn == NULL) {
		PROV_EMSG("Error: SS_ERROR_BAD_PARAMETERS");
		res = SS_ERROR_BAD_PARAMETERS;
	} else {
		*dest_size = (size_t)bn_num_bytes(src_bn);
		*dest_ptr = (uint8_t *)ss_malloc(*dest_size, &res);
		crypto_bignum_bn2bin(src_bn, *dest_ptr);
	}

	PROV_OUTMSG("dest_ptr=%p, dest_size=%ld\n",*dest_ptr,*dest_size);
	PROV_OUTMSG("return res=0x%08x\n",res);
	return res;
}

/*
 * brief:	Convert bignum into binary.
 *
 * param[in]	*src_bin	- Pointer to the bignum data buffer.
 * param[out]	**dest_ptr	- Pointer to the binary data address.
 * param[out]	*dest_size	- Pointer to the binary data size.
 * return	TEE_Result	- TEE internal API error code.
 */
SSError_t ss_copy_bn2bin_uint16(struct bignum *src_bn, uint8_t **dest_ptr,
		uint16_t *dest_size)
{
	SSError_t res;
	size_t tmp_size = 0U;

	PROV_INMSG("*src_bin=%p, dest_size=%d\n",(void *)src_bn, *dest_size);
	res = ss_copy_bn2bin(src_bn, dest_ptr, &tmp_size);

	if (res == SS_SUCCESS) {
		if (tmp_size > 0xFFFFU) {
			PROV_EMSG("Error: SS_ERROR_OVERFLOW");
			res = SS_ERROR_OVERFLOW;
		} else {
			*dest_size = (uint16_t)tmp_size;
		}
	}

	PROV_OUTMSG("dest_ptr=%p, dest_size=%d\n",*dest_ptr,*dest_size);
	PROV_OUTMSG("return res=0x%08x\n",res);
	return res;
}

/*
 * brief:	Translate SS provider error into TEE internal API error.
 *
 * param[in]	err		- Error code for provider
 * return	TEE_Result
 */
TEE_Result ss_translate_error_ss2tee(SSError_t err)
{
	uint8_t i;
	TEE_Result res = TEE_ERROR_GENERIC;

	PROV_INMSG("SSError_t  err = 0x%08x\n", err);

	for (i = 0U; i < (SS_ERROR_LAST_NUM - 1U); i++) {
		if (err == error_tbl[i].ss_error) {
			res = error_tbl[i].tee_result;
			break;
		}
	}

	PROV_OUTMSG("TEE_Result res = 0x%08x\n", res);
	return res;
}


