/*
 * Copyright (c) 2015-2017, Renesas Electronics Corporation
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

#define SS_MAX_BITS_PER_VARIABLE   (4096)
#define SS_VARIABLE_NUMBER         (50)


/*
 * brief:	Calculate the bignum size (byte).
 *
 * param[in]	*a		- Pointer to bignum data.
 * return	size_t		- Size of bignum represented in byte.
 */
size_t bn_num_bytes(struct bignum *a)
{
	PROV_INMSG("a=%p\n", (void *)a);
	return mp_unsigned_bin_size(a);
}

/*
 * brief:	Calculate the bignum size (bit).
 *
 * param[in]	*a		- Pointer to bignum data.
 * return	size_t		- Size of bignum represented in bit.
 */
size_t bn_num_bits(struct bignum *a)
{
	PROV_INMSG("a=%p\n",(void *)a);
	return (size_t)mp_count_bits(a);
}

/*
 * brief:	Compare two bignum date.
 *
 * param[in]	*a		- The bignum data(op1).
 * param[in]	*b		- The bignum data(op2).
 * return	size_t		- 0 op1 == op2
 *          			  1 op1 >  op2
 *          			 -1 op1 <  op2
 */
int32_t bn_compare(struct bignum *a, struct bignum *b)
{
	PROV_INMSG("a=%p b=%p\n",(void *)a,(void *)b);
	return mp_cmp(a, b);
}

/*
 * brief:	Convert bignum into binary.
 *
 * param[in]	*from		- Bignum data.
 * param[out]	*to		- Binary data.
 * return	void
 */
void bn_bn2bin(const struct bignum *from, uint8_t *to)
{
	void *from_tmp;
	from_tmp = (void *)from;

	PROV_INMSG("from=%p to=%p\n",(void *)from, to);

	mp_to_unsigned_bin(from_tmp, to);

	PROV_OUTMSG("return (void)");
}

/*
 * brief:	Convert binary into bignum.
 *
 * param[in]	*from		- Pointer to the binary data buffer.
 * param[in]	fromsize	- Size of the binary data buffer.
 * param[out]	*to		- Pointer to the output data of bignum.
 * return	TEE_Result	- TEE internal API error code.
 */
TEE_Result bn_bin2bn(const uint8_t *from, size_t fromsize,
		struct bignum *to)
{
	TEE_Result res = (TEE_Result)TEE_SUCCESS;
	void *to_tmp;
	uint8_t *from_tmp;

	PROV_INMSG("from=%p fromsize=%ld to=%p\n",from, fromsize, (void *)to);

	to_tmp = to;
	from_tmp = (uint8_t *)from;
	if (mp_read_unsigned_bin(to_tmp, from_tmp, fromsize)
			!= (int)CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
		PROV_EMSG("ERROR TEE_ERROR_BAD_PARAMETERS");
	}

	PROV_OUTMSG("return res=0x%08x\n",res);
	return res;
}

/*
 * brief:	Copy the bignum data.
 *
 * param[out]	*to		- Pointer to the output bignum data.
 * param[in]	*from		- Pointer to the input bignum data.
 * return	void
 */
void bn_copy(struct bignum *to, const struct bignum *from)
{
	void *from_tmp;
	from_tmp = (void *)from;

	PROV_INMSG("to=%p from=%p\n",(void *)to, (void *)from);
	mp_copy(from_tmp, (void * )to);
	PROV_OUTMSG("return (void)");
}

/*
 * brief:	Allocate memory block of the bignum.
 *
 * param[in]	*size_bits	- Size of memory block (bit).
 * return	TEE_Result	- Pointer to the memory block allocated.
 */
struct bignum *bn_allocate(size_t size_bits)
{
	struct bignum *res;
	struct mpa_numbase_struct *bn;
	size_t mpaSize;
	size_t sz;

	PROV_INMSG("size_bits=%ld\n",size_bits);
	mpaSize = (size_t)mpa_StaticVarSizeInU32(size_bits);
	sz = mpaSize * sizeof(uint32_t);
	bn = (struct mpa_numbase_struct *)calloc(1U, sz);
	if (bn == NULL) {
		PROV_EMSG("Error: bn=%p\n",(void *)bn);
		res = NULL;
	} else {
		PROV_DMSG("success memory allocate\n");
		bn->alloc = sz - ((size_t)MPA_NUMBASE_METADATA_SIZE_IN_U32
				* sizeof(uint32_t));
		res = (struct bignum *)bn;
	}

	PROV_OUTMSG("return res=%p\n",(void *)res);
	return res;
}

/*
 * brief:	Free memory block of bignum.
 *
 * param[in]	*s		- Pointer to the bignum data.
 * return	void
 */
void bn_free(struct bignum *s)
{
	PROV_INMSG("s=%p\n",(void *)s);
	ss_free((void *)s);
	PROV_OUTMSG("return (void)");
}

/*
 * brief:	Fill the bignum data 0.
 *
 * param[in]	*s		- Pointer to the bignum data.
 * return	void
 */
void bn_clear(struct bignum *s)
{
	struct mpa_numbase_struct *bn;
	PROV_INMSG("s=%p\n",(void *)s);
	bn = (struct mpa_numbase_struct *)s;
	/* despite mpa_numbase_struct description, 'alloc' field a byte size */
	(void)memset(bn->d, 0, bn->alloc);
	PROV_OUTMSG("return (void)");
}

/*
 * brief:	Allocate memory block of the bignum max size.
 *
 * param[in]	**s		- Double pointer to the bignum data.
 * return	SSError_t	- SS provider error code.
 */
SSError_t bn_alloc_max(struct bignum **s)
{
	size_t sz;
	SSError_t res;

	PROV_INMSG("s=%p\n",(void *)s);
	sz = (size_t)mpa_StaticVarSizeInU32(SS_MAX_BITS_PER_VARIABLE*2)
			* sizeof(uint32_t) * 8U;

	PROV_DMSG("Call: bn_allocate(%ld)",sz);
	*s = bn_allocate(sz);

	if (*s == 0) {
		PROV_EMSG("Error: bn_allocate");
		res = SS_ERROR_OUT_OF_MEMORY;
	} else {
		PROV_DMSG("Success: bn_allocate");
		res = SS_SUCCESS;
	}

	PROV_OUTMSG("return res=0x%08x",res);
	return res;
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
		bn_bn2bin(src_bn, *dest_ptr);
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
 * param[in]	err		- TEE Internal API error code
 * return	TEE_Result
 */
SSError_t ss_translate_error_tee2ss(TEE_Result err)
{
	uint8_t i;
	SSError_t res = SS_ERROR_GENERIC;

	PROV_INMSG("TEE_Result err= 0x%08x\n", err);

	for (i = 0U; i < (SS_ERROR_LAST_NUM - 1U); i++) {
		if (err == error_tbl[i].tee_result) {
			res = error_tbl[i].ss_error;
			break;
		}
	}

	PROV_OUTMSG("SSError_t res = 0x%08x\n", res);
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


