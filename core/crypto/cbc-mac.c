// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 * Copyright (c) 2020-2021, Renesas Electronics Corporation
 */

/*
 * This is implemented here as being the plain text which is encoded with IV=0.
 * Result of the CBC-MAC is the last 16-bytes cipher.
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <types_ext.h>
#include <util.h>

#define CBCMAC_MAX_BLOCK_LEN 16

struct crypto_cbc_mac_ctx {
	struct crypto_mac_ctx ctx;
	void *cbc_ctx;
	uint32_t cbc_algo;
	uint8_t block[CBCMAC_MAX_BLOCK_LEN];
	uint8_t digest[CBCMAC_MAX_BLOCK_LEN];
	unsigned char current_block_len;
	unsigned char block_len;
	bool is_computed;
	bool pkcs5_pad;
};

static const struct crypto_mac_ops crypto_cbc_mac_ops;

static struct crypto_cbc_mac_ctx *to_cbc_mac_ctx(struct crypto_mac_ctx *ctx)
{
	assert(ctx && ctx->ops == &crypto_cbc_mac_ops);

	return container_of(ctx, struct crypto_cbc_mac_ctx, ctx);
}

#ifdef CFG_CRYPT_HW_CRYPTOENGINE
static const struct crypto_cipher_ops *cipher_ops(void *ctx)
{
    struct crypto_cipher_ctx *c = ctx;

    assert(c && c->ops);

    return c->ops;
}

static TEE_Result crypto_cbc_mac_des_init(void *ctx, TEE_OperationMode mode,
                  const uint8_t *key1, size_t key1_len,
                  const uint8_t *key2, size_t key2_len,
                  const uint8_t *iv, size_t iv_len)
{
    if (mode != TEE_MODE_DECRYPT && mode != TEE_MODE_ENCRYPT)
        return TEE_ERROR_BAD_PARAMETERS;

    return cipher_ops(ctx)->init(ctx, mode, key1, key1_len, key2, key2_len,
                    iv, iv_len);
}
#endif

static TEE_Result crypto_cbc_mac_init(struct crypto_mac_ctx *ctx,
				      const uint8_t *key, size_t len)
{
	struct crypto_cbc_mac_ctx *mc = to_cbc_mac_ctx(ctx);

	memset(mc->block, 0, sizeof(mc->block));
	memset(mc->digest, 0, sizeof(mc->digest));
	mc->current_block_len = 0;
	mc->is_computed = false;

	/* IV should be zero and mc->block happens to be zero at this stage */
#ifdef CFG_CRYPT_HW_CRYPTOENGINE
    /* When HW-Engine is valid, this function is called only in DES processing of MAC. */
	return crypto_cbc_mac_des_init(mc->cbc_ctx, TEE_MODE_ENCRYPT, key, len,
				  NULL, 0, mc->block, mc->block_len);
#else
	return crypto_cipher_init(mc->cbc_ctx, TEE_MODE_ENCRYPT, key, len,
				  NULL, 0, mc->block, mc->block_len);
#endif
}

#ifdef CFG_CRYPT_HW_CRYPTOENGINE
static TEE_Result crypto_cbc_mac_des_update(void *ctx, TEE_OperationMode mode __unused,
                bool last_block, const uint8_t *data,
                size_t len, uint8_t *dst)
{
    return cipher_ops(ctx)->update(ctx, last_block, data, len, dst);
}
#endif

static TEE_Result crypto_cbc_mac_update(struct crypto_mac_ctx *ctx,
					const uint8_t *data, size_t len)
{
	TEE_Result res = TEE_SUCCESS;
	struct crypto_cbc_mac_ctx *mc = to_cbc_mac_ctx(ctx);

	if ((mc->current_block_len > 0) &&
	    (len + mc->current_block_len >= mc->block_len)) {
		size_t pad_len = mc->block_len - mc->current_block_len;

		memcpy(mc->block + mc->current_block_len, data, pad_len);
		data += pad_len;
		len -= pad_len;
		res = crypto_cipher_update(mc->cbc_ctx, TEE_MODE_ENCRYPT,
					   false, mc->block, mc->block_len,
					   mc->digest);
		if (res)
			return res;
		mc->is_computed = 1;
		mc->current_block_len = 0;
	}

	while (len >= mc->block_len) {
#ifdef CFG_CRYPT_HW_CRYPTOENGINE
        /* When HW-Engine is valid, this function is called only in DES processing of MAC. */
		res = crypto_cbc_mac_des_update(mc->cbc_ctx, TEE_MODE_ENCRYPT,
					   false, data, mc->block_len,
					   mc->digest);
#else
		res = crypto_cipher_update(mc->cbc_ctx, TEE_MODE_ENCRYPT,
					   false, data, mc->block_len,
					   mc->digest);
#endif
		if (res)
			return res;
		mc->is_computed = 1;
		data += mc->block_len;
		len -= mc->block_len;
	}

	if (len > 0) {
		assert(mc->current_block_len + len < mc->block_len);
		memcpy(mc->block + mc->current_block_len, data, len);
		mc->current_block_len += len;
	}

	return TEE_SUCCESS;
}

#ifdef CFG_CRYPT_HW_CRYPTOENGINE
static void crypto_cbc_mac_des_final(void *ctx)
{
    cipher_ops(ctx)->final(ctx);
}
#endif

static TEE_Result crypto_cbc_mac_final(struct crypto_mac_ctx *ctx,
				       uint8_t *digest, size_t digest_len)
{
	struct crypto_cbc_mac_ctx *mc = to_cbc_mac_ctx(ctx);

	if (mc->pkcs5_pad) {
		/*
		 * Padding is in whole bytes. The value of each added
		 * byte is the number of bytes that are added, i.e. N
		 * bytes, each of value N are added
		 */
		size_t pad_len = mc->block_len - mc->current_block_len;

		memset(mc->block + mc->current_block_len, pad_len, pad_len);
		mc->current_block_len = 0;
		if (crypto_cbc_mac_update(ctx, mc->block, mc->block_len))
			return TEE_ERROR_BAD_STATE;
	}

	if (!mc->is_computed || mc->current_block_len)
		return TEE_ERROR_BAD_STATE;

	memcpy(digest, mc->digest, MIN(digest_len, mc->block_len));
#ifdef CFG_CRYPT_HW_CRYPTOENGINE
    /* When HW-Engine is valid, this function is called only in DES processing of MAC. */
	crypto_cbc_mac_des_final(mc->cbc_ctx);
#else
	crypto_cipher_final(mc->cbc_ctx);
#endif

	return TEE_SUCCESS;
}

static void crypto_cbc_mac_free_ctx(struct crypto_mac_ctx *ctx)
{
	struct crypto_cbc_mac_ctx *mc = to_cbc_mac_ctx(ctx);

	crypto_cipher_free_ctx(mc->cbc_ctx);
	free(mc);
}

static void crypto_cbc_mac_copy_state(struct crypto_mac_ctx *dst_ctx,
				      struct crypto_mac_ctx *src_ctx)
{
	struct crypto_cbc_mac_ctx *dst = to_cbc_mac_ctx(dst_ctx);
	struct crypto_cbc_mac_ctx *src = to_cbc_mac_ctx(src_ctx);

	assert(dst->block_len == src->block_len);
	assert(dst->pkcs5_pad == src->pkcs5_pad);
	assert(dst->cbc_algo == src->cbc_algo);

	crypto_cipher_copy_state(dst->cbc_ctx, src->cbc_ctx);
	memcpy(dst->block, src->block, sizeof(dst->block));
	memcpy(dst->digest, src->digest, sizeof(dst->digest));
	dst->current_block_len = src->current_block_len;
	dst->is_computed = src->is_computed;
}

static const struct crypto_mac_ops crypto_cbc_mac_ops = {
	.init = crypto_cbc_mac_init,
	.update = crypto_cbc_mac_update,
	.final = crypto_cbc_mac_final,
	.free_ctx = crypto_cbc_mac_free_ctx,
	.copy_state = crypto_cbc_mac_copy_state,
};

#ifdef CFG_CRYPT_HW_CRYPTOENGINE
static TEE_Result crypto_cbc_mac_des_alloc_ctx(void **ctx, uint32_t algo)
{
    TEE_Result res = TEE_SUCCESS;
    struct crypto_cipher_ctx *c = NULL;

    switch (algo) {
         case TEE_ALG_DES_ECB_NOPAD:
             res = crypto_des_ecb_alloc_ctx(&c);
             break;
         case TEE_ALG_DES3_ECB_NOPAD:
             res = crypto_des3_ecb_alloc_ctx(&c);
             break;
         case TEE_ALG_DES_CBC_NOPAD:
             res = crypto_des_cbc_alloc_ctx(&c);
             break;
         case TEE_ALG_DES3_CBC_NOPAD:
             res = crypto_des3_cbc_alloc_ctx(&c);
             break;
         default:
             return TEE_ERROR_NOT_IMPLEMENTED;
    }

    if (!res)
    {
        *ctx = c;
    }

    return res;
}
#endif

static TEE_Result crypto_cbc_mac_alloc_ctx(struct crypto_mac_ctx **ctx_ret,
					   uint32_t cbc_algo, bool pkcs5_pad)
{
	TEE_Result res;
	void *cbc_ctx = NULL;
	struct crypto_cbc_mac_ctx *ctx = NULL;
	size_t block_size = 0;

	res = crypto_cipher_get_block_size(cbc_algo, &block_size);
	if (res)
		return res;

#ifdef CFG_CRYPT_HW_CRYPTOENGINE
    /* When HW-Engine is valid, this function is called only in DES processing of MAC. */
    res = crypto_cbc_mac_des_alloc_ctx(&cbc_ctx, cbc_algo);
#else
	res = crypto_cipher_alloc_ctx(&cbc_ctx, cbc_algo);
#endif
	if (res)
		return res;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		crypto_cipher_free_ctx(cbc_ctx);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	ctx->cbc_ctx = cbc_ctx;
	ctx->cbc_algo = cbc_algo;
	ctx->pkcs5_pad = pkcs5_pad;
	ctx->block_len = block_size;
	ctx->ctx.ops = &crypto_cbc_mac_ops;
	*ctx_ret = &ctx->ctx;

	return TEE_SUCCESS;
}

TEE_Result crypto_aes_cbc_mac_nopad_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return crypto_cbc_mac_alloc_ctx(ctx, TEE_ALG_AES_CBC_NOPAD, false);
}

TEE_Result crypto_aes_cbc_mac_pkcs5_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return crypto_cbc_mac_alloc_ctx(ctx, TEE_ALG_AES_CBC_NOPAD, true);
}

TEE_Result crypto_des_cbc_mac_nopad_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return crypto_cbc_mac_alloc_ctx(ctx, TEE_ALG_DES_CBC_NOPAD, false);
}

TEE_Result crypto_des_cbc_mac_pkcs5_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return crypto_cbc_mac_alloc_ctx(ctx, TEE_ALG_DES_CBC_NOPAD, true);
}

TEE_Result crypto_des3_cbc_mac_nopad_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return crypto_cbc_mac_alloc_ctx(ctx, TEE_ALG_DES3_CBC_NOPAD, false);
}

TEE_Result crypto_des3_cbc_mac_pkcs5_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return crypto_cbc_mac_alloc_ctx(ctx, TEE_ALG_DES3_CBC_NOPAD, true);
}
