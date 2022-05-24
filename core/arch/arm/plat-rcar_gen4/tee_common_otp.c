// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015-2022, Renesas Electronics Corporation
 */

#include <stddef.h>
#include <string.h>
#include <trace.h>
#include <kernel/tee_common_otp.h>
#include <io.h>
#include <stdlib.h>
#include <tee/tee_cryp_utl.h>
#include <kernel/panic.h>
#include <utee_defines.h>
#include <mm/core_memprot.h>

#include <libcryptoengine/tee_provider_common.h>
#include <libcryptoengine/include_secure/dx_util.h>
#include <libcryptoengine/include_secure/dx_util_error.h>
#include "platform_config.h"

static void read_uid_reg(uint8_t *read_uid, uint32_t read_num);

static const uint32_t uid_read_num = 3U;
static const uint32_t reg_size = sizeof(uint32_t);

static void read_uid_reg(uint8_t *read_uid, uint32_t read_num)
{
	uint32_t uid;
	uint32_t i;
	uint32_t uid_addr = (uint32_t)((vaddr_t)phys_to_virt((LIFEC_BASE +
				0x0040U), MEM_AREA_IO_SEC));

	/* get uid from LifeC register. */
	for (i = 0U; i < read_num; i++) {
		uid = io_read32(uid_addr);
		uid = TEE_U32_TO_BIG_ENDIAN(uid);
		(void)memcpy(&read_uid[i * reg_size], &uid, reg_size);
		uid_addr += reg_size;
	}
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	const uint32_t uid_size = uid_read_num * reg_size;
	const uint8_t string_for_unique_key_gen[] = "R-Car_hw_unique_key";
	const uint32_t str_size = sizeof(string_for_unique_key_gen);
	const uint32_t data_size = uid_size + str_size;
	uint8_t input_data[data_size];
	SSError_t dx_util_ret;
	DX_UTIL_KeyType_t aesKeyType = DX_UTIL_KDR_KEY;
	DX_UTIL_AES_CmacResult_t util_aes_cmac_key;
	TEE_Result res = TEE_SUCCESS;

	if (hwkey != NULL) {
		/* get uid from LifeC register */
		read_uid_reg(input_data, uid_read_num);

		/* edit input data. add a fixed string. */
		(void)memcpy(&input_data[uid_size],
				string_for_unique_key_gen, str_size);

		/* get CMAC key, specify the Kdr */
		dx_util_ret = DX_UTIL_CmacDeriveKey(aesKeyType,
				input_data, data_size, util_aes_cmac_key);

		if (dx_util_ret == DX_UTIL_OK) {
			/* edit output data */
			(void)memcpy(hwkey, util_aes_cmac_key,
				sizeof(struct tee_hw_unique_key));
		} else {
			EMSG("DX_UTIL_CmacDeriveKey() error. 0x%x",
				dx_util_ret);
			res = TEE_ERROR_SECURITY;
		}
	} else {
		EMSG("hwkey is NULL");
		res = TEE_ERROR_BAD_PARAMETERS;
	}
	return res;
}

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	const uint32_t uid_size = uid_read_num * reg_size;
	const uint8_t string_for_die_id_gen[] = "R-Car_die_id";
	const uint32_t str_size = sizeof(string_for_die_id_gen);
	const uint32_t data_size = uid_size + str_size;
	const uint32_t digest_size = (uint32_t)TEE_SHA256_HASH_SIZE;
	uint8_t input_data[data_size];
	uint8_t digest[digest_size];
	uint32_t i;
	TEE_Result res;
	int32_t rc = -1;

	if ((buffer != NULL) && (len != 0U)) {
		/* get uid from LifeC register. */
		read_uid_reg(input_data, uid_read_num);

		/* edit input data. add a fixed string. */
		(void)memcpy(&input_data[uid_size],
				string_for_die_id_gen, str_size);

		/* get hash for SHA256 */
		res = tee_hash_createdigest((uint32_t)TEE_ALG_SHA256,
				input_data, data_size, digest, digest_size);

		if (res == (TEE_Result)TEE_SUCCESS) {
			/* edit output data */
			for (i = 0U; i < len; i++) {
				buffer[i] = digest[i % digest_size];
			}
			rc = 0;	/* success */
		} else {
			EMSG("tee_hash_createdigest() error. 0x%x", res);
		}
	} else {
		EMSG("buffer is 0x%p. len is %zu.", buffer, len);
	}

	return rc;
}
