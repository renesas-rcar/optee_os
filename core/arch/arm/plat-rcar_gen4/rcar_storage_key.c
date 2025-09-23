#include <stdint.h>
#include <tee_api_defines.h>
#include <stdlib.h>
#include <string.h>

#include "r_icumif_api.h"
#include "r_icumif_pub.h"
#include "rcar_storage_key.h"

static uint8_t *p_auth_key;

uint8_t she_get_key_id(uint8_t she_key_index);
TEE_Result create_she_enc_message(uint8_t auth_key_id, uint8_t she_key_id,
		void *plain_key_buf, size_t plain_key_size, void *uid_buf,
		size_t uid_size, SHE_key_update_type *she_mess);

void write_bit(uint8_t *buf, uint32_t bit_index, uint8_t value) {
	uint32_t byte = bit_index / 8;
	uint8_t bit = 7 - (bit_index % 8);  // reverse bit order within the byte

	if (value)
		buf[byte] |= (uint8_t)(1U << bit);   // set the bit
	else
		buf[byte] &= (uint8_t)~(1U << bit);  // clear the bit
}

void set_counter(uint8_t *buf, uint32_t counter_value) {
	for (uint32_t i = 0; i < 28; i++) {
		uint8_t bit = (counter_value >> (27 - i)) & 0x01;  // extract bit from MSB to LSB
		write_bit(buf, i, bit);  // write to bit position i in M2
	}
}

uint8_t* get_key_update_const(uint8_t she_key_index, uint8_t update_type)
{
	uint8_t logical_index = she_key_to_logical_index(she_key_index);
	uint8_t update_index = 0;

	// update_index: incease 1 every 10 keys
	update_index = (logical_index - 1) / 10;

	if(update_type == UPDATE_ENC) {
		return key_update_enc_c[update_index];
	} else if ( update_type == UPDATE_MAC) {
		return key_update_mac_c[update_index];
	} else {
		/* No operation */
		return;
	}
}

uint8_t she_get_key_id(uint8_t she_key_index)
{
	uint8_t logical_index = she_key_to_logical_index(she_key_index);
	if(logical_index == 0xFF) {
		return 0xFF;
	}

	// key_id: loop key id in HIS-SHE 4 → 13
	return ((logical_index - 1) % 10) + 4;
}

TEE_Result she_gen_m1(uint8_t auth_key_id, uint8_t she_key_id,
		void *uid_buf, size_t uid_size, void *she_m1_buf) {
	uint8_t ret = TEE_SUCCESS;
	uint8_t id_value;

	if (!uid_buf || uid_size != 15) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Get the value of key id and authenticate key id */
	id_value = she_get_key_id(she_key_id);
	id_value = (id_value << 4)|auth_key_id;

	/* Gen SHE M1 = UID (120 bits) + key ID (4 bits) + Auth key ID */
	memcpy(she_m1_buf, (uint8_t *)uid_buf, uid_size);
	memcpy(she_m1_buf + 15, (uint8_t *)&id_value, 1);

	return TEE_SUCCESS;
}

TEE_Result she_gen_m2(uint8_t she_key_id, void *plain_key_buf,
		size_t plain_key_size, void *she_m2_buf) {
	uint8_t ret = TEE_SUCCESS;
	uint8_t *p_update_enc;
	uint8_t *p_plain_m2;
	uint8_t *p_k1;
	uint8_t *iv;
	size_t k1_size;

	/* Init buffer */
	p_k1 = malloc(AES_KEY_LEN_128);
	p_plain_m2 = malloc(SHE_SINGLE_MESS_SIZE);
	iv = malloc(SHE_SINGLE_MESS_SIZE);

	if (!p_k1 || !iv || !p_plain_m2)
		return TEE_ERROR_OUT_OF_MEMORY;

	memset((uint8_t *)p_k1, 0, AES_KEY_LEN_128);
	memset((uint8_t *)iv, 0, SHE_SINGLE_MESS_SIZE);
	memset((uint8_t *)p_plain_m2, 0, SHE_SINGLE_MESS_SIZE);

	/* Get update encrypt value */
	p_update_enc = get_key_update_const(she_key_id, UPDATE_ENC);

	/* Derive K1 using MP (Miyaguchi-Preneel) */
	ret = fwss_calculate_MP(p_auth_key, AES_KEY_LEN_128,
			p_update_enc, SIZE_OF_CONSTANT, p_k1, &k1_size);
	if (ret != TEE_SUCCESS) {
		goto out;
	}

	/* Update K1 to key id 0 in KEY_GRP_AES_RAM */
	ret = fwss_plain_key_update(KEY_GRP_AES_RAM, 0, (uint8_t *)p_k1, k1_size);
	if (ret != TEE_SUCCESS) {
		goto out;
	}

	/* Prepare M2 plain text */
	write_bit(p_plain_m2, SHE_KEY_USAGE_BIT, 1);
	set_counter(p_plain_m2, 13);
	memcpy(p_plain_m2 + 16, (uint8_t *)plain_key_buf, plain_key_size);

	/* Generate SHE M2 using AES-CBC ecnryption*/
	ret = fwss_aes_cipher(CIPHER_DIR_ENCRYPTION, CIPHER_MOD_CBC,
			KEY_GRP_AES_RAM, 0, iv, p_plain_m2,
			SHE_SINGLE_MESS_SIZE, she_m2_buf);
out:
	free(p_k1);
	free(p_plain_m2);
	free(iv);
	return ret;
}

TEE_Result she_gen_m3(uint8_t she_key_id, void *she_m1_buf,
		void *she_m2_buf, void *she_m3_buf)
{
	uint8_t ret = TEE_SUCCESS;
	uint8_t *p_update_mac;
	uint8_t *p_plain_m3;
	uint8_t *p_k2;
	size_t k2_size;
	size_t plain_m3_size;
	size_t she_m3_size;

	/* Init buffer */
	p_k2 = malloc(AES_KEY_LEN_128);
	p_plain_m3 = malloc(SHE_SINGLE_MESS_SIZE + SHE_SINGLE_MESS_SIZE/2);

	if (!p_k2 || !p_plain_m3)
		return TEE_ERROR_OUT_OF_MEMORY;

	memset((uint8_t *)p_k2, 0, AES_KEY_LEN_128);
	memset((uint8_t *)p_plain_m3, 0, SHE_SINGLE_MESS_SIZE);

	/* Get update mac value */
	p_update_mac = get_key_update_const(she_key_id, UPDATE_MAC);

	/* Derive K2 using MP (Miyaguchi-Preneel) */
	ret = fwss_calculate_MP(p_auth_key, AES_KEY_LEN_128,
			p_update_mac, SIZE_OF_CONSTANT, p_k2, &k2_size);
	if (ret != TEE_SUCCESS) {
		goto out;
	}

	/* Update K2 to key id 1 in KEY_GRP_AES_RAM */
	ret = fwss_plain_key_update(KEY_GRP_AES_RAM, 1, (uint8_t *)p_k2, k2_size);
	if (ret != TEE_SUCCESS) {
		goto out;
	}

	/* Prepare M3 plain text */
	memcpy(p_plain_m3, (uint8_t *)she_m1_buf, SHE_SINGLE_MESS_SIZE/2);
	memcpy(p_plain_m3 + 16, (uint8_t *)she_m2_buf, SHE_SINGLE_MESS_SIZE);

	plain_m3_size = SHE_SINGLE_MESS_SIZE/2 + SHE_SINGLE_MESS_SIZE;

	/* Generate SHE M3 using AES-CMAC calculator */
	ret = fwss_aes_cmac(KEY_GRP_AES_RAM, 1, p_plain_m3, plain_m3_size,
			she_m3_buf, &she_m3_size);
out:
	free(p_k2);
	free(p_plain_m3);
	return ret;
}

TEE_Result create_she_enc_message(uint8_t auth_key_id, uint8_t she_key_id,
		void *plain_key_buf, size_t plain_key_size, void *uid_buf,
			size_t uid_size, SHE_key_update_type *she_mess)
{
	uint32_t ret = TEE_SUCCESS;

	/* Check if the inputs is valid */
	if ((she_key_id <= SHE_KEY_1 && she_key_id >= SHE_KEY_90
		&& she_key_id == SHE_RAM_KEY)
		|| auth_key_id != SHE_MASTER_ECU_KEY) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!plain_key_buf || !plain_key_size || !she_mess) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memset((uint8_t *)she_mess, 0, sizeof(SHE_key_update_type));

	/******************* Generate SHE M1 ********************/
	ret = she_gen_m1(auth_key_id, she_key_id, uid_buf,
			uid_size, she_mess->M1);
	if (ret != TEE_SUCCESS)
		goto out;

	/******************* Generate SHE M2 ********************/
	ret = she_gen_m2(she_key_id, plain_key_buf,
			plain_key_size, she_mess->M2);
	if (ret != TEE_SUCCESS)
		goto out;

	/******************* Generate SHE M3 ********************/
	ret = she_gen_m3(she_key_id, she_mess->M1, she_mess->M2,
			she_mess->M3);
	if (ret != TEE_SUCCESS)
		goto out;
out:
	return ret;
}

TEE_Result rcar_install_user_key(void *key_buf,size_t key_len)
{
	uint32_t res;
	uint32_t ret = FW_SERVICE_SUCCESS;
	SHE_key_update_type she_mess;
	uint8_t *p_trng_key;
	uint8_t *p_uid;
	size_t uid_size;

	/* Init ICUM Firmware interface */
	res = fwss_service_init();
	DMSG("is_init_icum = %d\n", is_init_icum);
	if(res != FW_SERVICE_SUCCESS) {
		EMSG("fwss_service_init() error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}

	/* Check if the ICUM Firmware has been initialized */
	ret = check_icum_init();
	if(ret != TEE_SUCCESS) {
		goto out;
	}

	/* Create the authentication key */
	p_auth_key = malloc(AES_KEY_LEN_128);
	if (!p_auth_key)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = fwss_trng_generate(p_auth_key, AES_KEY_LEN_128);
	if (ret != TEE_SUCCESS) {
		goto out;
	}

	/****************************************************
	 * Update the authenticate key as SHE_MASTER_ECU_KEY
	 * SHE_MASTER_ECU_KEY = KEY_GRP_AES, id 0
	 * **************************************************/
	ret = fwss_plain_key_update(KEY_GRP_AES, 0,
		(uint8_t *)p_auth_key, (uint16_t)AES_BLOCK_SIZE_IN_BYTES);
	if (ret != TEE_SUCCESS) {
		goto out;
	}

	/* Get UID */
	p_uid = malloc(SHE_UID_SIZE);
	if (!p_uid)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = fwss_get_id(p_uid, &uid_size);
	if (ret != TEE_SUCCESS) {
		goto out;
	}

	/* Generate SHE encrypted key message */
	ret = create_she_enc_message(SHE_MASTER_ECU_KEY,
			SHE_KEY_10, key_buf, key_len, p_uid,
			uid_size, &she_mess);
	if (ret != TEE_SUCCESS) {
	       goto out;
	}

	/*************************************************
	 * Update SHE encrypted key message as SHE_KEY_10.
	 * This key is the transported key used to decrypt
	 * the asset package.
	 * ***********************************************/
	ret = fwss_she_key_update(SHE_KEY_10, &she_mess, sizeof(she_mess));
	if (ret != TEE_SUCCESS) {
		goto out;
	} else {
		IMSG("SHE_KEY_10 has been updated !!!");
	}

	/* Init the true random key buffer */
	p_trng_key = malloc(AES_KEY_LEN_256);

	if (!p_trng_key)
		return TEE_ERROR_OUT_OF_MEMORY;

	memset((uint8_t *)p_trng_key, 0, AES_KEY_LEN_256);
	ret = fwss_trng_generate(p_trng_key, AES_KEY_LEN_256);
	if (ret != TEE_SUCCESS) {
		goto out;
	}

	/*************************************************
	 * Update the true random key as key id = 5 in KEY_GRP_AES.
	 * This key is used for RPMB secure storage.
	 * ***********************************************/
	ret = fwss_plain_key_update(KEY_GRP_AES, 5, (uint8_t *)p_trng_key,
			(uint16_t)AES_BLOCK_SIZE_IN_BYTES*2);
	if (ret != TEE_SUCCESS) {
		goto out;
	} else {
		IMSG("TRNG key has been updated !!!");
	}

	/* Exports secure data to export area */
	ret = fwss_ext_flash_write();
out:
	free(p_auth_key);
	free(p_uid);
	free(p_trng_key);
	return ret;
}
