#include <stdint.h>
#include <tee_api_defines.h>
#include <stdlib.h>
#include <string.h>

#include "r_icumif_api.h"
#include "r_icumif_pub.h"
#include "rcar_storage_key.h"

TEE_Result rcar_install_user_key(void *key_buf, size_t key_len)
{
	uint32_t res;
	uint32_t ret = FW_SERVICE_SUCCESS;
	uint8_t *p_trng_key = NULL;

	/* Init ICUM Firmware interface */
	res = fwss_service_init();
	if (res != FW_SERVICE_SUCCESS) {
		EMSG("fwss_service_init() error");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}

	/* Install Kut into key group KEY_GRP_AES, id = 11 */
	ret = fwss_plain_key_update(KEY_GRP_AES, 11, (uint8_t *)key_buf,
			key_len, ENABLE_KEY_WRITE_PROTECT);
	if (ret != TEE_SUCCESS) {
		DMSG("Failed to install User-Transported Key !");
		goto out;
	} else {
		DMSG("User-Transport Key installed successfully !");
	}

	/* Init the true random key buffer */
	p_trng_key = malloc(AES_KEY_LEN_256);
	if (!p_trng_key)
		return TEE_ERROR_OUT_OF_MEMORY;

	memset((uint8_t *)p_trng_key, 0, AES_KEY_LEN_256);
	ret = fwss_trng_generate(p_trng_key, AES_KEY_LEN_256);
	if (ret != TEE_SUCCESS) {
		DMSG("Failed to generate a true random value !");
		goto out;
	}

	/*************************************************
	 * Update the true random key as key id = 5 in KEY_GRP_AES.
	 * This key is used for RPMB secure storage.
	 * ***********************************************/
	ret = fwss_plain_key_update(KEY_GRP_AES, 5, (uint8_t *)p_trng_key,
			(uint16_t)AES_KEY_LEN_256, ENABLE_KEY_WRITE_PROTECT);
	if (ret != TEE_SUCCESS) {
		DMSG("Failed to install TRNG Key !");
		goto out;
	} else {
		IMSG("TRNG key installed successfully !");
	}

	/* Exports secure data to export area */
	ret = fwss_ext_flash_write();
	if (ret != TEE_SUCCESS) {
		DMSG("Failed to export secure data !");
		goto out;
	}
out:
	free(p_trng_key);
	return ret;
}
