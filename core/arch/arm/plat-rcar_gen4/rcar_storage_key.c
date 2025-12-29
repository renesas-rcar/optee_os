#include <stdint.h>
#include <tee_api_defines.h>
#include <stdlib.h>
#include <string.h>
#include <platform_config.h>

#include "r_icumif_api.h"
#include "r_icumif_pub.h"
#include "rcar_storage_key.h"

#include "pe_target_device.h"
#include "drivers/qspi_hyper_flash.h"

TEE_Result icum_clear_secure_data(void)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t res;

	res = qspi_hyper_flash_init();
	if (res != FL_DRV_OK) {
		ret = TEE_ERROR_TARGET_DEAD;
	}

	res = qspi_hyper_flash_erase(EXTERNAL_FLASH_ADDR);
	if (res == FL_DRV_OK) {
		ret = TEE_SUCCESS;
	} else if (res == FL_DRV_ERR_OUT_OF_MEMORY) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
	} else {
		ret = TEE_ERROR_TARGET_DEAD;
	}

	return ret;
}

TEE_Result icum_write_secure_data(void)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t res;
	uint8_t *p_export_area = (uint8_t *)(uintptr_t)MEM_INFO_EXPORT_DATA_ADDR;
	uint32_t align = sizeof(uint32_t);
	uint32_t export_size = ((MEM_INFO_EXPORT_DATA_SIZE + align - 1) / align) * align;

	res = qspi_hyper_flash_init();
	if (res != FL_DRV_OK) {
		ret = TEE_ERROR_TARGET_DEAD;
	}

	res = qspi_hyper_flash_write(EXTERNAL_FLASH_ADDR, p_export_area, export_size);
	if (res == FL_DRV_OK) {
		ret = TEE_SUCCESS;
	} else if (res == FL_DRV_ERR_OUT_OF_MEMORY) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
	} else {
		ret = TEE_ERROR_TARGET_DEAD;
	}

	return ret;
}

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

	/* Write ICUM secure data to External Flash memory */
	ret = icum_clear_secure_data();
	if (ret != TEE_SUCCESS) {
		DMSG("Failed to clear ICUM secure data in External FLash memory !");
		goto out;
	}

	ret = icum_write_secure_data();
	if (ret != TEE_SUCCESS) {
		DMSG("Failed to write ICUM secure data to External FLash memory !");
		goto out;
	}
out:
	free(p_trng_key);
	return ret;
}
