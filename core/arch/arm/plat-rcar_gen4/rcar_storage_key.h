#ifndef RCAR_STORAGE_KEY_H
#define RCAR_STORAGE_KEY_H

#include <stdint.h>
#include "tee_api_types.h"
#include "trace.h"
#include "rcar_fw_security_service.h"

/*******************************************************************************
 * Function & variable prototypes
 ******************************************************************************/
TEE_Result rcar_install_user_key(void *key_buf, size_t key_len);
TEE_Result icum_clear_secure_data(void);
TEE_Result icum_write_secure_data(void);
#endif /* RCAR_STORAGE_KEY_H */
