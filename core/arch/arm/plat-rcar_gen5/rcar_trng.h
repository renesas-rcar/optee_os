/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Renesas Electronics Corporation
 */

#ifndef RCAR_TRNG_FUNC_H
#define RCAR_TRNG_FUNC_H

#include <tee_api_defines.h>

/*
 * Constant definition
 */
#define TRNG_MAX_WORD	(128u) /* Size in bytes*/
#define TRNG_BLOCK_SIZE	(4u)

/* Service ID */
#define SERVICE_ID_TRNG         (0x01uL)
#define SERVICE_RESULT_OK       (0x0uL)

/*
 * Struct definition
 */

/*
 * Global variable declaration
 */

/*
 * Prototype declaration
 */

void rsipm_trng_generate(uint8_t *buf, uint32_t buf_len);
void rsipm_communication(uint8_t *buf, uint32_t buf_len);

#endif /* RCAR_TRNG_FUNC_H */
