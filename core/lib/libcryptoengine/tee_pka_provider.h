/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
 */

#ifndef TEE_PKA_PROVIDER_H
#define TEE_PKA_PROVIDER_H

#include <crypto/crypto.h>

/******************************************************************************/
/* Public Function Prototypes                                                 */
/******************************************************************************/
TEE_Result ss_ecc_verify_pka(struct ecc_public_key *key,
		const uint8_t *msg, size_t msg_len, const uint8_t *sig,
		size_t sig_len);

TEE_Result pka_verify_init(void);

#endif
