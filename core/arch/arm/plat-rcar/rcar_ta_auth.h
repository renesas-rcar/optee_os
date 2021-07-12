/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2020 Renesas Electronics Corporation
 */

#ifndef RCAR_TA_AUTH_H
#define RCAR_TA_AUTH_H

#include <stdint.h>
#include <signed_hdr.h>
#include "tee_api_types.h"

TEE_Result rcar_auth_ta_certificate(const struct shdr *key_cert,
				struct shdr **secmem_ta);

#endif /* RCAR_TA_AUTH_H */
