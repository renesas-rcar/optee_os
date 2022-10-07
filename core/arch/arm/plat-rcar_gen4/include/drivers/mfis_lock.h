/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Renesas Electronics Corporation
 */

#ifndef MFIS_LOCK_H
#define MFIS_LOCK_H

#include <stdint.h>
#include <string.h>
#include "rcar_common.h"

#define MFIS_CODE_VALID			(0xACCE0000U)
#define MFISLCKR_LOCK_BIT		((uint32_t)1U << 0U)
#define MFISLCKR_UNLOCK			(0U)
#define MFISLCKR_TARGET_ADDRESS	(0x0800U)
#define MFIS_LCKR_ADDRESS		(0xE6260800U)
#define MFIS_WACNTR_ADDRESS		(0xE6260904U)
#define MFIS_LCKR			p2v_regadr(MFIS_LCKR_ADDRESS)
#define MFIS_WACNTR			p2v_regadr(MFIS_WACNTR_ADDRESS)

void mfis_lock(void);
void mfis_unlock(void);

#endif /* MFIS_LOCK_H */
