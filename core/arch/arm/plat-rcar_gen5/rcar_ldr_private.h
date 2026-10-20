/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#ifndef LDR_PRIVATE_H
#define LDR_PRIVATE_H

#include <stdbool.h>
#include <stdint.h>

struct ldr_state {
	bool     initialized;	/* Ring formatted and ready                   */
	uint8_t  msg_counter;	/* DLT mcnt field source (wraps at 255)       */
	uint32_t dropped_count;	/* Records refused because the ring was full  */
};

#endif /* LDR_PRIVATE_H */
