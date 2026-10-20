/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#ifndef LDR_H
#define LDR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define LDR_LOG_LEVEL_NONE		-1
#define LDR_LOG_LEVEL_INDEPENDENT	0
#define LDR_LOG_LEVEL_ERROR		1
#define LDR_LOG_LEVEL_INFO		2
#define LDR_LOG_LEVEL_DEBUG		3
#define LDR_LOG_LEVEL_FLOW		4

void rcar_ldr_init(void);
void rcar_ldr_record(int level, const char *fmt, ...) __printf(2, 3);
int ldr_level_from_trace_str(const char *str);

#endif /* LDR_H */
