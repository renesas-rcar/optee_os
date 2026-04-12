/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Renesas Electronics Corporation.
 */

#ifndef RCAR_VERSION_H
#define RCAR_VERSION_H

#include <stdint.h>
#include <kernel/thread_arch.h>

#define VERSION_OF_RENESAS	"1.3.1"

/* Struct to store version */
typedef struct {
	uint64_t major;
	uint64_t minor;
	uint64_t patch;
} version_t;

void tee_entry_get_rcar_bsp_revision(struct thread_smc_args *args);

#endif /* RCAR_VERSION_H */
