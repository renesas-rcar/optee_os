/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Renesas Electronics Corporation
 */

#ifndef RCAR_COMMON_H
#define RCAR_COMMON_H

#include <string.h>
#include <platform_config.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <drivers/gic.h>
#include <arm.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>

/*
 * Convert a physical address to a virtual address with the
 * MEM_AREA_IO_SEC attribute.
 */
#define p2v_ioadr(r, len) ((vaddr_t)(phys_to_virt((r), MEM_AREA_IO_SEC, (len))))
#define p2v_regadr(r, len) ((phys_to_virt((r), MEM_AREA_IO_SEC, (len))))

/* RPC No specific to R-Car */
#define TEE_RPC_DEBUG_LOG      (0x3F000000U)

/* Product Register */
#define PRR     p2v_ioadr(0xFFF00044U, MEMORY5_SIZE)

/* Debug log output for test confirmation */
#ifndef RCAR_TEST_LOG
#define TMSG(...)   ((void)0)
#else
#define TMSG(...)   trace_printf_helper(TRACE_DEBUG, true, __VA_ARGS__)
#endif /* RCAR_TEST_LOG */

/*
 * Define the information of debug log that communicates between Normal
 * World and Secure World.
 */
#define SMC_RCAR_CMD           (12345U)

#define NORMAL_WORLD_COMPLETE_INIT      (1U)

/* Declaration of global variables */
extern uint32_t product_type;
extern const int8_t *product_name;
extern uint32_t prr_cut;
extern uint32_t cpu_on_core_lock;
extern uint32_t cpu_on_core_bit;

/* Define a constant for the initialization flag */
#define INIT_FLAG_UNINITIALIZED		(0U)
#define INIT_FLAG_INITIALIZED		(1U)

#endif /* RCAR_COMMON_H */
