/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2023, Renesas Electronics Corporation
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
 *  MEM_AREA_IO_SEC attribute.
 */
#define p2v_ioadr(r)		((vaddr_t)(phys_to_virt((r), MEM_AREA_IO_SEC)))
#define p2v_regadr(r)		((phys_to_virt((r), MEM_AREA_IO_SEC)))

/* Interrupt ID */
#define INTID_PKA		(65U  + 32U)	/* Crypto Engine PKA sec */
#define INTID_CC		(70U  + 32U)	/* Crypto Engine sec */

/* RPC No specific to R-Car */
#define TEE_RPC_DEBUG_LOG	(0x3F000000U)

/* Product Register */
#define PRR			p2v_ioadr(0xFFF00044U)

/* Stack switching */
uint32_t asm_switch_stack_pointer(uintptr_t jump, uint32_t stack, void *arg);

/* Parameters value passed from ARM Trusted FW */
#define TFW_ARG_CPU_SUSPEND	(0x0UL)
#define TFW_ARG_SYSTEM_SUSPEND	(0x1UL)

/* Argument flag of the hw_engine_lock() */
#define HWENG_SECURE_CORE	(0x00000001U)

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
#define SMC_RCAR_CMD		(12345U)

#define START_DLOG_OUTPUT	(1U)

/* Define a constant for the initialization flag */
#define INIT_FLAG_UNINITIALIZED	(0U)
#define INIT_FLAG_INITIALIZED	(1U)

/* Declaration of global variables */
extern uint32_t product_type;
extern const int8_t *product_name;
extern uint32_t prr_cut;
extern uint32_t cpu_on_core_lock;
extern uint8_t cpu_on_core_bit;

/*
 * Prototype declaration
 */

#ifdef CFG_CRYPT_HW_CRYPTOENGINE
extern void hw_engine_lock(uint32_t *lock, uint32_t flag);
extern void hw_engine_unlock(uint32_t lock);
#else
#define hw_engine_lock(...)	((void)0)
#define hw_engine_unlock(lock)	((void)(lock))
#endif /* CFG_CRYPT_HW_CRYPTOENGINE */

/* Storage is provided by the QSPI/Hyper Flash */
#define TEE_STORAGE_PRIVATE_STANDALONE 0x80001000

extern const struct tee_file_operations standalone_fs_ops;

#endif /* RCAR_COMMON_H */
