/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2021, Renesas Electronics Corporation
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
#define p2v_ioadr(r)		((vaddr_t)(phys_to_virt((r), MEM_AREA_IO_SEC, 1)))
#define p2v_regadr(r)		((phys_to_virt((r), MEM_AREA_IO_SEC, 1)))

/* Interrupt ID */
#define INTID_PKA		(65U  + 32U)	/* Crypto Engine PKA sec */
#define INTID_CC		(70U  + 32U)	/* Crypto Engine sec */

/* RPC No specific to R-Car */
#define TEE_RPC_DEBUG_LOG	(0x3F000000U)

/* Product Register */
#define PRR			p2v_ioadr(0xFFF00044U)
#define PRR_PRODUCT_MASK	(0x0000FF00U)
#define PRR_PRODUCT_API_TABLE	(0x00010000U)
#define PRR_PRODUCT_H3		(0x00004F00U)	/* R-Car H3 */
#define PRR_PRODUCT_M3		(0x00005200U)	/* R-Car M3 */
#define PRR_PRODUCT_M3N		(0x00005500U)	/* R-Car M3N */
#define PRR_PRODUCT_E3		(0x00005700U)	/* R-Car E3 */
#define PRR_PRODUCT_D3		(0x00005800U)	/* R-Car D3 */
#define PRR_CUT_MASK		(0x000000FFU)
#define PRR_CUT_10		(0x00000000U)
#define PRR_CUT_11		(0x00000001U)
#define PRR_CUT_20		(0x00000010U)

/* Fuse Monitor Register */
#define FUSE_DUMMY5		p2v_ioadr(0xE60603E8U)	/* Fuse dummy5 */
#define	FUSE_M3_MASK		(0x1C000000U)	/* Dummy5[28:26] */
#define	M3_100			(0x00000000U)	/* M3 1.0  */
#define	M3_105			(0x04000000U)	/* M3 1.05 */
#define	M3_106			(0x08000000U)	/* M3 1.06 */

/* Parameters value passed from ARM Trusted FW */
#define TFW_ARG_CPU_SUSPEND	(0x0UL)
#define TFW_ARG_SYSTEM_SUSPEND	(0x1UL)

/* Argument flag of the hw_engine_lock() */
#define HWENG_SECURE_CORE	(0x00000001U)

/* Debug log output for test confirmation */
#ifndef RCAR_TEST_LOG
#define TMSG(...)   (void)0
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

/*
 * Prototype declaration
 */

#ifdef CFG_CRYPT_HW_CRYPTOENGINE
extern void hw_engine_lock(uint32_t *lock, uint32_t flag);
extern void hw_engine_unlock(uint32_t lock);
#else
#define hw_engine_lock(...)	(void)0
#define hw_engine_unlock(lock)	(void)(lock)
#endif /* CFG_CRYPT_HW_CRYPTOENGINE */

#endif /* RCAR_COMMON_H */
