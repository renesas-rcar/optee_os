/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2018, Renesas Electronics Corporation
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

/* System Timer Register */
#define CMSSTR			(SYSTIM_BASE + 0x000U)
#define CMSCSR			(SYSTIM_BASE + 0x040U)
#define CMSCNT			(SYSTIM_BASE + 0x044U)
#define CMSCOR			(SYSTIM_BASE + 0x048U)

#define CMSSTR_BIT_STR5		(0x0020U)	/* CMSSTR Bit 5   */

#define CMSCSR_BIT_CMF		(0x8000U)	/* CMSCSR Bit 15  */
#define CMSCSR_BIT_OVF		(0x4000U)	/* CMSCSR Bit 14  */
#define CMSCSR_BIT_WRFLG	(0x2000U)	/* CMSCSR Bit 13  */
#define CMSCSR_BIT_CMS		(0x0200U)	/* CMSCSR Bit 9   */
#define CMSCSR_BIT_CMM		(0x0100U)	/* CMSCSR Bit 8   */
#define CMSCSR_BIT_CMR		(0x0030U)	/* CMSCSR Bit 4-5 */
#define CMSCSR_BIT_DBGIVD	(0x0008U)	/* CMSCSR Bit 3   */
#define CMSCSR_BIT_CKS		(0x0007U)	/* CMSCSR Bit 0-2 */

#define CKS_DIVISION_RATIO_1	(0x7U)		/* CKS clock/1    */
#define CKS_DIVISION_RATIO_8	(0x4U)		/* CKS clock/8    */
#define CKS_DIVISION_RATIO_32	(0x5U)		/* CKS clock/32   */
#define CKS_DIVISION_RATIO_128	(0x6U)		/* CKS clock/128  */
#define CMR_INTERRUPT_ENABLE	(0x20U)		/* CMR Interrupt Enable */
#define CMM_FREE_RUN_OPERATION	(0x100U)	/* CMM Free-running operation */
#define CMM_ONE_SHOT_OPERATION	(0x000U)	/* CMM One-shot operation     */

#define SYSTIM_PRIORITY		(0x1U)

/* Reset(RST) */
#define MODEMR			(0xE6160060U)	/* Mode Monitor Register */

#define CHECK_MD13_MD14		(0x6000U)
#define MD14_L_MD13_H		(0x2000U)

/* Interrupt ID */
#define INTID_SCMT		(134U + 32U)	/* System Timer */
#define INTID_PKA		(65U  + 32U)	/* Crypto Engine PKA sec */
#define INTID_CC		(70U  + 32U)	/* Crypto Engine sec */

/* RPC No specific to R-Car */
#define TEE_RPC_DEBUG_LOG	(0x3F000000U)

/* Product Register */
#define PRR			(0xFFF00044U)
#define PRR_PRODUCT_MASK	(0x0000FF00U)
#define PRR_PRODUCT_UNKNOWN	(0x000000FFU)
#define PRR_PRODUCT_API_TABLE	(0x00010000U)
#define PRR_PRODUCT_H3		(0x00004F00U)	/* R-Car H3 */
#define PRR_PRODUCT_M3		(0x00005200U)	/* R-Car M3 */
#define PRR_PRODUCT_M3N		(0x00005500U)	/* R-Car M3N */
#define PRR_PRODUCT_E3		(0x00005700U)	/* R-Car E3 */
#define PRR_CUT_MASK		(0x000000FFU)
#define PRR_CUT_10		(0x00000000U)
#define PRR_CUT_11		(0x00000001U)
#define PRR_CUT_20		(0x00000010U)

/* Fuse Monitor Register */
#define FUSE_DUMMY5		(0xE60603E8U)	/* Fuse dummy5 */
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
