/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Renesas Electronics Corporation. All rights reserved.
 *
 */
#include <platform_config.h>

#ifndef MFIS_REGISTER_H
#define MFIS_REGISTER_H

/******************************************************************************/
/* Definition                                                                 */
/******************************************************************************/
/* MFIS_COMMON_BASE base address  */
#define MFIS_COMMON_BASE		(MFIS_BASE)
/* MFIS lock 5 Register Address  */
#define MFIS_MFISLCKR5			(MFIS_COMMON_BASE + (0x000000D4uL))
/* Write Protection Control Register  */
#define MFIS_MFISWPCNTR			(MFIS_COMMON_BASE + (0x00000900uL))
/* Write Access Control Register Address  */
#define MFIS_MFISWACNTR			(MFIS_COMMON_BASE + (0x00000904uL))

/* MFISLCKR bit[0] (LCK) Mask   */
#define MFISLCKR_LCK_MASK                                     (0x00000001uL)
/* MFISLCKR bit[0] (LCK) Mutex Control Forbidden Set   */
#define MFISLCKR_LCK_RELEASE_SET                              (0x00000000uL)
/* MFISLCKR bit[0] (LCK) Mutex acquired Check  */
#define MFISLCKR_LCK_ACQUIRED_CHECK                           (0x00000001uL)
/* MFISLCKR bit[0] (LCK) Mutex not acquired Check  */
#define MFISLCKR_LCK_NOT_ACQUIRED_CHECK                       (0x00000000uL)
/* MFISWPCNTR bit[31:16] (Code value) Set  */
#define MFISWPCNTR_CODEVALUE_SET                              (0xACCE0000uL)
/* MFISWPCNTR bit[0] (WPD) Set  */
#define MFISWPCNTR_WPD_SET                                    (0x00000000uL)
/* MFISWACNTR bit[31:16] (Code value) Set  */
#define MFISWACNTR_CODEVALUE_SET                              (0xACCE0000uL)
/* MFISWACNTR bit[15:0] (RegisterAddress) Set  */
#define MFISWACNTR_REGISTERADDRESS_MASK                       (0x0000FFFFuL)

/******************************************************************************/
/* Prototype                                                                  */
/******************************************************************************/

#endif /* MFIS_REGISTER_H */
