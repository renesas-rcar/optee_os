/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Renesas Electronics Corporation
 */

#include <platform_config.h>
#ifndef HSCIF_REGISTER_H_
#define HSCIF_REGISTER_H_

/* define macros */
#define HSCIF_SCSCR_TE_EN	((uint16_t)((uint16_t)1U << 5U))
#define HSCIF_SCSCR_RE_EN	((uint16_t)((uint16_t)1U << 4U))
#define HSCIF_SCSCR_INIT_DATA	((uint16_t)(HSCIF_SCSCR_TE_EN \
					| HSCIF_SCSCR_RE_EN))
#define HSCIF_SCSCR_HW_INIT	((uint16_t)(0x0000U))
/* HSCIF0 base address */
#define HSCIF0_BASE     (0xC0710000U)

#define HSCIF_HSSMR  (HSCIF0_BASE + 0x0000U) /* 16 Serial mode register */
#define HSCIF_HSBRR  (HSCIF0_BASE + 0x0004U) /* 8  Bit rate register */
#define HSCIF_HSSCR  (HSCIF0_BASE + 0x0008U) /* 16 Serial control register */
#define HSCIF_HSFTDR (HSCIF0_BASE + 0x000CU) /* 8 Transmit FIFO data register */
#define HSCIF_HSFSR  (HSCIF0_BASE + 0x0010U) /*  16  Serial status register */
#define HSCIF_HSFCR  (HSCIF0_BASE + 0x0018U) /*  16  FIFO control register */
#define HSCIF_HSFDR  (HSCIF0_BASE + 0x001CU) /*  16  FIFO Data count register */
#define HSCIF_HSLSR  (HSCIF0_BASE + 0x0024U) /*  16  Line status register */
#define HSCIF_DL    (HSCIF0_BASE + 0x0030U) /* 16 Frequency division register */
#define HSCIF_CKS    (HSCIF0_BASE + 0x0034U) /*  16  Clock Select register */
#define HSCIF_HSSRR  (HSCIF0_BASE + 0x0040U) /*  16  Sampling rate register */

/*Define some macro after enable mmu*/
#define HSCIF_HSFDR_OFFSET     (0x001CU) /*  16  FIFO Data count register */
#define HSCIF_HSFTDR_OFFSET    (0x000CU) /*  8   Transmit FIFO data register */
#endif /* HSCIF_REGISTER_H_ */
