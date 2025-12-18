/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Renesas Electronics Corporation.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#define RCAR_CACHE_LINE_SZ		64
#define CFG_RCAR_GEN5   1

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		RCAR_CACHE_LINE_SZ

#if defined(CFG_RCAR_GEN5)
#define GICD_BASE              0x38000000
#define GICR_BASE              0x38080000

#if CFG_RCAR_UART == 200	/* HSCIF0 */
#define CONSOLE_UART_START	0xC0710000
#endif
/* config for MMU mapping */
#define RCAR_SRAM_BASE		    0x8C300000U
#define TZDRAM_BASE             RCAR_SRAM_BASE
#define TZDRAM_SIZE             (0x02000000U) /* 1024*1024*32 */

#define CFG_TEE_RAM_VA_SIZE         (1024 * 1024 * 3) /* = 300000*/
#define TEE_RAM_START     (0x8C400000)  /* TEE RAM address */
#define TEE_RAM_SIZE      (0x00300000U) /* TEE RAM size*/

#ifdef CFG_TEE_RAM_VA_SIZE
#ifdef CFG_WITH_PAGER
#define TEE_RAM_PH_SIZE		TZSRAM_SIZE
#else
#define TEE_RAM_PH_SIZE		TEE_RAM_SIZE
#endif
#endif

#ifndef TEE_LOAD_ADDR
#define TEE_LOAD_ADDR   TEE_RAM_START
#endif

#define TA_RAM_START            (RCAR_SRAM_BASE	\
				  + 0x400000U)   /* TA RAM address */
#define TA_RAM_SIZE             (0x01400000U)	/* TA RAM size */

#define TEE_SHMEM_START         (RCAR_SRAM_BASE	\
				  + 0x3E00000U) /* Share Memory address */
#define TEE_SHMEM_SIZE          (0x00100000U) /* Share Memory size    */

#define OPTEE_LOG_BASE          (RCAR_SRAM_BASE	\
				  + 0x1E00000U) /* OP-TEE Log Area address */
#define OPTEE_LOG_NS_BASE       (RCAR_SRAM_BASE	\
				  + 0x3F00000U) /* OP-TEE Log Area NS addr */
#define OPTEE_LOG_NS_SIZE       (0x00014000U)   /* OP-TEE Log Area NS size */

#define TA_VERIFICATION_BASE    (RCAR_SRAM_BASE	\
				  + 0x1800000U) /* TA area for verification */
#define TA_VERIFICATION_SIZE    (0x00100000U)   /* TA for verification size */

#define NONCACHE_WORK_BASE      (RCAR_SRAM_BASE	\
				 + 0x1F00000U) /* Non Cache Area address   */
#define NONCACHE_WORK_SIZE      (0x00100000U)   /* Non Cache Area Size  */

#define RSIPM_FW_SHMEM_BASE    (0x41C00000U) /* RSIPM FW Share Memory address */
#define RSIPM_FW_SHMEM_SIZE    (0x00100000U) /* RSIPM FW Share Memory size */

/* for Soc Register mapping function */
#define MAP_DEVICE_REG_RCAR_BASE	(0xC0400000)
#define MAP_DEVICE_REG_RCAR_SIZE	(0x1FC00000)

#define LIFEC_BASE              (0x1C020000)    /* Life Cycle address   */
#define PRR_BASE                (0xFFF00000U)   /* Product Register address */
#define MFIS_BASE               (0x18800000U)   /* MFIS address */

#define MEM_SECTION_SIZE        (0x00100000U)
#ifdef CFG_WITH_LPAE
#define MAX_XLAT_TABLES         CFG_MMAP_REGIONS
#endif

#define DEVICE0_PA_BASE	ROUNDDOWN(LIFEC_BASE, CORE_MMU_PGDIR_SIZE)
#define DEVICE0_SIZE		(MEM_SECTION_SIZE)
#define DEVICE0_TYPE		MEM_AREA_IO_SEC

#define DEVICE1_PA_BASE		ROUNDDOWN(GICD_BASE, CORE_MMU_PGDIR_SIZE)
#define DEVICE1_SIZE		(MEM_SECTION_SIZE * 9)
#define DEVICE1_TYPE		MEM_AREA_IO_SEC

/* LOG Area for Secure World */
#define MEMORY1_BASE		ROUNDDOWN(OPTEE_LOG_BASE, MEM_SECTION_SIZE)
#define MEMORY1_SIZE		(MEM_SECTION_SIZE)
#define MEMORY1_TYPE		MEM_AREA_IO_SEC

/* LOG Area for Normal World */
#define MEMORY2_BASE           ROUNDDOWN(OPTEE_LOG_NS_BASE, MEM_SECTION_SIZE)
#define MEMORY2_SIZE		(OPTEE_LOG_NS_SIZE)
#define MEMORY2_TYPE		MEM_AREA_RAM_NSEC

/* HSCIF address map area */
#define MEMORY3_BASE           ROUNDDOWN(MAP_DEVICE_REG_RCAR_BASE, \
					MAP_DEVICE_REG_RCAR_SIZE)
#define MEMORY3_SIZE           (MAP_DEVICE_REG_RCAR_SIZE)
#define MEMORY3_TYPE           MEM_AREA_IO_SEC

/* TA area for verification */
#define MEMORY4_BASE		ROUNDDOWN(TA_VERIFICATION_BASE, \
					MEM_SECTION_SIZE)
#define MEMORY4_SIZE		(TA_VERIFICATION_SIZE)
#define MEMORY4_TYPE		MEM_AREA_IO_SEC

/* Product Register (PRR) */
#define MEMORY5_BASE		ROUNDDOWN(PRR_BASE, MEM_SECTION_SIZE)
#define MEMORY5_SIZE		(MEM_SECTION_SIZE)
#define MEMORY5_TYPE		MEM_AREA_IO_SEC

/* Non Cache Stack Area */
#define MEMORY6_BASE           ROUNDDOWN(NONCACHE_WORK_BASE, \
					MEM_SECTION_SIZE)
#define MEMORY6_SIZE		(MEM_SECTION_SIZE)
#define MEMORY6_TYPE		MEM_AREA_IO_SEC

/* ICU FW Share Memory Address Map */
#define MEMORY7_BASE		ROUNDDOWN(RSIPM_FW_SHMEM_BASE, MEM_SECTION_SIZE)
#define MEMORY7_SIZE		(RSIPM_FW_SHMEM_SIZE)
#define MEMORY7_TYPE		MEM_AREA_IO_SEC

/* MFIS Address Map */
#define MEMORY8_BASE		ROUNDDOWN(MFIS_BASE, MEM_SECTION_SIZE)
#define MEMORY8_SIZE		(MEM_SECTION_SIZE)
#define MEMORY8_TYPE		MEM_AREA_IO_SEC
#endif	/* CFG_RCAR_GEN5 */

#endif /*PLATFORM_CONFIG_H*/
