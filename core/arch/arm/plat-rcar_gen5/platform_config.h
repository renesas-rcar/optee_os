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
#define GICD_BASE              0x39000000
#define GICR_BASE              0x39080000

#if CFG_RCAR_UART == 200	/* HSCIF0 */
#define CONSOLE_UART_START	0xC0710000
#endif
/* config for MMU mapping */
#define RCAR_SRAM_BASE		    0x8C400000
#define TZDRAM_BASE             RCAR_SRAM_BASE
#define TZDRAM_SIZE             (0x02000000U) /* 1024*1024*32 */

#define TEE_RAM_START     (RCAR_SRAM_BASE)  /* TEE RAM address */
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

#define TA_RAM_START            (TEE_RAM_START	\
				  + TEE_RAM_SIZE)   /* TA RAM address */
#define TA_RAM_SIZE             (0x01400000U)	/* TA RAM size */
#define OPTEE_LOG_BASE          (TA_RAM_START	\
				  + TA_RAM_SIZE) /* OP-TEE Log Area address */
#define OPTEE_LOG_SIZE		(0x900000U)	/* OP-TEE Log Area address size */
#define NONCACHE_WORK_BASE      (OPTEE_LOG_BASE	\
				 + OPTEE_LOG_SIZE) /* Non Cache Area address   */
#define NONCACHE_WORK_SIZE      (0x00100000U)   /* Non Cache Area Size  */
#define TEE_SHMEM_START         (NONCACHE_WORK_BASE	\
				  + 0x1D00000U) /* Share Memory address */
#define TEE_SHMEM_SIZE          (0x00100000U) /* Share Memory size    */
#define OPTEE_LOG_NS_BASE       (TEE_SHMEM_START	\
				  + TEE_SHMEM_SIZE) /* OP-TEE Log Area NS addr */
#define OPTEE_LOG_NS_SIZE       (0x00014000U)   /* OP-TEE Log Area NS size */

#define TA_VERIFICATION_BASE    (0x10100000U)	/* TA for verification addr */
#define TA_VERIFICATION_SIZE    (0x00100000U)   /* TA for verification size */

#define RSIPM_FW_SHMEM_BASE    (0x18500000U) /* RSIPM FW Share Memory address */
#define RSIPM_FW_SHMEM_SIZE    (0x00100000U) /* RSIPM FW Share Memory size */

#define SYSSS_MAIN_REGION_0_BASE	(0xC1320000)

/* for Soc Register mapping function */
#define MAP_DEVICE_REG_RCAR_BASE	(0xC0400000)
#define MAP_DEVICE_REG_RCAR_SIZE	(0x1FC00000)

#define LIFEC_BASE              (0x1C020000)    /* Life Cycle address   */
#define MFIS_BASE               (0x189E0000U)   /* MFIS address */
/*
 * Product Register address (R-Car Gen5: located inside MFIS).
 * Reserved for future use: not read by OP-TEE yet, kept for identifying
 * the product/cut when multiple Gen5 boards/SoCs need different handling.
 */
#define PRR_BASE                (MFIS_BASE + 0x44U)

#define MEM_SECTION_SIZE        (0x00100000U)
#define MEM_SECTION_MFIS_SIZE	(0x00010000U)
#ifdef CFG_WITH_LPAE
#define MAX_XLAT_TABLES         CFG_MMAP_REGIONS
#endif

#define DEVICE0_PA_BASE	ROUNDDOWN(LIFEC_BASE, CORE_MMU_PGDIR_SIZE)
#define DEVICE0_SIZE		(MEM_SECTION_SIZE)
#define DEVICE0_TYPE		MEM_AREA_IO_SEC
#define DEVICE0_PA_END          (LIFEC_BASE + DEVICE0_SIZE)

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
#define MEMORY3_PA_END         (MAP_DEVICE_REG_RCAR_BASE + MEMORY3_SIZE)

/* TA area for verification */
#define MEMORY4_BASE		ROUNDDOWN(TA_VERIFICATION_BASE, \
					MEM_SECTION_SIZE)
#define MEMORY4_SIZE		(TA_VERIFICATION_SIZE)
#define MEMORY4_TYPE		MEM_AREA_IO_SEC

/* Non Cache Stack Area */
#define MEMORY5_BASE           ROUNDDOWN(NONCACHE_WORK_BASE, \
					MEM_SECTION_SIZE)
#define MEMORY5_SIZE		(MEM_SECTION_SIZE)
#define MEMORY5_TYPE		MEM_AREA_IO_SEC

/* RSIPM Share Memory Address Map */
#define MEMORY6_BASE		ROUNDDOWN(RSIPM_FW_SHMEM_BASE, MEM_SECTION_SIZE)
#define MEMORY6_SIZE		(RSIPM_FW_SHMEM_SIZE)
#define MEMORY6_TYPE		MEM_AREA_IO_SEC

/* MFIS Address Map */
#define MEMORY7_BASE		ROUNDDOWN(MFIS_BASE, MEM_SECTION_MFIS_SIZE)
#define MEMORY7_SIZE		(MEM_SECTION_SIZE)
#define MEMORY7_TYPE		MEM_AREA_IO_SEC
#define MEMORY7_PA_END		(MFIS_BASE + MEMORY7_SIZE)

#define OPTEE_LDR_RING_BASE		UL(0x8C148000)
#define OPTEE_LDR_RING_SIZE		UL(0x0003FE00)

#define MEMORY8_BASE			ROUNDDOWN(OPTEE_LDR_RING_BASE, \
						MEM_SECTION_SIZE)
#define MEMORY8_SIZE                    OPTEE_LDR_RING_SIZE
#define MEMORY8_TYPE			MEM_AREA_IO_SEC

#endif  /* CFG_RCAR_GEN5 */

#endif /*PLATFORM_CONFIG_H*/
