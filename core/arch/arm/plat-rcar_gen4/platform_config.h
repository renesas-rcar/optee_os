/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, GlobalLogic
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright (c) 2021-2024, Renesas Electronics Corporation.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

/* Region-ID helper macros */
#ifndef CFG_RCAR_RGID_ENABLE
#define CFG_RCAR_RGID	0
#else
#define CFG_RCAR_RGID	2
#endif

#define ADDR_RGID(a)                    (((a) & 0xF) * 0x1000000000)
#define ADDR_RGID_MASK                  (0x000000F000000000)
#define ADDR_PA_MASK                    (0x0000000FFFFFFFFF)
#define ADDR_ASSIGN_RGID(a,b)           (((a) & ADDR_PA_MASK) | (ADDR_RGID(b) & ADDR_RGID_MASK))

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define GICC_BASE		ADDR_ASSIGN_RGID(0xF1060000U,CFG_RCAR_RGID)
#define GICD_BASE		ADDR_ASSIGN_RGID(0xF1000000U,CFG_RCAR_RGID)

#if CFG_RCAR_UART == 200        /* HSCIF0 */
#define CONSOLE_UART_START      ADDR_ASSIGN_RGID(0xE6540000, CFG_RCAR_RGID)
#endif

/*
 * Last part of DRAM is reserved as secure dram, note that the last 2MiB
 * of DRAM0 is used by SCP dor DDR retraining.
 */
#define TZDRAM_BASE		ADDR_ASSIGN_RGID(0x44000000U,CFG_RCAR_RGID)

/*
 * Should be
 * #define TZDRAM_SIZE		0x00FF8000
 * but is smaller due to SECTION_SIZE alignment, can be fixed once
 * OP-TEE OS is mapped using small pages instead.
 */
#define TZDRAM_SIZE		(0x02400000U)

#define TEE_RAM_VA_SIZE		(1024 * 1024 * 3)

#define TEE_RAM_START		ADDR_ASSIGN_RGID(0x44100000,CFG_RCAR_RGID)	/* TEE RAM address	*/
#define TEE_RAM_PH_SIZE		(0x00300000U)	/* TEE RAM size		*/

#define TA_RAM_START		ADDR_ASSIGN_RGID(0x44400000U,CFG_RCAR_RGID)	/* TA RAM address	*/
#define TA_RAM_SIZE		(0x01800000U)	/* TA RAM size		*/

#define TEE_SHMEM_START		ADDR_ASSIGN_RGID(0x47E00000U,CFG_RCAR_RGID)	/* Share Memory address	*/
#define TEE_SHMEM_SIZE		(0x00100000U)	/* Share Memory size	*/

#define OPTEE_LOG_BASE		ADDR_ASSIGN_RGID(0x45E00000U,CFG_RCAR_RGID)	/* OP-TEE Log Area address */
#define OPTEE_LOG_NS_BASE	ADDR_ASSIGN_RGID(0x46440000U,CFG_RCAR_RGID)	/* OP-TEE Log Area NS addr */
#define OPTEE_LOG_NS_SIZE	(0x00014000U)   /* OP-TEE Log Area NS size */

#define TA_VERIFICATION_BASE	ADDR_ASSIGN_RGID(0x41E00000U,CFG_RCAR_RGID)	/* TA area for verification */
#define TA_VERIFICATION_SIZE	(0x00100000U)	/* TA verification size */
#define CRYPTOENGINE_WORK_BASE	ADDR_ASSIGN_RGID(0x46000000U,CFG_RCAR_RGID)	/* Crypto Enegine Work area */

#define NONCACHE_WORK_BASE	ADDR_ASSIGN_RGID(0x45F00000U,CFG_RCAR_RGID)	/* Non Cache Area address */
#define NONCACHE_WORK_SIZE	(0x00100000U)	/* Non Cache Area Size */

#define ICU_FW_SHMEM_BASE	ADDR_ASSIGN_RGID(0x41C00000U,CFG_RCAR_RGID)	/* ICU FW Share Memory address */
#define ICU_FW_SHMEM_SIZE	(0x00100000U)	/* ICU FW Share Memory size */

#define LIFEC_BASE		ADDR_ASSIGN_RGID(0xE6110000U,CFG_RCAR_RGID) 	/* Life Cycle address	*/
#define RST_BASE		ADDR_ASSIGN_RGID(0xE6160000U,CFG_RCAR_RGID) 	/* Reset address	*/
#define CE_BASE			ADDR_ASSIGN_RGID(0xE6600000U,CFG_RCAR_RGID) 	/* Crypto Engine address */
#define RPC_BASE		ADDR_ASSIGN_RGID(0xEE200000U,CFG_RCAR_RGID) 	/* RPC address		*/
#define PRR_BASE		ADDR_ASSIGN_RGID(0xFFF00000U,CFG_RCAR_RGID) 	/* Product Register address */
#define MFIS_BASE		ADDR_ASSIGN_RGID(0xE6260000U,CFG_RCAR_RGID) 	/* MFIS address */
#define RPC_ADDR_MAP_BASE	ADDR_ASSIGN_RGID(0x08000000U,CFG_RCAR_RGID)	/* RPC Internal address	*/
#define RPC_ADDR_MAP_SIZE	(0x04000000U)	/* RPC Address Map size */
#define EXTERNAL_FLASH_ADDR	(0x00340000u)	/* ICU FW external flash memory address */

/* for HSCIF Register mapping function */
#define HSCIF_BASE        ADDR_ASSIGN_RGID(0xE6540000, CFG_RCAR_RGID)
#define HSCIF_SIZE        (0x00020000)

#define CPG_BASE        (LIFEC_BASE + 0x40000U)		/* 0xE6150000U */
#define CPG_SIZE        (0x00020000)

#define MEM_SECTION_SIZE	(0x00100000U)

#ifdef CFG_WITH_LPAE
/* Maximum number of memory mapping by MMU */
#define MAX_XLAT_TABLES		CFG_MMAP_REGIONS
#endif

#ifdef CFG_CORE_DYN_SHM
#define NSEC_DDR_0_BASE		ADDR_ASSIGN_RGID(0x48000000,CFG_RCAR_RGID)
#define NSEC_DDR_0_SIZE		0x78000000
#define NSEC_DDR_1_BASE		ADDR_ASSIGN_RGID(0x480000000U,CFG_RCAR_RGID)
#define NSEC_DDR_1_SIZE		0x80000000U
#endif

// #define DEVICE0_PA_BASE		ROUNDDOWN(LIFEC_BASE, CORE_MMU_PGDIR_SIZE)
#define DEVICE0_PA_BASE		LIFEC_BASE
#define DEVICE0_SIZE		(MEM_SECTION_SIZE)
#define DEVICE0_TYPE		MEM_AREA_IO_SEC

#define DEVICE1_PA_BASE		ROUNDDOWN(CE_BASE, CORE_MMU_PGDIR_SIZE)
#define DEVICE1_SIZE		(MEM_SECTION_SIZE * 2)
#define DEVICE1_TYPE		MEM_AREA_IO_SEC

#define DEVICE2_PA_BASE		ROUNDDOWN(GICD_BASE, CORE_MMU_PGDIR_SIZE)
#define DEVICE2_SIZE		(MEM_SECTION_SIZE)
#define DEVICE2_TYPE		MEM_AREA_IO_SEC

/* LOG Area for Secure World */
#define MEMORY1_BASE		ROUNDDOWN(OPTEE_LOG_BASE, MEM_SECTION_SIZE)
#define MEMORY1_SIZE		(MEM_SECTION_SIZE)
#define MEMORY1_TYPE		MEM_AREA_IO_SEC

/* LOG Area for Normal World */
#define MEMORY2_BASE		(OPTEE_LOG_NS_BASE)
#define MEMORY2_SIZE		(OPTEE_LOG_NS_SIZE)
#define MEMORY2_TYPE		MEM_AREA_RAM_NSEC

/* Crypto Engine Work area */
#define MEMORY3_BASE		ROUNDDOWN(CRYPTOENGINE_WORK_BASE, \
					MEM_SECTION_SIZE)
#define MEMORY3_SIZE		(MEM_SECTION_SIZE)
#define MEMORY3_TYPE		MEM_AREA_RAM_SEC

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
#define MEMORY6_BASE		ROUNDDOWN(NONCACHE_WORK_BASE, \
					NONCACHE_WORK_SIZE)
#define MEMORY6_SIZE		(MEM_SECTION_SIZE)
#define MEMORY6_TYPE		MEM_AREA_IO_SEC

/* SPI Multi I/O Bus Controller (RPC) */
#define MEMORY7_BASE		ROUNDDOWN(RPC_BASE, MEM_SECTION_SIZE)
#define MEMORY7_SIZE		(MEM_SECTION_SIZE)
#define MEMORY7_TYPE		MEM_AREA_IO_SEC

/* RPC Address Map */
#define MEMORY8_BASE		ROUNDDOWN(RPC_ADDR_MAP_BASE, MEM_SECTION_SIZE)
#define MEMORY8_SIZE		(RPC_ADDR_MAP_SIZE)
#define MEMORY8_TYPE		MEM_AREA_IO_SEC

/* ICU FW Share Memory Address Map */
#define MEMORY9_BASE		ROUNDDOWN(ICU_FW_SHMEM_BASE, MEM_SECTION_SIZE)
#define MEMORY9_SIZE		(ICU_FW_SHMEM_SIZE)
#define MEMORY9_TYPE		MEM_AREA_IO_SEC

/* MFIS Address Map */
#define MEMORY10_BASE		ROUNDDOWN(MFIS_BASE, MEM_SECTION_SIZE)
#define MEMORY10_SIZE		(MEM_SECTION_SIZE)
#define MEMORY10_TYPE		MEM_AREA_IO_SEC

/* HSCIF Address Map */
#define MEMORY11_BASE		ROUNDDOWN(HSCIF_BASE, HSCIF_SIZE)
#define MEMORY11_SIZE		HSCIF_SIZE
#define MEMORY11_TYPE           MEM_AREA_IO_SEC

/* Settings to wait for completion of Crypto Engine */
/* The followings are used by DX_HAL_WaitInterrupt */

/* Time until polling times out [msec] */
#define HAL_TIMEOUT  600U
/* Time until polling is suspended by a RPC command [msec] */
#define HAL_DELAYTIME 10U
/* Time when polling is temporarily suspended in Normal World [msec] */
#define HAL_WAITTIME 500U

#endif /*PLATFORM_CONFIG_H*/
