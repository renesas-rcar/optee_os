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
 * Copyright (c) 2021, Renesas Electronics Corporation.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define GICC_BASE		0xF1060000U
#define GICD_BASE		0xF1000000U

/*
 * Last part of DRAM is reserved as secure dram, note that the last 2MiB
 * of DRAM0 is used by SCP dor DDR retraining.
 */
#define TZDRAM_BASE		(0x44000000U)

/*
 * Should be
 * #define TZDRAM_SIZE		0x00FF8000
 * but is smaller due to SECTION_SIZE alignment, can be fixed once
 * OP-TEE OS is mapped using small pages instead.
 */
#define TZDRAM_SIZE		(0x02400000U)

#define TEE_RAM_VA_SIZE		(1024 * 1024 * 3)

#define TEE_RAM_START		(0x44100000)	/* TEE RAM address	*/
#define TEE_RAM_PH_SIZE		(0x00300000U)	/* TEE RAM size		*/

#define TA_RAM_START		(0x44400000U)	/* TA RAM address	*/
#define TA_RAM_SIZE		(0x01800000U)	/* TA RAM size		*/

#define TEE_SHMEM_START		(0x47E00000U)	/* Share Memory address	*/
#define TEE_SHMEM_SIZE		(0x00100000U)	/* Share Memory size	*/

#define OPTEE_LOG_BASE		(0x45E00000U)	/* OP-TEE Log Area address */
#define OPTEE_LOG_NS_BASE	(0x47FEC000U)	/* OP-TEE Log Area NS addr */
#define OPTEE_LOG_NS_SIZE	(0x00014000U)   /* OP-TEE Log Area NS size */

#define TA_VERIFICATION_BASE	(0x45C00000U)	/* TA area for verification */
#define TA_VERIFICATION_SIZE	(0x00100000U)	/* TA verification size */
#define CRYPTOENGINE_WORK_BASE	(0x46000000U)	/* Crypto Enegine Work area */

#define NONCACHE_WORK_BASE	(0x45F00000U)	/* Non Cache Area address */
#define NONCACHE_WORK_SIZE	(0x00100000U)	/* Non Cache Area Size */

#define LIFEC_BASE		(0xE6110000U)	/* Life Cycle address	*/
#define RST_BASE		(0xE6160000U)	/* Reset address	*/
#define CE_BASE			(0xE6600000U)	/* Crypto Engine address */
#define RPC_BASE		(0xEE200000U)	/* RPC address		*/
#define PRR_BASE		(0xFFF00000U)	/* Product Register address */
#define RPC_ADDR_MAP_BASE	(0x08000000U)	/* RPC Internal address	*/
#define RPC_ADDR_MAP_SIZE	(0x04000000U)	/* RPC Address Map size */

#define MEM_SECTION_SIZE	(0x00100000U)

#if defined(PLATFORM_FLAVOR_salvator_h3)
#define NSEC_DDR_0_BASE		0x47E00000
#define NSEC_DDR_0_SIZE		0x38200000
#define NSEC_DDR_1_BASE		0x500000000U
#define NSEC_DDR_1_SIZE		0x40000000
#define NSEC_DDR_2_BASE		0x600000000U
#define NSEC_DDR_2_SIZE		0x40000000
#define NSEC_DDR_3_BASE		0x700000000U
#define NSEC_DDR_3_SIZE		0x40000000

#elif defined(PLATFORM_FLAVOR_salvator_h3_4x2g)
#define NSEC_DDR_0_BASE		0x47E00000
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x500000000U
#define NSEC_DDR_1_SIZE		0x80000000U
#define NSEC_DDR_2_BASE		0x600000000U
#define NSEC_DDR_2_SIZE		0x80000000U
#define NSEC_DDR_3_BASE		0x700000000U
#define NSEC_DDR_3_SIZE		0x80000000U

#elif defined(PLATFORM_FLAVOR_salvator_m3)
#define NSEC_DDR_0_BASE		0x47E00000
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x600000000U
#define NSEC_DDR_1_SIZE		0x80000000U

#elif defined(PLATFORM_FLAVOR_salvator_m3_2x4g)
#define NSEC_DDR_0_BASE		0x47E00000
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x400000000U
#define NSEC_DDR_1_SIZE		0x80000000U
#define NSEC_DDR_2_BASE		0x600000000U
#define NSEC_DDR_2_SIZE		0x100000000U

#else

/* Generic DT-based platform */

#endif

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

#endif /*PLATFORM_CONFIG_H*/
