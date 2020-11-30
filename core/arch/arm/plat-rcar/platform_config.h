/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015-2020, Renesas Electronics Corporation
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		(64)

#define GIC_BASE		(0xF1000000U)
#define GIC_SIZE		(0x00100000U)

#define DRAM0_BASE		(0x44000000U)
#define DRAM0_SIZE		(0x04000000U)

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
#define TZDRAM_SIZE		(0x03E00000U)

#define GICC_OFFSET		(0x20000)
#define GICD_OFFSET		(0x10000)

#define TEE_RAM_VA_SIZE		(1024 * 1024 * 3)

#ifndef TEE_LOAD_ADDR
#define TEE_LOAD_ADDR		TEE_RAM_START
#endif

#define TEE_RAM_START		(0x44100000)	/* TEE RAM address	*/
#define TEE_RAM_PH_SIZE		(0x00300000U)	/* TEE RAM size		*/

#define TA_RAM_START		(0x44400000U)	/* TA RAM address	*/
#define TA_RAM_SIZE		(0x01E00000U)	/* TA RAM size		*/

#define TEE_SHMEM_START		(0x47E00000U)	/* Share Memory address	*/
#define TEE_SHMEM_SIZE		(0x00100000U)	/* Share Memory size	*/

#define OPTEE_LOG_BASE		(0x46400000U)	/* OP-TEE Log Area address */
#define OPTEE_LOG_NS_BASE	(0x47FEC000U)	/* OP-TEE Log Area NS address */
#define OPTEE_LOG_NS_SIZE	(0x00014000U)   /* OP-TEE Log Area NS size */

#define TA_VERIFICATION_BASE	(0x46200000U)	/* TA area for verification */
#define TA_VERIFICATION_SIZE	(0x00100000U)	/* TA verification size */
#define CRYPTOENGINE_WORK_BASE	(0x46600000U)	/* Crypto Enegine Work area */

#define NONCACHE_WORK_BASE	(0x46500000U)	/* Non Cache Area address */
#define NONCACHE_WORK_SIZE	(0x00100000U)	/* Non Cache Area Size */

#define SYSWDT_BASE		(0xE6030000U)	/* System WDT address	*/
#define SYSTIM_BASE		(0xE6040000U)	/* System Timer address	*/
#define LIFEC_BASE		(0xE6110000U)	/* Life Cycle address	*/
#define RST_BASE		(0xE6160000U)	/* Reset address	*/
#define SYSUTC_BASE		(0xE61D0000U)	/* System Up Time Clock */
#define MFIS_BASE		(0xE6260000U)	/* MFIS address		*/
#define CE_BASE			(0xE6600000U)	/* Crypto Engine Secure address	*/
#define PKA_BASE		(0xE6602000U)	/* Crypto Engine PKA address */
#define DBSC_BASE		(0xE6790000U)	/* DBSC address		*/
#define CPG_BASE		(0xE6B10000U)	/* CPG address		*/
#define SYSDMAC2_BASE		(0xE7310000U)	/* SYS-DMAC2 address	*/
#define SRAM_BASE		(0xE6300000U)	/* System RAM address	*/
#define ROMAPI_BASE		(0xEB100000U)	/* MaskROM API address	*/
#define RPC_BASE		(0xEE200000U)	/* RPC address		*/
#define PRR_BASE		(0xFFF00000U)	/* Product Register address */
#define RPC_ADDR_MAP_BASE	(0x08000000U)	/* RPC Internal address	*/
#define RPC_ADDR_MAP_SIZE	(0x04000000U)	/* RPC Address Map size */

#define MEM_SECTION_SIZE	(0x00100000U)

#ifdef CFG_WITH_LPAE
#define MAX_XLAT_TABLES		CFG_MMAP_REGIONS
#endif

#define OPTEE_LIMIT		(TEE_RAM_START + 0x00100000)

#define DEVICE0_PA_BASE		ROUNDDOWN(SYSWDT_BASE, CORE_MMU_PGDIR_SIZE)
#define DEVICE0_VA_BASE		DEVICE0_PA_BASE
#define DEVICE0_SIZE		(MEM_SECTION_SIZE * 3)
#define DEVICE0_TYPE		MEM_AREA_IO_SEC

#define DEVICE1_PA_BASE		ROUNDDOWN(CE_BASE, CORE_MMU_PGDIR_SIZE)
#define DEVICE1_VA_BASE		DEVICE1_PA_BASE
#define DEVICE1_SIZE		(MEM_SECTION_SIZE * 2)
#define DEVICE1_TYPE		MEM_AREA_IO_SEC

#define DEVICE2_PA_BASE		ROUNDDOWN(CPG_BASE, CORE_MMU_PGDIR_SIZE)
#define DEVICE2_VA_BASE		DEVICE2_PA_BASE
#define DEVICE2_SIZE		(MEM_SECTION_SIZE * 9)
#define DEVICE2_TYPE		MEM_AREA_IO_NSEC

#define GICD_BASE		(GIC_BASE + GICD_OFFSET)
#define GICC_BASE		(GIC_BASE + GICC_OFFSET)

#define DEVICE3_PA_BASE		ROUNDDOWN(GIC_BASE, CORE_MMU_PGDIR_SIZE)
#define DEVICE3_VA_BASE		DEVICE3_PA_BASE
#define DEVICE3_SIZE		(MEM_SECTION_SIZE)
#define DEVICE3_TYPE		MEM_AREA_IO_SEC

/* LOG Area for Secure World */
#define MEMORY1_BASE		ROUNDDOWN(OPTEE_LOG_BASE, MEM_SECTION_SIZE)
#define MEMORY1_SIZE		(MEM_SECTION_SIZE)
#define MEMORY1_TYPE		MEM_AREA_IO_SEC

/* LOG Area for Normal World */
#define MEMORY2_BASE		(OPTEE_LOG_NS_BASE)
#define MEMORY2_SIZE		(OPTEE_LOG_NS_SIZE)
#define MEMORY2_TYPE		MEM_AREA_RAM_NSEC

/* System RAM */
#define MEMORY3_BASE		ROUNDDOWN(SRAM_BASE, MEM_SECTION_SIZE)
#define MEMORY3_SIZE		(MEM_SECTION_SIZE)
#define MEMORY3_TYPE		MEM_AREA_IO_SEC

/* Crypto Engine Work area */
#define MEMORY4_BASE		ROUNDDOWN(CRYPTOENGINE_WORK_BASE, \
					MEM_SECTION_SIZE)
#define MEMORY4_SIZE		(MEM_SECTION_SIZE)
#define MEMORY4_TYPE		MEM_AREA_RAM_SEC

/* TA area for verification */
#define MEMORY5_BASE		ROUNDDOWN(TA_VERIFICATION_BASE, \
					MEM_SECTION_SIZE)
#define MEMORY5_SIZE		(TA_VERIFICATION_SIZE)
#define MEMORY5_TYPE		MEM_AREA_IO_SEC

/* MaskROM API */
#define MEMORY6_BASE		ROUNDDOWN(ROMAPI_BASE, MEM_SECTION_SIZE)
#define MEMORY6_SIZE		(MEM_SECTION_SIZE)
#define MEMORY6_TYPE		MEM_AREA_TEE_COHERENT

/* Product Register (PRR) */
#define MEMORY7_BASE		ROUNDDOWN(PRR_BASE, MEM_SECTION_SIZE)
#define MEMORY7_SIZE		(MEM_SECTION_SIZE)
#define MEMORY7_TYPE		MEM_AREA_IO_SEC

/* Non Cache Stack Area */
#define MEMORY8_BASE		ROUNDDOWN(NONCACHE_WORK_BASE, NONCACHE_WORK_SIZE)
#define MEMORY8_SIZE		(MEM_SECTION_SIZE)
#define MEMORY8_TYPE		MEM_AREA_IO_SEC

/* SPI Multi I/O Bus Controller (RPC) */
#define MEMORY9_BASE		ROUNDDOWN(RPC_BASE, MEM_SECTION_SIZE)
#define MEMORY9_SIZE		(MEM_SECTION_SIZE)
#define MEMORY9_TYPE		MEM_AREA_IO_SEC

/* RPC Address Map */
#define MEMORY10_BASE		ROUNDDOWN(RPC_ADDR_MAP_BASE, MEM_SECTION_SIZE)
#define MEMORY10_SIZE		(RPC_ADDR_MAP_SIZE)
#define MEMORY10_TYPE		MEM_AREA_IO_SEC

#endif /*PLATFORM_CONFIG_H*/
