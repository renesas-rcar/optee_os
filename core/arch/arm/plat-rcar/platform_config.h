/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
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

#define CFG_TEE_CORE_NB_CORE	(8)

#define GICC_OFFSET		(0x20000)
#define GICD_OFFSET		(0x10000)

#ifndef CFG_CRYPT_HW_CRYPTOENGINE
#define CFG_TEE_RAM_VA_SIZE	(1024 * 1024)
#else
#define CFG_TEE_RAM_VA_SIZE	(1024 * 1024 * 3)
#endif

#ifndef CFG_TEE_LOAD_ADDR
#define CFG_TEE_LOAD_ADDR	CFG_TEE_RAM_START
#endif

#define CFG_TEE_RAM_START	(0x44100000)	/* TEE RAM address	*/
#ifndef CFG_CRYPT_HW_CRYPTOENGINE
#define CFG_TEE_RAM_PH_SIZE	(0x00100000U)	/* TEE RAM size		*/
#else
#define CFG_TEE_RAM_PH_SIZE	(0x00300000U)	/* TEE RAM size		*/
#endif

#ifndef CFG_CRYPT_HW_CRYPTOENGINE
#define CFG_TA_RAM_START	(0x44200000U)	/* TA RAM address	*/
#define CFG_TA_RAM_SIZE		(0x02000000U)	/* TA RAM size		*/
#else
#define CFG_TA_RAM_START	(0x44400000U)	/* TA RAM address	*/
#define CFG_TA_RAM_SIZE		(0x01E00000U)	/* TA RAM size		*/
#endif

#define CFG_SHMEM_START		(0x47E00000U)	/* Share Memory address	*/
#define CFG_SHMEM_SIZE		(0x00100000U)	/* Share Memory size	*/

#define OPTEE_LOG_BASE		(0x46400000U)	/* OP-TEE Log Area address */
#define OPTEE_LOG_NS_BASE	(0x47FEC000U)	/* OP-TEE Log Area NS address */

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

#define MAX_MMAP_REGIONS	(17)

#ifdef CFG_WITH_LPAE
#define MAX_XLAT_TABLES		MAX_MMAP_REGIONS
#endif

#define DEVICE0_PA_BASE		ROUNDDOWN(SYSWDT_BASE, CORE_MMU_DEVICE_SIZE)
#define DEVICE0_VA_BASE		DEVICE0_PA_BASE
#define DEVICE0_SIZE		(MEM_SECTION_SIZE * 3)
#define DEVICE0_TYPE		MEM_AREA_IO_SEC

#define DEVICE1_PA_BASE		ROUNDDOWN(CE_BASE, CORE_MMU_DEVICE_SIZE)
#define DEVICE1_VA_BASE		DEVICE1_PA_BASE
#define DEVICE1_SIZE		(MEM_SECTION_SIZE * 2)
#define DEVICE1_TYPE		MEM_AREA_IO_SEC

#define DEVICE2_PA_BASE		ROUNDDOWN(CPG_BASE, CORE_MMU_DEVICE_SIZE)
#define DEVICE2_VA_BASE		DEVICE2_PA_BASE
#define DEVICE2_SIZE		(MEM_SECTION_SIZE * 9)
#define DEVICE2_TYPE		MEM_AREA_IO_NSEC

#define GICD_BASE		(GIC_BASE + GICD_OFFSET)
#define GICC_BASE		(GIC_BASE + GICC_OFFSET)

#define DEVICE3_PA_BASE		ROUNDDOWN(GIC_BASE, CORE_MMU_DEVICE_SIZE)
#define DEVICE3_VA_BASE		DEVICE3_PA_BASE
#define DEVICE3_SIZE		(MEM_SECTION_SIZE)
#define DEVICE3_TYPE		MEM_AREA_IO_SEC

/* LOG Area for Secure World */
#define MEMORY1_BASE		ROUNDDOWN(OPTEE_LOG_BASE, MEM_SECTION_SIZE)
#define MEMORY1_SIZE		(MEM_SECTION_SIZE)
#define MEMORY1_TYPE		MEM_AREA_IO_SEC
#define MEMORY1_SECURE		true
#define MEMORY1_CACHED		false
#define MEMORY1_DEVICE		false
#define MEMORY1_RW		true
#define MEMORY1_EXEC		false

/* LOG Area for Normal World */
#define MEMORY2_BASE		ROUNDDOWN(OPTEE_LOG_NS_BASE, MEM_SECTION_SIZE)
#define MEMORY2_SIZE		(MEM_SECTION_SIZE)
#define MEMORY2_TYPE		MEM_AREA_IO_NSEC
#define MEMORY2_SECURE		false
#define MEMORY2_CACHED		false
#define MEMORY2_DEVICE		false
#define MEMORY2_RW		true
#define MEMORY2_EXEC		false

/* System RAM */
#define MEMORY3_BASE		ROUNDDOWN(SRAM_BASE, MEM_SECTION_SIZE)
#define MEMORY3_SIZE		(MEM_SECTION_SIZE)
#define MEMORY3_TYPE		MEM_AREA_IO_SEC
#define MEMORY3_SECURE		true
#define MEMORY3_CACHED		false
#define MEMORY3_DEVICE		false
#define MEMORY3_RW		true
#define MEMORY3_EXEC		true

/* Crypto Engine Work area */
#define MEMORY4_BASE		ROUNDDOWN(CRYPTOENGINE_WORK_BASE, \
					MEM_SECTION_SIZE)
#define MEMORY4_SIZE		(MEM_SECTION_SIZE)
#define MEMORY4_TYPE		MEM_AREA_RAM_SEC
#define MEMORY4_SECURE		true
#define MEMORY4_CACHED		true
#define MEMORY4_DEVICE		false
#define MEMORY4_RW		true
#define MEMORY4_EXEC		false

/* TA area for verification */
#define MEMORY5_BASE		ROUNDDOWN(TA_VERIFICATION_BASE, \
					MEM_SECTION_SIZE)
#define MEMORY5_SIZE		(TA_VERIFICATION_SIZE)
#define MEMORY5_TYPE		MEM_AREA_IO_SEC
#define MEMORY5_SECURE		true
#define MEMORY5_CACHED		false
#define MEMORY5_DEVICE		false
#define MEMORY5_RW		true
#define MEMORY5_EXEC		false

/* MaskROM API */
#define MEMORY6_BASE		ROUNDDOWN(ROMAPI_BASE, MEM_SECTION_SIZE)
#define MEMORY6_SIZE		(MEM_SECTION_SIZE)
#define MEMORY6_TYPE		MEM_AREA_IO_SEC
#define MEMORY6_SECURE		true
#define MEMORY6_CACHED		false
#define MEMORY6_DEVICE		false
#define MEMORY6_RW		true
#define MEMORY6_EXEC		true

/* Product Register (PRR) */
#define MEMORY7_BASE		ROUNDDOWN(PRR_BASE, MEM_SECTION_SIZE)
#define MEMORY7_SIZE		(MEM_SECTION_SIZE)
#define MEMORY7_TYPE		MEM_AREA_IO_SEC
#define MEMORY7_SECURE		true
#define MEMORY7_CACHED		false
#define MEMORY7_DEVICE		true
#define MEMORY7_RW		true
#define MEMORY7_EXEC		false

/* Non Cache Stack Area */
#define MEMORY8_BASE		ROUNDDOWN(NONCACHE_WORK_BASE, NONCACHE_WORK_SIZE)
#define MEMORY8_SIZE		(MEM_SECTION_SIZE)
#define MEMORY8_TYPE		MEM_AREA_IO_SEC
#define MEMORY8_SECURE		true
#define MEMORY8_CACHED		false
#define MEMORY8_DEVICE		true
#define MEMORY8_RW		true
#define MEMORY8_EXEC		false

/* SPI Multi I/O Bus Controller (RPC) */
#define MEMORY9_BASE		ROUNDDOWN(RPC_BASE, MEM_SECTION_SIZE)
#define MEMORY9_SIZE		(MEM_SECTION_SIZE)
#define MEMORY9_TYPE		MEM_AREA_IO_SEC
#define MEMORY9_SECURE		true
#define MEMORY9_CACHED		false
#define MEMORY9_DEVICE		true
#define MEMORY9_RW		true
#define MEMORY9_EXEC		false

/* RPC Address Map */
#define MEMORY10_BASE		ROUNDDOWN(RPC_ADDR_MAP_BASE, MEM_SECTION_SIZE)
#define MEMORY10_SIZE		(RPC_ADDR_MAP_SIZE)
#define MEMORY10_TYPE		MEM_AREA_IO_SEC
#define MEMORY10_SECURE		true
#define MEMORY10_CACHED		true
#define MEMORY10_DEVICE		true
#define MEMORY10_RW		true
#define MEMORY10_EXEC		false

#endif /*PLATFORM_CONFIG_H*/
