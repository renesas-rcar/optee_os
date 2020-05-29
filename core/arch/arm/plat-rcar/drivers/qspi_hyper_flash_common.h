/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2019, Renesas Electronics Corporation
 */

#ifndef QSPI_HYPER_FLASH_COMMON_H
#define QSPI_HYPER_FLASH_COMMON_H

#include <stdint.h>
#include <string.h>
#include <platform_config.h>

/*
 * Constant definition
 */

/* RCarH3_RPC  SPI Multi I/O Bus Controller (RPC) */
/* Top of RPC memory space : 0x08000000-0x0BFFFFFF = 64MBytes */
#define SPI_IOADDRESS_TOP	0x08000000U
/* Common control register */
#define RPC_CMNCR	(RPC_BASE + 0x0000U)
/* Data read control register */
#define RPC_DRCR	(RPC_BASE + 0x000CU)
/* Data read command setting register */
#define RPC_DRCMR	(RPC_BASE + 0x0010U)
/* Data read enable setting register */
#define RPC_DREAR	(RPC_BASE + 0x0014U)
#define	RPC_DROPR	(RPC_BASE + 0x0018U)
/* Data read enable setting register */
#define RPC_DRENR	(RPC_BASE + 0x001CU)
/* Manual mode control register */
#define RPC_SMCR	(RPC_BASE + 0x0020U)
/* Manual mode command setting register */
#define RPC_SMCMR	(RPC_BASE + 0x0024U)
/* Manual mode address setting register */
#define RPC_SMADR	(RPC_BASE + 0x0028U)
/* Manual mode option setting register */
#define RPC_SMOPR	(RPC_BASE + 0x002CU)
/* Manual mode enable setting register */
#define RPC_SMENR	(RPC_BASE + 0x0030U)
/* Manual mode read data register 0 */
#define RPC_SMRDR0	(RPC_BASE + 0x0038U)
/* Manual mode read data register 1 */
#define RPC_SMRDR1	(RPC_BASE + 0x003CU)
/* Manual mode write data register 0 */
#define RPC_SMWDR0	(RPC_BASE + 0x0040U)
/* Common status register */
#define RPC_CMNSR	(RPC_BASE + 0x0048U)
/* Data read dummy cycle setting register */
#define RPC_DRDMCR	(RPC_BASE + 0x0058U)
/* Data read DDR enable register */
#define RPC_DRDRENR	(RPC_BASE + 0x005CU)
/* Manual mode dummy cycle setting register */
#define RPC_SMDMCR	(RPC_BASE + 0x0060U)
/* Manual mode DDR enable register */
#define RPC_SMDRENR	(RPC_BASE + 0x0064U)
/* PHY control register */
#define RPC_PHYCNT	(RPC_BASE + 0x007CU)
/* Offset */
#define RPC_OFFSET1	(RPC_BASE + 0x0080U)
/* PHY interrupt register */
#define RPC_PHYINT	(RPC_BASE + 0x0088U)

#define CPG_CPGWPR	(0xE6150900U)
#define CPG_RPCCKCR	(0xE6150238U)
#define CPG_SRCR9	(0xE6150924U)
#define CPG_SRSTCLR9	(0xE6150964U)

/* device id */
/* QSPI_ONBOARD : S25FS128S */
#define QSPI_ONBOARD 0x00182001U
/* HyperFlash : S26KS512S */
#define HYPER_FLASH 0x007E0001U
/* Unsupport device */
#define DEVICE_UNKNOWN 0xFFFFFFFFU

/* Timeout / Wait time */
/* HyperFlash : S26KS512S */
#define HF_ERASE_TIMEOUT	3000U
#define HF_READ_TIMEOUT		100U
#define HF_WRITE_TIMEOUT	100U
#define HF_ERASE_WAIT		50U
#define HF_READ_WAIT		10U
#define HF_WRITE_WAIT		10U

/* QSPI onboard : S25FS128S */
#define QSPI_ERASE_TIMEOUT	3000U
#define QSPI_READ_TIMEOUT	100U
#define QSPI_WRITE_TIMEOUT	100U
#define QSPI_ERASE_WAIT		50U
#define QSPI_READ_WAIT		10U
#define QSPI_WRITE_WAIT		10U

#define FL_DEVICE_BUSY		0U
#define FL_DEVICE_READY		1U
#define FL_DEVICE_ERR		2U

/* HyperFlash write command control */
#define HYPER_FL_UNLOCK1_ADD		0x555U
#define HYPER_FL_UNLOCK1_DATA		((uint32_t)0xAAU << (uint32_t)24U)
#define HYPER_FL_UNLOCK2_ADD		0x2AAU
#define HYPER_FL_UNLOCK2_DATA		((uint32_t)0x55U << (uint32_t)24U)
#define HYPER_FL_UNLOCK3_ADD		0x555U
#define HYPER_FL_RESET_COM		((uint32_t)0xF0U << (uint32_t)24U)
#define	HYPER_FL_WORD_PROGRAM_COM	((uint32_t)0xA0U << (uint32_t)24U)
#define HYPER_FL_ID_ENTRY_COM		((uint32_t)0x90U << (uint32_t)24U)
#define	HYPER_FL_RD_STATUS_COM		((uint32_t)0x70U << (uint32_t)24U)
#define HYPER_FL_ERASE_1ST_COM		((uint32_t)0x80U << (uint32_t)24U)
#define HYPER_FL_SECTOR_ERASE_COM	((uint32_t)0x30U << (uint32_t)24U)
/* SMADR Register address */
#define HYPER_FL_SMADR_TOP_ADD		0x00000000U

/* QSPI Flash write command control */
/*Write Enable command */
#define QSPI_FL_COMMAND_WRITE_ENABLE	0x00060000U

/* bit code for mask */
#define BIT0	((uint32_t)0x00000001U)
#define BIT1	((uint32_t)0x00000002U)
#define BIT5	((uint32_t)0x00000020U)
#define BIT7	((uint32_t)0x00000080U)
#define EXT_ADDR_MASK	((uint32_t)0xFC000000U)

/* Volatile Status and Configuration Registers (CR3V) */
#define SPIREG_CR3V	0x00800004U

/* read byte count, offset byte count */
#define FLASH_DATA_READ_BYTE_COUNT_2	2U
#define FLASH_DATA_READ_BYTE_COUNT_4	4U
#define FLASH_DATA_READ_BYTE_COUNT_8	8U
#define FLASH_DATA_OFFSET_BYTE_8	8U

/* bit shift count */
#define FLASH_DATA_BIT_SHIFT_8		8U
#define EXT_ADDR_BIT_SHIFT_9		9U

/* access size */
#define WORD_SIZE		0x00000004U
#define WRITE_BUFF_SIZE		0x00000100U
#define ERASE_SIZE_256KB	0x00040000U
#define ERASE_SIZE_64KB		0x00010000U
#define EXT_ADD_BORDER_SIZE_64MB 0x04000000U

/* read_sector_size_bit on/off flag */
#define READ_SECTOR_SIZE_BIT_OFF	0U
#define READ_SECTOR_SIZE_BIT_ON		1U

/* RPC clock mode */
#define RPC_CLK_40M			(0x01U)
#define RPC_CLK_80M			(0x02U)
#define RPC_CLK_160M			(0x03U)
#define RPC_CLK_150M			(0x04U)

/*
 * Global variable declaration
 */
extern uint32_t rpc_clock_mode;
extern uint32_t phycnt_reg;

struct flash_control_operations {
	uint32_t (*erase)(uint32_t sector_addr);
	uint32_t (*set_ext_addr_read_mode)(uint32_t read_ext_top_addr,
			uint32_t r_flash_addr, uint8_t *buf, size_t rsize);
	uint32_t (*write)(uint32_t buf_addr,
				uint32_t flash_addr, uint32_t wsize);
};

uint32_t common_wait_spi_transfer(uint32_t *dataL);
uint32_t common_wait(uint32_t (*read_status)(uint32_t *), uint32_t *data,
					uint32_t timeout, uint32_t wait);
uint32_t set_rpc_clock_mode(uint32_t mode);

#endif /* QSPI_HYPER_FLASH_COMMON_H */
