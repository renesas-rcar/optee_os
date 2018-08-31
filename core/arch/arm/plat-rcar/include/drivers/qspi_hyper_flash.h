/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2018, Renesas Electronics Corporation
 */

#ifndef QSPI_HYPER_FLASH_H
#define QSPI_HYPER_FLASH_H

#include <stdint.h>
#include <string.h>

/*
 * Constant definition
 */

/* function return code */
/* correct end */
#define FL_DRV_OK			0U
/* incorrect end */
#define FL_DRV_ERR_UNSUPPORT_DEV	1U
#define FL_DRV_ERR_SECTOR_ADDR		2U
#define FL_DRV_ERR_BUF_INCORRECT	3U
#define FL_DRV_ERR_OUT_OF_RANGE		4U
#define FL_DRV_ERR_SECTOR_EXCEED	5U
#define FL_DRV_ERR_TIMEOUT		6U
#define FL_DRV_ERR_GET_SYS_TIME		7U
#define FL_DRV_ERR_STATUS_INCORRECT	9U
#define FL_DRV_ERR_OUT_OF_MEMORY	10U

/* sector size */
#define SECTOR_SIZE			0x00040000U

uint32_t qspi_hyper_flash_init(void);
uint32_t qspi_hyper_flash_erase(uint32_t sector_addr);
uint32_t qspi_hyper_flash_read(uint32_t flash_addr, uint8_t *buf,
				size_t rsize);
uint32_t qspi_hyper_flash_write(uint32_t flash_addr, const uint8_t *buf,
				size_t wsize);

#endif /* QSPI_HYPER_FLASH_H */
