/*
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
#define FL_DRV_ERR_SYSCALL_WAIT		8U
#define FL_DRV_ERR_STATUS_INCORRECT	9U

/* sector size */
#define SECTOR_SIZE			0x00040000U

uint32_t qspi_hyper_flash_init(void);
uint32_t qspi_hyper_flash_erase(uint32_t sector_addr);
uint32_t qspi_hyper_flash_read(uint32_t flash_addr, uint8_t *buf,
				size_t rsize);
uint32_t qspi_hyper_flash_write(uint32_t flash_addr, const uint8_t *buf,
				size_t wsize);

#endif /* QSPI_HYPER_FLASH_H */
