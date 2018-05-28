/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
 */

#ifndef QSPI_FLASH_COMMON_H
#define QSPI_FLASH_COMMON_H

#include "qspi_hyper_flash_common.h"

uint32_t qspi_common_init(struct flash_control_operations *ops);
uint32_t qspi_common_set_command(uint32_t command);
uint32_t qspi_common_erase_control(uint32_t sector_addr);
uint32_t qspi_common_read_device_status(uint32_t *read_status);

#endif /* QSPI_FLASH_COMMON_H */
