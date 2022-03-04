/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
 */

#ifndef HYPER_FLASH_CONTROL_H
#define HYPER_FLASH_CONTROL_H

#include "qspi_hyper_flash_common.h"

uint32_t hyper_flash_init(struct flash_control_operations *ops);
uint32_t hyper_flash_read_device_status(uint32_t *read_status);

#endif /* HYPER_FLASH_CONTROL_H */
