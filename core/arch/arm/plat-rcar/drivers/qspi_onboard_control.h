/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
 */

#ifndef QSPI_ONBOARD_CONTROL_H
#define QSPI_ONBOARD_CONTROL_H

#include "qspi_hyper_flash_common.h"

void qspi_onboard_set_control_ops(struct flash_control_operations *ops);

#endif /* QSPI_ONBOARD_CONTROL_H */
