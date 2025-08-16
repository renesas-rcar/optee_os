/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Renesas Electronics Corporation
 */

#ifndef __DRIVERS_HSCIF_H
#define __DRIVERS_HSCIF_H

#include <types_ext.h>
#include <drivers/serial.h>

#define HSCIF_REG_SIZE	0x1000

struct hscif_uart_data {
	struct io_pa_va base;
	struct serial_chip chip;
};

void hscif_uart_init(struct hscif_uart_data *pd, paddr_t base);
void hscif_console_init(void);
#endif /* __DRIVERS_HSCIF_H */
