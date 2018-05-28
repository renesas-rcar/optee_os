/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
 */

#ifndef SWDT_DRIVER_H_
#define SWDT_DRIVER_H_

#define	SWDT_FREQ_OSC_DIV_1_1		(0U)
#define	SWDT_FREQ_OSC_DIV_1_4		(1U)
#define	SWDT_FREQ_OSC_DIV_1_16		(2U)
#define	SWDT_FREQ_OSC_DIV_1_32		(3U)
#define	SWDT_FREQ_OSC_DIV_1_64		(4U)
#define	SWDT_FREQ_OSC_DIV_1_128		(5U)
#define	SWDT_FREQ_OSC_DIV_1_1024	(6U)
#define	SWDT_FREQ_EXPANDED		(7U)

#define	SWDT_SUCCESS			(0)
#define	SWDT_ERR_PARAMETER		(-1)
#define	SWDT_ERR_SEQUENCE		(-2)

int32_t swdt_start(uint16_t count, uint8_t clk,
		uint8_t expanded_clk, void (*cb)(void));
int32_t swdt_stop(void);
int32_t swdt_kick(void);

#endif /* SWDT_DRIVER_H_ */
