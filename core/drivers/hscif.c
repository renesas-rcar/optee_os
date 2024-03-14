// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Renesas Electronics Corporation
 */

#include <stdio.h>
#include <io.h>
#include <keep.h>
#include <util.h>
#include <drivers/hscif.h>
#include <drivers/hscif_register.h>
#include <mm/core_mmu.h>

#define SCSCR_TE		BIT(5)
#define SCFSR_TDFE		BIT(5)
#define SCFSR_TEND		BIT(6)

#define SCFDR_T_SHIFT		8

#define SCIF_TX_FIFO_SIZE	16

static void hscif_uart_putc(struct serial_chip *chip, uint8_t outchar);
static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct hscif_uart_data *pd =
		container_of(chip, struct hscif_uart_data, chip);

	return io_pa_or_va(&pd->base, HSCIF_REG_SIZE);
}

static void hscif_uart_flush(struct serial_chip __maybe_unused *chip)
{
/*
 * do not anything
 */
}

static void hscif_uart_putc(struct serial_chip *chip, uint8_t outchar)
{
	static uint8_t remain;
	bool mmu_enabled = cpu_mmu_enabled();

	if (mmu_enabled) {
		vaddr_t base = chip_to_base(chip);

		while (remain == 0) {
			remain = 128 - (io_read16(base + HSCIF_HSFDR_OFFSET)
					>> SCFDR_T_SHIFT);
			if (remain < 64)
				remain = 0;
			else
				remain -= 64;
		}
		/* Transfer one character */
		io_write8(base + HSCIF_HSFTDR_OFFSET, outchar);
	} else {
		/* Wait until there is space in the FIFO */
		while (remain == 0) {
			remain = 128 - (io_read16(HSCIF_HSFDR)
					>> SCFDR_T_SHIFT);
			if (remain < 64)
				remain = 0;
			else
				remain -= 64;
		}
		/* Transfer one character */
		io_write8(HSCIF_HSFTDR, outchar);
	}
	remain--;
}

static const struct serial_ops hscif_uart_ops = {
	.flush = hscif_uart_flush,
	.putc = hscif_uart_putc,
};

DECLARE_KEEP_PAGER(hscif_uart_ops);

void hscif_uart_init(struct hscif_uart_data *pd, paddr_t pbase)
{
	pd->base.pa = pbase;
	pd->chip.ops = &hscif_uart_ops;
	hscif_console_init();
	hscif_uart_flush(&pd->chip);
}

void hscif_console_init(void)
{
	uint16_t reg;

	io_write16(HSCIF_HSSCR, HSCIF_SCSCR_HW_INIT);
	reg = io_read16(HSCIF_HSSCR);
	reg |= HSCIF_SCSCR_INIT_DATA;
	io_write16(HSCIF_HSSCR, reg);
	/* enable TE, RE; SC_CLK=no output */
	io_setbits16(HSCIF_HSSCR, SCSCR_TE);
}

