/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2020, Renesas Electronics Corporation
 */

#ifndef RCAR_SUSPEND_TO_RAM_H
#define RCAR_SUSPEND_TO_RAM_H

#include <types_ext.h>
#include <tee_api_types.h>

enum suspend_to_ram_state {
	SUS2RAM_STATE_SUSPEND = 1,	/* CPU Suspend */
	SUS2RAM_STATE_RESUME		/* CPU Resume */
};

typedef void (*backup_call_t)(enum suspend_to_ram_state s2r_state, uint32_t cpu_id);

#define def_attribete(symbol_name) \
	__attribute__((used)) __attribute__((__section__(symbol_name)))

#define suspend_to_ram_cbfunc(fn) \
	static backup_call_t __s2r_cbfunc_##fn \
	def_attribete(".suspend_to_ram_cbfunc") = (fn)

void suspend_to_ram_save(void);
void suspend_to_ram_restore(void);

#endif /* RCAR_SUSPEND_TO_RAM_H */
