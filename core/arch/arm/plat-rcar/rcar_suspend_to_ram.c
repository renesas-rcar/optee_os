// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2020, Renesas Electronics Corporation
 */

#include <io.h>
#include <trace.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <kernel/misc.h>
#include "rcar_suspend_to_ram.h"

extern backup_call_t __suspend_to_ram_cbfunc_start;
extern backup_call_t __suspend_to_ram_cbfunc_end;

void suspend_to_ram_save(void)
{
	suspend_to_ram_call_cbfunc(SUS2RAM_STATE_SUSPEND);
}

void suspend_to_ram_restore(void)
{
	suspend_to_ram_call_cbfunc(SUS2RAM_STATE_RESUME);
}

#define SUSPEND_TO_RAM_ALIGN 8U

void suspend_to_ram_call_cbfunc(enum suspend_to_ram_state state)
{
	const uint64_t cbfunc_obj_num = (((uint64_t)&__suspend_to_ram_cbfunc_end
		- (uint64_t)&__suspend_to_ram_cbfunc_start) /
		SUSPEND_TO_RAM_ALIGN);
	if (0U != cbfunc_obj_num) {
		const backup_call_t *cbfunc;
		uint32_t cpu_id;
		volatile uintptr_t cbfunc_ptr;
		uint8_t i;

		cpu_id = get_core_pos();

		for (i = 0U; i < cbfunc_obj_num; i++) {
		        cbfunc_ptr = ((uint64_t)&__suspend_to_ram_cbfunc_start +
		        		((uint64_t)i * SUSPEND_TO_RAM_ALIGN));
		        cbfunc = (const backup_call_t *)cbfunc_ptr;
		        (*cbfunc)(state, cpu_id);
		}
	}
}
