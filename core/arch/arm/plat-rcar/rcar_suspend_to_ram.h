/*
 * Copyright (c) 2016, Renesas Electronics Corporation
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

#ifndef RCAR_SUSPEND_TO_RAM_H
#define RCAR_SUSPEND_TO_RAM_H

#include <types_ext.h>
#include <tee_api_types.h>

union reg_backup_buf {
	uint32_t d32;
	uint16_t d16;
	uint8_t d8;
};

struct reg_backup_info {
	paddr_t reg_paddr;	/* register Physical address */
	int16_t reg_rsize;	/* register Read Byte size (1 or 2 or 4) */
	int16_t reg_wsize;	/* register Write Byte size (1 or 2 or 4) */

	/* private member */
	vaddr_t reg_vaddr;	/* register Virtual address */
	union reg_backup_buf reg_buf;
};

enum suspend_to_ram_state {
	SUS2RAM_STATE_SUSPEND = 1,	/* CPU Suspend */
	SUS2RAM_STATE_RESUME		/* CPU Resume */
};

typedef void (*backup_call_t)(enum suspend_to_ram_state state, uint32_t cpu_id);

#define _def_attribete(symbol_name) \
	__attribute__((used)) __attribute__((__section__(symbol_name)))

#define _suspend_to_ram_backup(array_name) \
	static struct reg_backup_info *__s2r_backup_##array_name \
	_def_attribete(".suspend_to_ram_backup") = (array_name); \
	static size_t __s2r_backup_num_##array_name \
	_def_attribete(".suspend_to_ram_backup_num") = \
	sizeof(array_name) / sizeof(struct reg_backup_info)

#define suspend_to_ram_backup(array_name) \
	_suspend_to_ram_backup(array_name)

#define suspend_to_ram_cbfunc(fn) \
	static backup_call_t __s2r_cbfunc_##fn \
	_def_attribete(".suspend_to_ram_cbfunc") = (fn)

void suspend_to_ram_save(void);
void suspend_to_ram_restore(void);
void suspend_to_ram_call_cbfunc(enum suspend_to_ram_state state);
void suspend_to_ram_init_helper(struct reg_backup_info *bkarray,
		size_t array_num);
void suspend_to_ram_save_helper(struct reg_backup_info *bkarray,
		size_t array_num);
void suspend_to_ram_restore_helper(struct reg_backup_info *bkarray,
		size_t array_num);

#endif /* RCAR_SUSPEND_TO_RAM_H */
