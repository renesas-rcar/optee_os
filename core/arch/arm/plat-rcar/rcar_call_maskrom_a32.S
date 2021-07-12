/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
 */

#include <asm.S>

.global asm_switch_stack_pointer

/* R0 : Jump address */
/* R1 : Stack address */
/* R2 : arg */
FUNC asm_switch_stack_pointer , :

	mov	r0, #-1		/* not supported */
	bx	lr
END_FUNC asm_switch_stack_pointer
