/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
 */

#include <asm.S>
#include <arm64_macros.S>
#include <arm64.h>

.global asm_switch_stack_pointer

/* X0 : Jump address */
/* X1 : Stack address */
/* X2 : arg */
FUNC asm_switch_stack_pointer , :

	/* lr to stack */
	mov	x3, x2
	mov	x2, x30
	sub	sp, sp, #16
	store_xregs sp, 0, 1, 2	/* x1 is dummy (sp is 16byte alignment) */

	/* change stack pointer */
	mov	x2, sp
	mov	sp, x1

	/* save stack pointer */
	sub	sp, sp, #16
	store_xregs sp, 0, 1, 2	/* x1 is dummy (sp is 16byte alignment) */

	/* data synchronization barrier */
	dsb	sy

	/* jump to code */
	mov	x1, x0
	mov	x0, x3
	blr	x1

	/* load stack pointer */
	load_xregs sp, 0, 1, 2	/* x1 is dummy (sp is 16byte alignment) */

	/* change stack pointer */
	add	sp, sp, #16
	mov	sp, x2

	/* return */
	load_xregs sp, 0, 1, 2	/* x1 is dummy (sp is 16byte alignment) */
	add	sp, sp, #16
	mov	x30, x2
	ret
END_FUNC asm_switch_stack_pointer
