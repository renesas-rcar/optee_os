/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
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

#ifndef RCAR_MASKROM_H_
#define RCAR_MASKROM_H_

#define MASKROM_CRYPTO_ENGINE_BASE_ADDRESS	(0xE6600000U)

#define NONCACHE_STACK_AREA		(NONCACHE_WORK_BASE + \
					NONCACHE_WORK_SIZE)

typedef uint32_t (*ROM_FuncReadFlash) (
			uint64_t srcAddr,
			uint8_t *pDest,
			uint32_t sizeToRead);

typedef uint32_t (*ROM_SECURE_API)(uint32_t *pKeyCert,
			uint32_t *pContentCert,
			ROM_FuncReadFlash pFuncReadFlash);

typedef uint32_t(*ROM_GETLCS_API)(uint32_t *pLcs);

extern ROM_SECURE_API ROM_SecureBootAPI;
extern ROM_GETLCS_API ROM_GetLcs;

uint32_t asm_switch_stack_pointer(uintptr_t jump, uint32_t stack, void *arg);
uint32_t switch_stack_pointer(void *func, uint8_t *data);
uint32_t get_PRR_type(void);

#endif /* RCAR_MASKROM_H_ */
