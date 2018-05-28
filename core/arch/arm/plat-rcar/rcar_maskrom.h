/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
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
