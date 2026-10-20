/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Renesas Electronics Corporation
 */

#ifndef LDR_RING_BUFFER_RETURN_TYPES_H
#define LDR_RING_BUFFER_RETURN_TYPES_H

#include <stdint.h>

#define RETURN_OK			0
#define RETURN_ERROR			-1
#define RETURN_SIZE_OVERFLOW		-2
#define RETURN_ACCESS_ERROR		-3
#define RETURN_FULL_BUFFER		-4
#define RETURN_ALREADY_INITIALIZED	-5
#define RETURN_QUEUE_ERROR		-6

#define ALIGN_UP(x, align)	(((x) + (align) - 1U) & ~((align) - 1U))
#define ALIGN_DOWN(x, align)	((x) & ~((align) - 1U))
#define ALIGN_OFFSET(x, align) \
	(((align) - ((uintptr_t)(x) & ((align) - 1U))) & ((align) - 1U))
#define ALIGN_UP_16(x)		ALIGN_UP(x, 16)

#define ALIGN_UP_PTR(p, align) \
	(((uintptr_t)(p) + ((uintptr_t)(align) - (uintptr_t)1)) & \
	 ~((uintptr_t)(align) - (uintptr_t)1))

#define ALIGN_PTR_UP_16(ptr) \
	((__typeof__(ptr))ALIGN_UP_PTR((ptr), 16))

#define MEMCPY(dest, src, size) \
	do { \
		for (size_t i = 0; i < (size); ++i) { \
			((uint8_t *)(dest))[i] = ((const uint8_t *)(src))[i]; \
		} \
	} while (0)

#define MEMSET(dest, value, size) \
	do { \
		for (size_t i = 0; i < (size); ++i) { \
			((uint8_t *)(dest))[i] = (uint8_t)(value); \
		} \
	} while (0)

#endif /* LDR_RING_BUFFER_RETURN_TYPES_H */
