/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Renesas Electronics Corporation
 */

#ifndef LDR_RING_BUFFER_H
#define LDR_RING_BUFFER_H

#include <compiler.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define LDR_RING_BUFFER_MAGIC_NUMBER	0x5a26
#define LDR_ALIGNE_LENGTH		16
#define LDR_ALIGNED			__aligned(LDR_ALIGNE_LENGTH)

typedef int8_t ldr_errno_t;

enum ldr_rb_error_code {
	LDR_RB_OK = 0,
	LDR_RB_ERROR = -1,
	LDR_RB_SIZE_OVERFLOW = -2,
	LDR_RB_ACCESS_ERROR = -3,
	LDR_RB_FULL_BUFFER = -4,
	LDR_RB_ALREADY_INITIALIZED = -5,
	LDR_RB_QUEUE_ERROR = -6
};

enum ldr_ring_buffer_status {
	LDR_RING_BUFFER_OK = 0,
	LDR_RING_BUFFER_CREATED = 1,
	LDR_RING_BUFFER_EXITED = 2,
	LDR_RING_BUFFER_EDITING = 3,
	LDR_RING_BUFFER_WAITING = 4,
	LDR_RING_BUFFER_HEARTBEAT = 5,
};

struct ldr_queue_header {
	uint16_t size;
	bool exists;
} LDR_ALIGNED;

struct ldr_ring_buffer_header {
	uint32_t magic_num;
	uint32_t buffer_size;
	uint32_t size;
	uint8_t status;
	uint32_t head;
	uint32_t tail;
	int32_t cnt;
	uint32_t fold_point;
} LDR_ALIGNED;

ldr_errno_t ldr_ring_buf_mmgr_init(uint8_t *ptr, uint32_t size);
ldr_errno_t ldr_ring_buf_mmgr_enqueue(uint8_t *rb_ptr, uint8_t *data,
				      uint32_t size);

#endif /* LDR_RING_BUFFER_H */
