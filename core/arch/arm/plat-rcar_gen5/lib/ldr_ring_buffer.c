// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Renesas Electronics Corporation
 */

#include <io.h>
#include <stddef.h>

#include "ldr_ring_buffer.h"
#include "ldr_ring_buffer_return_types.h"

#define RB_RD32(rb, field) \
	io_read32((vaddr_t)(rb) + \
		  offsetof(struct ldr_ring_buffer_header, field))
#define RB_WR32(rb, field, val) \
	io_write32((vaddr_t)(rb) + \
		   offsetof(struct ldr_ring_buffer_header, field), (val))
#define RB_WR8(rb, field, val) \
	io_write8((vaddr_t)(rb) + \
		  offsetof(struct ldr_ring_buffer_header, field), (val))

static void ldr_ring_buf_header_init(struct ldr_ring_buffer_header *rb,
				     uint32_t size);
static uint8_t *ldr_mem_mmgr_get_queue_entry(uint8_t *mem_ptr, uint32_t head);

ldr_errno_t ldr_ring_buf_mmgr_init(uint8_t *ptr, uint32_t size)
{
	struct ldr_ring_buffer_header *rb = (void *)ptr;
	ldr_errno_t ret = RETURN_OK;

	if (RB_RD32(rb, magic_num) == LDR_RING_BUFFER_MAGIC_NUMBER)
		ret = RETURN_ALREADY_INITIALIZED;
	else
		ldr_ring_buf_header_init(rb, size);

	return ret;
}

ldr_errno_t ldr_ring_buf_mmgr_enqueue(uint8_t *rb_ptr, uint8_t *data,
				      uint32_t size)
{
	struct ldr_ring_buffer_header *rb = (void *)rb_ptr;
	struct ldr_queue_header *queue = NULL;
	uint8_t *queue_addr = NULL;
	uint8_t *data_ptr = NULL;
	uint8_t *data_ptr_aligned = NULL;
	uint32_t raw_size = 0;
	uint32_t queue_size = 0;
	uint32_t buffer_size = 0;
	uint32_t head = 0;
	uint32_t tail = 0;
	uint32_t updated_tail = 0;

	if (RB_RD32(rb, magic_num) != LDR_RING_BUFFER_MAGIC_NUMBER)
		ldr_ring_buf_mmgr_init(rb_ptr, size);

	raw_size = sizeof(struct ldr_queue_header) + size;
	queue_size = ALIGN_UP_16(raw_size);

#ifdef __aarch64__
	__sync_synchronize();
#endif

	buffer_size = RB_RD32(rb, buffer_size);
	head = RB_RD32(rb, head);
	tail = RB_RD32(rb, tail);

	if ((buffer_size - tail) < queue_size) {
		if (head < queue_size)
			return RETURN_SIZE_OVERFLOW;

		/* Not enough room at the end: fold back to the beginning */
		updated_tail = 0;
		queue_addr = ldr_mem_mmgr_get_queue_entry(rb_ptr, updated_tail);
		queue = (void *)queue_addr;

		queue->size = (uint16_t)size;
		queue->exists = true;

#ifdef __aarch64__
		__sync_synchronize();
#endif

		data_ptr = (uint8_t *)queue + sizeof(struct ldr_queue_header);
		data_ptr_aligned = ALIGN_PTR_UP_16(data_ptr);
		MEMCPY(data_ptr_aligned, data, size);

#ifdef __aarch64__
		__sync_synchronize();
#endif

		RB_WR32(rb, tail, ALIGN_UP_16(updated_tail + queue_size));
		RB_WR32(rb, fold_point, tail);
	} else {
		if (tail < head && (head - tail) <= queue_size)
			return RETURN_SIZE_OVERFLOW;

		queue_addr = ldr_mem_mmgr_get_queue_entry(rb_ptr, tail);
		queue_addr = ALIGN_PTR_UP_16(queue_addr);
		queue = (void *)queue_addr;
		data_ptr = (uint8_t *)queue + sizeof(struct ldr_queue_header);
		data_ptr_aligned = ALIGN_PTR_UP_16(data_ptr);

		queue->size = (uint16_t)size;
		queue->exists = true;

#ifdef __aarch64__
		__sync_synchronize();
#endif
		MEMCPY(data_ptr_aligned, data, size);

#ifdef __aarch64__
		__sync_synchronize();
#endif

		RB_WR32(rb, tail, tail + queue_size);
	}

	return RETURN_OK;
}

static uint8_t *ldr_mem_mmgr_get_queue_entry(uint8_t *mem_ptr, uint32_t head)
{
	return mem_ptr + sizeof(struct ldr_ring_buffer_header) + head;
}

static void ldr_ring_buf_header_init(struct ldr_ring_buffer_header *rb,
				     uint32_t size)
{
	uint32_t clear_size = size - (uint32_t)sizeof(*rb);

	RB_WR32(rb, magic_num, LDR_RING_BUFFER_MAGIC_NUMBER);
	RB_WR32(rb, buffer_size, clear_size);
	RB_WR32(rb, size, 0);
	RB_WR8(rb, status, LDR_RING_BUFFER_CREATED);
	RB_WR32(rb, head, 0);
	RB_WR32(rb, tail, 0);
	RB_WR32(rb, cnt, 0);
	RB_WR32(rb, fold_point, 0);

	MEMSET((uint8_t *)rb + sizeof(*rb), '\0', clear_size);
}
