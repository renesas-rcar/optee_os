/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
 */

#ifndef RCAR_LOG_FUNC_H
#define RCAR_LOG_FUNC_H

#include <types_ext.h>
#include <kernel/mutex.h>
#include <platform_config.h>

/*
 * Constant definition
 */

#define LOG_RAM_MAX_SIZE	(81920U)
#define LOG_RAM_HEADER_SIZE	(16U)
#define LOG_RAM_RESERVE_SIZE	(64U)
#define LOG_AREA_MAX_SIZE	(LOG_RAM_MAX_SIZE - \
				(LOG_RAM_HEADER_SIZE + LOG_RAM_RESERVE_SIZE))
#define LOG_TIME_BUF_MAX_SIZE	(31)
#define LOG_NS_CPU_AREA_SIZE	(1024U)
#define LOG_SEC_PREFIX		"SLOG"
#define LOG_SEC_PREFIX_LEN	(4)
#define LOG_SEND_MAX_SIZE	(256U)

#define SECRAM_MSG_BLK_NUM	(2)
#define SECRAM_IDX_TIME		(0)
#define SECRAM_IDX_MESG		(1)

#define TRMLOG_MSG_BLK_NUM	(3)
#define TRMLOG_IDX_PRFX		(0)
#define TRMLOG_IDX_TIME		(1)
#define TRMLOG_IDX_MESG		(2)

#ifdef RCAR_DEBUG_LOG
#define MSG_BLK_MAX_NUM		TRMLOG_MSG_BLK_NUM
#else
#define MSG_BLK_MAX_NUM		SECRAM_MSG_BLK_NUM
#endif  /* RCAR_DEBUG_LOG */

/*
 * Struct definition
 */

struct log_buf_header_t {
	int8_t prefix[LOG_SEC_PREFIX_LEN];
	uint32_t index;
	uint32_t size;
	uint32_t reserve;
};

struct msg_block_t {
	const int8_t *addr;
	size_t size;
};

/*
 * Global variable declaration
 */

extern struct log_buf_header_t *log_secram_header;
extern uint32_t log_spin_lock;
extern int32_t is_normal_world_initialized;

/*
 * Prototype declaration
 */

void log_buf_write(const struct msg_block_t *msg_block, int32_t msg_block_num);
#ifdef RCAR_DEBUG_LOG
void log_debug_send(const struct msg_block_t *msg_block, int32_t msg_block_num);
#endif /* RCAR_DEBUG_LOG */

#endif /* RCAR_LOG_FUNC_H */
