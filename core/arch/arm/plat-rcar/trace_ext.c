// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015-2017, Renesas Electronics Corporation
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <trace.h>
#include <arm.h>
#include <kernel/tee_time.h>
#include <kernel/spinlock.h>
#include "rcar_log_func.h"
#include "rcar_common.h"

const char trace_ext_prefix[] = "TEE-CORE";
int trace_level = TRACE_LEVEL;

void trace_ext_puts(const char *str)
{
	int8_t time_buf[LOG_TIME_BUF_MAX_SIZE] = {0};
	size_t time_len = 0U;
	TEE_Time sys_time = {0U, 0U};
	TEE_Result ret;
	int32_t res;
	struct msg_block_t msg_block[MSG_BLK_MAX_NUM];
	int32_t msg_block_num;
	uint32_t exceptions;
#ifdef RCAR_DEBUG_LOG
	const int8_t TERM_LOG_PREFIX[] = "[OP-TEE]";
	const size_t TERM_LOG_PREFIX_LEN = sizeof(TERM_LOG_PREFIX) - 1U;
	size_t log_sum_size = 0U;
	int32_t i;
#endif

	if ((str != NULL) && (log_secram_header != NULL)) {
		exceptions = cpu_spin_lock_xsave(&log_spin_lock);

		ret = tee_time_get_sys_time(&sys_time);
		if (ret == TEE_SUCCESS) {
			res = snprintf((char *)time_buf, sizeof(time_buf),
				"[%u.%06u][%d]",
				sys_time.seconds,
				sys_time.millis * 1000U,
				(int32_t)get_core_pos());
			if (0 < res) {
				time_len = (size_t)res;
			}
		}

		msg_block[SECRAM_IDX_TIME].addr = time_buf;
		msg_block[SECRAM_IDX_TIME].size = time_len;
		msg_block[SECRAM_IDX_MESG].addr = (const int8_t *)str;
		msg_block[SECRAM_IDX_MESG].size = strlen(str);
		msg_block_num = SECRAM_MSG_BLK_NUM;

		log_buf_write(msg_block, msg_block_num);

		cpu_spin_unlock_xrestore(&log_spin_lock, exceptions);

#ifdef RCAR_DEBUG_LOG
		if (is_normal_world_initialized != 0) {
			msg_block[TRMLOG_IDX_PRFX].addr = TERM_LOG_PREFIX;
			msg_block[TRMLOG_IDX_PRFX].size = TERM_LOG_PREFIX_LEN;
			msg_block[TRMLOG_IDX_TIME].addr = time_buf;
			msg_block[TRMLOG_IDX_TIME].size = time_len;
			msg_block[TRMLOG_IDX_MESG].addr = (const int8_t *)str;
			msg_block[TRMLOG_IDX_MESG].size = strlen(str);
			msg_block_num = TRMLOG_MSG_BLK_NUM;

			/* Log size is limited to 256 byte */
			for (i = 0; i < msg_block_num; i++) {
				log_sum_size += msg_block[i].size;
			}
			if (log_sum_size > MAX_PRINT_SIZE) {
				msg_block[msg_block_num - 1].size -=
					log_sum_size - (uint32_t)MAX_PRINT_SIZE;
			}

			if ((exceptions & THREAD_EXCP_NATIVE_INTR) == 0U) {
				/* User context */
				log_debug_send(msg_block, msg_block_num);
			} else {
				/* Interrupt context */
			}
		}
#endif
	}
}

int trace_ext_get_thread_id(void)
{
	return -1;
}
