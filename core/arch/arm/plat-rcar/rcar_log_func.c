// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2018, Renesas Electronics Corporation
 */

#include <string.h>
#include <platform_config.h>
#include <kernel/misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/tz_proc_def.h>
#include <kernel/linker.h>
#include <kernel/spinlock.h>
#include <optee_msg.h>
#include <mm/core_mmu.h>
#include <initcall.h>
#include <trace.h>
#include <tee/cache.h>
#include "rcar_log_func.h"
#include "rcar_common.h"
#include "rcar_version.h"

struct log_buf_header_t *log_secram_header __data;
static int8_t *log_nonsec_ptr;
uint32_t log_spin_lock;
int32_t is_normal_world_initialized;
const int8_t version_of_renesas[] __attribute__((__section__(".version"))) =
	VERSION_OF_RENESAS;

static TEE_Result log_buf_init(void);

static TEE_Result log_buf_init(void)
{
	const int8_t secram_prefix[] = LOG_SEC_PREFIX;
	int32_t i;

	/* initialize global variable */
	log_secram_header = (struct log_buf_header_t *)OPTEE_LOG_BASE;
	log_nonsec_ptr = (int8_t *)OPTEE_LOG_NS_BASE;
	log_spin_lock = (uint32_t)SPINLOCK_UNLOCK;
	is_normal_world_initialized = 0;

	/* initialize SDRAM area */
	for (i = 0; i < LOG_SEC_PREFIX_LEN; i++) {
		if (secram_prefix[i] != log_secram_header->prefix[i]) {
			break;
		}
	}
	if ((i < LOG_SEC_PREFIX_LEN) ||
	    (log_secram_header->index >= LOG_AREA_MAX_SIZE)) {
		(void)memset((int8_t *)log_secram_header,
			0, sizeof(struct log_buf_header_t));
		(void)memcpy(log_secram_header->prefix,
			secram_prefix, sizeof(log_secram_header->prefix));
	}

	IMSG("Logging RAM initialized. (%s)", core_v_str);
	return TEE_SUCCESS;
}

service_init(log_buf_init);

void log_buf_write(const struct msg_block_t *msg_block, int32_t msg_block_num)
{
	int8_t *log_area = NULL;
	uint32_t end_index;
	size_t ram_wsize;
	size_t total_wsize = 0U;
	size_t index_wsize;
	size_t head_wsize;
	int32_t i;

	for (i = 0; i < msg_block_num; i++) {
		if ((log_secram_header == NULL) ||
		    (total_wsize >= LOG_AREA_MAX_SIZE)) {
			break;
		}
		if (log_area == NULL) {
			log_area = (int8_t *)(&log_secram_header[1]);
		}
		ram_wsize = msg_block[i].size;
		if ((total_wsize + ram_wsize) > LOG_AREA_MAX_SIZE) {
			ram_wsize = LOG_AREA_MAX_SIZE - total_wsize;
		}

		end_index = log_secram_header->index + ram_wsize;
		head_wsize = 0U;

		if (end_index > LOG_AREA_MAX_SIZE) {
			head_wsize = end_index - LOG_AREA_MAX_SIZE;
		}
		index_wsize = ram_wsize - head_wsize;

		(void)memcpy(&log_area[log_secram_header->index],
			&msg_block[i].addr[0], index_wsize);
		total_wsize += index_wsize;

		if (0U < head_wsize) {
			(void)memcpy(&log_area[0],
				&msg_block[i].addr[index_wsize], head_wsize);
			total_wsize += head_wsize;
			log_secram_header->index = head_wsize;
		} else {
			log_secram_header->index += index_wsize;
			if (log_secram_header->index == LOG_AREA_MAX_SIZE) {
				log_secram_header->index = 0U;
			}
		}

		if (log_secram_header->size < LOG_AREA_MAX_SIZE) {
			log_secram_header->size += index_wsize;
		}
	}
}

#ifdef RCAR_DEBUG_LOG
void log_debug_send(const struct msg_block_t *msg_block, int32_t msg_block_num)
{
	static size_t send_log_size[CFG_TEE_CORE_NB_CORE] = {0U};
	struct optee_msg_param params;
	uint32_t cpu_id;
	int8_t *log_area;
	size_t log_offs = 0U;
	size_t memcpy_size;
	int32_t i;

	cpu_id = get_core_pos();

	if ((log_nonsec_ptr != NULL) && (cpu_id < CFG_TEE_CORE_NB_CORE)) {
		log_area = &log_nonsec_ptr[cpu_id * LOG_NS_CPU_AREA_SIZE];
		if ((send_log_size[cpu_id] + LOG_SEND_MAX_SIZE) <
		     LOG_NS_CPU_AREA_SIZE) {
			if (send_log_size[cpu_id] > 0U) {
				log_area[send_log_size[cpu_id]] = (int8_t)'\r';
				log_area += send_log_size[cpu_id] + 1U;
			}
			for (i = 0; i < msg_block_num; i++) {
				memcpy_size = msg_block[i].size;
				if ((log_offs + memcpy_size) >
				     LOG_SEND_MAX_SIZE) {
					memcpy_size = LOG_SEND_MAX_SIZE -
							log_offs;
				}
				(void)memcpy(&log_area[log_offs],
					msg_block[i].addr, memcpy_size);
				log_offs += memcpy_size;
			}
			log_area[log_offs] = (int8_t)'\0';
			(void)cache_operation(TEE_CACHEFLUSH, log_area,
					LOG_NS_CPU_AREA_SIZE);

			if (send_log_size[cpu_id] == 0U) {
				(void)memset(&params, 0, sizeof(params));
				params.attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
				params.u.value.a = cpu_id;
				params.u.value.b = 0U;

				send_log_size[cpu_id] = log_offs;

				(void)thread_rpc_cmd(TEE_RPC_DEBUG_LOG, 1,
						&params);

				send_log_size[cpu_id] = 0U;
			} else {
				send_log_size[cpu_id] = log_offs + 1U;
			}
		}
	}
}
#endif
