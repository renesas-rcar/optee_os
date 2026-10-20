// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#include <arm.h>
#include <compiler.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tee/cache.h>
#include <trace.h>

#include "platform_config.h"
#include "rcar_ldr.h"
#include "rcar_ldr_private.h"
#include "rcar_ldr_dlt_wire.h"
#include "lib/ldr_ring_buffer.h"

#define OPTEE_LDR_RING_SIZE_MAX UL(0x3FE00)

static_assert(sizeof(struct ldr_ring_buffer_header) == 32U,
	      "ldr_ring_buffer_header ABI size changed");

static_assert(sizeof(struct ldr_queue_header) == 16U,
	      "ldr_queue_header ABI size changed");

static_assert(sizeof(struct user_protocol_header) == 8U,
	      "user_protocol_header ABI size changed");

static_assert(sizeof(struct standard_header) == 4U,
	      "standard_header ABI size changed");

static_assert(sizeof(struct standard_header_extra) == 12U,
	      "standard_header_extra ABI size changed");

static_assert(sizeof(struct extended_header) == 10U,
	      "extended_header ABI size changed");

static_assert((OPTEE_LDR_RING_BASE % LDR_ALIGNE_LENGTH) == 0U,
	      "OPTEE_LDR_RING_BASE must be 16-byte aligned");

static_assert(OPTEE_LDR_RING_SIZE <= OPTEE_LDR_RING_SIZE_MAX,
	      "OPTEE_LDR_RING_SIZE exceeds the reserved 255 KB");

/* Application and context IDs reported to the daemon and viewers. */
#define LDR_OPTEE_APID			"TEE "
#define LDR_OPTEE_CTID			"TEE "

/*
 * ECU id placeholder.
 */
#define LDR_OPTEE_ECUID			"ECU1"

/* htyp: version 1, ECU id + session id + timestamp present, extended hdr. */
#define LDR_OPTEE_HTYP			(LDR_HTYP_PROTOCOL_VERSION1 |	\
					 LDR_HTYP_WEID |		\
					 LDR_HTYP_WSID |		\
					 LDR_HTYP_WTMS |		\
					 LDR_HTYP_UEH)

/*
 * DLT message-type-info (MTIN) values for log messages.
 */
#define LDR_DLT_MTIN_NONE              -1
#define LDR_DLT_MTIN_FATAL             1U
#define LDR_DLT_MTIN_ERROR             2U
#define LDR_DLT_MTIN_WARN              3U
#define LDR_DLT_MTIN_INFO              4U
#define LDR_DLT_MTIN_DEBUG             5U
#define LDR_DLT_MTIN_VERBOSE           6U

/* Fixed header bytes ahead of the payload: 8 + 4 + 12 + 10 = 34. */
#define LDR_HDR_TOTAL			(sizeof(struct user_protocol_header) +	\
					 sizeof(struct standard_header) +	\
					 sizeof(struct standard_header_extra) +	\
					 sizeof(struct extended_header))

/* Payload argument header: 4-byte type_info + 2-byte length. */
#define LDR_PAYLOAD_HDR			(sizeof(uint32_t) + sizeof(uint16_t))

/*
 * Maximum formatted text per record, including the NUL terminator.
 */
#define LDR_MSG_TEXT_MAX		MAX_PRINT_SIZE

#define LDR_MSG_BUF_SIZE		(LDR_HDR_TOTAL + LDR_PAYLOAD_HDR +	\
					 LDR_MSG_TEXT_MAX)

static_assert(LDR_MSG_BUF_SIZE < 2000U,
	      "LDR record exceeds daemon size limit");

static struct ldr_state ldr_state __nex_bss;

static unsigned int ldr_lock __nex_bss = SPINLOCK_UNLOCK;

static uint8_t ldr_msg_buf[LDR_MSG_BUF_SIZE] __nex_bss;

/*
 * Resolve the ring region address, honouring MMU state.
 * -MMU off : return the physical address directly. The CPU is in
 *            identity-mapped mode; PA == VA. No TLB or cache is active.
 *
 * -MMU on  : resolve via phys_to_virt(MEM_AREA_IO_SEC).
 *
 */
static vaddr_t ldr_get_ring_va(void)
{
	if (cpu_mmu_enabled()) {
		vaddr_t va = (vaddr_t)phys_to_virt((paddr_t)OPTEE_LDR_RING_BASE,
						   MEM_AREA_IO_SEC,
						   OPTEE_LDR_RING_SIZE);
		if (!va)
			panic("LDR: failed to resolve ring VA");
		return va;
	}
	return (vaddr_t)OPTEE_LDR_RING_BASE;
}

/*
 * Map an LDR log level to a DLT MTIN value.
 */
static uint8_t ldr_level_to_mtin(int level)
{
	switch (level) {
	case LDR_LOG_LEVEL_ERROR:
		return LDR_DLT_MTIN_ERROR;
	case LDR_LOG_LEVEL_INFO:
		return LDR_DLT_MTIN_INFO;
	case LDR_LOG_LEVEL_DEBUG:
		return LDR_DLT_MTIN_DEBUG;
	case LDR_LOG_LEVEL_FLOW:
		return LDR_DLT_MTIN_VERBOSE;
	case LDR_LOG_LEVEL_INDEPENDENT:
		return LDR_DLT_MTIN_INFO;
	default:
		return LDR_DLT_MTIN_NONE;
	}
}

/*
 * Short level tag placed at the start of the text payload so a raw memory
 * dump of the region stays readable without a DLT viewer.
 */
static const char *ldr_level_prefix(int level)
{
	switch (level) {
	case LDR_LOG_LEVEL_ERROR:
		return "E:";
	case LDR_LOG_LEVEL_INFO:
		return "I:";
	case LDR_LOG_LEVEL_DEBUG:
		return "D:";
	case LDR_LOG_LEVEL_FLOW:
		return "V:";
	case LDR_LOG_LEVEL_INDEPENDENT:
		return "I:";
	default:
		return "?:";
	}
}

/*
 * 32-bit DLT timestamp in 100 us units, from the ARM generic counter.
 *
 * barrier_read_counter_timer() issues an ISB before reading CNTPCT_EL0,
 * preventing the read from being reordered ahead of preceding instructions.
 * OP-TEE at S-EL1 has no authority to write CNTFRQ_EL0 (EL3-only).
 *
 */
static uint32_t ldr_get_timestamp_100us(void)
{
	uint64_t counter = barrier_read_counter_timer();
	uint64_t freq = read_cntfrq();
	uint64_t ticks;

	if (freq == 0ULL)
		return 0U;

	ticks = ((counter / freq) * 10000ULL) +
		(((counter % freq) * 10000ULL) / freq);

	return (uint32_t)ticks;
}

/*
 * Initialize the LDR subsystem.
 *
 */
void rcar_ldr_init(void)
{
	vaddr_t ring_va;

	if (ldr_state.initialized)
		return;

	ring_va = ldr_get_ring_va();

	(void)ldr_ring_buf_mmgr_init((uint8_t *)ring_va,
				     (uint32_t)OPTEE_LDR_RING_SIZE);

	ldr_state.msg_counter   = 0U;
	ldr_state.dropped_count = 0U;

	if (cpu_mmu_enabled())
		cache_operation(TEE_CACHEFLUSH, (void *)ring_va,
				OPTEE_LDR_RING_SIZE);

	ldr_state.initialized = true;
}

/*
 * Format one OP-TEE trace message, wrap it in a DLT log frame and enqueue the
 * frame into the Shared DRAM ring buffer. The LDR Daemon running in the Normal
 * World reads the frame from the ring buffer and forwards it to DLT Viewer.
 *
 */
void rcar_ldr_record(int level, const char *fmt, ...)
{
	uint8_t *buf = ldr_msg_buf;
	struct user_protocol_header *usr_hdr;
	struct standard_header *std_hdr;
	struct standard_header_extra *extra_hdr;
	struct extended_header *ext_hdr;
	const char *prefix;
	uint8_t *text;
	uint32_t type_info = LDR_TYPE_INFO_STRG | LDR_SCOD_ASCII;
	uint16_t text_len;
	size_t prefix_len;
	size_t total;
	va_list args;
	int formatted;
	uint8_t msin;
	ldr_errno_t ret;
	uint32_t exceptions;

	if (!ldr_state.initialized || !fmt || level == LDR_LOG_LEVEL_NONE)
		return;

	exceptions = cpu_spin_lock_xsave(&ldr_lock);

	text = buf + LDR_HDR_TOTAL + LDR_PAYLOAD_HDR;

	prefix = ldr_level_prefix(level);
	prefix_len = strlen(prefix);
	(void)memcpy(text, prefix, prefix_len);

	va_start(args, fmt);
	formatted = vsnprintf((char *)text + prefix_len,
			      LDR_MSG_TEXT_MAX - prefix_len, fmt, args);
	va_end(args);

	if (formatted < 0) {
		cpu_spin_unlock_xrestore(&ldr_lock, exceptions);
		return;
	}

	if ((size_t)formatted >= (LDR_MSG_TEXT_MAX - prefix_len))
		text_len = (uint16_t)LDR_MSG_TEXT_MAX;
	else
		text_len = (uint16_t)(prefix_len + (size_t)formatted + 1U);

	/* user_protocol_header: LDR transport envelope "DUH\x01" + type tag. */
	usr_hdr = (struct user_protocol_header *)buf;
	usr_hdr->pattern[0] = 'D';
	usr_hdr->pattern[1] = 'U';
	usr_hdr->pattern[2] = 'H';
	usr_hdr->pattern[3] = 1;
	usr_hdr->message = LDR_USER_MESSAGE_LOG;

	/* standard_header: len is patched below once the total is known. */
	std_hdr = (struct standard_header *)(buf + sizeof(struct user_protocol_header));
	std_hdr->htyp = (uint8_t)LDR_OPTEE_HTYP;
	std_hdr->mcnt = ldr_state.msg_counter;
	ldr_state.msg_counter++;

	/* standard_header_extra: ECU id, session id, timestamp (big-endian). */
	extra_hdr = (struct standard_header_extra *)(buf + sizeof(struct user_protocol_header) +
					    sizeof(struct standard_header));
	(void)memcpy(extra_hdr->ecu, LDR_OPTEE_ECUID, LDR_ID_SIZE);
	extra_hdr->seid = LDR_HTOBE_32((uint32_t)get_core_pos() + 1U);
	extra_hdr->tmsp = LDR_HTOBE_32(ldr_get_timestamp_100us());
	ext_hdr = (struct extended_header *)(buf + sizeof(struct user_protocol_header) +
				    sizeof(struct standard_header) +
				    sizeof(struct standard_header_extra));
	msin = (uint8_t)(((uint32_t)LDR_TYPE_LOG << LDR_MSIN_MSTP_SHIFT) |
			 (((uint32_t)ldr_level_to_mtin(level) <<
			   LDR_MSIN_MTIN_SHIFT) & LDR_MSIN_MTIN));
	msin |= LDR_MSIN_VERB;
	ext_hdr->msin = msin;
	ext_hdr->noar = 1U;
	(void)memcpy(ext_hdr->apid, LDR_OPTEE_APID, LDR_ID_SIZE);
	(void)memcpy(ext_hdr->ctid, LDR_OPTEE_CTID, LDR_ID_SIZE);
	(void)memcpy(buf + LDR_HDR_TOTAL, &type_info, sizeof(type_info));
	(void)memcpy(buf + LDR_HDR_TOTAL + sizeof(type_info), &text_len,
		     sizeof(text_len));

	total = LDR_HDR_TOTAL + LDR_PAYLOAD_HDR + (size_t)text_len;

	std_hdr->len = (int16_t)LDR_HTOBE_16((uint16_t)total);

	ret = ldr_ring_buf_mmgr_enqueue((uint8_t *)ldr_get_ring_va(), buf,
					(uint32_t)total);

	if (ret == (ldr_errno_t)LDR_RB_SIZE_OVERFLOW) {
		/*
		 * Ring is full. ldr_ring_buffer refuses the write rather than
		 * overwriting the oldest record, so it is the newest log that
		 * is lost. Expected before the daemon starts draining; counted
		 * so the loss is visible rather than silent.
		 */
		ldr_state.dropped_count++;
	} else if (cpu_mmu_enabled()) {
		/*
		 * Only flush when the D-cache is active. Records written
		 * before MMU enablement go directly to DRAM and need no flush.
		 */
		cache_operation(TEE_CACHEFLUSH, (void *)ldr_get_ring_va(), OPTEE_LDR_RING_SIZE);
	}

	cpu_spin_unlock_xrestore(&ldr_lock, exceptions);
}

int ldr_level_from_trace_str(const char *str)
{
	if (!str || str[0] == '\0' || str[1] != '/')
		return LDR_LOG_LEVEL_NONE;

	switch (str[0]) {
	case 'M': return LDR_LOG_LEVEL_INDEPENDENT;
	case 'E': return LDR_LOG_LEVEL_ERROR;
	case 'I': return LDR_LOG_LEVEL_INFO;
	case 'D': return LDR_LOG_LEVEL_DEBUG;
	case 'F': return LDR_LOG_LEVEL_FLOW;
	default:  return LDR_LOG_LEVEL_NONE;
	}
}
