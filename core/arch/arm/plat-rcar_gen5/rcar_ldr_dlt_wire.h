/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Renesas Electronics Corporation. All rights reserved.
 *
 * LDR DLT wire-format definitions for the OP-TEE producer.
 *
 */

#ifndef LDR_DLT_WIRE_H
#define LDR_DLT_WIRE_H

#include <stdint.h>

#define LDR_ID_SIZE			4U

#define LDR_USER_MESSAGE_LOG		1U

#define LDR_SWAP_16(x)			((uint16_t)((((x) >> 8) & 0xffU) |	\
					  (((x) << 8) & 0xff00U)))
#define LDR_SWAP_32(x)			((uint32_t)((((x) >> 24) & 0xffU) |	\
					  (((x) << 8)  & 0xff0000U) |		\
					  (((x) >> 8)  & 0xff00U) |		\
					  (((x) << 24) & 0xff000000U)))
#define LDR_HTOBE_16(x)			LDR_SWAP_16(x)
#define LDR_HTOBE_32(x)			LDR_SWAP_32(x)

/* Standard-header type (htyp) flags.*/

#define LDR_HTYP_UEH			0x01	/* Extended header present     */
#define LDR_HTYP_MSBF			0x02	/* MSB first                   */
#define LDR_HTYP_WEID			0x04	/* ECU id present              */
#define LDR_HTYP_WSID			0x08	/* Session id present          */
#define LDR_HTYP_WTMS			0x10	/* Timestamp present           */
#define LDR_HTYP_VERS			0xe0	/* Protocol version field      */

#define LDR_HTYP_PROTOCOL_VERSION1	(1 << 5)

/* Optional-field sizes.*/
#define LDR_SIZE_WEID			LDR_ID_SIZE
#define LDR_SIZE_WSID			(sizeof(uint32_t))
#define LDR_SIZE_WTMS			(sizeof(uint32_t))

/* Message types.*/
#define LDR_TYPE_LOG			0x00

/* Message-info (msin) field.*/
#define LDR_MSIN_VERB			0x01
#define LDR_MSIN_MSTP			0x0e
#define LDR_MSIN_MTIN			0xf0
#define LDR_MSIN_MSTP_SHIFT		1
#define LDR_MSIN_MTIN_SHIFT		4

/* Payload argument type info.*/
#define LDR_TYPE_INFO_STRG		0x00000200U
#define LDR_SCOD_ASCII			0x00000000U

struct user_protocol_header {
	char     pattern[LDR_ID_SIZE];	/* "DUH\x01"                          */
	uint32_t message;
} __packed;

struct standard_header {
	uint8_t  htyp;
	uint8_t  mcnt;
	int16_t  len;			/* big-endian on the wire             */
} __packed;

struct standard_header_extra {
	uint8_t  ecu[LDR_ID_SIZE];
	uint32_t seid;			/* big-endian on the wire             */
	uint32_t tmsp;			/* big-endian, 100us units            */
} __packed;

struct extended_header {
	uint8_t msin;
	uint8_t noar;
	char    apid[LDR_ID_SIZE];
	char    ctid[LDR_ID_SIZE];
} __packed;

#endif /* LDR_DLT_WIRE_H */
