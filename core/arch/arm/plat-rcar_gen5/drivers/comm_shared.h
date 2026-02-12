/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Renesas Electronics Corporation.
 */

#if !defined(SHARED_H)
#define SHARED_H

#include <stdint.h>

#define INTER_CORE_COMM_SHARED_MEM_ADDR     (0x185C0000uL)

#define SHARED_FLAG_SIZE          (16U)
#define SHARED_DATA_SIZE          (104U)
#define SHARED_PAYLOAD_SIZE       (76U)

#define REQ_STATE_NONE         (0xA5A5A500u)
#define REQ_STATE_REQUEST      (0xA5A5A505u)  /* Trigger request */
#define REQ_STATE_EXECUTE      (0xA5A5A506u)  /* Request executing */
#define REQ_STATE_COMPLETE     (0xA5A5A507u)  /* Request Completed */
#define REQ_STATE_GET_RESULT   (0xA5A5A508u)  /* Result acquisition completed */

#define  MAIN_CPU_INIT_DONE             (0x10000000u)
#define  SECURE_CPU_INIT_DONE           (0x10000000u)
#define SB_IMAGE_HASH_WORD_SIZE         (0x8u)       /* Image hash WORD size */

/*
 * Typedef definitions
 */

typedef enum {
	ALL_OK  = 0,
	NG,
	UNKNOWN_TYPE,
} result_t;

typedef struct {
	uint32_t flag;
	uint32_t status_main_to_sec;	/* For notification from the Main CPU
					 * to the Secure CPU
					 */
	uint32_t status_sec_to_main;	/* For notification from the Secure CPU
					 * to the Main CPU
					 */
} shared_flag_t;

typedef struct {
	uint8_t service_id;
	uint32_t param[100];
} generic_data_t;

typedef struct {
	uint32_t notify_type;    /* Communication notification type */
	uint16_t service_type;   /* The type of request to process */
	uint32_t service_result; /* Request processing status */
	uint32_t data_len;       /* Data Length */
	void *p_data;            /* A pointer where the actual data is stored */
} r_lsc_comm_payload_t;

extern volatile shared_flag_t *p_shared_flag;
extern volatile r_lsc_comm_payload_t *p_shared_payload;
extern volatile void *p_shared_data;

#endif /* SHARED_H */

/* End of file */
