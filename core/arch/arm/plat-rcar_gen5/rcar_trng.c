// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Renesas Electronics Corporation
 */
#include <stddef.h>
#include <string.h>
#include "platform_config.h"
#include "drivers/comm.h"
#include "rcar_trng.h"
#include "trace.h"
#include "drivers/comm_shared.h"

void rsipm_communication(uint8_t *buf, uint32_t buf_len)
{
	generic_data_t *p_payload = (generic_data_t *)p_shared_data;
	uint32_t *p_rng_out;

	/* Clear flag */
	p_shared_flag->flag = REQ_STATE_NONE;

	/* Set payload */
	p_payload->service_id = (uint8_t)SERVICE_ID_TRNG;
	p_shared_payload->service_result = SERVICE_RESULT_OK;
	p_shared_payload->data_len = buf_len;
	p_shared_payload->p_data = (void *)p_payload;

	/* trigger communication */
	r_comm_trigger_secure(p_payload, p_shared_payload->data_len);
	/* get the trng */
	p_rng_out = (uint32_t *)p_payload->param;

	(void)memcpy((uint8_t *)buf, (uint8_t *)p_rng_out, buf_len);
}

void rsipm_trng_generate(uint8_t *buf, uint32_t buf_len)
{
	/* Initialize shared buffer */
	IMSG("START: Initialize shared buffer: %lx\r\n",
			INTER_CORE_COMM_SHARED_MEM_ADDR);
	r_comm_main_init(INTER_CORE_COMM_SHARED_MEM_ADDR);
	IMSG("FINISHED: Initialize shared buffer: %lx\r\n",
			INTER_CORE_COMM_SHARED_MEM_ADDR);

	/* Wait for Secure CPU initialization to complete */
	/* r_comm_wait_secure_cpu_init(SECURE_CPU_INIT_DONE); */

	/* Notify the Secure CPU that initialization is complete */
	/* r_comm_set_status_main_to_sec(MAIN_CPU_INIT_DONE, 1); */

	/* Trigger communication*/
	IMSG("START: Trigger communication with LLD\r\n");
	rsipm_communication(buf, buf_len);
	IMSG("FINISHED: Trigger communication with LLD\r\n");
}
