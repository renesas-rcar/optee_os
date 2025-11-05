// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Renesas Electronics Corporation.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "comm_shared.h"
#include "comm.h"
#include "platform_config.h"

/*
 * Function name: r_comm_trigger_secure
 * Description  : Trigger secure CPU processing by setting shared flags
			and waiting for completion.
 * Arguments    : p_sevice_param : Pointer to the input parameters
 *                param_size   : Size of the input parameters
 * Return Value : None
 */

void r_comm_trigger_secure(const void *p_sevice_param, size_t param_size)
{
	while (p_shared_flag->flag != REQ_STATE_NONE)
		;	/* Wait */

	p_shared_payload->p_data = (void *)p_sevice_param;
	p_shared_payload->data_len = param_size;
	p_shared_flag->flag = REQ_STATE_REQUEST;

	/* Wait until the flag changes to REQ_STATE_COMPLETE
	 * on the SECURE_CPU side
	 */
	while (p_shared_flag->flag != REQ_STATE_COMPLETE)
		;	/* Wait */

	/* After the service is completed,
	 * set the flag to REQ_STATE_GET_RESULT
	 */
	 p_shared_flag->flag = REQ_STATE_GET_RESULT;
}

/*
 * Function name: r_comm_main_init
 * Description  : Initialize shared memory for communication with secure CPU.
 * Arguments    :
 *          (IN) base_share: the base address of shared memory
				for communicating with secure core
 * Return Value : None
 */
void r_comm_main_init(uint32_t base_shared_mem)
{
	p_shared_flag = (volatile void *)(uintptr_t)base_shared_mem;
	p_shared_payload = (volatile void *)(uintptr_t)(base_shared_mem
			+ SHARED_FLAG_SIZE);
	p_shared_data = (volatile void *)(uintptr_t)(base_shared_mem
			+ SHARED_FLAG_SIZE + SHARED_PAYLOAD_SIZE);

	p_shared_flag->flag = REQ_STATE_NONE;
}

/*
 * Function name: r_comm_wait_secure_cpu_init
 * Description  : Wait until the secure CPU sets the READY bit in shared status.
 * Arguments    :
 *              (IN) completed_state: the initial state of CPU
 *                  + MAIN_CPU_INIT_DONE for main CPU
 *                  + SECURE_CPU_INIT_DONE for secure CPU
 * Return Value : None
 */
void r_comm_wait_secure_cpu_init(uint32_t cpu_completed_state)
{
	while ((p_shared_flag->status_sec_to_main & cpu_completed_state)
			!= cpu_completed_state)
		;	/* Wait */
}

/*
 * Function name: r_comm_set_status_main_to_sec
 * Description  : Set or clear the status bits from Main to Secure CPU.
 * Arguments    : infor      : Bit(s) to set or clear
 *                set_value : 1 to set, 0 to clear the bit(s)
 * Return Value : None
 */
void r_comm_set_status_main_to_sec(uint32_t infor, uint32_t set_value)
{
	if (set_value == 1)
		p_shared_flag->status_main_to_sec |= infor;
	else
		p_shared_flag->status_main_to_sec &= ~infor;
}

/* End of file */
