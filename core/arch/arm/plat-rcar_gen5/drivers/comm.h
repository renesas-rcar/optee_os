/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Renesas Electronics Corporation.
 */

#include "comm_shared.h"

void r_comm_trigger_secure(const void *p_sevice_param, size_t param_size);
void r_comm_main_init(uint32_t base_shared_mem);
void r_comm_wait_secure_cpu_init(uint32_t cpu_completed_state);
void r_comm_set_status_main_to_sec(uint32_t infor, uint32_t set_value);

/* End of file */
