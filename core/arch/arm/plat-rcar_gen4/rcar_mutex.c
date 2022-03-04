// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Renesas Electronics Corporation
 */

#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <optee_rpc_cmd.h>

#include "../kernel/mutex_lockdep.h"
#include "rcar_mutex.h"

void rcar_nex_mutex_lock(struct mutex *m)
{
#ifdef CFG_VIRTUALIZATION
	bool can_lock;
	TEE_Result res = TEE_SUCCESS;
	struct thread_param params = THREAD_PARAM_VALUE(IN,
					CFG_RCAR_MUTEX_DELAY, 0, 0);

	can_lock = mutex_trylock(m);

	while (!can_lock) {
		res = thread_rpc_cmd(OPTEE_RPC_CMD_SUSPEND, 1, &params);

		if (res != TEE_SUCCESS) {
			panic("rcar_nex_mutex_lock failed");
		}
		can_lock = mutex_trylock(m);
	}
#else
	mutex_lock(m);
#endif
}

void rcar_nex_mutex_unlock(struct mutex *m)
{
#ifdef CFG_VIRTUALIZATION
	uint32_t old_itr_status;

	old_itr_status = cpu_spin_lock_xsave(&m->spin_lock);

	if (m->state == 0U) {
		panic("rcar_nex_mutex_unlock failed");
	}

	m->state = 0;

	cpu_spin_unlock_xrestore(&m->spin_lock, old_itr_status);
#else
	mutex_unlock(m);
#endif
}
