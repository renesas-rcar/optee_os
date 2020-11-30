// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Renesas Electronics Corporation
 */

#ifndef RCAR_MUTEX_H
#define RCAR_MUTEX_H

void rcar_nex_mutex_lock(struct mutex *m);
void rcar_nex_mutex_unlock(struct mutex *m);

#endif /* RCAR_MUTEX_H */
