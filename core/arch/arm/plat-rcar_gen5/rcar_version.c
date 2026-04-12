// SPDX-License-Identifier: BSD-2-Clause
 /*
  * Copyright (c) 2026, Renesas Electronics Corporation
  */

#include <stdlib.h>
#include <string.h>
#include <rcar_version.h>

/*
 * brief:	Parsing the value of RCar renesas version from string to number
 *		for transferring to the TEE Driver of the Normal World
 * param[in]	*versionString	- pointer to the address where contains
 *					the revision value as string
 * return	version_t	- return the version that contains the value
 *					as number(uint) of the revision
 */
static version_t convertVersion(const char *versionString)
{
	char *endptr;
	version_t version = {0};

	if (!versionString)
		return version;

	version.major = (int)strtoul(versionString, &endptr, 10);
	if (*endptr != '.')
		return version;
	version.minor = (int)strtoul(endptr + 1, &endptr, 10);
	if (*endptr != '.')
		return version;
	version.patch = (int)strtoul(endptr + 1, &endptr, 10);
	return version;
}

/*
 * brief:	Getting the RCar BSP revision and start passing
 *		the value to the Normal World
 * param[in/out]	*args	- pointer to the address where will contain
 *				the revision value as number for accessing
 *				from TEE Driver
 */
void tee_entry_get_rcar_bsp_revision(struct thread_smc_args *args)
{
	version_t version = {0};

	/* Get the RCar revision */
	version = convertVersion(VERSION_OF_RENESAS);

	/* Passed revision value to TEE Drv */
	args->a0 = version.major;
	args->a1 = version.minor;
	args->a2 = version.patch;
}
