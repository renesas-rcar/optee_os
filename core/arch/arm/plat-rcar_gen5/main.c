// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Renesas Electronics Corporation.
 */

#include <console.h>
#include <crypto/crypto.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <drivers/hscif.h>
#include <drivers/gic.h>
#include <sm/optee_smc.h>
#include <tee/entry_fast.h>
#include <tee/tee_cryp_utl.h>

#include "rcar_log_func.h"
#include "rcar-common.h"

#ifdef MEMORY1_BASE
register_phys_mem_pgdir(MEMORY1_TYPE, MEMORY1_BASE, MEMORY1_SIZE);
#endif
#ifdef MEMORY2_BASE
register_phys_mem(MEMORY2_TYPE, MEMORY2_BASE, MEMORY2_SIZE);
#endif
#ifdef MEMORY3_BASE
register_phys_mem_pgdir(MEMORY3_TYPE, MEMORY3_BASE, MEMORY3_SIZE);
#endif
#ifdef MEMORY4_BASE
register_phys_mem(MEMORY4_TYPE, MEMORY4_BASE, MEMORY4_SIZE);
#endif
#ifdef MEMORY5_BASE
register_phys_mem_pgdir(MEMORY5_TYPE, MEMORY5_BASE, MEMORY5_SIZE);
#endif
#ifdef MEMORY6_BASE
register_phys_mem_pgdir(MEMORY6_TYPE, MEMORY6_BASE, MEMORY6_SIZE);
#endif
#ifdef MEMORY7_BASE
register_phys_mem_pgdir(MEMORY7_TYPE, MEMORY7_BASE, MEMORY7_SIZE);
#endif
#ifdef MEMORY8_BASE
register_phys_mem_pgdir(MEMORY8_TYPE, MEMORY8_BASE, MEMORY8_SIZE);
#endif
#ifdef DEVICE0_PA_BASE
register_phys_mem_pgdir(DEVICE0_TYPE, DEVICE0_PA_BASE, DEVICE0_SIZE);
#endif
#ifdef DEVICE1_PA_BASE
register_phys_mem_pgdir(DEVICE1_TYPE, DEVICE1_PA_BASE, DEVICE1_SIZE);
#endif

#ifdef CFG_SCIF
static struct hscif_uart_data console_data __nex_bss;
#endif

#ifdef PRR_BASE
uint32_t rcar_prr_value __nex_bss;
#endif

void plat_console_init(void)
{
#ifdef CFG_SCIF
	hscif_uart_init(&console_data, CONSOLE_UART_START);
	register_serial_console(&console_data.chip);
#endif
}

#ifdef CFG_RCAR_ROMAPI
/* Should only seed from a hardware random number generator */
unsigned long plat_get_aslr_seed(void)
{
	unsigned long seed = 0;

	/* On RCAR we can get hw random bytes on early boot stages */
	if (crypto_rng_read(&seed, sizeof(seed)))
		panic();

	return seed;
}
#endif

void boot_primary_init_intc(void)
{
	gic_init(GICC_BASE, GICD_BASE);
#ifndef CFG_SCIF
	/* Initialize logging feature */
	log_buf_init();
#endif
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}

#ifdef CFG_WITH_SOFTWARE_PRNG /* using the SW RNG supported*/
void plat_rng_init(void)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Time t = { };

	res = crypto_rng_init(&t, sizeof(t));
	if (res) {
		EMSG("Failed to initialize RNG: %#" PRIx32, res);
		panic();
	}
}
#endif /*END CFG_WITH_SOFTWARE_PRNG */
/* For logging output function */
/* Overriding the default __weak tee_entry_fast() */
void tee_entry_fast(struct thread_smc_args *args)
{
	DMSG("IN args->a0=0x%lX", args->a0);
	if (args->a0 == OPTEE_SMC_GET_SHM_CONFIG &&
	    args->a1 == SMC_RCAR_CMD &&
	    args->a2 == NORMAL_WORLD_COMPLETE_INIT) {
		is_normal_world_initialized = 1;
		DMSG("Normal World was initialized");
	}
	 __tee_entry_fast(args);
	 DMSG("OUT Received SMC from Normal World");
}

