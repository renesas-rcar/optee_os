PLATFORM_FLAVOR ?= X5H
include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_GIC,y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,36)
$(call force,CFG_LPAE_ADDR_SPACE_BITS,36)
# Disable core ASLR for two reasons:
# 1. There is no source for ALSR seed, as Rcar platform
# does not provide DTB to OP-TEE. Also, there is no
# publically available documentation on integrated
# hardware RNG, so we can't use it either.
# 2. OP-TEE crashes during boot with enabled CFG_CORE_ASLR.
$(call force,CFG_CORE_ASLR,n)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_WITH_LPAE,y)
ifeq ($(PLATFORM_FLAVOR), X5H)
$(call force,CFG_RCAR_GEN5, y)
endif

CFG_ARM_GICV3 ?= y
CFG_CRYPTO_WITH_CE ?= n
CFG_TZDRAM_START ?= 0x8C300000
CFG_TZDRAM_SIZE  ?= 0x02000000
supported-ta-targets = ta_arm64
CFG_DT ?= n
CFG_WITH_SOFTWARE_PRNG ?= y
CFG_TEE_CORE_DEBUG ?= n

ifeq ($(CFG_RCAR_GEN5), y)
# 1xx - for SCIFxx
# 2xx - for HSCIFxx
CFG_RCAR_UART ?= 200
$(call force,CFG_CORE_CLUSTER_SHIFT,2) #log2(2) = 4 --> 4(cores/per cluster)
$(call force,CFG_TEE_CORE_NB_CORE,32)
CFG_NUM_THREADS ?= $(CFG_TEE_CORE_NB_CORE)
CFG_MMAP_REGIONS ?= 21
endif

# For logging function
# Compiler switch - Debug log(Linux terminal log)
RCAR_DEBUG_LOG ?= 0
ifneq ($(RCAR_DEBUG_LOG),0)
core-platform-cflags += -DRCAR_DEBUG_LOG
endif

# For virtualization
ifeq ($(CFG_NS_VIRTUALIZATION),y)
CFG_VIRT_GUEST_COUNT ?= 3
CFG_RCAR_MUTEX_DELAY ?= 1
core-platform-cflags += -DCFG_RCAR_MUTEX_DELAY=$(CFG_RCAR_MUTEX_DELAY)
CFG_CORE_RESERVED_SHM ?= n
endif

# For Direct mapping function
core-platform-cflags += -DRCAR_MMU_DIRECT_MAPPING

# For using the rsipm functions
RCAR_TRNG_BY_RSIPM_HWENGINE ?= n
CFG_RSIPM_FW_SERVICE ?= n
ifeq ($(CFG_RSIPM_FW_SERVICE), y)
RCAR_TRNG_BY_RSIPM_HWENGINE = y
core-platform-cflags += -DRCAR_TRNG_BY_RSIPM_HWENGINE
endif

