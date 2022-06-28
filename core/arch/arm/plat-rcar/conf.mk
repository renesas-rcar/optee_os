PLATFORM_FLAVOR ?= salvator

include core/arch/arm/cpu/cortex-armv8-0.mk

# ARM debugger needs this
platform-cflags-debug-info = -gdwarf-2
platform-aflags-debug-info = -gdwarf-2

$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,36)
$(call force,CFG_GIC,y)
$(call force,CFG_SWDT,y)
$(call force,CFG_MFIS,y)

# Disable core ASLR for two reasons:
# 1. There is no source for ALSR seed, as Rcar platform
#    does not provide DTB to OP-TEE. Also, there is no
#    publically available documentation on integrated
#    hardware RNG, so we can't use it either.
# 2. OP-TEE crashes during boot with enabled CFG_CORE_ASLR.
$(call force,CFG_CORE_ASLR,n)

$(call force,CFG_TEE_CORE_NB_CORE,8)

# This somewhat abuses implementation of get_core_pos_mpidr()
# M3 have 6 cores, but internaly they have ids 0, 1, 4, 5, 6, 7.
# By setting CFG_CORE_CLUSTER_SHIFT to 1, get_core_pos_mpidr()
# will produce correct numbers: 0, 1, 2, 3, 4, 5
#$(call force,CFG_CORE_CLUSTER_SHIFT,1)

CFG_TZDRAM_START ?= 0x44100000
CFG_TZDRAM_SIZE	 ?= 0x03D00000
CFG_TEE_RAM_VA_SIZE ?= 0x100000
ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
supported-ta-targets = ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

CFG_NUM_THREADS ?= 8
CFG_MMAP_REGIONS ?= 21
CFG_TEE_CORE_DEBUG ?= n

CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_WITH_STATS ?= y
CFG_CRYPTO_WITH_CE ?= y

ifeq ($(CFG_EARLY_TA),y)
core-platform-cflags += -Wimplicit-fallthrough=0
endif

ifeq ($(CFG_CRYPT_HW_CRYPTOENGINE),y)
CFG_OTP_SUPPORT ?= y
CFG_DYNAMIC_TA_AUTH_BY_HWENGINE ?= y
CFG_CORE_HUK_SUBKEY_COMPAT_USE_OTP_DIE_ID = $(CFG_CORE_HUK_SUBKEY_COMPAT)
core-platform-cflags += -DCFG_OTP_SUPPORT
core-platform-cflags += -Icore/lib
else
CFG_OTP_SUPPORT := n
CFG_CORE_HUK_SUBKEY_COMPAT_USE_OTP_DIE_ID := n
endif

CFG_DYNAMIC_TA_AUTH_BY_HWENGINE ?= n
ifeq ($(CFG_DYNAMIC_TA_AUTH_BY_HWENGINE),y)
core-platform-cflags += -DRCAR_DYNAMIC_TA_AUTH_BY_HWENGINE
endif

# default setting for Secure Storage
CFG_REE_FS ?= n
CFG_STANDALONE_FS ?= y
STANDALONE_FS_SECTOR_ADDR ?= 0x300000
STANDALONE_FS_SECTOR_NUM ?= 4
# ---

ifeq ($(CFG_STANDALONE_FS),y)
core-platform-cflags += -DSTANDALONE_FS_SECTOR_ADDR=$(STANDALONE_FS_SECTOR_ADDR)
core-platform-cflags += -DSTANDALONE_FS_SECTOR_NUM=$(STANDALONE_FS_SECTOR_NUM)
CFG_HYPER_FLASH := y
CFG_RCAR_UNSUPPORT_TA_VER_DB := y
endif

ifeq ($(CFG_RPMB_FS),y)
CFG_RCAR_UNSUPPORT_TA_VER_DB := y
endif

core-platform-cflags += -DPLATFORM_RCAR
core-platform-cflags += -DMMU_DIRECT_MAPPING

# Not covered by compile - /core/arch/arm/kernel/trace_ext.c
WITH_TRACE_EXT := n

# Compiler switch - Debug log(Linux terminal log)
RCAR_DEBUG_LOG ?= 0
ifneq ($(RCAR_DEBUG_LOG),0)
core-platform-cflags += -DRCAR_DEBUG_LOG
endif

# Compiler switch - Test Debug log(Test verification log)
RCAR_TEST_LOG ?= n
ifeq ($(RCAR_TEST_LOG),y)
core-platform-cflags += -DRCAR_TEST_LOG
endif

VERSION_OF_RENESAS ?= $(shell awk '/VERSION_OF_RENESAS/{ \
	$$a=substr($$3,2); sub(/.$$/,"",$$a); print $$a}' \
	< core/arch/$(ARCH)/plat-$(PLATFORM)/rcar_version.h 2> /dev/null)
TEE_IMPL_VERSION ?= R-Car Rev.$(VERSION_OF_RENESAS)
CFG_TEE_MANUFACTURER ?= LINARO & Renesas Electronics
CFG_TEE_FW_IMPL_VERSION ?= $(TEE_IMPL_VERSION)
CFG_TEE_FW_MANUFACTURER ?= ARM & Renesas Electronics

CFG_CORE_HEAP_SIZE ?= 196608

ifeq ($(CFG_VIRTUALIZATION),y)
CFG_VIRT_GUEST_COUNT ?= 3
CFG_RCAR_MUTEX_DELAY ?= 1
core-platform-cflags += -DCFG_RCAR_MUTEX_DELAY=$(CFG_RCAR_MUTEX_DELAY)
CFG_CORE_RESERVED_SHM ?= n
PLATFORM_FLAVOR ?= salvator_h3
endif
