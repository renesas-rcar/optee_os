PLATFORM_FLAVOR ?= spider

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_SCIF,y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,36)
$(call force,CFG_GIC,y)

CFG_ARM_GICV3 ?= y
CFG_ARM64_core ?= y

# Disable core ASLR for two reasons:
# 1. There is no source for ALSR seed, as Rcar platform
#    does not provide DTB to OP-TEE. Also, there is no
#    publically available documentation on integrated
#    hardware RNG, so we can't use it either.
# 2. OP-TEE crashes during boot with enabled CFG_CORE_ASLR.
$(call force,CFG_CORE_ASLR,n)

define add_define
DEFINES			+=	-D$(1)$(if $(value $(1)),=$(value $(1)),)
endef

# LSI setting common define
RCAR_S4:=0
RCAR_V4H:=1
RCAR_V4M:=2

$(eval $(call add_define,RCAR_S4))
$(eval $(call add_define,RCAR_V4H))
$(eval $(call add_define,RCAR_V4M))

# The source code supports for R-Car S4, V4H, V4M.
# Set "LSI" as Make paramater with value: "S4", "V4H", "V4M" to select one of them.
ifeq (${LSI},V4H)
  RCAR_LSI:=${RCAR_V4H}
else ifeq (${LSI},V4M)
  RCAR_LSI:=${RCAR_V4M}
else
  LSI = S4
  RCAR_LSI:=${RCAR_S4}
endif
$(eval $(call add_define,RCAR_LSI))

ifeq ($(RCAR_LSI),$(RCAR_S4))			# Target board: S4
$(call force,CFG_TEE_CORE_NB_CORE,8)
CFG_NUM_THREADS = 8
CFG_CORE_CLUSTER_SHIFT = 1
else ifeq ($(RCAR_LSI),$(RCAR_V4H))		# Target board: V4H
$(call force,CFG_TEE_CORE_NB_CORE,4)
CFG_NUM_THREADS = 4
CFG_CORE_CLUSTER_SHIFT = 1
else						# Target board: V4M
$(call force,CFG_TEE_CORE_NB_CORE,4)
CFG_NUM_THREADS = 4
CFG_CORE_CLUSTER_SHIFT = 2
endif
$(info "-- Build for ${LSI} --")

CFG_TZDRAM_START ?= 0x44100000
CFG_TZDRAM_SIZE	 ?= 0x03D00000
CFG_TEE_RAM_VA_SIZE ?= 0x100000
ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
supported-ta-targets = ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

CFG_DT ?= y

CFG_MMAP_REGIONS ?= 22
CFG_CORE_CLUSTER_SHIFT ?= 1
CFG_NUM_THREADS ?= 8

CFG_REE_FS ?= n
CFG_STANDALONE_FS ?= y
STANDALONE_FS_SECTOR_ADDR ?= 0x3B00000
STANDALONE_FS_SECTOR_NUM ?= 4

ifeq ($(CFG_STANDALONE_FS),y)
core-platform-cflags += -DSTANDALONE_FS_SECTOR_ADDR=$(STANDALONE_FS_SECTOR_ADDR)
core-platform-cflags += -DSTANDALONE_FS_SECTOR_NUM=$(STANDALONE_FS_SECTOR_NUM)
CFG_HYPER_FLASH := y
CFG_RCAR_UNSUPPORT_TA_VER_DB := y
endif

ifeq ($(CFG_RPMB_FS),y)
CFG_RCAR_UNSUPPORT_TA_VER_DB := y
endif

core-platform-cflags += -DRCAR_MMU_DIRECT_MAPPING

ifeq ($(CFG_CRYPT_HW_CRYPTOENGINE),y)
CFG_OTP_SUPPORT ?= y
CFG_CORE_HUK_SUBKEY_COMPAT_USE_OTP_DIE_ID = $(CFG_CORE_HUK_SUBKEY_COMPAT)
core-platform-cflags += -DCFG_OTP_SUPPORT
core-platform-cflags += -Icore/lib
else
CFG_OTP_SUPPORT := n
CFG_CORE_HUK_SUBKEY_COMPAT_USE_OTP_DIE_ID := n
endif

CFG_CORE_HEAP_SIZE ?= 196608

# Compiler switch - Debug log(Linux terminal log)
RCAR_DEBUG_LOG ?= 0
ifneq ($(RCAR_DEBUG_LOG),0)
core-platform-cflags += -DRCAR_DEBUG_LOG
endif

CFG_DYNAMIC_TA_AUTH_BY_HWENGINE ?= n
ifeq ($(CFG_DYNAMIC_TA_AUTH_BY_HWENGINE),y)
core-platform-cflags += -DRCAR_DYNAMIC_TA_AUTH_BY_HWENGINE
CFG_ICUM_FW_SERVICE := y
core-platform-cflags += -DTARGET_CORTEX_A
core-platform-cflags += -DTARGET_DEVICE_S4X
core-platform-cflags += -DAARCH64
endif

CFG_TRNG_BY_ICUMX_HWENGINE ?= n
ifeq ($(CFG_TRNG_BY_ICUMX_HWENGINE),y)
core-platform-cflags += -DRCAR_TRNG_BY_ICUMX_HWENGINE
CFG_ICUM_FW_SERVICE := y
core-platform-cflags += -DTARGET_CORTEX_A
core-platform-cflags += -DTARGET_DEVICE_V4H
core-platform-cflags += -DAARCH64
endif

ifeq ($(CFG_VIRTUALIZATION),y)
CFG_VIRT_GUEST_COUNT ?= 3
CFG_RCAR_MUTEX_DELAY ?= 1
core-platform-cflags += -DCFG_RCAR_MUTEX_DELAY=$(CFG_RCAR_MUTEX_DELAY)
CFG_CORE_RESERVED_SHM ?= n
endif
