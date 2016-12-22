global-incdirs-y += .
global-incdirs-y += include
srcs-y += main.c
srcs-$(CFG_OTP_SUPPORT) += tee_common_otp.c
srcs-y += rcar_lock.c
srcs-y += rcar_log_func.c
srcs-y += rcar_ddr_training.c
srcs-$(CFG_ARM32_core) += rcar_interruptflags_a32.S
srcs-$(CFG_ARM64_core) += rcar_interruptflags_a64.S
srcs-$(CFG_DYNAMIC_TA_AUTH_BY_HWENGINE) += rcar_ta_auth.c
srcs-$(CFG_ARM32_core) += rcar_call_maskrom_a32.S
srcs-$(CFG_ARM64_core) += rcar_call_maskrom_a64.S
srcs-y += rcar_maskrom.c
srcs-y += rcar_suspend_to_ram.c

# Copy the base file - /core/arch/arm/kernel/
srcs-y += trace_ext.c

subdirs-y += drivers
subdirs-y += tee
