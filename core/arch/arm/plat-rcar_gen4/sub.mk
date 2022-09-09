global-incdirs-y += .
global-incdirs-y += include
srcs-y += main.c
srcs-$(CFG_OTP_SUPPORT) += tee_common_otp.c
srcs-y += rcar_log_func.c
srcs-y += rcar_mutex.c

# Copy the base file - /core/arch/arm/kernel/
srcs-y += trace_ext.c

subdirs-y += drivers
subdirs-y += tee
