global-incdirs-y += .
global-incdirs-y += include
srcs-y += main.c
srcs-$(CFG_OTP_SUPPORT) += tee_common_otp.c
srcs-y += rcar_log_func.c
srcs-y += rcar_mutex.c
srcs-$(CFG_DYNAMIC_TA_AUTH_BY_HWENGINE) += rcar_ta_auth.c
srcs-$(CFG_ICUM_FW_SERVICE) += rcar_fw_security_service.c

# Copy the base file - /core/arch/arm/kernel/
srcs-y += trace_ext.c

subdirs-y += drivers
subdirs-y += tee
subdirs-$(CFG_DYNAMIC_TA_AUTH_BY_HWENGINE) += secure
