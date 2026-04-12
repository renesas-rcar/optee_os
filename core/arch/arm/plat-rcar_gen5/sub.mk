global-incdirs-y += .
global-incdirs-y += include
srcs-y += main.c
srcs-y += rcar_log_func.c
srcs-y += trace_ext.c
srcs-$(RCAR_TRNG_BY_RSIPM_HWENGINE) += rcar_trng.c
srcs-$(CFG_DYNAMIC_TA_AUTH_BY_HWENGINE) += rcar_ta_auth.c
srcs-$(CFG_DYNAMIC_TA_AUTH_BY_HWENGINE) += rcar_fw_security_service.c
srcs-y += rcar_version.c

subdirs-y += drivers
