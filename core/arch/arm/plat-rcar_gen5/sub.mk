global-incdirs-y += .
global-incdirs-y += include
srcs-y += main.c
srcs-y += rcar_log_func.c
srcs-y += trace_ext.c
srcs-$(RCAR_TRNG_BY_RSIPM_HWENGINE) += rcar_trng.c

subdirs-y += drivers
