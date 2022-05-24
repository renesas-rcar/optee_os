global-incdirs-y += .
global-incdirs-y += include
srcs-y += main.c
srcs-$(CFG_OTP_SUPPORT) += tee_common_otp.c
srcs-y += rcar_mutex.c

subdirs-y += drivers
subdirs-y += tee
