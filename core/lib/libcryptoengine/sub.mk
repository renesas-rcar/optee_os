#Provider for Crypto Engine Secure
srcs-y += tee_ss_provider.c
cflags-tee_ss_provider.c-y += -Wno-unused-function
cflags-tee_ss_provider.c-y += -Wno-int-to-pointer-cast
cflags-tee_ss_provider.c-y += -Wno-strict-aliasing
cflags-tee_ss_provider.c-y += -Wno-pedantic
cflags-tee_ss_provider.c-y += -Wno-undef -Wno-maybe-uninitialized

# Common Function for Provider
srcs-y += tee_provider_common.c
