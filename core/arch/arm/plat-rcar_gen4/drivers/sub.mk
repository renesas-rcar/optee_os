global-incdirs-y += .
srcs-$(CFG_HYPER_FLASH) += qspi_hyper_flash_common.c
srcs-$(CFG_HYPER_FLASH) += qspi_hyper_flash.c
srcs-$(CFG_HYPER_FLASH) += hyper_flash_control.c
srcs-$(CFG_HYPER_FLASH) += qspi_flash_common.c
srcs-$(CFG_HYPER_FLASH) += qspi_onboard_control.c
srcs-$(CFG_HYPER_FLASH) += mfis_lock.c
