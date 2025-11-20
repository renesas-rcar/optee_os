global-incdirs-y += .

CFG_HYPER_FLASH_ENABLED := $(or $(CFG_HYPER_FLASH),$(CFG_SECURE_STORAGE_BY_ICUMX_HWENGINE))
srcs-$(CFG_HYPER_FLASH_ENABLED) += qspi_hyper_flash_common.c
srcs-$(CFG_HYPER_FLASH_ENABLED) += qspi_hyper_flash.c
srcs-$(CFG_HYPER_FLASH_ENABLED) += hyper_flash_control.c
srcs-$(CFG_HYPER_FLASH_ENABLED) += qspi_flash_common.c
srcs-$(CFG_HYPER_FLASH_ENABLED) += qspi_onboard_control.c
srcs-$(CFG_HYPER_FLASH_ENABLED) += mfis_lock.c
