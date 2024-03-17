$(info MZ kernel makefile main $$CONFIG_MEMORY_ZEROISATION is [${CONFIG_MEMORY_ZEROISATION}])
obj-$(CONFIG_MEMORY_ZEROISATION) += mz_ioctl.o mz.o mz_crypto.o mz_mem.o mz_log.o
ccflags-$(CONFIG_MEMORY_ZEROISATION) += -Wno-error \
	-Wno-unused \
	-DMZ_TA

ifneq (,$(filter $(CONFIG_SOC_S5E9925) $(CONFIG_SOC_S5E8825) $(CONFIG_MZ_PAGE_V2), y))
	obj-$(CONFIG_MEMORY_ZEROISATION) += mz_page_v5_10.o
else
	obj-$(CONFIG_MEMORY_ZEROISATION) += mz_page.o
endif

ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
	ccflags-$(CONFIG_MEMORY_ZEROISATION) += -DMZ_DEBUG -DDEBUG
endif

ifeq ($(CONFIG_SEC_KUNIT), y)
	GCOV_PROFILE := y
	ccflags-y += -DMEZ_KUNIT_ENABLED
	obj-$(CONFIG_MEMORY_ZEROISATION) += test/
endif
