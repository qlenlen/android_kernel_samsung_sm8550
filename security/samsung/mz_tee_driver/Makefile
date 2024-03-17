#
# Crypto TEE Driver
#

obj-$(CONFIG_MZ_TEE_DRIVER) += tee_driver.o

tee_driver-$(CONFIG_MZ_USE_QSEECOM) += mz_tee_driver_qc.o
tee_driver-$(CONFIG_MZ_USE_TZDEV) += mz_tee_driver_teegris.o

ccflags-$(CONFIG_MZ_TEE_DRIVER) += -I$(srctree)/drivers/security/samsung/mz
ccflags-$(CONFIG_MZ_TEE_DRIVER) += -I$(srctree)/drivers/misc
ccflags-$(CONFIG_MZ_USE_TZDEV) += -I$(srctree)/drivers/misc/tzdev/include

subdir-ccflags-y := -Wformat

ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
	ccflags-y += -DMZ_DEBUG -DDEBUG
endif
