#
# Makefile for the DSMS
#
DSMS_PREBOOT_BUFFER = true

ccflags-y := -Wformat
ccflags-y += -DDSMS_ALLOWLIST_IGNORE_NAME_SUFFIXES_ENABLE
ccflags-y += -I$(srctree)/$(src)

obj-$(CONFIG_SECURITY_DSMS) := dsms_access_control.o
obj-$(CONFIG_SECURITY_DSMS) += dsms_init.o
obj-$(CONFIG_SECURITY_DSMS) += dsms_kernel_api.o
obj-$(CONFIG_SECURITY_DSMS) += dsms_policy.o
obj-$(CONFIG_SECURITY_DSMS) += dsms_rate_limit.o
obj-$(CONFIG_SECURITY_DSMS) += dsms_netlink.o

ifeq ($(DSMS_PREBOOT_BUFFER), true)
    ccflags-y += -DDSMS_PREBOOT_BUFFER_ENABLE
    obj-$(CONFIG_SECURITY_DSMS) += dsms_preboot_buffer.o
endif

# kunit tests options:
ifeq ($(CONFIG_SEC_KUNIT), y)
    GCOV_PROFILE := y
    ccflags-y += -DDSMS_KUNIT_ENABLED
    obj-$(CONFIG_SECURITY_DSMS) += kunit_test/
endif
