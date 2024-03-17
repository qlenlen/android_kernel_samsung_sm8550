#
# Makefile for the DSMS
#
DSMS_PREBOOT_BUFFER = true

ccflags-y := -Wformat
ccflags-y += -DDSMS_ALLOWLIST_IGNORE_NAME_SUFFIXES_ENABLE
ccflags-y += -DDSMS_KUNIT_ENABLED
ccflags-y += -I$(srctree)/$(src)/..
ccflags-y += -I$(srctree)/$(src)

obj-y += dsms_test_utils.o
obj-y += security_dsms_access_control_test.o
obj-y += security_dsms_debug_test.o
obj-y += security_dsms_init_test.o
obj-y += security_dsms_kernel_api_test.o
obj-y += security_dsms_netlink_test.o
obj-y += security_dsms_policy_test.o
ifeq ($(DSMS_PREBOOT_BUFFER), true)
    ccflags-y += -DDSMS_PREBOOT_BUFFER_ENABLE
    obj-y += security_dsms_preboot_buffer_test.o
endif
obj-y += security_dsms_rate_limit_test.o
obj-y += security_dsms_test_utils_test.o
