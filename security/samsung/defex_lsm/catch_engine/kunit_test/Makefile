#
# Makefile for the Defex kunit tests
#

# Features to Enable
PED_ENABLE=true
SAFEPLACE_ENABLE=true
IMMUTABLE_ENABLE=true
LP_ENABLE=true
UMH_RESTRICTION_ENABLE=true
USER_BUILD=false

ifeq (,$(TARGET_BUILD_VARIANT))
    ifeq ($(CONFIG_SECURITY_DEFEX_USER),y)
        USER_BUILD := true
    endif
else
    ifeq ($(TARGET_BUILD_VARIANT),user)
        USER_BUILD := true
    endif
endif

ifneq ($(wildcard $(srctree)/include/crypto/internal/rsa.h),)
    $(warning [DEFEX] INTEGRITY_ENABLE)
    INTEGRITY_ENABLE=true
endif

# caches to enable
CACHES_ENABLE=true

# OEM Unlock dependency
OEM_UNLOCK_DEPENDENCY=true

# use the ramdisk or system_root to store rules file
RAMDISK_ENABLE=true

# do signing for rules
SIGN_ENABLE=true

defex-y += defex_catch_list_test.o
defex-y += defex_ht_test.o
defex-$(CONFIG_COMPAT) += defex_catch_list_compat_test.o

# Immutable Feature is applied with permissive mode first.
DEFEX_DEFINES := -DDEFEX_PERMISSIVE_IM

# Integrity Feature is applied with permissive mode first.
DEFEX_DEFINES += -DDEFEX_PERMISSIVE_INT

ifeq ($(CONFIG_DEFEX_KERNEL_ONLY), y)
    DEFEX_DEFINES += -DDEFEX_KERNEL_ONLY
    ifeq ($(CONFIG_SAMSUNG_PRODUCT_SHIP), y)
        $(warning [DEFEX-KUNIT] Kernel_only & Ship)
    else
        $(warning [DEFEX-KUNIT] Kernel_only & Noship)
        DEFEX_DEFINES += -DDEFEX_PERMISSIVE_INT
        DEFEX_DEFINES += -DDEFEX_PERMISSIVE_SP
        DEFEX_DEFINES += -DDEFEX_PERMISSIVE_IM
        DEFEX_DEFINES += -DDEFEX_PERMISSIVE_LP
        DEFEX_DEFINES += -DDEFEX_DEBUG_ENABLE
    endif
endif

ifeq ($(CONFIG_SEC_FACTORY), y)
    DEFEX_DEFINES += -DDEFEX_FACTORY_ENABLE
endif

ifeq ($(PED_ENABLE), true)
    DEFEX_DEFINES += -DDEFEX_PED_ENABLE
endif

ifeq ($(SAFEPLACE_ENABLE), true)
    DEFEX_DEFINES += -DDEFEX_SAFEPLACE_ENABLE
endif

ifeq ($(INTEGRITY_ENABLE), true)
    DEFEX_DEFINES += -DDEFEX_INTEGRITY_ENABLE
endif

ifeq ($(IMMUTABLE_ENABLE), true)
    DEFEX_DEFINES += -DDEFEX_IMMUTABLE_ENABLE
endif

ifeq ($(LP_ENABLE), true)
    DEFEX_DEFINES += -DDEFEX_LP_ENABLE
endif

ifeq ($(UMH_RESTRICTION_ENABLE), true)
    DEFEX_DEFINES += -DDEFEX_UMH_RESTRICTION_ENABLE
endif

ifeq ($(CACHES_ENABLE), true)
    defex-y += defex_caches_test.o
    DEFEX_DEFINES += -DDEFEX_CACHES_ENABLE
endif

ifeq ($(OEM_UNLOCK_DEPENDENCY), true)
    DEFEX_DEFINES += -DDEFEX_DEPENDING_ON_OEMUNLOCK
endif

ifeq ($(RAMDISK_ENABLE), true)
    DEFEX_DEFINES += -DDEFEX_RAMDISK_ENABLE
ifeq ($(SIGN_ENABLE), true)
    DEFEX_DEFINES += -DDEFEX_SIGN_ENABLE
endif
endif

ifeq ($(USER_BUILD), true)
    $(warning [DEFEX] DEBUG_DISABLE)
    ifeq ($(CONFIG_SECURITY_DSMS), y)
        DEFEX_DEFINES += -DDEFEX_DSMS_ENABLE
    endif
else
    $(warning [DEFEX] DEBUG_ENABLE)
    DEFEX_DEFINES += -DDEFEX_PERMISSIVE_INT
    DEFEX_DEFINES += -DDEFEX_PERMISSIVE_SP
    DEFEX_DEFINES += -DDEFEX_PERMISSIVE_IM
    DEFEX_DEFINES += -DDEFEX_PERMISSIVE_LP
    DEFEX_DEFINES += -DDEFEX_DEBUG_ENABLE
    DEFEX_DEFINES += -DDEFEX_SYSFS_ENABLE
endif

# kunit tests options:
ifeq ($(CONFIG_KUNIT), y)
    DEFEX_DEFINES += -DDEFEX_KUNIT_ENABLED
else
    DEFEX_DEFINES += -D__visible_for_testing=static
endif

ccflags-y := -Wformat

EXTRA_CFLAGS += -I$(srctree)/$(src)/../..
EXTRA_AFLAGS += -Isecurity/samsung/defex_lsm
EXTRA_CFLAGS += -I$(srctree)/$(src)/../../cert
EXTRA_AFLAGS += -Isecurity/samsung/defex_lsm/cert

ifneq ($(wildcard  $(srctree)/$(src)/../../pack_rules.c),)
    DEFEX_DEFINES += -DDEFEX_USE_PACKED_RULES
endif
EXTRA_CFLAGS += $(DEFEX_DEFINES)
EXTRA_AFLAGS += $(DEFEX_DEFINES)

obj-$(CONFIG_SECURITY_DEFEX) := $(defex-y)
