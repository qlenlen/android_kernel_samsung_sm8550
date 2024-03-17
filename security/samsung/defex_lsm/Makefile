#
# Makefile for the Defex
#

# Features to Enable
PED_ENABLE=true
SAFEPLACE_ENABLE=true
IMMUTABLE_ENABLE=true
LP_ENABLE=true
UMH_RESTRICTION_ENABLE=true
TRUSTED_MAP_ENABLE=false
USER_BUILD=false

# Additional debug
LOG_BUFFER_ENABLE=false
SHOW_RULES_ENABLE=false

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

defex-y := core/defex_common.o
defex-y += core/defex_lsm.o
defex-y += core/defex_main.o
defex-y += core/defex_get_mode.o
defex-y += core/defex_rules_proc.o
defex-y += core/defex_tailer.o
defex-y += catch_engine/defex_catch_list.o
defex-y += catch_engine/defex_ht.o
defex-y += defex_rules.o
defex-$(CONFIG_COMPAT) += catch_engine/defex_catch_list_compat.o

# Immutable Feature is applied with permissive mode first.
DEFEX_DEFINES := -DDEFEX_PERMISSIVE_IM

# Integrity Feature is applied with permissive mode first.
DEFEX_DEFINES += -DDEFEX_PERMISSIVE_INT

ifeq ($(CONFIG_DEFEX_KERNEL_ONLY), y)
    DEFEX_DEFINES += -DDEFEX_KERNEL_ONLY
    ifeq ($(CONFIG_SAMSUNG_PRODUCT_SHIP), y)
        $(warning [DEFEX] Kernel_only & Ship)
    else
        $(warning [DEFEX] Kernel_only & Noship)
        defex-y += debug/defex_debug.o
        defex-y += core/defex_sysfs.o
        DEFEX_DEFINES += -DDEFEX_PERMISSIVE_INT
        DEFEX_DEFINES += -DDEFEX_PERMISSIVE_SP
        DEFEX_DEFINES += -DDEFEX_PERMISSIVE_TM
        DEFEX_DEFINES += -DDEFEX_PERMISSIVE_IM
        DEFEX_DEFINES += -DDEFEX_PERMISSIVE_LP
        DEFEX_DEFINES += -DDEFEX_DEBUG_ENABLE
        ifeq ($(LOG_BUFFER_ENABLE), true)
            DEFEX_DEFINES += -DDEFEX_LOG_BUFFER_ENABLE
        endif
	ifeq ($(SHOW_RULES_ENABLE), true)
	    defex-y += debug/defex_rules_show.o
	    DEFEX_DEFINES += -DDEFEX_SHOW_RULES_ENABLE
	endif
    endif
endif

ifeq ($(SEC_FACTORY_BUILD), true)
    DEFEX_DEFINES += -DDEFEX_FACTORY_ENABLE
    DEFEX_DEFINES += -DDEFEX_PERMISSIVE_LP
endif

ifeq ($(PED_ENABLE), true)
    defex-y += feature_privilege_escalation_detection/defex_priv.o
    DEFEX_DEFINES += -DDEFEX_PED_ENABLE
endif

ifeq ($(SAFEPLACE_ENABLE), true)
    defex-y += feature_safeplace/defex_safeplace.o
    DEFEX_DEFINES += -DDEFEX_SAFEPLACE_ENABLE
endif

ifeq ($(INTEGRITY_ENABLE), true)
    defex-y += feature_safeplace/defex_integrity.o
    DEFEX_DEFINES += -DDEFEX_INTEGRITY_ENABLE
endif

ifeq ($(IMMUTABLE_ENABLE), true)
    defex-y += feature_immutable/defex_immutable.o
    DEFEX_DEFINES += -DDEFEX_IMMUTABLE_ENABLE
endif

ifeq ($(LP_ENABLE), true)
    DEFEX_DEFINES += -DDEFEX_LP_ENABLE
endif

ifeq ($(UMH_RESTRICTION_ENABLE), true)
    DEFEX_DEFINES += -DDEFEX_UMH_RESTRICTION_ENABLE
endif

ifeq ($(CACHES_ENABLE), true)
    defex-y += catch_engine/defex_caches.o
    DEFEX_DEFINES += -DDEFEX_CACHES_ENABLE
endif

ifeq ($(OEM_UNLOCK_DEPENDENCY), true)
    DEFEX_DEFINES += -DDEFEX_DEPENDING_ON_OEMUNLOCK
endif

ifeq ($(RAMDISK_ENABLE), true)
    DEFEX_DEFINES += -DDEFEX_RAMDISK_ENABLE
ifeq ($(SIGN_ENABLE), true)
    defex-y += cert/defex_cert.o
    defex-y += cert/defex_sign.o
    DEFEX_DEFINES += -DDEFEX_SIGN_ENABLE
endif
endif

ifeq ($(TRUSTED_MAP_ENABLE), true)
    DEFEX_DEFINES += -DDEFEX_TRUSTED_MAP_ENABLE
    DEFEX_DEFINES += -DDEFEX_PERMISSIVE_TM
    #DEFEX_DEFINES += -DDEFEX_TM_DEFAULT_POLICY_ENABLE
    defex-y += feature_trusted_map/defex_trusted_map.o
    defex-y += feature_trusted_map/dtm.o
    defex-y += feature_trusted_map/dtm_engine.o
    defex-y += feature_trusted_map/dtm_log.o
    defex-y += feature_trusted_map/dtm_utils.o
    defex-y += feature_trusted_map/ptree.o
endif

ifeq ($(USER_BUILD), true)
    $(warning [DEFEX] DEBUG_DISABLE)
    ifeq ($(CONFIG_SECURITY_DSMS), y)
        DEFEX_DEFINES += -DDEFEX_DSMS_ENABLE
    endif
else
    $(warning [DEFEX] DEBUG_ENABLE)
    defex-y += debug/defex_debug.o
    defex-y += core/defex_sysfs.o
    DEFEX_DEFINES += -DDEFEX_PERMISSIVE_INT
    DEFEX_DEFINES += -DDEFEX_PERMISSIVE_SP
    DEFEX_DEFINES += -DDEFEX_PERMISSIVE_TM
    DEFEX_DEFINES += -DDEFEX_PERMISSIVE_IM
    DEFEX_DEFINES += -DDEFEX_PERMISSIVE_LP
    DEFEX_DEFINES += -DDEFEX_DEBUG_ENABLE
    ifeq ($(LOG_BUFFER_ENABLE), true)
        DEFEX_DEFINES += -DDEFEX_LOG_BUFFER_ENABLE
    endif
    ifeq ($(SHOW_RULES_ENABLE), true)
	defex-y += debug/defex_rules_show.o
	DEFEX_DEFINES += -DDEFEX_SHOW_RULES_ENABLE
    endif
endif

# kunit tests options:
ifeq ($(CONFIG_SEC_KUNIT), y)
    GCOV_PROFILE := y
    DEFEX_DEFINES += -DDEFEX_KUNIT_ENABLED
    defex-y += catch_engine/kunit_test/
    defex-y += cert/kunit_test/
    defex-y += core/kunit_test/
    defex-y += debug/kunit_test/
    defex-y += feature_immutable/kunit_test/
    defex-y += feature_privilege_escalation_detection/kunit_test/
    defex-y += feature_safeplace/kunit_test/
    defex-y += feature_trusted_map/kunit_test/
else
    DEFEX_DEFINES += -D__visible_for_testing=static
endif

ccflags-y := -Wformat

EXTRA_CFLAGS += -I$(srctree)/$(src)
EXTRA_AFLAGS += -Isecurity/samsung/defex_lsm
EXTRA_CFLAGS += -I$(srctree)/$(src)/cert
EXTRA_AFLAGS += -Isecurity/samsung/defex_lsm/cert

ifneq ($(wildcard  $(srctree)/$(src)/pack_rules.c),)
    EXTRA_CFLAGS += $(DEFEX_DEFINES)
    EXTRA_AFLAGS += $(DEFEX_DEFINES)
    hostprogs := pack_rules
    hostprogs-y := pack_rules
    HOST_EXTRACFLAGS += $(DEFEX_DEFINES)
    clean-files := $(srctree)/$(src)/defex_packed_rules.inc
    DEPEND_LIST := $(obj)/pack_rules

    quiet_cmd_pack = PACK    $<
          cmd_pack = $(obj)/pack_rules -p $< $@ $(srctree)/$(src)/defex_packed_rules.bin

    quiet_cmd_mkey = MAKEKEY $<
          cmd_mkey = cp -n $< $@ 2>/dev/null || true

    $(obj)/core/defex_rules_proc.o: $(obj)/pack_rules $(srctree)/$(src)/defex_packed_rules.inc

    $(obj)/cert/defex_cert.o: $(obj)/cert/pubkey_eng.der $(obj)/cert/pubkey_user.der

    $(obj)/cert/pubkey_eng.der: $(srctree)/$(src)/cert/x509_five_eng.der
	$(call cmd,mkey)

    $(obj)/cert/pubkey_user.der: $(srctree)/$(src)/cert/x509_five_user.der
	$(call cmd,mkey)

    SOURCE_RULES := $(srctree)/$(src)/defex_rules.c
    ifneq ($(wildcard $(srctree)/$(src)/file_list),)
        $(warning '[DEFEX] file_list found')
        SOURCE_RULES := $(srctree)/$(src)/defex_rules_reduced.c
        DEPEND_LIST += $(SOURCE_RULES)
        DEPEND_LIST += $(srctree)/$(src)/file_list
        clean-files += $(DEPEND_LIST)

        quiet_cmd_reduce = REDUCE  $<
              cmd_reduce = $(obj)/pack_rules -r $< $@ $(srctree)/$(src)/file_list

        $(srctree)/$(src)/defex_rules_reduced.c: $(srctree)/$(src)/defex_rules.c $(obj)/pack_rules
		$(call cmd,reduce)
    endif

    $(srctree)/$(src)/defex_packed_rules.inc: $(SOURCE_RULES) $(DEPEND_LIST)
	$(call cmd,pack)
	@cp -n $(obj)/pack_rules $(srctree)/$(src)/pack_rules 2>/dev/null || true

else
    EXTRA_CFLAGS += $(DEFEX_DEFINES)
    EXTRA_AFLAGS += $(DEFEX_DEFINES)
endif

obj-$(CONFIG_SECURITY_DEFEX) := $(defex-y)
