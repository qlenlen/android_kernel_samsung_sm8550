
obj-$(CONFIG_FIVE) += five.o
obj-$(CONFIG_FIVE_PA_FEATURE) += five_pa.o

EXTRA_CFLAGS += -I$(src)
asflags-y += -Isecurity/integrity/five
asflags-y += -Isecurity/samsung/five
ccflags-y += -I$(srctree)
ccflags-y += -Wformat

five-y := five_lv.o five_cert.o five_keyring.o five_init.o  \
	  five_cert_builtin.o five_cache.o \
	  five_dmverity.o
five-$(CONFIG_FIVE_DSMS) += five_dsms.o

ifdef CONFIG_FIVE_GKI_20
  FILES := five_main.o five_appraise.o five_crypto.o five_audit.o \
           five_hooks.o task_integrity.o five_state.o five_vfs.o \
           five_tint_dev.o five_tee_interface.o
  five-y += $(addprefix gki/,$(FILES))
else
  five-y +=  five_crypto.o five_audit.o \
              five_hooks.o task_integrity.o five_state.o
  ifdef CONFIG_PROCA_S_OS
    five-y += s_os/five_main.o s_os/five_appraise.o
  else
    five-y += five_main.o five_appraise.o five_tee_interface.o
  endif
endif

# kunit tests options:
ifeq ($(CONFIG_SEC_KUNIT)$(CONFIG_UML), yy)
  GCOV_PROFILE := y
  subdir-$(CONFIG_FIVE) += kunit_test
  obj-$(CONFIG_FIVE) += kunit_test/
  five-$(CONFIG_FIVE) += five_dsms.o
  EXTRA_CFLAGS += -DFIVE_KUNIT_ENABLED
endif
