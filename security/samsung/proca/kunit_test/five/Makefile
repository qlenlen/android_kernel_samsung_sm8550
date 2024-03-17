#############################################
## This Makefile for PROCA KUnit test only ##
#############################################

obj-$(CONFIG_FIVE) += five.o

asflags-y += -Isecurity/integrity/five
asflags-y += -Isecurity/samsung/five
ccflags-y += -I$(src) \
             -I$(srctree) \
             -Wformat

five-y := five_lv.o five_cert.o five_keyring.o five_init.o  \
	  five_cert_builtin.o five_cache.o \
	  five_dmverity.o five_crypto.o five_audit.o \
	  five_hooks.o task_integrity.o five_state.o

ifdef CONFIG_PROCA_S_OS
  five-y += s_os/five_main.o s_os/five_appraise.o
else
  five-y += five_main.o five_appraise.o five_tee_interface.o
endif

GCOV_PROFILE := y
five-$(CONFIG_FIVE) += five_dsms.o

ifeq ($(CONFIG_SEC_KUNIT)$(CONFIG_UML), yy)
  ccflags-$(CONFIG_FIVE) += -DFIVE_KUNIT_ENABLED
  ccflags-$(CONFIG_PROCA) += -DPROCA_KUNIT_ENABLED
endif
