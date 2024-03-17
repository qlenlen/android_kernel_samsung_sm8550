SHELL := /bin/bash

ifeq ($(CONFIG_MACH_MT6853),y)
    KERNEL := 4_14
else ifeq ($(CONFIG_MACH_MT6833),y)
    KERNEL := 4_14
else ifeq ($(CONFIG_MACH_MT6768),y)
    KERNEL := 4_14
endif

# For kernel version 4.14 or lower
ifeq ($(KERNEL),4_14)
$(obj)/proca_certificate-asn1.o: $(obj)/proca_certificate-asn1.c \
                               $(obj)/proca_certificate-asn1.h

$(obj)/proca_certificate.o: $(obj)/proca_certificate-asn1.h

obj-$(CONFIG_PROCA) += proca_identity.o proca_fcntl.o \
                               proca_task_descr.o proca_certificate-asn1.o \
                               proca_certificate.o proca_table.o \
                               proca_config.o
else
$(obj)/proca_certificate.asn1.o: $(obj)/proca_certificate.asn1.c \
                               $(obj)/proca_certificate.asn1.h

$(obj)/proca_certificate.o: $(obj)/proca_certificate.asn1.h


obj-$(CONFIG_PROCA) += proca_identity.o proca_fcntl.o \
                               proca_task_descr.o proca_certificate.asn1.o \
                               proca_certificate.o proca_table.o \
                               proca_config.o
endif

ccflags-y += -I$(srctree)/security/samsung/proca/
ccflags-y += -I$(srctree)/security/samsung/five/

ifdef CONFIG_PROCA_S_OS
obj-$(CONFIG_PROCA) += s_os/proca_lsm.o
else
obj-$(CONFIG_PROCA) += proca_lsm.o
endif

# clean-files is given relative to the current directory,
# so don't use (obj)/ prefix here.
# Look at file ../../scripts/Makefile.clean for details.
ifeq ($(KERNEL),4_14)
clean-files += proca_certificate-asn1.c proca_certificate-asn1.h
else
clean-files += proca_certificate.asn1.c proca_certificate.asn1.h
endif

subdir-ccflags-y += -Wformat

# kunit tests options:
ifeq ($(CONFIG_SEC_KUNIT)$(CONFIG_UML), yy)
  GCOV_PROFILE := y
  subdir-$(CONFIG_PROCA) += kunit_test
  obj-$(CONFIG_PROCA) += kunit_test/
  ccflags-$(CONFIG_PROCA) += -DPROCA_KUNIT_ENABLED
endif
