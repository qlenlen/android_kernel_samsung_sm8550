# When adding new entries keep the list in alphabetical order
obj-$(CONFIG_GAF_V3)		+= gaf_v3.o
obj-$(CONFIG_GAF_V4)		+= gaf_v4.o
obj-$(CONFIG_GAF_V5)		+= gaf_v5.o
obj-$(CONFIG_GAF_V6)		+= gaf_v6.o

ccflags-y += -I$(srctree)/security/samsung/proca

# kunit tests options:
ifeq ($(CONFIG_SEC_KUNIT)$(CONFIG_UML), yy)
  GCOV_PROFILE := y
  ccflags-$(CONFIG_PROCA) += -DPROCA_KUNIT_ENABLED
endif

