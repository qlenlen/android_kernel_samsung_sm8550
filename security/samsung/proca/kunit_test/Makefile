ccflags-y += -I$(srctree) \
             -I$(srctree)/security/samsung/proca \
             -DPROCA_KUNIT_ENABLED

KBUILD_CFLAGS := $(subst -Werror=strict-prototypes,,$(KBUILD_CFLAGS))

obj-y += proca_certificate_test.o
obj-y += proca_identity_test.o
obj-y += proca_table_test.o
