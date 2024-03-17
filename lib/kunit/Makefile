obj-$(CONFIG_KUNIT) +=			kunit.o

kunit-objs +=				test.o \
					string-stream.o \
					assert.o \
					try-catch.o \
					mock.o \
					common-mocks.o \
					kunit-stream.o \
					strerror.o \
					executor.o

ifeq ($(CONFIG_KUNIT_DEBUGFS),y)
kunit-objs +=				debugfs.o
endif

obj-$(CONFIG_KUNIT_TEST) +=		kunit-test.o \
					mock-test.o \
					mock-macro-test.o \
					strerror-test.o

# string-stream-test compiles built-in only.
ifeq ($(CONFIG_KUNIT_TEST),y)
obj-$(CONFIG_KUNIT_TEST) +=		string-stream-test.o
endif

obj-$(CONFIG_KUNIT_EXAMPLE_TEST) +=	kunit-example-test.o
obj-$(CONFIG_KUNIT_MANAGER) +=		kunit_manager.o
