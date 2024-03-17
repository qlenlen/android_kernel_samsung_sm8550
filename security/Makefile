# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the kernel security code
#

obj-$(CONFIG_KEYS)			+= keys/
subdir-$(CONFIG_SECURITY_DEFEX)		+= samsung/defex_lsm

# always enable default capabilities
obj-y					+= commoncap.o
obj-$(CONFIG_MMU)			+= min_addr.o

# Object file lists
obj-$(CONFIG_SECURITY)			+= security.o
obj-$(CONFIG_SECURITYFS)		+= inode.o
obj-$(CONFIG_SECURITY_SELINUX)		+= selinux/
obj-$(CONFIG_SECURITY_SMACK)		+= smack/
obj-$(CONFIG_SECURITY)			+= lsm_audit.o
obj-$(CONFIG_SECURITY_TOMOYO)		+= tomoyo/
obj-$(CONFIG_SECURITY_APPARMOR)		+= apparmor/
obj-$(CONFIG_SECURITY_YAMA)		+= yama/
obj-$(CONFIG_SECURITY_LOADPIN)		+= loadpin/
obj-$(CONFIG_SECURITY_SAFESETID)       += safesetid/
obj-$(CONFIG_SECURITY_LOCKDOWN_LSM)	+= lockdown/
obj-$(CONFIG_SECURITY_DEFEX)		+= samsung/defex_lsm/built-in.a
obj-$(CONFIG_CGROUPS)			+= device_cgroup.o
obj-$(CONFIG_BPF_LSM)			+= bpf/
obj-$(CONFIG_SECURITY_LANDLOCK)		+= landlock/

# Object integrity file lists
obj-$(CONFIG_INTEGRITY)			+= integrity/
obj-$(CONFIG_SECURITY_DSMS)		+= samsung/dsms/

# KNOX DAR
obj-$(CONFIG_DDAR) += ddar/
obj-$(CONFIG_DDAR) += ddar/built-in.a

# FIVE
subdir-$(CONFIG_FIVE)			+= samsung/five
obj-$(CONFIG_FIVE)			+= samsung/five/
# PROCA
subdir-$(CONFIG_PROCA)			+= samsung/proca
obj-$(CONFIG_PROCA)			+= samsung/proca/
subdir-$(CONFIG_PROCA)			+= samsung/proca/gaf
obj-$(CONFIG_PROCA)			+= samsung/proca/gaf/

# MZ
subdir-$(CONFIG_MEMORY_ZEROISATION)			+= samsung/mz
obj-$(CONFIG_MEMORY_ZEROISATION)			+= samsung/mz/

