/*
 * Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <kunit/test.h>
#include <kunit/mock.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include "include/defex_catch_list.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
#define __COMPAT_SYSCALL_NR
#include <asm/unistd.h>
#else
#ifdef __NR_clone3
#define __NR_compat_syscalls		(__NR_clone3 + 10)
#elif defined(__NR_rseq)
#define __NR_compat_syscalls		(__NR_rseq + 10)
#elif defined(__NR_seccomp)
#define __NR_compat_syscalls		(__NR_seccomp + 10)
#else
#define __NR_compat_syscalls		400
#endif
#endif /* < KERNEL_VERSION(4, 0, 0) */

#ifdef DEFEX_KUNIT_ENABLED
#ifndef __NR_syscalls
#define __NR_syscalls   436
#endif
#endif

#define DEFEX_CATCH_COUNT	__NR_syscalls

#include "catch_engine/defex_catch_list.inc"

static void get_local_syscall_compat_test(struct kunit *test)
{
	const struct local_syscall_struct *l_syscall;

	/* T1: syscall_no >= __NR_compat_syscalls */
	KUNIT_EXPECT_PTR_EQ(test, (const struct local_syscall_struct *)NULL, get_local_syscall_compat(__NR_compat_syscalls));
	KUNIT_EXPECT_PTR_EQ(test, (const struct local_syscall_struct *)NULL, get_local_syscall_compat(__NR_compat_syscalls + 1));

	/* T2/T3: If defined, return syscall. If not, return syscall_catch_arr[0] */
#ifdef __NR_rmdir
	l_syscall = get_local_syscall_compat(__NR_rmdir);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_rmdir);
#endif
#ifdef __NR_utimes
	l_syscall = get_local_syscall(__NR_utimes);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_utimes);
#endif
#ifdef __NR_stat
	l_syscall = get_local_syscall(__NR_stat);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_stat);
#endif
#ifdef __NR_lstat
	l_syscall = get_local_syscall(__NR_lstat);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_lstat);
#endif
#ifdef __NR_umount
	l_syscall = get_local_syscall(__NR_umount);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_umount);
#endif
#ifdef __NR_utime
	l_syscall = get_local_syscall(__NR_utime);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_utime);
#endif
#ifdef __NR_futimesat
	l_syscall = get_local_syscall(__NR_futimesat);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_futimesat);
#endif
#ifdef __NR_uselib
	l_syscall = get_local_syscall(__NR_uselib);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_uselib);
#endif
#ifdef __NR_send
	l_syscall = get_local_syscall(__NR_send);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_send);
#endif
#ifdef __NR_ustat
	l_syscall = get_local_syscall(__NR_ustat);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_ustat);
#endif
#ifdef __NR_getdents
	l_syscall = get_local_syscall(__NR_getdents);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_getdents);
#endif
#ifdef __NR_recv
	l_syscall = get_local_syscall(__NR_recv);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_recv);
#endif
#ifdef __NR_fork
	l_syscall = get_local_syscall(__NR_fork);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_fork);
#endif
#ifdef __NR_vfork
	l_syscall = get_local_syscall(__NR_vfork);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_vfork);
#endif
#ifdef __NR_sigprocmask
	l_syscall = get_local_syscall(__NR_sigprocmask);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_sigprocmask);
#endif
#ifdef __NR_sigpending
	l_syscall = get_local_syscall(__NR_sigpending);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_sigpending);
#endif
#ifdef __NR_sigaction
	l_syscall = get_local_syscall(__NR_sigaction);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_sigaction);
#endif
#ifdef __NR_sigaltstack
	l_syscall = get_local_syscall(__NR_sigaltstack);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_sigaltstack);
#endif
#ifdef __NR_sigsuspend
	l_syscall = get_local_syscall(__NR_sigsuspend);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_sigsuspend);
#endif
#ifdef __NR_truncate64
	l_syscall = get_local_syscall(__NR_truncate64);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_truncate64);
#endif
#ifdef __NR_ftruncate64
	l_syscall = get_local_syscall(__NR_ftruncate64);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_ftruncate64);
#endif
#ifdef __NR_fstat64
	l_syscall = get_local_syscall(__NR_fstat64);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_fstat64);
#endif
#ifdef __NR_fstatat64
	l_syscall = get_local_syscall(__NR_fstatat64);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_fstatat64);
#endif
#ifdef __NR_statfs64
	l_syscall = get_local_syscall(__NR_statfs64);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_statfs64);
#endif
#ifdef __NR_stat64
	l_syscall = get_local_syscall(__NR_stat64);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_stat64);
#endif
#ifdef __NR_lstat64
	l_syscall = get_local_syscall(__NR_lstat64);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_lstat64);
#endif
#ifdef __NR_eventfd
	l_syscall = get_local_syscall(__NR_eventfd);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_eventfd);
#endif
#ifdef __NR_epoll_create
	l_syscall = get_local_syscall(__NR_epoll_create);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_epoll_create);
#endif
#ifdef __NR_shmget
	l_syscall = get_local_syscall(__NR_shmget);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_shmget);
#endif
#ifdef __NR_shmctl
	l_syscall = get_local_syscall(__NR_shmctl);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_shmctl);
#endif
#ifdef __NR_semctl
	l_syscall = get_local_syscall(__NR_semctl);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_semctl);
#endif
#ifdef __NR_move_pages
	l_syscall = get_local_syscall(__NR_move_pages);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_move_pages);
#endif
#ifdef __NR_lookup_dcookie
	l_syscall = get_local_syscall(__NR_lookup_dcookie);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_lookup_dcookie);
#endif
#ifdef __NR_truncate
	l_syscall = get_local_syscall(__NR_truncate);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_truncate);
#endif
#ifdef __NR_ftruncate
	l_syscall = get_local_syscall(__NR_ftruncate);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_ftruncate);
#endif
#ifdef __NR_chdir
	l_syscall = get_local_syscall(__NR_chdir);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_chdir);
#endif
#ifdef __NR_chroot
	l_syscall = get_local_syscall(__NR_chroot);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_chroot);
#endif
#ifdef __NR_fchmod
	l_syscall = get_local_syscall(__NR_fchmod);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_fchmod);
#endif
#ifdef __NR_fchmodat
	l_syscall = get_local_syscall(__NR_fchmodat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_fchmodat);
#endif
#ifdef __NR_fchownat
	l_syscall = get_local_syscall(__NR_fchownat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_fchownat);
#endif
#ifdef __NR_fchown
	l_syscall = get_local_syscall(__NR_fchown);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_fchown);
#endif
#ifdef __NR_open
	l_syscall = get_local_syscall(__NR_open);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, l_syscall->local_syscall, __DEFEX_open);
#endif
#ifdef __NR_openat
	l_syscall = get_local_syscall(__NR_openat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_openat);
#endif
#ifdef __NR_write
	l_syscall = get_local_syscall(__NR_write);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_write);
#endif
#ifdef __NR_writev
	l_syscall = get_local_syscall(__NR_writev);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_writev);
#endif
#ifdef __NR_pwrite64
	l_syscall = get_local_syscall(__NR_pwrite64);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_pwrite64);
#endif
#ifdef __NR_pwritev
	l_syscall = get_local_syscall(__NR_pwritev);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_pwritev);
#endif
#ifdef __NR_sendfile
	l_syscall = get_local_syscall(__NR_sendfile);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_sendfile);
#endif
#ifdef __NR_signalfd4
	l_syscall = get_local_syscall(__NR_signalfd4);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_signalfd4);
#endif
#ifdef __NR_vmsplice
	l_syscall = get_local_syscall(__NR_vmsplice);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_vmsplice);
#endif
#ifdef __NR_splice
	l_syscall = get_local_syscall(__NR_splice);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_splice);
#endif
#ifdef __NR_tee
	l_syscall = get_local_syscall(__NR_tee);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_tee);
#endif
#ifdef __NR_fsync
	l_syscall = get_local_syscall(__NR_fsync);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_fsync);
#endif
#ifdef __NR_fdatasync
	l_syscall = get_local_syscall(__NR_fdatasync);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_fdatasync);
#endif
#ifdef __NR_sync_file_range
	l_syscall = get_local_syscall(__NR_sync_file_range);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_sync_file_range);
#endif
#ifdef __NR_acct
	l_syscall = get_local_syscall(__NR_acct);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_acct);
#endif
#ifdef __NR_sched_setparam
	l_syscall = get_local_syscall(__NR_sched_setparam);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_sched_setparam);
#endif
#ifdef __NR_sched_setscheduler
	l_syscall = get_local_syscall(__NR_sched_setscheduler);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_sched_setscheduler);
#endif
#ifdef __NR_sched_setaffinity
	l_syscall = get_local_syscall(__NR_sched_setaffinity);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_sched_setaffinity);
#endif
#ifdef __NR_reboot
	l_syscall = get_local_syscall(__NR_reboot);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_reboot);
#endif
#ifdef __NR_mq_timedsend
	l_syscall = get_local_syscall(__NR_mq_timedsend);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_mq_timedsend);
#endif
#ifdef __NR_mq_timedreceive
	l_syscall = get_local_syscall(__NR_mq_timedreceive);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_mq_timedreceive);
#endif
#ifdef __NR_msgrcv
	l_syscall = get_local_syscall(__NR_msgrcv);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_msgrcv);
#endif
#ifdef __NR_msgsnd
	l_syscall = get_local_syscall(__NR_msgsnd);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_msgsnd);
#endif
#ifdef __NR_semtimedop
	l_syscall = get_local_syscall(__NR_semtimedop);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_semtimedop);
#endif
#ifdef __NR_add_key
	l_syscall = get_local_syscall(__NR_add_key);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_add_key);
#endif
#ifdef __NR_request_key
	l_syscall = get_local_syscall(__NR_request_key);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_request_key);
#endif
#ifdef __NR_keyctl
	l_syscall = get_local_syscall(__NR_keyctl);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_keyctl);
#endif
#ifdef __NR_mmap
	l_syscall = get_local_syscall(__NR_mmap);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_mmap);
#endif
#ifdef __NR_mincore
	l_syscall = get_local_syscall(__NR_mincore);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_mincore);
#endif
#ifdef __NR_mbind
	l_syscall = get_local_syscall(__NR_mbind);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_mbind);
#endif
#ifdef __NR_set_mempolicy
	l_syscall = get_local_syscall(__NR_set_mempolicy);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_set_mempolicy);
#endif
#ifdef __NR_migrate_pages
	l_syscall = get_local_syscall(__NR_migrate_pages);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_migrate_pages);
#endif
#ifdef __NR_accept4
	l_syscall = get_local_syscall(__NR_accept4);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_accept4);
#endif
#ifdef __NR_recvmmsg
	l_syscall = get_local_syscall(__NR_recvmmsg);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_recvmmsg);
#endif
#ifdef __NR_link
	l_syscall = get_local_syscall(__NR_link);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_link);
#endif
#ifdef __NR_unlink
	l_syscall = get_local_syscall(__NR_unlink);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_unlink);
#endif
#ifdef __NR_mknod
	l_syscall = get_local_syscall(__NR_mknod);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_mknod);
#endif
#ifdef __NR_chmod
	l_syscall = get_local_syscall(__NR_chmod);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_chmod);
#endif
#ifdef __NR_chown
	l_syscall = get_local_syscall(__NR_chown);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_chown);
#endif
#ifdef __NR_mknodat
	l_syscall = get_local_syscall(__NR_mknodat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_mknodat);
#endif
#ifdef __NR_mkdirat
	l_syscall = get_local_syscall(__NR_mkdirat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_mkdirat);
#endif
#ifdef __NR_unlinkat
	l_syscall = get_local_syscall(__NR_unlinkat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_unlinkat);
#endif
#ifdef __NR_symlinkat
	l_syscall = get_local_syscall(__NR_symlinkat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_symlinkat);
#endif
#ifdef __NR_linkat
	l_syscall = get_local_syscall(__NR_linkat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_linkat);
#endif
#ifdef __NR_mkdir
	l_syscall = get_local_syscall(__NR_mkdir);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_mkdir);
#endif
#ifdef __NR_lchown
	l_syscall = get_local_syscall(__NR_lchown);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_lchown);
#endif
#ifdef __NR_rename
	l_syscall = get_local_syscall(__NR_rename);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_rename);
#endif
#ifdef __NR_epoll_wait
	l_syscall = get_local_syscall(__NR_epoll_wait);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_epoll_wait);
#endif
#ifdef __NR_sysctl
	l_syscall = get_local_syscall(__NR_sysctl);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_sysctl);
#endif
#ifdef __NR_renameat
	l_syscall = get_local_syscall(__NR_renameat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_renameat);
#endif
#ifdef __NR_umount2
	l_syscall = get_local_syscall(__NR_umount2);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_umount2);
#endif
#ifdef __NR_mount
	l_syscall = get_local_syscall(__NR_mount);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_mount);
#endif
#ifdef __NR_pivot_root
	l_syscall = get_local_syscall(__NR_pivot_root);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_pivot_root);
#endif
#ifdef __NR_utimensat
	l_syscall = get_local_syscall(__NR_utimensat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_utimensat);
#endif
#ifdef __NR_fcntl
	l_syscall = get_local_syscall(__NR_fcntl);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_fcntl);
#endif
#ifdef __NR_kexec_load
	l_syscall = get_local_syscall(__NR_kexec_load);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_kexec_load);
#endif
#ifdef __NR_ptrace
	l_syscall = get_local_syscall(__NR_ptrace);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_ptrace);
#endif
#ifdef __NR_setgroups
	l_syscall = get_local_syscall(__NR_setgroups);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setgroups);
#endif
#ifdef __NR_settimeofday
	l_syscall = get_local_syscall(__NR_settimeofday);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_settimeofday);
#endif
#ifdef __NR_delete_module
	l_syscall = get_local_syscall(__NR_delete_module);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_delete_module);
#endif
#ifdef __NR_init_module
	l_syscall = get_local_syscall(__NR_init_module);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_init_module);
#endif
#ifdef __NR_capset
	l_syscall = get_local_syscall(__NR_capset);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_capset);
#endif
#ifdef __NR_setpriority
	l_syscall = get_local_syscall(__NR_setpriority);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setpriority);
#endif
#ifdef __NR_setregid
	l_syscall = get_local_syscall(__NR_setregid);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setregid);
#endif
#ifdef __NR_setgid
	l_syscall = get_local_syscall(__NR_setgid);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setgid);
#endif
#ifdef __NR_setreuid
	l_syscall = get_local_syscall(__NR_setreuid);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setreuid);
#endif
#ifdef __NR_setuid
	l_syscall = get_local_syscall(__NR_setuid);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setuid);
#endif
#ifdef __NR_setresuid
	l_syscall = get_local_syscall(__NR_setresuid);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setresuid);
#endif
#ifdef __NR_setresgid
	l_syscall = get_local_syscall(__NR_setresgid);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setresgid);
#endif
#ifdef __NR_setpgid
	l_syscall = get_local_syscall(__NR_setpgid);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setpgid);
#endif
#ifdef __NR_setfsuid
	l_syscall = get_local_syscall(__NR_setfsuid);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setfsuid);
#endif
#ifdef __NR_setfsgid
	l_syscall = get_local_syscall(__NR_setfsgid);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setfsgid);
#endif
#ifdef __NR_getsid
	l_syscall = get_local_syscall(__NR_getsid);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_getsid);
#endif
#ifdef __NR_setsid
	l_syscall = get_local_syscall(__NR_setsid);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setsid);
#endif
#ifdef __NR_sethostname
	l_syscall = get_local_syscall(__NR_sethostname);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_sethostname);
#endif
#ifdef __NR_setdomainname
	l_syscall = get_local_syscall(__NR_setdomainname);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setdomainname);
#endif
#ifdef __NR_setrlimit
	l_syscall = get_local_syscall(__NR_setrlimit);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setrlimit);
#endif
#ifdef __NR_umask
	l_syscall = get_local_syscall(__NR_umask);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_umask);
#endif
#ifdef __NR_prctl
	l_syscall = get_local_syscall(__NR_prctl);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_prctl);
#endif
#ifdef __NR_getcpu
	l_syscall = get_local_syscall(__NR_getcpu);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_getcpu);
#endif
#ifdef __NR_kill
	l_syscall = get_local_syscall(__NR_kill);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_kill);
#endif
#ifdef __NR_tgkill
	l_syscall = get_local_syscall(__NR_tgkill);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_tgkill);
#endif
#ifdef __NR_tkill
	l_syscall = get_local_syscall(__NR_tkill);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_tkill);
#endif
#ifdef __NR_rt_tgsigqueueinfo
	l_syscall = get_local_syscall(__NR_rt_tgsigqueueinfo);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_rt_tgsigqueueinfo);
#endif
#ifdef __NR_rt_sigqueueinfo
	l_syscall = get_local_syscall(__NR_rt_sigqueueinfo);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_rt_sigqueueinfo);
#endif
#ifdef __NR_listen
	l_syscall = get_local_syscall(__NR_listen);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_listen);
#endif
#ifdef __NR_accept
	l_syscall = get_local_syscall(__NR_accept);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_accept);
#endif
#ifdef __NR_shutdown
	l_syscall = get_local_syscall(__NR_shutdown);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_shutdown);
#endif
#ifdef __NR_shmat
	l_syscall = get_local_syscall(__NR_shmat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_shmat);
#endif
#ifdef __NR_shmdt
	l_syscall = get_local_syscall(__NR_shmdt);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_shmdt);
#endif
#ifdef __NR_semget
	l_syscall = get_local_syscall(__NR_semget);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_semget);
#endif
#ifdef __NR_semop
	l_syscall = get_local_syscall(__NR_semop);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_semop);
#endif
#ifdef __NR_faccessat
	l_syscall = get_local_syscall(__NR_faccessat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_faccessat);
#endif
#ifdef __NR_fchdir
	l_syscall = get_local_syscall(__NR_fchdir);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_fchdir);
#endif
#ifdef __NR_fstat
	l_syscall = get_local_syscall(__NR_fstat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_fstat);
#endif
#ifdef __NR_readlinkat
	l_syscall = get_local_syscall(__NR_readlinkat);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_readlinkat);
#endif
#ifdef __NR_statfs
	l_syscall = get_local_syscall(__NR_statfs);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_statfs);
#endif
#ifdef __NR_fstatfs
	l_syscall = get_local_syscall(__NR_fstatfs);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_fstatfs);
#endif
#ifdef __NR_getcwd
	l_syscall = get_local_syscall(__NR_getcwd);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_getcwd);
#endif
#ifdef __NR_futex
	l_syscall = get_local_syscall(__NR_futex);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_futex);
#endif
#ifdef __NR_perf_event_open
	l_syscall = get_local_syscall(__NR_perf_event_open);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_perf_event_open);
#endif
#ifdef __NR_socket
	l_syscall = get_local_syscall(__NR_socket);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_socket);
#endif
#ifdef __NR_bind
	l_syscall = get_local_syscall(__NR_bind);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_bind);
#endif
#ifdef __NR_connect
	l_syscall = get_local_syscall(__NR_connect);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_connect);
#endif
#ifdef __NR_sendto
	l_syscall = get_local_syscall(__NR_sendto);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_sendto);
#endif
#ifdef __NR_mprotect
	l_syscall = get_local_syscall(__NR_mprotect);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_mprotect);
#endif
#ifdef __NR_mremap
	l_syscall = get_local_syscall(__NR_mremap);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_mremap);
#endif
#ifdef __NR_pselect6
	l_syscall = get_local_syscall(__NR_pselect6);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_pselect6);
#endif
#ifdef __NR_ioctl
	l_syscall = get_local_syscall(__NR_ioctl);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_ioctl);
#endif
#ifdef __NR_ioprio_set
	l_syscall = get_local_syscall(__NR_ioprio_set);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_ioprio_set);
#endif
#ifdef __NR_pipe2
	l_syscall = get_local_syscall(__NR_pipe2);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_pipe2);
#endif
#ifdef __NR_getdents64
	l_syscall = get_local_syscall(__NR_getdents64);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_getdents64);
#endif
#ifdef __NR_setitimer
	l_syscall = get_local_syscall(__NR_setitimer);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setitimer);
#endif
#ifdef __NR_capget
	l_syscall = get_local_syscall(__NR_capget);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_capget);
#endif
#ifdef __NR_getresuid
	l_syscall = get_local_syscall(__NR_getresuid);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_getresuid);
#endif
#ifdef __NR_getresgid
	l_syscall = get_local_syscall(__NR_getresgid);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_getresgid);
#endif
#ifdef __NR_rt_sigprocmask
	l_syscall = get_local_syscall(__NR_rt_sigprocmask);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_rt_sigprocmask);
#endif
#ifdef __NR_socketpair
	l_syscall = get_local_syscall(__NR_socketpair);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_socketpair);
#endif
#ifdef __NR_getsockname
	l_syscall = get_local_syscall(__NR_getsockname);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_getsockname);
#endif
#ifdef __NR_getpeername
	l_syscall = get_local_syscall(__NR_getpeername);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_getpeername);
#endif
#ifdef __NR_recvfrom
	l_syscall = get_local_syscall(__NR_recvfrom);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_recvfrom);
#endif
#ifdef __NR_setsockopt
	l_syscall = get_local_syscall(__NR_setsockopt);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setsockopt);
#endif
#ifdef __NR_sendmsg
	l_syscall = get_local_syscall(__NR_sendmsg);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_sendmsg);
#endif
#ifdef __NR_recvmsg
	l_syscall = get_local_syscall(__NR_recvmsg);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_recvmsg);
#endif
#ifdef __NR_socketcall
	l_syscall = get_local_syscall(__NR_socketcall);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_socketcall);
#endif
#ifdef __NR_rt_sigsuspend
	l_syscall = get_local_syscall(__NR_rt_sigsuspend);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_rt_sigsuspend);
#endif
#ifdef __NR_rt_sigpending
	l_syscall = get_local_syscall(__NR_rt_sigpending);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_rt_sigpending);
#endif
#ifdef __NR_rt_sigaction
	l_syscall = get_local_syscall(__NR_rt_sigaction);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_rt_sigaction);
#endif
#ifdef __NR_signal
	l_syscall = get_local_syscall(__NR_signal);
	KUNIT_EXPECT_NE(test, l_syscall, NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_signal);
#endif
#ifdef __NR_remap_file_pages
	l_syscall = get_local_syscall(__NR_remap_file_pages);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_remap_file_pages);
#endif
#ifdef __NR_ppoll
	l_syscall = get_local_syscall(__NR_ppoll);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_ppoll);
#endif
#ifdef __NR_dup
	l_syscall = get_local_syscall(__NR_dup);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_dup);
#endif
#ifdef __NR_dup3
	l_syscall = get_local_syscall(__NR_dup3);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_dup3);
#endif
#ifdef __NR_eventfd2
	l_syscall = get_local_syscall(__NR_eventfd2);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_eventfd2);
#endif
#ifdef __NR_timerfd_create
	l_syscall = get_local_syscall(__NR_timerfd_create);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_timerfd_create);
#endif
#ifdef __NR_timerfd_gettime
	l_syscall = get_local_syscall(__NR_timerfd_gettime);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_timerfd_gettime);
#endif
#ifdef __NR_timerfd_settime
	l_syscall = get_local_syscall(__NR_timerfd_settime);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_timerfd_settime);
#endif
#ifdef __NR_epoll_create1
	l_syscall = get_local_syscall(__NR_epoll_create1);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_epoll_create1);
#endif
#ifdef __NR_epoll_ctl
	l_syscall = get_local_syscall(__NR_epoll_ctl);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_epoll_ctl);
#endif
#ifdef __NR_epoll_pwait
	l_syscall = get_local_syscall(__NR_epoll_pwait);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_epoll_pwait);
#endif
#ifdef __NR_rt_sigtimedwait
	l_syscall = get_local_syscall(__NR_rt_sigtimedwait);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_rt_sigtimedwait);
#endif
#ifdef __NR_clone
	l_syscall = get_local_syscall(__NR_clone);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_clone);
#endif
#ifdef __NR_execve
	l_syscall = get_local_syscall(__NR_execve);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_execve);
#endif
#ifdef __NR_setxattr
	l_syscall = get_local_syscall(__NR_setxattr);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_setxattr);
#endif
#ifdef __NR_lsetxattr
	l_syscall = get_local_syscall(__NR_lsetxattr);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_lsetxattr);
#endif
#ifdef __NR_fsetxattr
	l_syscall = get_local_syscall(__NR_fsetxattr);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_fsetxattr);
#endif
#ifdef __NR_removexattr
	l_syscall = get_local_syscall(__NR_removexattr);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_removexattr);
#endif
#ifdef __NR_lremovexattr
	l_syscall = get_local_syscall(__NR_lremovexattr);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_lremovexattr);
#endif
#ifdef __NR_fremovexattr
	l_syscall = get_local_syscall(__NR_fremovexattr);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_fremovexattr);
#endif
#ifdef __NR_inotify_init1
	l_syscall = get_local_syscall(__NR_inotify_init1);
	KUNIT_EXPECT_PTR_NE(test, l_syscall, (const struct local_syscall_struct *)NULL);
	KUNIT_EXPECT_EQ(test, (int)l_syscall->local_syscall, __DEFEX_inotify_init1);
#endif
}


static int defex_catch_list_compat_test_init(struct kunit *test)
{
	return 0;
}

static void defex_catch_list_compat_test_exit(struct kunit *test)
{
}

static struct kunit_case defex_catch_list_compat_test_cases[] = {
	/* TEST FUNC DEFINES */
	KUNIT_CASE(get_local_syscall_compat_test),
	{},
};

static struct kunit_suite defex_catch_list_compat_test_module = {
	.name = "defex_catch_list_compat_test",
	.init = defex_catch_list_compat_test_init,
	.exit = defex_catch_list_compat_test_exit,
	.test_cases = defex_catch_list_compat_test_cases,
};
kunit_test_suites(&defex_catch_list_compat_test_module);

