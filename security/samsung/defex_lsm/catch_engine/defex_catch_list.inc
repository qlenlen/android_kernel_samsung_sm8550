static const struct local_syscall_struct syscall_catch_arr[DEFEX_CATCH_COUNT] = {
	/* */
	[0] = {
		.local_syscall = 0,
		.err_code = -EPERM
	},

#ifdef __NR_rmdir
	SYSCALL_CATCH(rmdir, -EPERM),
#endif
#ifdef __NR_utimes
	SYSCALL_CATCH(utimes, -EPERM),
#endif
#ifdef __NR_stat
	SYSCALL_CATCH(stat, -EACCES),
#endif
#ifdef __NR_lstat
	SYSCALL_CATCH(lstat, -EACCES),
#endif
#ifdef __NR_umount
	SYSCALL_CATCH(umount, -EPERM),
#endif
#ifdef __NR_utime
	SYSCALL_CATCH(utime, -EPERM),
#endif
#ifdef __NR_futimesat
	SYSCALL_CATCH(futimesat, -EPERM),
#endif
#ifdef __NR_uselib
	SYSCALL_CATCH(uselib, -EACCES),
#endif
#ifdef __NR_send
	SYSCALL_CATCH(send, -EACCES),
#endif
#ifdef __NR_ustat
	SYSCALL_CATCH(ustat, -EFAULT),
#endif
#ifdef __NR_getdents
	SYSCALL_CATCH(getdents, -EFAULT),
#endif
#ifdef __NR_recv
	SYSCALL_CATCH(recv, -EFAULT),
#endif
#ifdef __NR_fork
	SYSCALL_CATCH(fork, -EINVAL),
#endif
#ifdef __NR_vfork
	SYSCALL_CATCH(vfork, -EINVAL),
#endif
#ifdef __NR_sigprocmask
	SYSCALL_CATCH(sigprocmask, -EFAULT),
#endif
#ifdef __NR_sigpending
	SYSCALL_CATCH(sigpending, -EFAULT),
#endif
#ifdef __NR_sigaction
	SYSCALL_CATCH(sigaction, -EFAULT),
#endif
#ifdef __NR_sigaltstack
	SYSCALL_CATCH(sigaltstack, -EFAULT),
#endif
#ifdef __NR_sigsuspend
	SYSCALL_CATCH(sigsuspend, -EFAULT),
#endif
#ifdef __NR_truncate64
	SYSCALL_CATCH(truncate64, -EPERM),
#endif
#ifdef __NR_ftruncate64
	SYSCALL_CATCH(ftruncate64, -EPERM),
#endif
#ifdef __NR_fstat64
	SYSCALL_CATCH(fstat64, -EACCES),
#endif
#ifdef __NR_fstatat64
	SYSCALL_CATCH(fstatat64, -EACCES),
#endif
#ifdef __NR_statfs64
	SYSCALL_CATCH(statfs64, -EACCES),
#endif
#ifdef __NR_stat64
	SYSCALL_CATCH(stat64, -EACCES),
#endif
#ifdef __NR_lstat64
	SYSCALL_CATCH(lstat64, -EACCES),
#endif
#ifdef __NR_eventfd
	SYSCALL_CATCH(eventfd, -EINVAL),
#endif
#ifdef __NR_epoll_create
	SYSCALL_CATCH(epoll_create, -EINVAL),
#endif
#ifdef __NR_shmget
	SYSCALL_CATCH(shmget, -EPERM),
#endif
#ifdef __NR_shmctl
	SYSCALL_CATCH(shmctl, -EPERM),
#endif
#ifdef __NR_semctl
	SYSCALL_CATCH(semctl, -EPERM),
#endif
#ifdef __NR_move_pages
	SYSCALL_CATCH(move_pages, -EPERM),
#endif
#ifdef __NR_lookup_dcookie
	SYSCALL_CATCH(lookup_dcookie, -EPERM),
#endif
#ifdef __NR_truncate
	SYSCALL_CATCH(truncate, -EPERM),
#endif
#ifdef __NR_ftruncate
	SYSCALL_CATCH(ftruncate, -EPERM),
#endif
#ifdef __NR_chdir
	SYSCALL_CATCH(chdir, -EPERM),
#endif
#ifdef __NR_chroot
	SYSCALL_CATCH(chroot, -EPERM),
#endif
#ifdef __NR_fchmod
	SYSCALL_CATCH(fchmod, -EPERM),
#endif
#ifdef __NR_fchmodat
	SYSCALL_CATCH(fchmodat, -EPERM),
#endif
#ifdef __NR_fchownat
	SYSCALL_CATCH(fchownat, -EPERM),
#endif
#ifdef __NR_fchown
	SYSCALL_CATCH(fchown, -EPERM),
#endif
#ifdef __NR_mknodat
	SYSCALL_CATCH(mknodat, -EPERM),
#endif
#ifdef __NR_mkdirat
	SYSCALL_CATCH(mkdirat, -EPERM),
#endif
#ifdef __NR_unlinkat
	SYSCALL_CATCH(unlinkat, -EPERM),
#endif
#ifdef __NR_symlinkat
	SYSCALL_CATCH(symlinkat, -EPERM),
#endif
#ifdef __NR_linkat
	SYSCALL_CATCH(linkat, -EPERM),
#endif
#ifdef __NR_renameat
	SYSCALL_CATCH(renameat, -EPERM),
#endif
#ifdef __NR_umount2
	SYSCALL_CATCH(umount2, -EPERM),
#endif
#ifdef __NR_mount
	SYSCALL_CATCH(mount, -EPERM),
#endif
#ifdef __NR_pivot_root
	SYSCALL_CATCH(pivot_root, -EPERM),
#endif
#ifdef __NR_utimensat
	SYSCALL_CATCH(utimensat, -EPERM),
#endif
#ifdef __NR_fcntl
	SYSCALL_CATCH(fcntl, -EPERM),
#endif
#ifdef __NR_kexec_load
	SYSCALL_CATCH(kexec_load, -EPERM),
#endif
#ifdef __NR_ptrace
	SYSCALL_CATCH(ptrace, -EPERM),
#endif
#ifdef __NR_setgroups
	SYSCALL_CATCH(setgroups, -EPERM),
#endif
#ifdef __NR_settimeofday
	SYSCALL_CATCH(settimeofday, -EPERM),
#endif
#ifdef __NR_delete_module
	SYSCALL_CATCH(delete_module, -EPERM),
#endif
#ifdef __NR_init_module
	SYSCALL_CATCH(init_module, -EPERM),
#endif
#ifdef __NR_capset
	SYSCALL_CATCH(capset, -EPERM),
#endif
#ifdef __NR_setpriority
	SYSCALL_CATCH(setpriority, -EPERM),
#endif
#ifdef __NR_setregid
	SYSCALL_CATCH(setregid, -EPERM),
#endif
#ifdef __NR_setfsuid
	SYSCALL_CATCH(setfsuid, 0), //-EPERM
#endif
#ifdef __NR_setfsgid
	SYSCALL_CATCH(setfsgid, 0), //-EPERM
#endif
#ifdef __NR_umask
	SYSCALL_CATCH(umask, 0), //-EPERM
#endif
#ifdef __NR_setgid
	SYSCALL_CATCH(setgid, -EPERM),
#endif
#ifdef __NR_setreuid
	SYSCALL_CATCH(setreuid, -EPERM),
#endif
#ifdef __NR_setuid
	SYSCALL_CATCH(setuid, -EPERM),
#endif
#ifdef __NR_setresuid
	SYSCALL_CATCH(setresuid, -EPERM),
#endif
#ifdef __NR_setresgid
	SYSCALL_CATCH(setresgid, -EPERM),
#endif
#ifdef __NR_setpgid
	SYSCALL_CATCH(setpgid, -EPERM),
#endif
#ifdef __NR_getsid
	SYSCALL_CATCH(getsid, -EPERM),
#endif
#ifdef __NR_setsid
	SYSCALL_CATCH(setsid, -EPERM),
#endif
#ifdef __NR_sethostname
	SYSCALL_CATCH(sethostname, -EPERM),
#endif
#ifdef __NR_setdomainname
	SYSCALL_CATCH(setdomainname, -EPERM),
#endif
#ifdef __NR_setrlimit
	SYSCALL_CATCH(setrlimit, -EPERM),
#endif
#ifdef __NR_prctl
	SYSCALL_CATCH(prctl, -EPERM),
#endif
#ifdef __NR_getcpu
	SYSCALL_CATCH(getcpu, -EPERM),
#endif
#ifdef __NR_kill
	SYSCALL_CATCH(kill, -EPERM),
#endif
#ifdef __NR_tgkill
	SYSCALL_CATCH(tgkill, -EPERM),
#endif
#ifdef __NR_tkill
	SYSCALL_CATCH(tkill, -EPERM),
#endif
#ifdef __NR_rt_tgsigqueueinfo
	SYSCALL_CATCH(rt_tgsigqueueinfo, -EPERM),
#endif
#ifdef __NR_rt_sigqueueinfo
	SYSCALL_CATCH(rt_sigqueueinfo, -EPERM),
#endif
#ifdef __NR_listen
	SYSCALL_CATCH(listen, -EPERM),
#endif
#ifdef __NR_accept
	SYSCALL_CATCH(accept, -EPERM),
#endif
#ifdef __NR_open
	SYSCALL_CATCH(open, 0), //-EPERM
#endif
#ifdef __NR_openat
	SYSCALL_CATCH(openat, 0), //-EPERM
#endif
#ifdef __NR_shutdown
	SYSCALL_CATCH(shutdown, -EBADF),
#endif
#ifdef __NR_shmat
	SYSCALL_CATCH(shmat, -EACCES),
#endif
#ifdef __NR_shmdt
	SYSCALL_CATCH(shmdt, -EACCES),
#endif
#ifdef __NR_semget
	SYSCALL_CATCH(semget, -EACCES),
#endif
#ifdef __NR_semop
	SYSCALL_CATCH(semop, -EACCES),
#endif
#ifdef __NR_faccessat
	SYSCALL_CATCH(faccessat, -EACCES),
#endif
#ifdef __NR_fchdir
	SYSCALL_CATCH(fchdir, -EACCES),
#endif
#ifdef __NR_fstat
	SYSCALL_CATCH(fstat, -EACCES),
#endif
#ifdef __NR_readlinkat
	SYSCALL_CATCH(readlinkat, -EACCES),
#endif
#ifdef __NR_statfs
	SYSCALL_CATCH(statfs, -EACCES),
#endif
#ifdef __NR_fstatfs
	SYSCALL_CATCH(fstatfs, -EACCES),
#endif
#ifdef __NR_getcwd
	SYSCALL_CATCH(getcwd, -EACCES),
#endif
#ifdef __NR_futex
	SYSCALL_CATCH(futex, -EACCES),
#endif
#ifdef __NR_perf_event_open
	SYSCALL_CATCH(perf_event_open, -EACCES),
#endif
#ifdef __NR_socket
	SYSCALL_CATCH(socket, -EACCES),
#endif
#ifdef __NR_bind
	SYSCALL_CATCH(bind, -EACCES),
#endif
#ifdef __NR_connect
	SYSCALL_CATCH(connect, -EACCES),
#endif
#ifdef __NR_sendto
	SYSCALL_CATCH(sendto, -EACCES),
#endif
#ifdef __NR_mprotect
	SYSCALL_CATCH(mprotect, -EACCES),
#endif
#ifdef __NR_mremap
	SYSCALL_CATCH(mremap, -EFAULT),
#endif
#ifdef __NR_pselect6
	SYSCALL_CATCH(pselect6, -EFAULT),
#endif
#ifdef __NR_ioctl
	SYSCALL_CATCH(ioctl, -EFAULT),
#endif
#ifdef __NR_ioprio_set
	SYSCALL_CATCH(ioprio_set, -EFAULT),
#endif
#ifdef __NR_pipe2
	SYSCALL_CATCH(pipe2, -EFAULT),
#endif
#ifdef __NR_getdents64
	SYSCALL_CATCH(getdents64, -EFAULT),
#endif
#ifdef __NR_setitimer
	SYSCALL_CATCH(setitimer, -EFAULT),
#endif
#ifdef __NR_capget
	SYSCALL_CATCH(capget, -EFAULT),
#endif
#ifdef __NR_getresuid
	SYSCALL_CATCH(getresuid, -EFAULT),
#endif
#ifdef __NR_getresgid
	SYSCALL_CATCH(getresgid, -EFAULT),
#endif
#ifdef __NR_rt_sigprocmask
	SYSCALL_CATCH(rt_sigprocmask, 0), //-EFAULT, Skip this syscall due to HTML5 score of Geekbench5.4
#endif
#ifdef __NR_socketpair
	SYSCALL_CATCH(socketpair, -EFAULT),
#endif
#ifdef __NR_getsockname
	SYSCALL_CATCH(getsockname, -EFAULT),
#endif
#ifdef __NR_getpeername
	SYSCALL_CATCH(getpeername, -EFAULT),
#endif
#ifdef __NR_recvfrom
	SYSCALL_CATCH(recvfrom, -EFAULT),
#endif
#ifdef __NR_setsockopt
	SYSCALL_CATCH(setsockopt, -EFAULT),
#endif
#ifdef __NR_sendmsg
	SYSCALL_CATCH(sendmsg, -EFAULT),
#endif
#ifdef __NR_recvmsg
	SYSCALL_CATCH(recvmsg, -EFAULT),
#endif
#ifdef __NR_rt_sigsuspend
	SYSCALL_CATCH(rt_sigsuspend, -EFAULT),
#endif
#ifdef __NR_rt_sigpending
	SYSCALL_CATCH(rt_sigpending, -EFAULT),
#endif
#ifdef __NR_rt_sigaction
	SYSCALL_CATCH(rt_sigaction, -EFAULT),
#endif
#ifdef __NR_remap_file_pages
	SYSCALL_CATCH(remap_file_pages, -EINVAL),
#endif
#ifdef __NR_ppoll
	SYSCALL_CATCH(ppoll, -EINVAL),
#endif
#ifdef __NR_dup
	SYSCALL_CATCH(dup, -EINVAL),
#endif
#ifdef __NR_dup3
	SYSCALL_CATCH(dup3, -EINVAL),
#endif
#ifdef __NR_eventfd2
	SYSCALL_CATCH(eventfd2, -EINVAL),
#endif
#ifdef __NR_timerfd_create
	SYSCALL_CATCH(timerfd_create, -EINVAL),
#endif
#ifdef __NR_timerfd_gettime
	SYSCALL_CATCH(timerfd_gettime, -EINVAL),
#endif
#ifdef __NR_timerfd_settime
	SYSCALL_CATCH(timerfd_settime, -EINVAL),
#endif
#ifdef __NR_epoll_create1
	SYSCALL_CATCH(epoll_create1, -EINVAL),
#endif
#ifdef __NR_rt_sigtimedwait
	SYSCALL_CATCH(rt_sigtimedwait, -EINVAL),
#endif
#ifdef __NR_setxattr
	SYSCALL_CATCH(setxattr, -EEXIST),
#endif
#ifdef __NR_lsetxattr
	SYSCALL_CATCH(lsetxattr, -EEXIST),
#endif
#ifdef __NR_fsetxattr
	SYSCALL_CATCH(fsetxattr, -EEXIST),
#endif
#ifdef __NR_removexattr
	SYSCALL_CATCH(removexattr, -EEXIST),
#endif
#ifdef __NR_lremovexattr
	SYSCALL_CATCH(lremovexattr, -EEXIST),
#endif
#ifdef __NR_fremovexattr
	SYSCALL_CATCH(fremovexattr, -EEXIST),
#endif
#ifdef __NR_inotify_init1
	SYSCALL_CATCH(inotify_init1, -EMFILE),
#endif
#ifdef __NR_clone
	SYSCALL_CATCH(clone, -EINVAL),
#endif
#ifdef __NR_execve
	SYSCALL_CATCH(execve, 0), //-EPERM
#endif
#ifdef __NR_write
	SYSCALL_CATCH(write, 0), //-EPERM
#endif
#ifdef __NR_writev
	SYSCALL_CATCH(writev, -EPERM),
#endif
#ifdef __NR_pwrite64
	SYSCALL_CATCH(pwrite64, -EPERM),
#endif
#ifdef __NR_pwritev
	SYSCALL_CATCH(pwritev, -EPERM),
#endif
#ifdef __NR_epoll_ctl
	SYSCALL_CATCH(epoll_ctl, -EINVAL),
#endif
#ifdef __NR_epoll_pwait
	SYSCALL_CATCH(epoll_pwait, -EINVAL),
#endif
#ifdef __NR_sendfile
	SYSCALL_CATCH(sendfile, -EFAULT),
#endif
#ifdef __NR_signalfd4
	SYSCALL_CATCH(signalfd4, -EFAULT),
#endif
#ifdef __NR_vmsplice
	SYSCALL_CATCH(vmsplice, -EINVAL),
#endif
#ifdef __NR_splice
	SYSCALL_CATCH(splice, -EINVAL),
#endif
#ifdef __NR_tee
	SYSCALL_CATCH(tee, -EINVAL),
#endif
#ifdef __NR_fsync
	SYSCALL_CATCH(fsync, -EINVAL),
#endif
#ifdef __NR_fdatasync
	SYSCALL_CATCH(fdatasync, -EINVAL),
#endif
#ifdef __NR_sync_file_range
	SYSCALL_CATCH(sync_file_range, -EINVAL),
#endif
#ifdef __NR_acct
	SYSCALL_CATCH(acct, -EPERM),
#endif
#ifdef __NR_sched_setparam
	SYSCALL_CATCH(sched_setparam, -EINVAL),
#endif
#ifdef __NR_sched_setscheduler
	SYSCALL_CATCH(sched_setscheduler, -EINVAL),
#endif
#ifdef __NR_sched_setaffinity
	SYSCALL_CATCH(sched_setaffinity, -EINVAL),
#endif
#ifdef __NR_reboot
	SYSCALL_CATCH(reboot, -EPERM),
#endif
#ifdef __NR_mq_timedsend
	SYSCALL_CATCH(mq_timedsend, -EINVAL),
#endif
#ifdef __NR_mq_timedreceive
	SYSCALL_CATCH(mq_timedreceive, -EBADF),
#endif
#ifdef __NR_msgrcv
	SYSCALL_CATCH(msgrcv, -EINVAL),
#endif
#ifdef __NR_msgsnd
	SYSCALL_CATCH(msgsnd, -EFAULT),
#endif
#ifdef __NR_semtimedop
	SYSCALL_CATCH(semtimedop, -EINVAL),
#endif
#ifdef __NR_add_key
	SYSCALL_CATCH(add_key, -EINVAL),
#endif
#ifdef __NR_request_key
	SYSCALL_CATCH(request_key, -EINVAL),
#endif
#ifdef __NR_keyctl
	SYSCALL_CATCH(keyctl, -EOPNOTSUPP),
#endif
#ifdef __NR_mmap
	SYSCALL_CATCH(mmap, -EINVAL),
#endif
#ifdef __NR_mincore
	SYSCALL_CATCH(mincore, -EINVAL),
#endif
#ifdef __NR_mbind
	SYSCALL_CATCH(mbind, -EINVAL),
#endif
#ifdef __NR_set_mempolicy
	SYSCALL_CATCH(set_mempolicy, -EINVAL),
#endif
#ifdef __NR_migrate_pages
	SYSCALL_CATCH(migrate_pages, -EINVAL),
#endif
#ifdef __NR_accept4
	SYSCALL_CATCH(accept4, -EINVAL),
#endif
#ifdef __NR_recvmmsg
	SYSCALL_CATCH(recvmmsg, -EINVAL),
#endif
#ifdef __NR_link
	SYSCALL_CATCH(link, -EPERM),
#endif
#ifdef __NR_unlink
	SYSCALL_CATCH(unlink, -EPERM),
#endif
#ifdef __NR_mknod
	SYSCALL_CATCH(mknod, -EPERM),
#endif
#ifdef __NR_chmod
	SYSCALL_CATCH(chmod, -EPERM),
#endif
#ifdef __NR_chown
	SYSCALL_CATCH(chown, -EPERM),
#endif
#ifdef __NR_mkdir
	SYSCALL_CATCH(mkdir, -EPERM),
#endif
#ifdef __NR_lchown
	SYSCALL_CATCH(lchown, -EPERM),
#endif
#ifdef __NR_rename
	SYSCALL_CATCH(rename, -EPERM),
#endif
#ifdef __NR_epoll_wait
	SYSCALL_CATCH(epoll_wait, -EINVAL),
#endif
#ifdef __NR_sysctl
	SYSCALL_CATCH(sysctl, -EFAULT),
#endif
};
