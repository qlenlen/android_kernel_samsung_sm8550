/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef __CONFIG_SECURITY_DEFEX_H
#define __CONFIG_SECURITY_DEFEX_H

/* Defex init API */
int task_defex_enforce(struct task_struct *p, struct file *f, int syscall, ...);
int task_defex_zero_creds(struct task_struct *tsk);
asmlinkage int defex_syscall_enter(long int syscallno, struct pt_regs *regs);
int task_defex_user_exec(const char *new_file);
void __init defex_load_rules(void);
#endif /* CONFIG_SECURITY_DEFEX_H */
