/* SPDX-License-Identifier: GPL-2.0 */

#ifndef KMONITOR_H
#define KMONITOR_H

int binder_monitor(int from_pid, int from_tid, unsigned int code, int target_pid);

#define binder_monitor_attr(_name) \
static struct kobj_attribute _name##_attr = {	\
	.attr	= {				\
		.name = __stringify(_name),	\
		.mode = 0644,			\
	},					\
	.show	= _name##_show,			\
	.store	= _name##_store,		\
}

#define binder_monitor_attr_ro(_name) \
static struct kobj_attribute _name##_attr = {	\
	.attr	= {				\
		.name = __stringify(_name),	\
		.mode = S_IRUGO,		\
	},					\
	.show	= _name##_show,			\
}

#endif
