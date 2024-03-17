#ifndef KFRECESS_H
#define KFRECESS_H

#include <linux/sched.h>

#define KERNEL_ID_NETLINK      0x12341234
#define UID_MIN_VALUE          10000
#define MSG_NOOP               0
#define LOOPBACK_MSG           1
#define MSG_TO_KERN            2
#define MSG_TO_USER            3
#define MSG_TYPE_END           4

#define MOD_NOOP               0
#define MOD_BINDER             1
#define MOD_SIG                2
#define MOD_PKG                3
#define MOD_CFB                4
#define MOD_END                5
#define INTERFACETOKEN_BUFF_SIZE 100

typedef enum {
	ADD_UID,
	DEL_UID,
	CLEAR_ALL_UID,
} pkg_cmd_t;

typedef struct {
	pkg_cmd_t cmd;
	uid_t uid;
}pkg_info_t;


/*
 *  Freecess version management
 *  we have two definitions in both FW and kernel side for the kfreecess_msg_data
 *  and we also have many branches: different android versions, different devices,
 *  different chips, different kernel versions.
 *  and freecess have new features continuously in both FW & kernel side.
 *  So it is become more and more important that we need a version management
 *  for these different things.
 *  To keep compatibility with the old version, we re-use the "caller_pid" field
 *  because it is invalild in old version.
 *  we don't remove "caller_pid" for compatibility, instead, use an union to re-use the field.
 *  maybe in future, we can remove the caller_pid, DO NOT use this field.
 *
 *  use 28 bits to store the useless caller_pid, max pid num 268435455
 *  |-- 4bits version --|---------- 28bits caller_pid ----------|    0xF0000000
 *
 */

/* The initial version is 0, and used until P(contain P)
 *  For Q, because 8bytes ->12 bytes issue, use version 1
 *  If new featue added, version increased.
 */
#define FREECESS_KERNEL_VERSION 1
#define FREECESS_PEER_VERSION(version)   (((version) & 0xF0000000) >> 28)
#define FREECESS_PACK_VERSION(version)    ((version) << 28)

struct kfreecess_msg_data
{
	int type;
	int mod;
	int src_portid;
	int dst_portid;
	union {
		unsigned int caller_pid;
		unsigned int version;   // |--4bits version--|----28bits caller_pid----|
	};
	int target_uid;
	int flag;		//MOD_SIG,MOD_BINDER
	int code;
	char rpcname[INTERFACETOKEN_BUFF_SIZE];
	pkg_info_t pkg_info;	//MOD_PKG
};


extern int freecess_fw_version;    // record freecess framework version

typedef void (*freecess_hook)(void* data, unsigned int len);

int sig_report(struct task_struct *p, bool report_pid);
int binder_report(struct task_struct *p, int code, const char *str, int flag);
int pkg_report(int target_uid);
int cfb_report(int target_uid, const char *reason);
int register_kfreecess_hook(int mod, freecess_hook hook);
int unregister_kfreecess_hook(int mod);
int thread_group_is_frozen(struct task_struct* task);
#endif
