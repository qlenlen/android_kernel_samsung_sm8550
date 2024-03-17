#ifndef __KDP_H__
#define __KDP_H__

#ifndef __ASSEMBLY__
#include <linux/mm_types.h>
#include <linux/stddef.h>
#include <linux/uh.h>

#define __kdp_ro __section(".kdp_ro")
#define __lsm_ro_after_init_kdp __section(".kdp_ro")

#define CRED_JAR_RO		"cred_jar_ro"
#define TSEC_JAR		"tsec_jar"
#define VFSMNT_JAR		"vfsmnt_cache"

enum __KDP_CMD_ID {
	KDP_INIT			= 0x00,
	//SET_VERIFIED		= 0x01, // for BL. change to 0x00
	JARRO_TSEC_SIZE		= 0x02,
	SET_SLAB_RO			= 0x03,
	SET_FREEPTR			= 0x04,
	PREPARE_RO_CRED		= 0x05,
	SET_CRED_PGD		= 0x06,
	SELINUX_CRED_FREE	= 0x07,
	PGD_RWX				= 0x08,
	MARK_PPT			= 0x09,
	PROTECT_SELINUX_VAR = 0x0A,
	SET_CRED_UCOUNTS = 0x0B,
	NS_INIT				= 0x10,
	SET_NS_BP			= 0x11,
	SET_NS_DATA			= 0x12,
	SET_NS_ROOT_SB		= 0x13,
	SET_NS_SB_VFSMOUNT	= 0x14,
	SET_NS_FLAGS		= 0x15,
#ifdef CONFIG_KDP_TEST
	TEST_INIT			= 0x16,
	TEST_GET_PAR		= 0x17,
	TEST_EXIT			= 0x18,
#endif
	SET_NS_USERNS		= 0x20,
};

//kernel/cred.c
enum __CRED_CMD_ID {
	CMD_COPY_CREDS = 0,
	CMD_COMMIT_CREDS,
	CMD_OVRD_CREDS,
};

enum _KMEM_TYPE {
	UNKNOWN_JAR_TYPE = 0,
	CRED_JAR_TYPE,
	TSEC_JAR_TYPE,
	VFSMNT_JAR_TYPE
};

struct kdp_init {
	u64 _srodata;
	u64 _erodata;
	u64 init_mm_pgd;
	u32 credSize;
	u32 sp_size;
	u32 pgd_mm;
	u32 uid_cred;
	u32 euid_cred;
	u32 gid_cred;
	u32 egid_cred;
	u32 bp_pgd_cred;
	u32 bp_task_cred;
	u32 type_cred;
	u32 security_cred;
	u32 usage_cred;
	u32 cred_task;
	u32 mm_task;
	u32 pid_task;
	u32 rp_task;
	u32 comm_task;
	u32 bp_cred_secptr;
	u32 task_threadinfo;
	u64 verifiedbootstate;
	struct {
		u64 selinux_enforcing_va;
		u64 ss_initialized_va;
	} selinux;
};

extern bool kdp_enable;
extern void __init kdp_init(void);
extern int get_kdp_kmem_cache_type(const char *name);
extern bool is_kdp_kmem_cache(struct kmem_cache *s);
extern bool is_kdp_kmem_cache_name(const char *name);

#ifdef CONFIG_KDP_CRED
/***************** KDP_CRED *****************/
struct ro_rcu_head {
	/* RCU deletion */
	union {
		int non_rcu;		/* Can we skip RCU deletion? */
		struct rcu_head	rcu;	/* RCU deletion hook */
	};
	void *bp_cred;
	void *reflected_cred;
};

struct cred_param {
	struct cred_kdp *cred;
	struct cred_kdp *cred_ro;
	void *use_cnt_ptr;
	void *sec_ptr;
	unsigned long type;
	union {
		void *task_ptr;
		u64 use_cnt;
	};
};

#define PROTECT_INIT 1
#define PROTECT_KMEM 2

#define GET_ROCRED_RCU(cred) \
( \
	((u64)cred == (u64)&init_cred)? \
		(struct ro_rcu_head *)((atomic_t *)init_cred_kdp.use_cnt + 1): \
		(struct ro_rcu_head *)((atomic_t *)((struct cred_kdp *)cred)->use_cnt + 1) \
)

extern struct cred init_cred;
extern struct cred_kdp init_cred_kdp;
extern struct task_security_struct init_sec;
struct filename;

extern void __init kdp_cred_init(void);
extern void __init kdp_do_early_param_setup(char *param, char *val);

// match for kernel/cred.c function
extern inline void set_cred_subscribers(struct cred *cred, int n);

extern void put_rocred_rcu(struct rcu_head *rcu);
extern void kdp_put_cred_rcu(struct cred *cred, void *put_cred_rcu);
extern unsigned int kdp_get_usecount(struct cred *cred);
extern void kdp_usecount_inc(struct cred *cred);
extern unsigned int kdp_usecount_inc_not_zero(struct cred *cred);
extern unsigned int kdp_usecount_dec_and_test(struct cred *cred);
extern void kdp_set_cred_non_rcu(struct cred *cred, int val);

// linux/cred.h
extern int security_integrity_current(void);
extern struct cred *prepare_ro_creds(struct cred *old, int kdp_cmd, u64 p);

extern void kdp_assign_pgd(struct task_struct *p);
extern inline int kdp_restrict_fork(struct filename *path);
extern void kdp_free_security(unsigned long tsec);

extern int is_kdp_protect_addr(unsigned long addr);
extern void set_rocred_ucounts(struct cred *cred, struct ucounts *new_ucounts);
#endif /* CONFIG_KDP_CRED */

#ifdef CONFIG_KDP_NS
/***************** KDP_NS *****************/
struct ns_param {
	u32 ns_buff_size;
	u32 ns_size;
	u32 bp_offset;
	u32 sb_offset;
	u32 flag_offset;
	u32 data_offset;
	u32 userns_offset;
};

/* Populate all superblocks required for NS Protection */
enum __KDP_SB {
	KDP_SB_ROOTFS = 0,
	KDP_SB_ODM,
	KDP_SB_SYS,
	KDP_SB_VENDOR,
	KDP_SB_ART,
	KDP_SB_CRYPT,
	KDP_SB_DEX2OAT,
	KDP_SB_ADBD,
	KDP_SB_SYS_EXT,
	KDP_SB_MAX
};

/* fs/pnode.h */
#define IS_MNT_SHARED(m) (((struct kdp_mount *)(m))->mnt->mnt_flags & MNT_SHARED)
#define CLEAR_MNT_SHARED(m) kdp_clear_mnt_flags(((struct kdp_mount *)(m))->mnt,MNT_SHARED)
#define IS_MNT_UNBINDABLE(m) (((struct kdp_mount *)(m))->mnt->mnt_flags & MNT_UNBINDABLE)
#define IS_MNT_MARKED(m) (((struct kdp_mount *)(m))->mnt->mnt_flags & MNT_MARKED)
#define SET_MNT_MARK(m) kdp_set_mnt_flags(((struct kdp_mount *)(m))->mnt,MNT_MARKED)
#define CLEAR_MNT_MARK(m) kdp_clear_mnt_flags(((struct kdp_mount *)(m))->mnt,MNT_MARKED)
#define IS_MNT_LOCKED(m) (((struct kdp_mount *)(m))->mnt->mnt_flags & MNT_LOCKED)

struct mount;
struct vfsmount;
struct super_block;
struct path;
extern void __init kdp_mnt_init(void);
extern void __init kdp_init_mount_tree(struct vfsmount *mnt);

extern int kdp_mnt_alloc_vfsmount(struct mount *mnt);
extern void kdp_set_ns_data(struct vfsmount *mnt,void *data);
inline extern void kdp_set_mnt_root_sb(struct vfsmount *mnt, struct dentry *mnt_root, struct super_block *mnt_sb);
extern void kdp_set_mnt_flags(struct vfsmount *mnt, int flags);
inline extern void kdp_clear_mnt_flags(struct vfsmount *mnt,int flags);
inline extern void kdp_assign_mnt_flags(struct vfsmount *mnt, int flags);
extern void kdp_set_mnt_userns(struct vfsmount *mnt, struct user_namespace *userns);

extern bool is_kdp_vfsmnt_cache(unsigned long addr);
extern void kdp_free_vfsmount(void *objp);

#endif /* CONFIG_KDP_NS */

#endif //__ASSEMBLY__
#endif //__KDP_H__
