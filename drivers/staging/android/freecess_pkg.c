#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/file.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/list.h>
#include <linux/types.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/inet_hashtables.h>
#include <net/inet6_hashtables.h>
#include <linux/freecess.h>


#define MAX_REC_UID 64
static atomic_t uid_rec[MAX_REC_UID];
extern void binders_in_transcation(int uid);

static void freecess_add_uid(uid_t uid)
{
	int i, j;
	uid_t inner_uid;

	for (i = 0, j = MAX_REC_UID; i < MAX_REC_UID; i++) {
		inner_uid = atomic_read(&uid_rec[i]);
		if (inner_uid == 0 && j == MAX_REC_UID)
			j = i;
		else if (inner_uid == uid)
			goto out;
	}

	if (j < MAX_REC_UID)
		atomic_set(&uid_rec[j], uid);
	else
		pr_err("%s : add uid:%d failed (full)!\n", __func__, uid);
out:

	return;
}

static void freecess_del_uid(uid_t uid)
{
	int i;
	uid_t inner_uid;
	
	for (i = 0; i < MAX_REC_UID; i++) {
		inner_uid = (uid_t)atomic_read(&uid_rec[i]);
		if (inner_uid == uid) {
			atomic_set(&uid_rec[i], 0);
			break;
		}
	}

	return;
}

static void freecess_clear_all(void)
{
	int i;

	for (i = 0; i < MAX_REC_UID; i++) {
		atomic_set(&uid_rec[i], 0);
	}

	return;
}

static int find_and_clear_uid(uid_t uid)
{
	int found = 0;
	int i = 0;
	uid_t inner_uid;

	for (i = 0; i < MAX_REC_UID; i++) {
		inner_uid = atomic_read(&uid_rec[i]);
		if (unlikely (inner_uid == uid)) {
			if (atomic_cmpxchg(&uid_rec[i], uid, 0) == uid)
				found = 1;
			break;
		}
	}

	return found;
}

static void kfreecess_pkg_hook(void* data, unsigned int len)
{
	struct kfreecess_msg_data* payload = (struct kfreecess_msg_data*)data;

	switch (payload->pkg_info.cmd) {
		case ADD_UID:
			freecess_add_uid(payload->pkg_info.uid);
			break;
		case DEL_UID:
			freecess_del_uid(payload->pkg_info.uid);
			break;
		case CLEAR_ALL_UID:
			freecess_clear_all();
			break;
		default:
			break;
	}

	return;
}

static void kfreecess_cfb_hook(void* data, unsigned int len)
{
	struct kfreecess_msg_data* payload = (struct kfreecess_msg_data*)data;
	int uid = payload->target_uid;

	printk(KERN_INFO "cfb_target: uid = %d\n", uid);
	binders_in_transcation(uid);
}

static uid_t __sock_i_uid(struct sock *sk)
{
	uid_t uid;

	if(sk && sk->sk_socket) {
		uid = SOCK_INODE(sk->sk_socket)->i_uid.val;
		return uid;
	}

	return 0;
}

static unsigned int freecess_ip4_in(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	struct sock *sk;
	uid_t uid;
	int found;
	int protocol;

	protocol = ip_hdr(skb)->protocol;
	if (protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	sk = skb_to_full_sk(skb);
	if (sk == NULL || !sk_fullsock(sk))
		return NF_ACCEPT;

	uid = __sock_i_uid(sk);
	if (uid < UID_MIN_VALUE)
		return NF_ACCEPT;	

	found = find_and_clear_uid(uid);
	if (!found)
		return NF_ACCEPT;
	else if (pkg_report((int)uid) < 0)
		pr_err("%s : up report failed!\n", __func__);

	return NF_ACCEPT;
}

static unsigned int freecess_ip6_in(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	struct sock *sk;
	unsigned int thoff = 0;
	unsigned short frag_off = 0;
	int protohdr;
	uid_t uid;
	int found;

	protohdr = ipv6_find_hdr(skb, &thoff, -1, &frag_off, NULL);
	if (protohdr != IPPROTO_TCP)
		return NF_ACCEPT;

	sk = skb_to_full_sk(skb);
	if (sk == NULL || !sk_fullsock(sk))
		return NF_ACCEPT;

	uid = __sock_i_uid(sk);	
	if (uid < UID_MIN_VALUE)
		return NF_ACCEPT;

	found = find_and_clear_uid(uid);
	if (!found)
		return NF_ACCEPT;
	else if (pkg_report((int)uid) < 0)
		pr_err("%s : up report failed!\n", __func__);

	return NF_ACCEPT;
}

static inline unsigned int freecess_ip4_out(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{	
	return NF_ACCEPT;
}

static inline unsigned int freecess_ip6_out(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}

static struct nf_hook_ops freecess_nf_ops[] = {

	{
		.hook 		= 	freecess_ip4_in,
		.pf 		= 	NFPROTO_IPV4,
		.hooknum 	= 	NF_INET_LOCAL_IN,
		.priority 	= 	NF_IP_PRI_SELINUX_LAST + 1,
	},
	{
		.hook 		= 	freecess_ip6_in,
		.pf 		= 	NFPROTO_IPV6,
		.hooknum 	= 	NF_INET_LOCAL_IN,
		.priority 	= 	NF_IP6_PRI_SELINUX_LAST + 1,
	},

	{
		.hook		=	freecess_ip4_out,
		.pf		=	NFPROTO_IPV4,
		.hooknum	=	NF_INET_LOCAL_OUT,
		.priority	=	NF_IP_PRI_SELINUX_LAST + 1,
	},
	{
		.hook 		= 	freecess_ip6_out,
		.pf 		= 	NFPROTO_IPV6,
		.hooknum 	= 	NF_INET_LOCAL_OUT,
		.priority 	= 	NF_IP6_PRI_SELINUX_LAST + 1,
	},

};

static int __init kfreecess_pkg_init(void)
{
	int ret;
	int i;
	struct net *net;

	for (i = 0; i < MAX_REC_UID; i++)
		atomic_set(&uid_rec[i], 0);
	
	rtnl_lock();
	for_each_net(net) {
		ret = nf_register_net_hooks(net, freecess_nf_ops,
						ARRAY_SIZE(freecess_nf_ops));
		if (ret < 0) {
			pr_err("nf_register_hooks(freecess hooks) error\n");
			break;
		}
	}
	rtnl_unlock();

	if (ret < 0) {
		rtnl_lock();
		for_each_net(net) {
			nf_unregister_net_hooks(net, freecess_nf_ops,
						ARRAY_SIZE(freecess_nf_ops));
		}
		rtnl_unlock();
		return -1;
	}
	
	pr_err("nf_register_hooks(freecess hooks) success\n");

	register_kfreecess_hook(MOD_PKG, kfreecess_pkg_hook);
	register_kfreecess_hook(MOD_CFB, kfreecess_cfb_hook);

	return 0;
}

static void __exit kfreecess_pkg_exit(void)
{
	struct net *net;

	unregister_kfreecess_hook(MOD_PKG);
	unregister_kfreecess_hook(MOD_CFB);

	rtnl_lock();
	for_each_net(net) {
		nf_unregister_net_hooks(net, freecess_nf_ops,
					ARRAY_SIZE(freecess_nf_ops));
	}
	rtnl_unlock();
}


module_init(kfreecess_pkg_init);
module_exit(kfreecess_pkg_exit);

MODULE_LICENSE("GPL");
