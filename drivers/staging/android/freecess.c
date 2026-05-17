/*
 * Copyright (c) Samsung Technologies Co., Ltd. 2001-2017. All rights reserved.
 *
 * File name: freecess.c
 * Description: Use to thaw process from state 'D'
 * Author: chao.gu@samsung.com
 * Version: 0.2
 * Date:  2017/07/17
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/freecess.h>
#include <linux/freezer.h>
#include <net/sock.h>
#include <linux/hrtimer.h>
#include <linux/proc_fs.h>


#define RET_OK   0
#define RET_ERR  1
static struct sock *kfreecess_mod_sock = NULL;
static atomic_t bind_port[MOD_END];
static atomic_t kfreecess_init_suc;
static int last_kill_pid = -1;

int freecess_fw_version = 0;    // record freecess framework version

struct priv_data
{
	int target_uid;
	int flag;		    //MOD_SIG,MOD_BINDER
	int code; //RPC code
	char rpcname[INTERFACETOKEN_BUFF_SIZE]; //interface token
	pkg_info_t pkg_info;	//MOD_PKG
};

static freecess_hook mod_recv_handler[MOD_END];

static int check_msg_type(int type)
{
	return (type < MSG_TYPE_END) && (type > 0);
}

static int check_mod_type(int mod)
{
	return (mod < MOD_END) && (mod > 0);
}

int thread_group_is_frozen(struct task_struct* task)
{
	struct task_struct *leader = task->group_leader;

	return (freezing(leader) || frozen(leader));
}

static void dump_kfreecess_msg(struct kfreecess_msg_data *msg)
{
	printk(KERN_ERR "-----kfreecess msg dump-----\n");
	if (!msg) {
		printk(KERN_ERR "msg is NULL");
		return;
	}

	printk(KERN_ERR "type: %d\n", msg->type);
	printk(KERN_ERR "mode: %d\n", msg->mod);
	printk(KERN_ERR "src_portid: %d\n", msg->src_portid);
	printk(KERN_ERR "dest_portid: %d\n", msg->dst_portid);
	printk(KERN_ERR "kernel version: %d\n", FREECESS_KERNEL_VERSION);
	printk(KERN_ERR "fw version: %d\n", FREECESS_PEER_VERSION(msg->version));
	printk(KERN_ERR "target_uid: %d\n", msg->target_uid);
}


int mod_sendmsg(int type, int mod, struct priv_data* data)
{
	int ret, msg_len = 0;
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	struct kfreecess_msg_data *payload = NULL;

	if (!atomic_read(&kfreecess_init_suc))
		return RET_ERR;

	if (!check_msg_type(type)) {
		pr_err("%s: msg type is invalid! %d\n", __func__, type);
		return RET_ERR;
	}

	if (!check_mod_type(mod)) {
		pr_err("%s: mod type is invalid! %d\n", __func__, mod);
		return RET_ERR;
	}

	msg_len = sizeof(struct	kfreecess_msg_data);
	skb = nlmsg_new(msg_len, GFP_ATOMIC);
	if (!skb) {
		pr_err("%s alloc_skb failed! %d\n", __func__, mod);
		return RET_ERR;
	}

	nlh = nlmsg_put(skb, 0, 0, 0, msg_len, 0);
	if (!nlh) {
		kfree_skb(skb);
		return RET_ERR;
	}

	payload = nlmsg_data(nlh);
	payload->type = type;
	payload->mod = mod;
	payload->src_portid = KERNEL_ID_NETLINK;
	payload->dst_portid = atomic_read(&bind_port[mod]);
	payload->version = FREECESS_PACK_VERSION(FREECESS_KERNEL_VERSION);

	if (data) {
		payload->target_uid = data->target_uid;
		if (payload->mod == MOD_BINDER) {
			payload->code = data->code;
			memcpy(payload->rpcname, data->rpcname, sizeof(data->rpcname));
			payload->pkg_info.cmd = data->pkg_info.cmd;
		}
		if (payload->mod == MOD_PKG)
			memcpy(&payload->pkg_info, &data->pkg_info, sizeof(pkg_info_t));
		else
			payload->flag = data->flag;
	}
	if ((ret = nlmsg_unicast(kfreecess_mod_sock, skb, payload->dst_portid)) < 0) {
		pr_err("nlmsg_unicast failed! %s errno %d\n", __func__ , ret);
		return RET_ERR;
	}

	return RET_OK;
}

int sig_report(struct task_struct *p, bool report_pid)
{
	int ret = RET_OK;
	struct priv_data data;
	int target_pid = task_tgid_nr(p);
	memset(&data, 0, sizeof(struct priv_data));
	data.target_uid = task_uid(p).val;
	if (report_pid && !p->group_leader->ptrace) {
		data.flag = target_pid;
	}
	if (thread_group_is_frozen(p) && (target_pid != last_kill_pid)) {
		last_kill_pid = target_pid;
		ret = mod_sendmsg(MSG_TO_USER, MOD_SIG, &data);
	}

	return ret;
}

int binder_report(struct task_struct *p, int code, const char *str, int flag)
{
	int ret = RET_OK;
	struct priv_data data;
	memset(&data, 0, sizeof(struct priv_data));
	data.target_uid = -1;
	data.flag = flag;
	data.code = code;
	strlcpy(data.rpcname, str, INTERFACETOKEN_BUFF_SIZE);
	if(p) {
		data.target_uid = task_uid(p).val;
		data.pkg_info.cmd = p->pid;
	}
	ret = mod_sendmsg(MSG_TO_USER, MOD_BINDER, &data);
	return ret;
}

int pkg_report(int target_uid)
{
	int ret = RET_OK;
	struct priv_data data;
	memset(&data, 0, sizeof(struct priv_data));
	data.target_uid = target_uid;
	data.pkg_info.uid = (uid_t)target_uid;
	ret = mod_sendmsg(MSG_TO_USER, MOD_PKG, &data);
	return ret;
}

int cfb_report(int target_uid, const char *reason)
{
	int ret = RET_OK;
	struct priv_data data;

	printk(KERN_INFO "cfb_report: uid %d frozen, reason: %s\n", target_uid, reason);
	memset(&data, 0, sizeof(struct priv_data));
	data.target_uid = target_uid;
	ret = mod_sendmsg(MSG_TO_USER, MOD_CFB, &data);

	return ret;
}

static void recv_handler(struct sk_buff *skb)
{
	struct kfreecess_msg_data *payload = NULL;
	struct nlmsghdr *nlh = NULL;
	unsigned int msglen  = 0;
	uid_t uid = 0;

	if (!skb) {
		pr_err("recv_handler %s: skb is	NULL!\n", __func__);
		return;
	}

	uid = (*NETLINK_CREDS(skb)).uid.val;
	//only allow system user to communicate with Freecess kernel part.
	if (uid != 1000) {
		pr_err("freecess--uid: %d, permission denied\n", uid);
		return;
	}

	if (skb->len < NLMSG_SPACE(0) + sizeof(struct kfreecess_msg_data)) {
		pr_err("freecess recv_handler msglen invalid %u %lu\n", skb->len, (unsigned long)(NLMSG_SPACE(0) + sizeof(struct kfreecess_msg_data)));
		return;
	}

	nlh = nlmsg_hdr(skb);
	msglen = NLMSG_PAYLOAD(nlh, 0);
	if (msglen < sizeof(struct kfreecess_msg_data)) {
		pr_err("USER_HOOK_CALLBACK: payload msglen invalid %u %lu\n", msglen, (unsigned long)sizeof(struct kfreecess_msg_data));
		return;
	}

	payload = (struct kfreecess_msg_data*)NLMSG_DATA(nlh);

	if (payload->src_portid < 0) {
		pr_err("USER_HOOK_CALLBACK %s: src_portid %d is not valid!\n", __func__, payload->src_portid);
		return;
	}

	if (payload->dst_portid != KERNEL_ID_NETLINK) {
		pr_err("USER_HOOK_CALLBACK %s: dst_portid is %d not kernel!\n", __func__, payload->dst_portid);
		return;
	}

	if (!check_mod_type(payload->mod)) {
		pr_err("USER_HOOK_CALLBACK %s: mod %d is not valid!\n", __func__, payload->mod);
		return;
	}

	switch (payload->type) {
		case LOOPBACK_MSG:
			atomic_set(&bind_port[payload->mod], payload->src_portid);
			freecess_fw_version = FREECESS_PEER_VERSION(payload->version);
			dump_kfreecess_msg(payload);
			mod_sendmsg(LOOPBACK_MSG, payload->mod, NULL);
			break;
		case MSG_TO_KERN:
			if (mod_recv_handler[payload->mod])
				mod_recv_handler[payload->mod](payload, sizeof(struct kfreecess_msg_data));
			break;
		default:
			pr_err("msg type is valid %d\n", payload->type);
	}
}


int register_kfreecess_hook(int mod, freecess_hook hook)
{

	if (!check_mod_type(mod)) {
		pr_err("%s: mod type is invalid! %d\n", __func__, mod);
		return RET_ERR;
	}

	if (hook)
		mod_recv_handler[mod] = hook;
	return RET_OK;
}

int unregister_kfreecess_hook(int mod)
{
	if (!check_mod_type(mod)) {
		pr_err("%s: mod type is invalid! %d\n", __func__, mod);
		return RET_ERR;
	}
	mod_recv_handler[mod] = NULL;
	return RET_OK;
}

static int __init kfreecess_init(void)
{
	int ret = RET_ERR;
	int i;

	struct netlink_kernel_cfg cfg = {
		.input = recv_handler,
	};
	kfreecess_mod_sock = netlink_kernel_create(&init_net, NETLINK_KFREECESS, &cfg);
	if (!kfreecess_mod_sock) {
		pr_err("%s: create kfreecess_mod_sock socket error!\n", __func__);
		return ret;
	}

	for(i = 1; i<MOD_END; i++)
		atomic_set(&bind_port[i], 0);

	atomic_set(&kfreecess_init_suc, 1);
	return RET_OK;
}

static void __exit kfreecess_exit(void)
{
	if (kfreecess_mod_sock)
		netlink_kernel_release(kfreecess_mod_sock);
}

module_init(kfreecess_init);
module_exit(kfreecess_exit);

MODULE_LICENSE("GPL");
