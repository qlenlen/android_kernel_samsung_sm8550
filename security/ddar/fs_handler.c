/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 *
 * Sensitive Data Protection
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <crypto/internal/hash.h>
#include <crypto/scatterwalk.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/netlink.h>
#include <linux/net.h>
#include <net/netlink.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/audit.h>
#include <linux/jiffies.h>

#include <linux/version.h>
#include <ddar/fs_handler.h>
#include <ddar/fs_request.h>

#define RESULT_ARRAY_MAX_LEN 100

#define CRYPTO_MAX_TIMEOUT (HZ/5)

#define SDP_FS_HANDLER_REQ_TIMEOUT 3000

sdp_fs_handler_control_t g_sdp_fs_handler_control;

DEFINE_MUTEX(g_send_mutex);
static int g_user_pid = 0;
static struct sock *g_sock = NULL;

static int to_netlink_msg(sdp_fs_handler_request_t *req, char **msg);
static void request_send(sdp_fs_handler_control_t *con,
		sdp_fs_handler_request_t *req);
static sdp_fs_handler_request_t *request_find(sdp_fs_handler_control_t *con,
		u32 request_id);
static sdp_fs_handler_request_t *request_alloc(u32 opcode);
static void request_free(sdp_fs_handler_request_t *req);
static void req_dump(sdp_fs_handler_request_t *req, const char *msg);

/* Debug */
#define SDP_FS_HANDLER_DEBUG       0

#if SDP_FS_HANDLER_DEBUG
#define SDP_FS_HANDLER_LOGD(FMT, ...) printk("SDP_FS_HANDLER[%d] : %s " FMT, current->pid, __func__, ##__VA_ARGS__)
#else
#define SDP_FS_HANDLER_LOGD(FMT, ...)
#endif /* SDP_FS_HANDLER_DEBUG */
#define SDP_FS_HANDLER_LOGE(FMT, ...) printk("SDP_FS_HANDLER[%d]  : %s " FMT, current->pid, __func__, ##__VA_ARGS__)

static int __handle_request(sdp_fs_handler_request_t *req, char *ret)
{
	int rc = 0;

	struct sk_buff *skb_in = NULL;
	struct sk_buff *skb_out = NULL;
	struct nlmsghdr *nlh = NULL;

	char *nl_msg = NULL;
	int nl_msg_size = 0;

	SDP_FS_HANDLER_LOGD("====================== \t entred\n");

	if (req == NULL) {
		SDP_FS_HANDLER_LOGE("invalid request\n");
		return -1;
	}

	request_send(&g_sdp_fs_handler_control, req);

	nl_msg_size = to_netlink_msg(req, &nl_msg);
	if (nl_msg_size <= 0) {
		SDP_FS_HANDLER_LOGE("invalid opcode %d\n", req->opcode);
		return -1;
	}

	// sending netlink message
	skb_in = nlmsg_new(nl_msg_size, 0);
	if (!skb_in) {
		SDP_FS_HANDLER_LOGE("Failed to allocate new skb: \n");
		return -1;
	}

	nlh = nlmsg_put(skb_in, 0, 0, NLMSG_DONE, nl_msg_size, 0);
	if (nlh == NULL) {
		kfree_skb(skb_in);
		SDP_FS_HANDLER_LOGE("Failed to nlmsg_put \n");
		return -1;
	}
	NETLINK_CB(skb_in).dst_group = 0;
	memcpy(nlmsg_data(nlh), nl_msg, nl_msg_size);

	mutex_lock(&g_send_mutex);
	rc = nlmsg_unicast(g_sock, skb_in, g_user_pid);
	mutex_unlock(&g_send_mutex);

	skb_out = skb_dequeue(&g_sock->sk_receive_queue);
	if (skb_out) {
		kfree_skb(skb_out);
	}
	return 0;

}

int sdp_fs_request(sdp_fs_command_t *cmd, fs_request_cb_t callback)
{
	sdp_fs_handler_request_t *req = request_alloc(cmd->opcode);
	int ret = -1;
	req_dump(req, "request allocated");

	if (req) {
		memcpy(&req->command, cmd, sizeof(sdp_fs_command_t));
		req->command.req_id = req->id;

		req_dump(req, "__handle_reqeust start");
		ret = __handle_request(req, NULL);
		req_dump(req, "__handle_reqeust end");

		if (ret != 0) {
			SDP_FS_HANDLER_LOGE("opcode[%d] failed\n", cmd->opcode);
			goto error;
		}
	} else {
		SDP_FS_HANDLER_LOGE("request allocation failed\n");
		return -ENOMEM;
	}

	return 0;
error:
	request_free(req);
	return -1;
}

static int __recver(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	void *data;
	u16 msg_type = nlh->nlmsg_type;
	u32 err = 0;
	struct audit_status *status_get = NULL;
	u16 len = 0;

	data = NLMSG_DATA(nlh);
	len = ntohs(*(uint16_t *) (data + 1));
	switch (msg_type) {
	case SDP_FS_HANDLER_PID_SET:
		status_get = (struct audit_status *) data;
		g_user_pid = status_get->pid;
		break;
	case SDP_FS_HANDLER_RESULT: {
		result_t *result = (result_t *) data;
		sdp_fs_handler_request_t *req = NULL;

		printk("result : req_id[%d], opcode[%d] ret[%d]\n", result->request_id,
				result->opcode, result->ret);
		spin_lock(&g_sdp_fs_handler_control.lock);
		req = request_find(&g_sdp_fs_handler_control, result->request_id);
		spin_unlock(&g_sdp_fs_handler_control.lock);

		if (req == NULL) {
			SDP_FS_HANDLER_LOGE(
					"crypto result :: error! can't find request %d\n",
					result->request_id);
		} else {
			memcpy(&req->result, result, sizeof(result_t));
			req->state = SDP_FS_HANDLER_REQ_FINISHED;

			if (req->callback)
				req->callback(req->opcode, req->result.ret, req->command.ino);

			memset(result, 0, sizeof(result_t));
			request_free(req);
		}
		break;
	}
	default:
		SDP_FS_HANDLER_LOGE("unknown message type : %d\n", msg_type);
		break;
	}

	return err;
}

/* Receive messages from netlink socket. */
static void recver(struct sk_buff  *skb)
{
	struct nlmsghdr *nlh;
	int len;
	int err;

	nlh = nlmsg_hdr(skb);
	len = skb->len;

	err = __recver(skb, nlh);
}

static int to_netlink_msg(sdp_fs_handler_request_t *req, char **msg)
{
	*msg = (char *)&req->command;
	return sizeof(sdp_fs_command_t);
}

static u32 get_unique_id(sdp_fs_handler_control_t *control)
{
	SDP_FS_HANDLER_LOGD("locked\n");
	spin_lock(&control->lock);

	control->reqctr++;
	/* zero is special */
	if (control->reqctr == 0)
		control->reqctr = 1;

	spin_unlock(&control->lock);
	SDP_FS_HANDLER_LOGD("unlocked\n");

	return control->reqctr;
}
static void req_dump(sdp_fs_handler_request_t *req, const char *msg)
{
#if SDP_FS_HANDLER_DEBUG
	SDP_FS_HANDLER_LOGD("DUMP REQUEST [%s] ID[%d] opcode[%d] state[%d]\n", msg, req->id, req->opcode, req->state);
#endif
}

static void request_send(sdp_fs_handler_control_t *con,
		sdp_fs_handler_request_t *req)
{
	spin_lock(&con->lock);
	SDP_FS_HANDLER_LOGD("entered, control lock\n");

	list_add_tail(&req->list, &con->pending_list);
	req->state = SDP_FS_HANDLER_REQ_PENDING;

	SDP_FS_HANDLER_LOGD("exit, control unlock\n");
	spin_unlock(&con->lock);
}

static sdp_fs_handler_request_t *request_find(sdp_fs_handler_control_t *con,
		u32 request_id)
{
	struct list_head *entry;

	list_for_each(entry, &con->pending_list)
	{
		sdp_fs_handler_request_t *req;
		req = list_entry(entry, sdp_fs_handler_request_t, list);
		if (req->id == request_id)
			return req;
	}

	return NULL;
}

static struct kmem_cache *req_cachep;

static void request_init(sdp_fs_handler_request_t *req, u32 opcode)
{
	memset(req, 0, sizeof(sdp_fs_handler_request_t));

	req->state = SDP_FS_HANDLER_REQ_INIT;
	req->id = get_unique_id(&g_sdp_fs_handler_control);

	INIT_LIST_HEAD(&req->list);
	atomic_set(&req->count, 1);
	req->aborted = 0;
	req->opcode = opcode;
	req->callback = NULL;
}

static sdp_fs_handler_request_t *request_alloc(u32 opcode)
{
	sdp_fs_handler_request_t *req = kmem_cache_alloc(req_cachep, GFP_KERNEL);

	if (req)
		request_init(req, opcode);
	return req;
}

static void request_free(sdp_fs_handler_request_t *req)
{
	if (req) {
		req_dump(req, "request freed");
		/*
		 * TODO : lock needed here?
		 */
		list_del(&req->list);
		memset(req, 0, sizeof(sdp_fs_handler_request_t));
		kmem_cache_free(req_cachep, req);
	} else {
		SDP_FS_HANDLER_LOGE("req is NULL, skip free\n");
	}
}

static void control_init(sdp_fs_handler_control_t *con)
{
	SDP_FS_HANDLER_LOGD("sdp_fs_handler_control_init");
	spin_lock_init(&con->lock);
	INIT_LIST_HEAD(&con->pending_list);

	spin_lock(&con->lock);
	con->reqctr = 0;
	spin_unlock(&con->lock);
}

static int __init sdp_fs_handler_mod_init(void)
{
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 4, 0))
	struct netlink_kernel_cfg cfg = {
			.input  = recver,
	};

	g_sock = netlink_kernel_create(&init_net, SDP_FS_HANDLER_NETLINK, &cfg);
#else
	g_sock = netlink_kernel_create(&init_net, SDP_FS_HANDLER_NETLINK, 0, recver, NULL, THIS_MODULE);
#endif

	if (!g_sock) {
		SDP_FS_HANDLER_LOGE("Failed to create Crypto Netlink Socket .. Exiting \n");
		return -ENOMEM;
	}
	SDP_FS_HANDLER_LOGE("netlink socket is created successfully! \n");

	control_init(&g_sdp_fs_handler_control);
	req_cachep = kmem_cache_create("sdp_fs_handler_requst",
			sizeof(sdp_fs_handler_request_t),
			0, 0, NULL);
	if (!req_cachep) {
		netlink_kernel_release(g_sock);
		SDP_FS_HANDLER_LOGE("Failed to create sdp_fs_handler_requst cache mem.. Exiting \n");
		return -ENOMEM;
	}

	return 0;
}

static void __exit sdp_fs_handler_mod_exit(void)
{
	netlink_kernel_release(g_sock);
	kmem_cache_destroy(req_cachep);
}

module_init(sdp_fs_handler_mod_init);
module_exit(sdp_fs_handler_mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SDP FS netlink");

