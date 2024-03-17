/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd.
 *
 * Network Context Metadata Module[NCM]:Implementation.
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// SEC_PRODUCT_FEATURE_KNOX_SUPPORT_NPA {
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sctp.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/time.h>
#include <linux/err.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/kfifo.h>
#include <linux/kthread.h>
#include <linux/interrupt.h>
#include <linux/poll.h>
#include <linux/udp.h>
#include <linux/sctp.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/inet.h>

#include <net/sock.h>
#include <net/ncm.h>
#include <net/ip.h>
#include <net/protocol.h>

#include <asm/current.h>

#define SUCCESS 0

#define FAILURE 1
/* fifo size in elements (bytes) */
#define FIFO_SIZE   1024
#define WAIT_TIMEOUT  10000 /*milliseconds */
/* Lock to maintain orderly insertion of elements into kfifo */
static DEFINE_MUTEX(ncm_lock);

static unsigned int ncm_activated_flag = 1;

static unsigned int ncm_deactivated_flag; // default = 0

static unsigned int intermediate_activated_flag = 1;

static unsigned int intermediate_deactivated_flag; // default = 0

static unsigned int device_open_count; // default = 0

static int ncm_activated_type = NCM_FLOW_TYPE_DEFAULT;

static struct nf_hook_ops nfho_ipv4_pr_conntrack;

static struct nf_hook_ops nfho_ipv6_pr_conntrack;

static struct nf_hook_ops nfho_ipv4_li_conntrack;

static struct nf_hook_ops nfho_ipv6_li_conntrack;

static struct workqueue_struct *eWq; // default = 0

wait_queue_head_t ncm_wq;

static atomic_t isNCMEnabled = ATOMIC_INIT(0);

static atomic_t isIntermediateFlowEnabled = ATOMIC_INIT(0);

static unsigned int intermediate_flow_timeout; // default = 0

extern struct knox_socket_metadata knox_socket_metadata;

DECLARE_KFIFO(knox_sock_info, struct knox_socket_metadata, FIFO_SIZE);

/* The function is used to check if ncm feature has been enabled or not; The default value is disabled */
unsigned int check_ncm_flag(void) {
	return atomic_read(&isNCMEnabled);
}
EXPORT_SYMBOL(check_ncm_flag);

/* This function is used to check if ncm feature has been enabled with intermediate flow feature */
unsigned int check_intermediate_flag(void) {
	return atomic_read(&isIntermediateFlowEnabled);
}
EXPORT_SYMBOL(check_intermediate_flag);

/** The funcation is used to chedk if the kfifo is active or not;
 *  If the kfifo is active, then the socket metadata would be inserted into the queue which will be read by the user-space;
 *  By default the kfifo is inactive;
 */
bool kfifo_status(void) {
	bool isKfifoActive = false;
	if (kfifo_initialized(&knox_sock_info)) {
		NCM_LOGD("The fifo queue for ncm was already intialized \n");
		isKfifoActive = true;
	} else {
		NCM_LOGE("The fifo queue for ncm is not intialized \n");
		isKfifoActive = false;
	}
	return isKfifoActive;
}
EXPORT_SYMBOL(kfifo_status);

/** The function is used to insert the socket meta-data into the fifo queue; insertion of data will happen in a seperate kernel thread;
 *  The meta data information will be collected from the context of the process which originates it;
 *  If the kfifo is full, then the kfifo is freed before inserting new meta-data;
 */
void insert_data_kfifo(struct work_struct *pwork) {
	struct knox_socket_metadata *knox_socket_metadata;

	knox_socket_metadata = container_of(pwork, struct knox_socket_metadata, work_kfifo);
	if (IS_ERR(knox_socket_metadata)) {
		NCM_LOGE("inserting data into the kfifo failed due to unknown error \n");
		goto err;
	}

	if (mutex_lock_interruptible(&ncm_lock)) {
		NCM_LOGE("inserting data into the kfifo failed due to an interuppt \n");
		goto err;
	}

	if (kfifo_initialized(&knox_sock_info)) {
		if (kfifo_is_full(&knox_sock_info)) {
			NCM_LOGD("The kfifo is full and need to free it \n");
			kfree(knox_socket_metadata);
		} else {
			kfifo_in(&knox_sock_info, knox_socket_metadata, 1);
			kfree(knox_socket_metadata);
		}
	} else {
		kfree(knox_socket_metadata);
	}
	mutex_unlock(&ncm_lock);
	return;

	err:
	if (knox_socket_metadata != NULL)
		kfree(knox_socket_metadata);
	return;
}

/** The function is used to insert the socket meta-data into the kfifo in a seperate kernel thread;
 *  The kernel threads which handles the responsibility of inserting the meta-data into the kfifo is manintained by the workqueue function;
 */
void insert_data_kfifo_kthread(struct knox_socket_metadata* knox_socket_metadata) {
	if (knox_socket_metadata != NULL)
	{
		INIT_WORK(&(knox_socket_metadata->work_kfifo), insert_data_kfifo);
		if (!eWq) {
			NCM_LOGD("ewq ncmworkqueue not initialized. Data not collected\r\n");
			kfree(knox_socket_metadata);
		}
		if (eWq) {
			queue_work(eWq, &(knox_socket_metadata->work_kfifo));
		}
	}
}
EXPORT_SYMBOL(insert_data_kfifo_kthread);


/* The function is used to check if the caller is system server or not; */
static int is_system_server(void) {
	uid_t uid = current_uid().val;
	switch (uid) {
	case 1000:
		return 1;
	case 0:
		return 1;
	default:
		break;
	}
	return 0;
}

/* The function is used to intialize the kfifo */
static void initialize_kfifo(void) {
	INIT_KFIFO(knox_sock_info);
	if (kfifo_initialized(&knox_sock_info)) {
		NCM_LOGD("The kfifo for knox ncm has been initialized \n");
		init_waitqueue_head(&ncm_wq);
	}
}

/* The function is used to create work queue */
static void initialize_ncmworkqueue(void) {
	if (!eWq) {
		NCM_LOGD("ewq..Single Thread created\r\n");
		eWq = create_workqueue("ncmworkqueue");
	}
}

/* The function is ued to free the kfifo */
static void free_kfifo(void) {
	if (kfifo_status()) {
		NCM_LOGD("The kfifo for knox ncm which was intialized is freed \n");
		kfifo_free(&knox_sock_info);
	}
}

/* The function is used to update the flag indicating whether the feature has been enabled or not */
static void update_ncm_flag(unsigned int ncmFlag) {
	if (ncmFlag == ncm_activated_flag)
		atomic_set(&isNCMEnabled, ncm_activated_flag);
	else
		atomic_set(&isNCMEnabled, ncm_deactivated_flag);
}

/* The function is used to update the flag indicating whether the intermediate flow feature has been enabled or not */
static void update_intermediate_flag(unsigned int ncmIntermediateFlag) {
	if (ncmIntermediateFlag == intermediate_activated_flag)
		atomic_set(&isIntermediateFlowEnabled, intermediate_activated_flag);
	else
		atomic_set(&isIntermediateFlowEnabled, intermediate_deactivated_flag);
}

/* The function is used to update the flag indicating start or stop flow  */
static void update_ncm_flow_type(int ncmFlowType) {
	ncm_activated_type = ncmFlowType;
}

/* This function is used to update the intermediate flow timeout value */
static void update_intermediate_timeout(unsigned int timeout) {
	intermediate_flow_timeout = timeout;
}

/* This function is used to get the intermediate flow timeout value */
unsigned int get_intermediate_timeout(void) {
	return intermediate_flow_timeout;
}
EXPORT_SYMBOL(get_intermediate_timeout);

/* IPv4 hook function to copy information from struct socket into struct nf_conn during first packet of the network flow */
static unsigned int hook_func_ipv4_out_conntrack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

	struct iphdr *ip_header = NULL;
	struct tcphdr *tcp_header = NULL;
	struct udphdr *udp_header = NULL;
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_tuple *tuple = NULL;
	char srcaddr[INET6_ADDRSTRLEN_NAP];
	char dstaddr[INET6_ADDRSTRLEN_NAP];

	if ((skb) && (skb->sk) && (skb->sk->sk_protocol != IPPROTO_UDP) && (skb->sk->sk_protocol != IPPROTO_TCP) && (skb->sk->sk_protocol != IPPROTO_ICMP) && (skb->sk->sk_protocol != IPPROTO_SCTP) && (skb->sk->sk_protocol != IPPROTO_ICMPV6)) {
		return NF_ACCEPT;
	}
	if ((current == NULL) || (current->cred == NULL)) {
		return NF_ACCEPT;
	}
	if ((current->cred->uid.val == INIT_UID_NAP && current->tgid == INIT_UID_NAP) || (current->cred->uid.val == INIT_UID_NAP && current->tgid == INIT_PID_NAP)) {
		return NF_ACCEPT;
	}

	if ( (skb) && (skb->sk) && (SOCK_NPA_VENDOR_DATA_GET(skb->sk) != NULL) ) {
		if ( (SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_pid == INIT_PID_NAP) && (SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_uid == INIT_UID_NAP) && (skb->sk->sk_protocol == IPPROTO_TCP) ) {
			return NF_ACCEPT;
		}
		if ( (skb->sk->sk_protocol == IPPROTO_UDP) || (skb->sk->sk_protocol == IPPROTO_TCP) || (skb->sk->sk_protocol == IPPROTO_ICMP) || (skb->sk->sk_protocol == IPPROTO_SCTP) || (skb->sk->sk_protocol == IPPROTO_ICMPV6) ) {
			ct = nf_ct_get(skb, &ctinfo);
			if ( (ct) && (NF_CONN_NPA_VENDOR_DATA_GET(ct) != NULL) && (!atomic_read(&NF_CONN_NPA_VENDOR_DATA_GET(ct)->startFlow)) && (!nf_ct_is_dying(ct)) ) {
				tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
				if (tuple) {
					sprintf(srcaddr,"%pI4",(void *)&tuple->src.u3.ip);
					sprintf(dstaddr,"%pI4",(void *)&tuple->dst.u3.ip);
					if ( isIpv4AddressEqualsNull(srcaddr, dstaddr) ) {
						return NF_ACCEPT;
					}
				} else {
					return NF_ACCEPT;
				}
				atomic_set(&NF_CONN_NPA_VENDOR_DATA_GET(ct)->startFlow, 1);
				if ( check_intermediate_flag() ) {
					NF_CONN_NPA_VENDOR_DATA_GET(ct)->npa_timeout = ((u32)(jiffies)) + (get_intermediate_timeout() * HZ);
					atomic_set(&NF_CONN_NPA_VENDOR_DATA_GET(ct)->intermediateFlow, 1);
				}
				NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_uid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_uid;
				NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_pid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_pid;
				memcpy(NF_CONN_NPA_VENDOR_DATA_GET(ct)->process_name,SOCK_NPA_VENDOR_DATA_GET(skb->sk)->process_name,sizeof(NF_CONN_NPA_VENDOR_DATA_GET(ct)->process_name)-1);
				NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_puid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_puid;
				NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_ppid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_ppid;
				memcpy(NF_CONN_NPA_VENDOR_DATA_GET(ct)->parent_process_name,SOCK_NPA_VENDOR_DATA_GET(skb->sk)->parent_process_name,sizeof(NF_CONN_NPA_VENDOR_DATA_GET(ct)->parent_process_name)-1);
				memcpy(NF_CONN_NPA_VENDOR_DATA_GET(ct)->domain_name,SOCK_NPA_VENDOR_DATA_GET(skb->sk)->domain_name,sizeof(NF_CONN_NPA_VENDOR_DATA_GET(ct)->domain_name)-1);
				if ( (skb->dev) ) {
					memcpy(NF_CONN_NPA_VENDOR_DATA_GET(ct)->interface_name,skb->dev->name,sizeof(NF_CONN_NPA_VENDOR_DATA_GET(ct)->interface_name)-1);
				} else {
					sprintf(NF_CONN_NPA_VENDOR_DATA_GET(ct)->interface_name,"%s","null");
				}
				ip_header = (struct iphdr *)skb_network_header(skb);
				if ( (ip_header) && (ip_header->protocol == IPPROTO_UDP) ) {
					udp_header = (struct udphdr *)skb_transport_header(skb);
					if (udp_header) {
						int udp_payload_size = (ntohs(udp_header->len)) - sizeof(struct udphdr);
						if ( (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + udp_payload_size) > ULLONG_MAX )
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = ULLONG_MAX;
						else
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + udp_payload_size;
						if ( (ntohs(udp_header->dest) ==  DNS_PORT_NAP) && (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_uid == INIT_UID_NAP) && (SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_dns_uid > INIT_UID_NAP) ) {
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_puid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_dns_uid;
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_ppid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_dns_pid;
							memcpy(NF_CONN_NPA_VENDOR_DATA_GET(ct)->parent_process_name,SOCK_NPA_VENDOR_DATA_GET(skb->sk)->dns_process_name,sizeof(NF_CONN_NPA_VENDOR_DATA_GET(ct)->parent_process_name)-1);
						}
					}
				} else if ( (ip_header) && (ip_header->protocol == IPPROTO_TCP) ) {
					tcp_header = (struct tcphdr *)skb_transport_header(skb);
					if (tcp_header) {
						int tcp_payload_size = (ntohs(ip_header->tot_len)) - (ip_header->ihl * 4) - (tcp_header->doff * 4);
						if ( (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + tcp_payload_size) > ULLONG_MAX )
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = ULLONG_MAX;
						else
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + tcp_payload_size;
						if ( (ntohs(tcp_header->dest) ==  DNS_PORT_NAP) && (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_uid == INIT_UID_NAP) && (SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_dns_uid > INIT_UID_NAP) ) {
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_puid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_dns_uid;
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_ppid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_dns_pid;
							memcpy(NF_CONN_NPA_VENDOR_DATA_GET(ct)->parent_process_name,SOCK_NPA_VENDOR_DATA_GET(skb->sk)->dns_process_name,sizeof(NF_CONN_NPA_VENDOR_DATA_GET(ct)->parent_process_name)-1);
						}
					}
				} else {
					NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = 0;
				}
				knox_collect_conntrack_data(ct, NCM_FLOW_TYPE_OPEN, 1);
			} else if ( (ct) && (NF_CONN_NPA_VENDOR_DATA_GET(ct) != NULL) && (!nf_ct_is_dying(ct)) ) {
				ip_header = (struct iphdr *)skb_network_header(skb);
				if ( (ip_header) && (ip_header->protocol == IPPROTO_UDP) ) {
					udp_header = (struct udphdr *)skb_transport_header(skb);
					if (udp_header) {
						int udp_payload_size = (ntohs(udp_header->len)) - sizeof(struct udphdr);
						if ( (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + udp_payload_size) > ULLONG_MAX )
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = ULLONG_MAX;
						else
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + udp_payload_size;
					}
				} else if ( (ip_header) && (ip_header->protocol == IPPROTO_TCP) ) {
					tcp_header = (struct tcphdr *)skb_transport_header(skb);
					if (tcp_header) {
						int tcp_payload_size = (ntohs(ip_header->tot_len)) - (ip_header->ihl * 4) - (tcp_header->doff * 4);
						if ( (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + tcp_payload_size) > ULLONG_MAX )
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = ULLONG_MAX;
						else
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + tcp_payload_size;
					}
				} else {
					NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = 0;
				}
			}
		}
	}

	return NF_ACCEPT;
}

/* IPv6 hook function to copy information from struct socket into struct nf_conn during first packet of the network flow */
static unsigned int hook_func_ipv6_out_conntrack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct ipv6hdr *ipv6_header = NULL;
	struct tcphdr *tcp_header = NULL;
	struct udphdr *udp_header = NULL;
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_tuple *tuple = NULL;
	char srcaddr[INET6_ADDRSTRLEN_NAP];
	char dstaddr[INET6_ADDRSTRLEN_NAP];

	if ((skb) && (skb->sk) && (skb->sk->sk_protocol != IPPROTO_UDP) && (skb->sk->sk_protocol != IPPROTO_TCP) && (skb->sk->sk_protocol != IPPROTO_ICMP) && (skb->sk->sk_protocol != IPPROTO_SCTP) && (skb->sk->sk_protocol != IPPROTO_ICMPV6)) {
		return NF_ACCEPT;
	}
	if ((current == NULL) || (current->cred == NULL)) {
		return NF_ACCEPT;
	}
	if ((current->cred->uid.val == INIT_UID_NAP && current->tgid == INIT_UID_NAP) || (current->cred->uid.val == INIT_UID_NAP && current->tgid == INIT_PID_NAP)) {
		return NF_ACCEPT;
	}

	if ( (skb) && (skb->sk) && (SOCK_NPA_VENDOR_DATA_GET(skb->sk) != NULL) ) {
		if ( (SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_pid == INIT_PID_NAP) && (SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_uid == INIT_UID_NAP) && (skb->sk->sk_protocol == IPPROTO_TCP) ) {
			return NF_ACCEPT;
		}
		if ( (skb->sk->sk_protocol == IPPROTO_UDP) || (skb->sk->sk_protocol == IPPROTO_TCP) || (skb->sk->sk_protocol == IPPROTO_ICMP) || (skb->sk->sk_protocol == IPPROTO_SCTP) || (skb->sk->sk_protocol == IPPROTO_ICMPV6) ) {
			ct = nf_ct_get(skb, &ctinfo);
			if ( (ct) && (NF_CONN_NPA_VENDOR_DATA_GET(ct) != NULL) && (!atomic_read(&NF_CONN_NPA_VENDOR_DATA_GET(ct)->startFlow)) && (!nf_ct_is_dying(ct)) ) {
				tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
				if (tuple) {
					sprintf(srcaddr,"%pI6",(void *)&tuple->src.u3.ip6);
					sprintf(dstaddr,"%pI6",(void *)&tuple->dst.u3.ip6);
					if ( isIpv6AddressEqualsNull(srcaddr, dstaddr) ) {
						return NF_ACCEPT;
					}
				} else {
					return NF_ACCEPT;
				}
				atomic_set(&NF_CONN_NPA_VENDOR_DATA_GET(ct)->startFlow, 1);
				if ( check_intermediate_flag() ) {
					NF_CONN_NPA_VENDOR_DATA_GET(ct)->npa_timeout = ((u32)(jiffies)) + (get_intermediate_timeout() * HZ);
					atomic_set(&NF_CONN_NPA_VENDOR_DATA_GET(ct)->intermediateFlow, 1);
				}
				NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_uid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_uid;
				NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_pid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_pid;
				memcpy(NF_CONN_NPA_VENDOR_DATA_GET(ct)->process_name,SOCK_NPA_VENDOR_DATA_GET(skb->sk)->process_name,sizeof(NF_CONN_NPA_VENDOR_DATA_GET(ct)->process_name)-1);
				NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_puid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_puid;
				NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_ppid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_ppid;
				memcpy(NF_CONN_NPA_VENDOR_DATA_GET(ct)->parent_process_name,SOCK_NPA_VENDOR_DATA_GET(skb->sk)->parent_process_name,sizeof(NF_CONN_NPA_VENDOR_DATA_GET(ct)->parent_process_name)-1);
				memcpy(NF_CONN_NPA_VENDOR_DATA_GET(ct)->domain_name,SOCK_NPA_VENDOR_DATA_GET(skb->sk)->domain_name,sizeof(NF_CONN_NPA_VENDOR_DATA_GET(ct)->domain_name)-1);
				if ( (skb->dev) ) {
					memcpy(NF_CONN_NPA_VENDOR_DATA_GET(ct)->interface_name,skb->dev->name,sizeof(NF_CONN_NPA_VENDOR_DATA_GET(ct)->interface_name)-1);
				} else {
					sprintf(NF_CONN_NPA_VENDOR_DATA_GET(ct)->interface_name,"%s","null");
				}
				ipv6_header = (struct ipv6hdr *)skb_network_header(skb);
				if ( (ipv6_header) && (ipv6_header->nexthdr == IPPROTO_UDP) ) {
					udp_header = (struct udphdr *)skb_transport_header(skb);
					if (udp_header) {
						int udp_payload_size = (ntohs(udp_header->len)) - sizeof(struct udphdr);
						if ( (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + udp_payload_size) > ULLONG_MAX )
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = ULLONG_MAX;
						else
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + udp_payload_size;
						if ( (ntohs(udp_header->dest) ==  DNS_PORT_NAP) && (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_uid == INIT_UID_NAP) && (SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_dns_uid > INIT_UID_NAP) ) {
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_puid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_dns_uid;
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_ppid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_dns_pid;
							memcpy(NF_CONN_NPA_VENDOR_DATA_GET(ct)->parent_process_name,SOCK_NPA_VENDOR_DATA_GET(skb->sk)->dns_process_name,sizeof(NF_CONN_NPA_VENDOR_DATA_GET(ct)->parent_process_name)-1);
						}
					}
				} else if ( (ipv6_header) && (ipv6_header->nexthdr == IPPROTO_TCP) ) {
					tcp_header = (struct tcphdr *)skb_transport_header(skb);
					if (tcp_header) {
						int tcp_payload_size = (ntohs(ipv6_header->payload_len)) - (tcp_header->doff * 4);
						if ( (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + tcp_payload_size) > ULLONG_MAX )
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = ULLONG_MAX;
						else
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + tcp_payload_size;
						if ( (ntohs(tcp_header->dest) ==  DNS_PORT_NAP) && (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_uid == INIT_UID_NAP) && (SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_dns_uid > INIT_UID_NAP) ) {
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_puid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_dns_uid;
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_ppid = SOCK_NPA_VENDOR_DATA_GET(skb->sk)->knox_dns_pid;
							memcpy(NF_CONN_NPA_VENDOR_DATA_GET(ct)->parent_process_name,SOCK_NPA_VENDOR_DATA_GET(skb->sk)->dns_process_name,sizeof(NF_CONN_NPA_VENDOR_DATA_GET(ct)->parent_process_name)-1);
						}
					}
				} else {
					NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = 0;
				}
				knox_collect_conntrack_data(ct, NCM_FLOW_TYPE_OPEN, 2);
			} else if ( (ct) && (NF_CONN_NPA_VENDOR_DATA_GET(ct) != NULL) && (!nf_ct_is_dying(ct)) ) {
				ipv6_header = (struct ipv6hdr *)skb_network_header(skb);
				if ( (ipv6_header) && (ipv6_header->nexthdr == IPPROTO_UDP) ) {
					udp_header = (struct udphdr *)skb_transport_header(skb);
					if (udp_header) {
						int udp_payload_size = (ntohs(udp_header->len)) - sizeof(struct udphdr);
						if ( (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + udp_payload_size) > ULLONG_MAX )
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = ULLONG_MAX;
						else
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + udp_payload_size;
					}
				} else if ( (ipv6_header) && (ipv6_header->nexthdr == IPPROTO_TCP) ) {
					tcp_header = (struct tcphdr *)skb_transport_header(skb);
					if (tcp_header) {
						int tcp_payload_size = (ntohs(ipv6_header->payload_len)) - (tcp_header->doff * 4);
						if ( (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + tcp_payload_size) > ULLONG_MAX )
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = ULLONG_MAX;
						else
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent + tcp_payload_size;
					}
				} else {
					NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent = 0;
				}
			}
		}
	}

	return NF_ACCEPT;
}

static unsigned int hook_func_ipv4_in_conntrack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct iphdr *ip_header = NULL;
	struct tcphdr *tcp_header = NULL;
	struct udphdr *udp_header = NULL;
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;

	if (skb){
		ip_header = (struct iphdr *)skb_network_header(skb);
		if ( (ip_header) && (ip_header->protocol == IPPROTO_TCP || ip_header->protocol == IPPROTO_UDP || ip_header->protocol == IPPROTO_SCTP || ip_header->protocol == IPPROTO_ICMP || ip_header->protocol == IPPROTO_ICMPV6) ) {
			ct = nf_ct_get(skb, &ctinfo);
			if ( (ct) && (NF_CONN_NPA_VENDOR_DATA_GET(ct) != NULL) &&  (!nf_ct_is_dying(ct)) ) {
				if (ip_header->protocol == IPPROTO_TCP) {
					tcp_header = (struct tcphdr *)skb_transport_header(skb);
					if (tcp_header) {
						int tcp_payload_size = (ntohs(ip_header->tot_len)) - (ip_header->ihl * 4) - (tcp_header->doff * 4);
						if ( (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv + tcp_payload_size) > ULLONG_MAX )
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv = ULLONG_MAX;
						else
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv + tcp_payload_size;
					}
				} else if (ip_header->protocol == IPPROTO_UDP) {
					udp_header = (struct udphdr *)skb_transport_header(skb);
					if (udp_header) {
						int udp_payload_size = (ntohs(udp_header->len)) - sizeof(struct udphdr);
						if ( (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv + udp_payload_size) > ULLONG_MAX )
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv = ULLONG_MAX;
						else
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv + udp_payload_size;
					}
				} else {
					NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv = 0;
				}
			}
		}
	}

	return NF_ACCEPT;
}

static unsigned int hook_func_ipv6_in_conntrack(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct ipv6hdr *ipv6_header = NULL;
	struct tcphdr *tcp_header = NULL;
	struct udphdr *udp_header = NULL;
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;

	if (skb){
		ipv6_header = (struct ipv6hdr *)skb_network_header(skb);
		if ( (ipv6_header) && (ipv6_header->nexthdr == IPPROTO_TCP || ipv6_header->nexthdr == IPPROTO_UDP || ipv6_header->nexthdr == IPPROTO_SCTP || ipv6_header->nexthdr == IPPROTO_ICMP || ipv6_header->nexthdr == IPPROTO_ICMPV6) ) {
			ct = nf_ct_get(skb, &ctinfo);
			if ( (ct) && (NF_CONN_NPA_VENDOR_DATA_GET(ct) != NULL) && (!nf_ct_is_dying(ct)) ) {
				if (ipv6_header->nexthdr == IPPROTO_TCP) {
					tcp_header = (struct tcphdr *)skb_transport_header(skb);
					if (tcp_header) {
						int tcp_payload_size = (ntohs(ipv6_header->payload_len)) - (tcp_header->doff * 4);
						if ( (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv + tcp_payload_size) > ULLONG_MAX )
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv = ULLONG_MAX;
						else
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv + tcp_payload_size;
					}
				} else if (ipv6_header->nexthdr == IPPROTO_UDP) {
					udp_header = (struct udphdr *)skb_transport_header(skb);
					if (udp_header) {
						int udp_payload_size = (ntohs(udp_header->len)) - sizeof(struct udphdr);
						if ( (NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv + udp_payload_size) > ULLONG_MAX )
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv = ULLONG_MAX;
						else
							NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv + udp_payload_size;
					}
				} else {
					NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv = 0;
				}
			}
		}
	}

	return NF_ACCEPT;
}

/* The fuction registers to listen for packets in the post-routing chain to collect detail; */
static void registerNetfilterHooks(void) {
	nfho_ipv4_pr_conntrack.hook = hook_func_ipv4_out_conntrack;
	nfho_ipv4_pr_conntrack.hooknum = NF_INET_POST_ROUTING;
	nfho_ipv4_pr_conntrack.pf = PF_INET;
	nfho_ipv4_pr_conntrack.priority = NF_IP_PRI_LAST;

	nfho_ipv6_pr_conntrack.hook = hook_func_ipv6_out_conntrack;
	nfho_ipv6_pr_conntrack.hooknum = NF_INET_POST_ROUTING;
	nfho_ipv6_pr_conntrack.pf = PF_INET6;
	nfho_ipv6_pr_conntrack.priority = NF_IP6_PRI_LAST;

	nfho_ipv4_li_conntrack.hook = hook_func_ipv4_in_conntrack;
	nfho_ipv4_li_conntrack.hooknum = NF_INET_LOCAL_IN;
	nfho_ipv4_li_conntrack.pf = PF_INET;
	nfho_ipv4_li_conntrack.priority = NF_IP_PRI_LAST;

	nfho_ipv6_li_conntrack.hook = hook_func_ipv6_in_conntrack;
	nfho_ipv6_li_conntrack.hooknum = NF_INET_LOCAL_IN;
	nfho_ipv6_li_conntrack.pf = PF_INET6;
	nfho_ipv6_li_conntrack.priority = NF_IP6_PRI_LAST;

	nf_register_net_hook(&init_net,&nfho_ipv4_pr_conntrack);
	nf_register_net_hook(&init_net,&nfho_ipv6_pr_conntrack);
	nf_register_net_hook(&init_net,&nfho_ipv4_li_conntrack);
	nf_register_net_hook(&init_net,&nfho_ipv6_li_conntrack);
}

/* The function un-registers the netfilter hook */
static void unregisterNetFilterHooks(void) {
	nf_unregister_net_hook(&init_net,&nfho_ipv4_pr_conntrack);
	nf_unregister_net_hook(&init_net,&nfho_ipv6_pr_conntrack);
	nf_unregister_net_hook(&init_net,&nfho_ipv4_li_conntrack);
	nf_unregister_net_hook(&init_net,&nfho_ipv6_li_conntrack);
}

/* Function to collect the conntrack meta-data information. This function is called from ncm.c during the flows first send data and nf_conntrack_core.c when flow is removed. */
void knox_collect_conntrack_data(struct nf_conn *ct, int startStop, int where) {
	if ( check_ncm_flag() && (ncm_activated_type == startStop || ncm_activated_type == NCM_FLOW_TYPE_ALL) && (NF_CONN_NPA_VENDOR_DATA_GET(ct) != NULL) ) {
		struct knox_socket_metadata *ksm = kzalloc(sizeof(struct knox_socket_metadata), GFP_ATOMIC);
		struct nf_conntrack_tuple *tuple = NULL;
		struct timespec64 close_timespec;

		if (ksm == NULL) {
			printk("kzalloc atomic memory allocation failed\n");
			return;
		}

		ksm->knox_uid = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_uid;
		ksm->knox_pid = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_pid;
		memcpy(ksm->process_name, NF_CONN_NPA_VENDOR_DATA_GET(ct)->process_name, sizeof(ksm->process_name)-1);
		ksm->trans_proto = nf_ct_protonum(ct);
		tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
		if (tuple != NULL) {
			if (nf_ct_l3num(ct) == IPV4_FAMILY_NAP) {
				sprintf(ksm->srcaddr,"%pI4",(void *)&tuple->src.u3.ip);
				sprintf(ksm->dstaddr,"%pI4",(void *)&tuple->dst.u3.ip);
			} else if (nf_ct_l3num(ct) == IPV6_FAMILY_NAP) {
				sprintf(ksm->srcaddr,"%pI6",(void *)&tuple->src.u3.ip6);
				sprintf(ksm->dstaddr,"%pI6",(void *)&tuple->dst.u3.ip6);
			}
			if (nf_ct_protonum(ct) == IPPROTO_UDP) {
				ksm->srcport = ntohs(tuple->src.u.udp.port);
				ksm->dstport = ntohs(tuple->dst.u.udp.port);
			} else if (nf_ct_protonum(ct) == IPPROTO_TCP) {
				ksm->srcport = ntohs(tuple->src.u.tcp.port);
				ksm->dstport = ntohs(tuple->dst.u.tcp.port);
			} else if (nf_ct_protonum(ct) == IPPROTO_SCTP) {
				ksm->srcport = ntohs(tuple->src.u.sctp.port);
				ksm->dstport = ntohs(tuple->dst.u.sctp.port);
			} else {
				ksm->srcport = 0;
				ksm->dstport = 0;
			}
		}
		memcpy(ksm->domain_name, NF_CONN_NPA_VENDOR_DATA_GET(ct)->domain_name, sizeof(ksm->domain_name)-1);
		ksm->open_time = NF_CONN_NPA_VENDOR_DATA_GET(ct)->open_time;
		if (startStop == NCM_FLOW_TYPE_OPEN) {
			ksm->close_time = 0;
		} else if (startStop == NCM_FLOW_TYPE_CLOSE) {
			ktime_get_ts64(&close_timespec);
            ksm->close_time = close_timespec.tv_sec;
		} else if (startStop == NCM_FLOW_TYPE_INTERMEDIATE) {
			ktime_get_ts64(&close_timespec);
            ksm->close_time = close_timespec.tv_sec;
		}
		ksm->knox_puid = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_puid;
		ksm->knox_ppid = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_ppid;
		memcpy(ksm->parent_process_name, NF_CONN_NPA_VENDOR_DATA_GET(ct)->parent_process_name, sizeof(ksm->parent_process_name)-1);
		if ( (nf_ct_protonum(ct) == IPPROTO_UDP) || (nf_ct_protonum(ct) == IPPROTO_TCP) || (nf_ct_protonum(ct) == IPPROTO_SCTP) ) {
			ksm->knox_sent = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_sent;
			ksm->knox_recv = NF_CONN_NPA_VENDOR_DATA_GET(ct)->knox_recv;
		} else {
			ksm->knox_sent = 0;
			ksm->knox_recv = 0;
		}
		if (ksm->dstport == DNS_PORT_NAP && ksm->knox_uid > INIT_UID_NAP) {
			ksm->knox_uid_dns = ksm->knox_uid;
		} else {
			ksm->knox_uid_dns = ksm->knox_puid;
		}
		memcpy(ksm->interface_name, NF_CONN_NPA_VENDOR_DATA_GET(ct)->interface_name, sizeof(ksm->interface_name)-1);
		if (startStop == NCM_FLOW_TYPE_OPEN) {
			ksm->flow_type = 1;
		} else if (startStop == NCM_FLOW_TYPE_CLOSE) {
			ksm->flow_type = 2;
		} else if (startStop == NCM_FLOW_TYPE_INTERMEDIATE) {
			ksm->flow_type = 3;
		} else {
			ksm->flow_type = 0;
		}

		insert_data_kfifo_kthread(ksm);
	}
}
EXPORT_SYMBOL(knox_collect_conntrack_data);

/* The function opens the char device through which the userspace reads the socket meta-data information */
static int ncm_open(struct inode *inode, struct file *file) {
	NCM_LOGD("ncm_open is being called. \n");

	if ( !(IS_ENABLED(CONFIG_NF_CONNTRACK)) ) {
		NCM_LOGE("ncm_open failed:Trying to open in device conntrack module is not enabled \n");
		return -EACCES;
	}

	if (!is_system_server()) {
		NCM_LOGE("ncm_open failed:Caller is a non system process with uid %u \n", (current_uid().val));
		return -EACCES;
	}

	if (device_open_count) {
		NCM_LOGE("ncm_open failed:The device is already in open state \n");
		return -EBUSY;
	}

	device_open_count++;

	try_module_get(THIS_MODULE);

	return SUCCESS;
}

#ifdef CONFIG_64BIT
static ssize_t ncm_copy_data_user_64(char __user *buf, size_t count)
{
	struct knox_socket_metadata kcm = {0};
	struct knox_user_socket_metadata user_copy = {0};

	unsigned long copied;
	int read = 0;

	if (mutex_lock_interruptible(&ncm_lock)) {
		NCM_LOGE("ncm_copy_data_user failed:Signal interuption \n");
		return 0;
	}
	read = kfifo_out(&knox_sock_info, &kcm, 1);
	mutex_unlock(&ncm_lock);
	if (read == 0) {
		return 0;
	}

	user_copy.srcport = kcm.srcport;
	user_copy.dstport = kcm.dstport;
	user_copy.trans_proto = kcm.trans_proto;
	user_copy.knox_sent = kcm.knox_sent;
	user_copy.knox_recv = kcm.knox_recv;
	user_copy.knox_uid = kcm.knox_uid;
	user_copy.knox_pid = kcm.knox_pid;
	user_copy.knox_puid = kcm.knox_puid;
	user_copy.open_time = kcm.open_time;
	user_copy.close_time = kcm.close_time;
	user_copy.knox_uid_dns = kcm.knox_uid_dns;
	user_copy.knox_ppid = kcm.knox_ppid;
	user_copy.flow_type = kcm.flow_type;

	memcpy(user_copy.srcaddr, kcm.srcaddr, sizeof(user_copy.srcaddr));
	memcpy(user_copy.dstaddr, kcm.dstaddr, sizeof(user_copy.dstaddr));

	memcpy(user_copy.process_name, kcm.process_name, sizeof(user_copy.process_name));
	memcpy(user_copy.parent_process_name, kcm.parent_process_name, sizeof(user_copy.parent_process_name));

	memcpy(user_copy.domain_name, kcm.domain_name, sizeof(user_copy.domain_name)-1);

	memcpy(user_copy.interface_name, kcm.interface_name, sizeof(user_copy.interface_name)-1);

	copied = copy_to_user(buf, &user_copy, sizeof(struct knox_user_socket_metadata));
	return count;
}
#else
static ssize_t ncm_copy_data_user(char __user *buf, size_t count)
{
	struct knox_socket_metadata *kcm = NULL;
	struct knox_user_socket_metadata user_copy = {0};

	unsigned long copied;
	int read = 0;

	if (mutex_lock_interruptible(&ncm_lock)) {
		NCM_LOGE("ncm_copy_data_user failed:Signal interuption \n");
		return 0;
	}

	kcm = kzalloc(sizeof (struct knox_socket_metadata), GFP_KERNEL);
	if (kcm == NULL) {
		mutex_unlock(&ncm_lock);
		return 0;
	}

	read = kfifo_out(&knox_sock_info, kcm, 1);
	mutex_unlock(&ncm_lock);
	if (read == 0) {
		kfree(kcm);
		return 0;
	}

	user_copy.srcport = kcm->srcport;
	user_copy.dstport = kcm->dstport;
	user_copy.trans_proto = kcm->trans_proto;
	user_copy.knox_sent = kcm->knox_sent;
	user_copy.knox_recv = kcm->knox_recv;
	user_copy.knox_uid = kcm->knox_uid;
	user_copy.knox_pid = kcm->knox_pid;
	user_copy.knox_puid = kcm->knox_puid;
	user_copy.open_time = kcm->open_time;
	user_copy.close_time = kcm->close_time;
	user_copy.knox_uid_dns = kcm->knox_uid_dns;
	user_copy.knox_ppid = kcm->knox_ppid;
	user_copy.flow_type = kcm->flow_type;

	memcpy(user_copy.srcaddr, kcm->srcaddr, sizeof(user_copy.srcaddr));
	memcpy(user_copy.dstaddr, kcm->dstaddr, sizeof(user_copy.dstaddr));

	memcpy(user_copy.process_name, kcm->process_name, sizeof(user_copy.process_name));
	memcpy(user_copy.parent_process_name, kcm->parent_process_name, sizeof(user_copy.parent_process_name));

	memcpy(user_copy.domain_name, kcm->domain_name, sizeof(user_copy.domain_name)-1);

	memcpy(user_copy.interface_name, kcm->interface_name, sizeof(user_copy.interface_name)-1);

	copied = copy_to_user(buf, &user_copy, sizeof(struct knox_user_socket_metadata));

	kfree(kcm);

	return count;
}
#endif

/* The function writes the socket meta-data to the user-space */
static ssize_t ncm_read(struct file *file, char __user *buf, size_t count, loff_t *off) {
	if (!is_system_server()) {
		NCM_LOGE("ncm_read failed:Caller is a non system process with uid %u \n", (current_uid().val));
		return -EACCES;
	}

	if (!eWq) {
		NCM_LOGD("ewq..Single Thread created\r\n");
		eWq = create_workqueue("ncmworkqueue");
	}

	#ifdef CONFIG_64BIT
	return ncm_copy_data_user_64(buf, count);
	#else
	return ncm_copy_data_user(buf, count);
	#endif

	return 0;
}

static ssize_t ncm_write(struct file *file, const char __user *buf, size_t count, loff_t *off) {
	char intermediate_string[6];
	int intermediate_value = 0;
	if (!is_system_server()) {
		NCM_LOGE("ncm_write failed:Caller is a non system process with uid %u \n", (current_uid().val));
		return -EACCES;
	}
	memset(intermediate_string,'\0',sizeof(intermediate_string));
	(void)copy_from_user(intermediate_string,buf,sizeof(intermediate_string)-1);
	intermediate_value = simple_strtol(intermediate_string, NULL, 10);
	if (intermediate_value > 0) {
		update_intermediate_timeout(intermediate_value);
		update_intermediate_flag(intermediate_activated_flag);
		return strlen(intermediate_string);
	}
	return intermediate_value;
}

/* The function closes the char device */
static int ncm_close(struct inode *inode, struct file *file) {
	NCM_LOGD("ncm_close is being called \n");
	if (!is_system_server()) {
		NCM_LOGE("ncm_close failed:Caller is a non system process with uid %u \n", (current_uid().val));
		return -EACCES;
	}
	device_open_count--;
	module_put(THIS_MODULE);
	if (!check_ncm_flag())  {
		NCM_LOGD("ncm_close success: The device was already in closed state \n");
		return SUCCESS;
	}
	update_ncm_flag(ncm_deactivated_flag);
	free_kfifo();
	unregisterNetFilterHooks();
	return SUCCESS;
}

/* The function sets the flag which indicates whether the ncm feature needs to be enabled or disabled */
static long ncm_ioctl_evt(struct file *file, unsigned int cmd, unsigned long arg) {
	if (!is_system_server()) {
		NCM_LOGE("ncm_ioctl_evt failed:Caller is a non system process with uid %u \n", (current_uid().val));
		return -EACCES;
	}
	switch (cmd) {
	case NCM_ACTIVATED_ALL: {
		NCM_LOGD("ncm_ioctl_evt is being NCM_ACTIVATED with the ioctl command %u \n", cmd);
		if (check_ncm_flag())
			return SUCCESS;
		registerNetfilterHooks();
		initialize_kfifo();
		initialize_ncmworkqueue();
		update_ncm_flag(ncm_activated_flag);
		update_ncm_flow_type(NCM_FLOW_TYPE_ALL);
		break;
	}
	case NCM_ACTIVATED_OPEN: {
		NCM_LOGD("ncm_ioctl_evt is being NCM_ACTIVATED with the ioctl command %u \n", cmd);
		if (check_ncm_flag())
			return SUCCESS;
		update_intermediate_timeout(0);
		update_intermediate_flag(intermediate_deactivated_flag);
		registerNetfilterHooks();
		initialize_kfifo();
		initialize_ncmworkqueue();
		update_ncm_flag(ncm_activated_flag);
		update_ncm_flow_type(NCM_FLOW_TYPE_OPEN);
		break;
	}
	case NCM_ACTIVATED_CLOSE: {
		NCM_LOGD("ncm_ioctl_evt is being NCM_ACTIVATED with the ioctl command %u \n", cmd);
		if (check_ncm_flag())
			return SUCCESS;
		update_intermediate_timeout(0);
		update_intermediate_flag(intermediate_deactivated_flag);
		registerNetfilterHooks();
		initialize_kfifo();
		initialize_ncmworkqueue();
		update_ncm_flag(ncm_activated_flag);
		update_ncm_flow_type(NCM_FLOW_TYPE_CLOSE);
		break;
	}
	case NCM_DEACTIVATED: {
		NCM_LOGD("ncm_ioctl_evt is being NCM_DEACTIVATED with the ioctl command %u \n", cmd);
		if (!check_ncm_flag())
			return SUCCESS;
		update_intermediate_flag(intermediate_deactivated_flag);
		update_ncm_flow_type(NCM_FLOW_TYPE_DEFAULT);
		update_ncm_flag(ncm_deactivated_flag);
		free_kfifo();
		unregisterNetFilterHooks();
		update_intermediate_timeout(0);
		break;
	}
	case NCM_GETVERSION: {
		NCM_LOGD("ncm_ioctl_evt is being NCM_GETVERSION with the ioctl command %u \n", cmd);
		return NCM_VERSION;
		break;
	}
	case NCM_MATCH_VERSION: {
		NCM_LOGD("ncm_ioctl_evt is being NCM_MATCH_VERSION with the ioctl command %u \n", cmd);
		return sizeof(struct knox_user_socket_metadata);
		break;
	}
	default:
		break;
	}
	return SUCCESS;
}

static unsigned int ncm_poll(struct file *file, poll_table *pt) {
	int mask = 0;
	int ret = 0;
	if (kfifo_is_empty(&knox_sock_info)) {
		ret = wait_event_interruptible_timeout(ncm_wq, !kfifo_is_empty(&knox_sock_info), msecs_to_jiffies(WAIT_TIMEOUT));
		switch (ret) {
		case -ERESTARTSYS:
			mask = -EINTR;
			break;
		case 0:
			mask = 0;
			break;
		case 1:
			mask |= POLLIN | POLLRDNORM;
			break;
		default:
			mask |= POLLIN | POLLRDNORM;
			break;
		}
		return mask;
	} else {
		mask |= POLLIN | POLLRDNORM;
	}
	return mask;
}

static const struct file_operations ncm_fops = {
	.owner          = THIS_MODULE,
	.open           = ncm_open,
	.read           = ncm_read,
	.write          = ncm_write,
	.release        = ncm_close,
	.unlocked_ioctl = ncm_ioctl_evt,
	.compat_ioctl   = ncm_ioctl_evt,
	.poll           = ncm_poll,
};

struct miscdevice ncm_misc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ncm_dev",
	.fops = &ncm_fops,
};

static int __init ncm_init(void) {
	int ret;
	ret = misc_register(&ncm_misc_device);
	if (unlikely(ret)) {
		NCM_LOGE("failed to register ncm misc device!\n");
		return ret;
	}
	NCM_LOGD("Network Context Metadata Module: initialized\n");
	return SUCCESS;
}

static void __exit ncm_exit(void) {
	misc_deregister(&ncm_misc_device);
	NCM_LOGD("Network Context Metadata Module: unloaded\n");
}

module_init(ncm_init)
module_exit(ncm_exit)

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Network Context Metadata Module:");
// SEC_PRODUCT_FEATURE_KNOX_SUPPORT_NPA }
