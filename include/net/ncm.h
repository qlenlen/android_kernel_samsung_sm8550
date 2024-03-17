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
#ifndef NCM_COMMON_H__
#define NCM_COMMON_H__

#define NCM_VERSION 11

#define INIT_UID_NAP 0
#define INIT_PID_NAP 1
#define DNS_PORT_NAP 53
#define IPV4_FAMILY_NAP 2
#define IPV6_FAMILY_NAP 10
#define INET6_ADDRSTRLEN_NAP 48

#define NCM_FLOW_TYPE_DEFAULT -1
#define NCM_FLOW_TYPE_ALL 0
#define NCM_FLOW_TYPE_OPEN 1
#define NCM_FLOW_TYPE_CLOSE 2
#define NCM_FLOW_TYPE_INTERMEDIATE 3

#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <net/netfilter/nf_conntrack.h>

#define isIpv4AddressEqualsNull(srcaddr, dstaddr) ((((strcmp(srcaddr, "0.0.0.0")) || (strcmp(dstaddr, "0.0.0.0"))) == 0) ? 1 : 0)
#define isIpv6AddressEqualsNull(srcaddr, dstaddr) ((((strcmp(srcaddr, "0000:0000:0000:0000:0000:0000:0000:0000")) || (strcmp(dstaddr, "0000:0000:0000:0000:0000:0000:0000:0000"))) == 0) ? 1 : 0)

/* Struct Socket definition */
struct knox_socket_metadata {
/* The source port of the socket */
	__u16   srcport;
/* The destination port of the socket */
	__u16   dstport;
/* The Transport layer protocol of the socket*/
	__u16   trans_proto;
/* The number of application layer bytes sent by the socket */
	__u64   knox_sent;
/* The number of application layer bytes recieved by the socket */
	__u64   knox_recv;
/* The uid which created the socket */
	uid_t   knox_uid;
/* The pid under which the socket was created */
	pid_t   knox_pid;
/* The parent user id under which the socket was created */
	uid_t   knox_puid;
/* The epoch time at which the socket was opened */
	__u64   open_time;
/* The epoch time at which the socket was closed */
	__u64   close_time;
/* The source address of the socket */
	char srcaddr[INET6_ADDRSTRLEN_NAP];
/* The destination address of the socket */
	char dstaddr[INET6_ADDRSTRLEN_NAP];
/* The name of the process which created the socket */
	char process_name[PROCESS_NAME_LEN_NAP];
/* The name of the parent process which created the socket */
	char parent_process_name[PROCESS_NAME_LEN_NAP];
/*  The Domain name associated with the ip address of the socket. The size needs to be in sync with the userspace implementation */
	char domain_name[DOMAIN_NAME_LEN_NAP];
/* The uid which originated the dns request */
	uid_t   knox_uid_dns;
/* The parent process id under which the socket was created */
	pid_t   knox_ppid;
/* The interface used by the flow to transmit packet */
	char interface_name[IFNAMSIZ];
/* The flow type is used identify the current state of the network flow*/
	int   flow_type;
/* The struct defined is responsible for inserting the socket meta-data into kfifo */
	struct work_struct work_kfifo;
};

/* Struct Socket definition */
struct knox_user_socket_metadata {
/* The source port of the socket */
	__u16   srcport;
/* The destination port of the socket */
	__u16   dstport;
/* The Transport layer protocol of the socket*/
	__u16   trans_proto;
/* The number of application layer bytes sent by the socket */
	__u64   knox_sent;
/* The number of application layer bytes recieved by the socket */
	__u64   knox_recv;
/* The uid which created the socket */
	uid_t   knox_uid;
/* The pid under which the socket was created */
	pid_t   knox_pid;
/* The parent user id under which the socket was created */
	uid_t   knox_puid;
/* The epoch time at which the socket was opened */
	__u64   open_time;
/* The epoch time at which the socket was closed */
	__u64   close_time;
/* The source address of the socket */
	char srcaddr[INET6_ADDRSTRLEN_NAP];
/* The destination address of the socket */
	char dstaddr[INET6_ADDRSTRLEN_NAP];
/* The name of the process which created the socket */
	char process_name[PROCESS_NAME_LEN_NAP];
/* The name of the parent process which created the socket */
	char parent_process_name[PROCESS_NAME_LEN_NAP];
/*  The Domain name associated with the ip address of the socket. The size needs to be in sync with the userspace implementation */
	char domain_name[DOMAIN_NAME_LEN_NAP];
/* The uid which originated the dns request */
	uid_t   knox_uid_dns;
/* The parent process id under which the socket was created */
	pid_t   knox_ppid;
/* The interface used by the flow to transmit packet */
	char interface_name[IFNAMSIZ];
/* The flow type is used identify the current state of the network flow*/
	int   flow_type;
};

/* The list of function which is being referenced */
extern unsigned int check_ncm_flag(void);
extern void knox_collect_conntrack_data(struct nf_conn *ct, int startStop, int where);
extern bool kfifo_status(void);
extern void insert_data_kfifo_kthread(struct knox_socket_metadata* knox_socket_metadata);
extern unsigned int check_intermediate_flag(void);
extern unsigned int get_intermediate_timeout(void);

/* Debug */
#define NCM_DEBUG        1
#if NCM_DEBUG
#define NCM_LOGD(...) printk("ncm: "__VA_ARGS__)
#else
#define NCM_LOGD(...)
#endif /* NCM_DEBUG */
#define NCM_LOGE(...) printk("ncm: "__VA_ARGS__)

/* IOCTL definitions*/
#define __NCMIOC    0x120
#define NCM_ACTIVATED_OPEN       _IO(__NCMIOC, 2)
#define NCM_DEACTIVATED          _IO(__NCMIOC, 4)
#define NCM_ACTIVATED_CLOSE      _IO(__NCMIOC, 8)
#define NCM_ACTIVATED_ALL        _IO(__NCMIOC, 16)
#define NCM_GETVERSION           _IO(__NCMIOC, 32)
#define NCM_MATCH_VERSION        _IO(__NCMIOC, 64)

#endif
// SEC_PRODUCT_FEATURE_KNOX_SUPPORT_NPA }
