/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Transparent Socket Impersonation Driver
 *
 * Copyright (C) 2022 Red Hat, Inc.
 *
 * Authors:
 *  Sergio Lopez <slp@redhat.com>
 */

#ifndef _AF_TSI_H_
#define _AF_TSI_H_

#include <linux/timer.h>
#include <linux/workqueue.h>

#define S_HYBRID           0
#define S_INET             1
#define S_VSOCK            2

#define TSI_DEFAULT_PORT   620
#define TSI_VERSION        4

#define TSI_PROXY_CREATE   1024
#define TSI_CONNECT        1025
#define TSI_GETNAME        1026
#define TSI_SENDTO_ADDR    1027
#define TSI_SENDTO_DATA    1028
#define TSI_LISTEN         1029
#define TSI_ACCEPT         1030
#define TSI_PROXY_RELEASE  1031
#define TSI_DATAGRAM       1032
#define TSI_DISCONNECT     1033
#define TSI_SETOPT         1034
#define TSI_GETOPT         1035
#define TSI_BIND           1036
#define TSI_OPTION_COUNT   8

#define TSI_ADDR_LEN       128
#define TSI_DGRAM_MAX_SIZE 65536
#define TSI_DGRAM_TRUNC    1
#define TSI_DGRAM_PKTINFO  2
#define TSI_DGRAM_HOPLIMIT 4
#define TSI_CONTROL_REPLY  1
#define TSI_CONTROL_ONEWAY 2
#define TSI_CONTROL_MAX    144
#define TSI_LISTEN_STRICT  1

struct tsi_control_hdr {
	__le32 version;
	__le32 operation;
	__le64 request_id;
	__le32 payload_len;
	__le32 flags;
};

struct tsi_proxy_create {
	__le32 svm_port;
	__le16 family;
	__le16 type;
	__le32 protocol;
} __attribute__((packed));

struct tsi_dgram_hdr {
	__le32 version;
	__le32 addr_len;
	__le32 data_len;
	__le32 flags;
	char addr[TSI_ADDR_LEN];
	__le32 ifindex;
	__le32 hop_limit;
	u8 local_addr[16];
};

struct tsi_connect_req {
	__le32 svm_port;
	__le32 addr_len;
	char addr[TSI_ADDR_LEN];
} __attribute__((packed));

struct tsi_connect_rsp {
	__le32 result;
};

struct tsi_sendto_addr {
	__le32 svm_port;
	__le32 addr_len;
	char addr[TSI_ADDR_LEN];
} __attribute__((packed));

struct tsi_listen_req {
	__le32 svm_port;
	__le32 vm_port;
	__le32 backlog;
	__le32 addr_len;
	char addr[TSI_ADDR_LEN];
} __attribute__((packed));

struct tsi_listen_rsp {
	__le32 result;
	__le32 flags;
};

struct tsi_accept_req {
	__le32 svm_port;
	__le32 flags;
} __attribute__((packed));

struct tsi_accept_rsp {
	__le32 result;
} __attribute__((packed));

struct tsi_getname_req {
	__le32 svm_port;
	__le32 svm_peer_port;
	__le32 peer;
} __attribute__((packed));

struct tsi_getname_rsp {
	__le32 result;
	__le32 addr_len;
	char addr[TSI_ADDR_LEN];
} __attribute__((packed));

struct tsi_option_req {
	__le32 svm_port;
	__le32 svm_peer_port;
	__le32 level;
	__le32 optname;
	__le32 value;
};

struct tsi_option_rsp {
	__le32 result;
	__le32 value;
};

enum tsi_connect_phase {
	TSI_CONNECT_NATIVE,
	TSI_CONNECT_HOST,
	TSI_CONNECT_DATA,
};

struct tsi_connect_watch {
	struct tsi_sock *tsk;
	struct sock *sk;
	void (*state_change)(struct sock *sk);
	void (*error_report)(struct sock *sk);
};

struct tsi_sock {
	/* sk must be the first member. */
	struct sock sk;
	struct socket *isocket;
	struct socket *vsocket;
	struct socket *csocket;
	unsigned int status;
	u32 svm_port;
	u32 svm_peer_port;
	struct sockaddr *bound_addr;
	struct sockaddr *sendto_addr;
	int bound_addr_len;
	int sendto_addr_len;
	u16 family;
	u32 protocol;
	u64 control_request_id;
	unsigned long control_deadline;
	bool control_broken;
	const struct cred *connect_cred;
	struct work_struct connect_work;
	struct timer_list connect_timer;
	struct tsi_connect_watch inet_watch;
	struct tsi_connect_watch vsock_watch;
	struct sockaddr_storage connect_addr;
	unsigned long connect_deadline;
	int connect_addr_len;
	int connect_error;
	enum tsi_connect_phase connect_phase;
	bool connect_pending;
	bool connect_cancelled;
	u8 option_mask;
	int option_values[TSI_OPTION_COUNT];
	bool accept_inet_first;
	struct sockaddr_storage udp_peer;
	int udp_peer_len;
	bool udp_proxy_connected;
	bool udp_proxy_synced;
	bool udp_recv_inet_first;
};

struct tsi_proxy_release {
	__le32 svm_port;
	__le32 svm_peer_port;
} __attribute__((packed));

#endif
