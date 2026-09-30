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

#define S_HYBRID           0
#define S_INET             1
#define S_VSOCK            2

#define TSI_DEFAULT_PORT   620

#define TSI_PROXY_CREATE   1024
#define TSI_CONNECT        1025
#define TSI_GETNAME        1026
#define TSI_SENDTO_ADDR    1027
#define TSI_SENDTO_DATA    1028
#define TSI_LISTEN         1029
#define TSI_ACCEPT         1030
#define TSI_PROXY_RELEASE  1031

#define TSI_ADDR_LEN       128

struct tsi_proxy_create {
	u32 svm_port;
	u16 family;
	u16 type;
} __attribute__((packed));

struct tsi_connect_req {
	u32 svm_port;
	u32 addr_len;
	char addr[TSI_ADDR_LEN];
} __attribute__((packed));

struct tsi_connect_rsp {
	int result;
};

struct tsi_sendto_addr {
	u32 svm_port;
	u32 addr_len;
	char addr[TSI_ADDR_LEN];
} __attribute__((packed));

struct tsi_listen_req {
	u32 svm_port;
	u32 vm_port;
	u32 backlog;
	u32 addr_len;
	char addr[TSI_ADDR_LEN];
} __attribute__((packed));

struct tsi_listen_rsp {
	int result;
};

struct tsi_accept_req {
	u32 svm_port;
	int flags;
} __attribute__((packed));

struct tsi_accept_rsp {
	int result;
} __attribute__((packed));

struct tsi_getname_req {
	u32 svm_port;
	u32 svm_peer_port;
	u32 peer;
} __attribute__((packed));

struct tsi_getname_rsp {
	int result;
	u32 addr_len;
	char addr[TSI_ADDR_LEN];
} __attribute__((packed));

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
};

struct tsi_proxy_release {
	u32 svm_port;
	u32 svm_peer_port;
} __attribute__((packed));

#endif
