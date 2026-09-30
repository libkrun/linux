/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Transparent Socket Impersonation Driver
 *
 * Copyright (C) 2022 Red Hat, Inc.
 *
 * Authors:
 *  Sergio Lopez <slp@redhat.com>
 */

#include <linux/types.h>
#include <linux/cred.h>
#include <linux/atomic.h>
#include <linux/inetdevice.h>
#include <linux/unaligned.h>
#include <linux/poll.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <net/af_vsock.h>
#include <net/route.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/inet_hashtables.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include "af_tsi.h"

static_assert(sizeof(struct tsi_dgram_hdr) == 168);
static_assert(sizeof(struct tsi_control_hdr) == 24);

/* IDs remain distinct even when a private control port is reused. */
static atomic64_t tsi_request_id = ATOMIC64_INIT(0);

/* TSI for IPv4 family. */
static struct proto tsi_in4_proto = {
	.name = "AF_TSI",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct tsi_sock),
};

/* TSI for IPv6 family. */
static struct proto tsi_in6_proto = {
	.name = "AF_TSI6",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct tsi_sock),
};

/* TSI for UNIX family. */
static struct proto tsi_un_proto = {
	.name = "AF_TSIU",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct tsi_sock),
};

#define tsi_sk(__sk) ((struct tsi_sock *)__sk)
#define sk_tsi(__tsk) (&(__tsk)->sk)

static void tsi_connect_work(struct work_struct *work);
static void tsi_connect_timer(struct timer_list *timer);
static int tsi_udp_bind_proxy(struct tsi_sock *tsk);

static void tsi_init_connect(struct tsi_sock *tsk)
{
	INIT_WORK(&tsk->connect_work, tsi_connect_work);
	timer_setup(&tsk->connect_timer, tsi_connect_timer, 0);
}

static bool tsi_connect_cancelled(struct tsi_sock *tsk)
{
	return READ_ONCE(tsk->connect_pending) && READ_ONCE(tsk->connect_cancelled);
}

static void tsi_queue_connect(struct tsi_sock *tsk)
{
	if (READ_ONCE(tsk->connect_pending) && !READ_ONCE(tsk->connect_cancelled))
		queue_work(system_unbound_wq, &tsk->connect_work);
}

static void tsi_connect_notify(struct sock *sk, bool error)
{
	struct tsi_connect_watch *watch;
	void (*state_change)(struct sock *) = NULL;

	rcu_read_lock();
	read_lock_bh(&sk->sk_callback_lock);
	watch = rcu_dereference_sk_user_data(sk);
	if (watch) {
		state_change = error ? watch->error_report : watch->state_change;
		tsi_queue_connect(watch->tsk);
	}
	read_unlock_bh(&sk->sk_callback_lock);
	rcu_read_unlock();
	if (state_change)
		state_change(sk);
}

static void tsi_connect_state_change(struct sock *sk)
{
	tsi_connect_notify(sk, false);
}

static void tsi_connect_error_report(struct sock *sk)
{
	tsi_connect_notify(sk, true);
}

static void tsi_watch_connect(struct tsi_sock *tsk, struct tsi_connect_watch *watch,
			      struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (watch->sk)
		return;
	write_lock_bh(&sk->sk_callback_lock);
	watch->tsk = tsk;
	watch->sk = sk;
	watch->state_change = sk->sk_state_change;
	watch->error_report = sk->sk_error_report;
	rcu_assign_sk_user_data(sk, watch);
	WRITE_ONCE(sk->sk_state_change, tsi_connect_state_change);
	WRITE_ONCE(sk->sk_error_report, tsi_connect_error_report);
	write_unlock_bh(&sk->sk_callback_lock);
}

static void tsi_unwatch_connect(struct tsi_connect_watch *watch)
{
	struct sock *sk = watch->sk;

	if (!sk)
		return;
	write_lock_bh(&sk->sk_callback_lock);
	WRITE_ONCE(sk->sk_state_change, watch->state_change);
	WRITE_ONCE(sk->sk_error_report, watch->error_report);
	rcu_assign_sk_user_data(sk, NULL);
	write_unlock_bh(&sk->sk_callback_lock);
}

static void tsi_cancel_connect(struct tsi_sock *tsk)
{
	WRITE_ONCE(tsk->connect_cancelled, true);
	tsi_unwatch_connect(&tsk->inet_watch);
	tsi_unwatch_connect(&tsk->vsock_watch);
	if (tsk->csocket) {
		write_lock_bh(&tsk->csocket->sk->sk_callback_lock);
		rcu_assign_sk_user_data(tsk->csocket->sk, NULL);
		write_unlock_bh(&tsk->csocket->sk->sk_callback_lock);
		wake_up_all(sk_sleep(tsk->csocket->sk));
	}
	/* Stop all work producers before draining the worker and its credentials. */
	timer_shutdown_sync(&tsk->connect_timer);
	cancel_work_sync(&tsk->connect_work);
	if (tsk->connect_cred) {
		put_cred(tsk->connect_cred);
		tsk->connect_cred = NULL;
	}
}

static int tsi_check_addr_len(struct tsi_sock *tsk, int addr_len)
{
	if (addr_len < (int)sizeof(sa_family_t))
		return -EINVAL;

	if (tsk->family == PF_INET) {
		if (addr_len != sizeof(struct sockaddr_in)) {
			return -EINVAL;
		}
	} else if (tsk->family == PF_INET6) {
		if (addr_len != sizeof(struct sockaddr_in6)) {
			return -EINVAL;
		}
	} else if (tsk->family == PF_UNIX) {
		if (addr_len > TSI_ADDR_LEN) {
			return -EINVAL;
		}
	} else {
		panic("Unsupported family in tsk->family=%d", tsk->family);
	}

	return 0;
}

static void tsi_control_data_ready(struct sock *sk)
{
	struct socket_wq *wq;
	struct tsi_sock *tsk;

	/* Post-accept accounting must finish even when a signal is pending. */
	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (wq)
		wake_up_all(&wq->wait);
	rcu_read_unlock();
	rcu_read_lock();
	read_lock_bh(&sk->sk_callback_lock);
	tsk = rcu_dereference_sk_user_data(sk);
	if (tsk)
		tsi_queue_connect(tsk);
	read_unlock_bh(&sk->sk_callback_lock);
	rcu_read_unlock();
}

static int tsi_create_control_socket(struct socket **csocket)
{
	struct sockaddr_vm vm_addr;
	int err;

	err = __sock_create(current->nsproxy->net_ns, PF_VSOCK, SOCK_DGRAM, 0,
			    csocket, 1);
	if (err) {
		pr_debug("%s: error creating control socket\n", __func__);
		return err;
	}
	(*csocket)->sk->sk_data_ready = tsi_control_data_ready;

	memset(&vm_addr, 0, sizeof(struct sockaddr_vm));
	vm_addr.svm_family = AF_VSOCK;
	vm_addr.svm_port = VMADDR_PORT_ANY;
	vm_addr.svm_cid = VMADDR_CID_ANY;

	err = kernel_bind(*csocket, (struct sockaddr_unsized *)&vm_addr,
			  sizeof(struct sockaddr_vm));
	if (err) {
		pr_debug("%s: error binding port\n", __func__);
		sock_release(*csocket);
		return err;
	}

	return 0;
}

static void tsi_control_failed(struct tsi_sock *tsk)
{
	if (!tsk->control_broken)
		WRITE_ONCE(sk_tsi(tsk)->sk_err, EIO);
	WRITE_ONCE(tsk->control_broken, true);
	if (tsk->isocket)
		wake_up_all(sk_sleep(tsk->isocket->sk));
	if (tsk->vsocket)
		wake_up_all(sk_sleep(tsk->vsocket->sk));
}

/* The TSI lock or pending connect worker owns this private control channel. */
static int tsi_control_sendmsg(struct tsi_sock *tsk, int port, void *data,
			       int data_len)
{
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = VMADDR_CID_HOST,
		.svm_port = port,
	};
	bool oneway = port == TSI_PROXY_RELEASE || port == TSI_SENDTO_ADDR;
	struct tsi_control_hdr hdr = {
		.version = cpu_to_le32(TSI_VERSION),
		.operation = cpu_to_le32(port),
		.payload_len = cpu_to_le32(data_len),
		.flags = cpu_to_le32(oneway ? TSI_CONTROL_ONEWAY : 0),
	};
	struct msghdr msg = {
		.msg_name = &addr,
		.msg_namelen = sizeof(addr),
		.msg_flags = MSG_DONTWAIT,
	};
	struct kvec iov[] = { { &hdr, sizeof(hdr) }, { data, data_len } };
	long timeo = 5 * HZ;
	int err;

	if (tsk->control_broken && port != TSI_PROXY_RELEASE)
		return -EIO;
	if (WARN_ON_ONCE(data_len > TSI_CONTROL_MAX))
		return -EINVAL;
	tsk->control_request_id = atomic64_inc_return(&tsi_request_id);
	if (!tsk->control_request_id)
		tsk->control_request_id = atomic64_inc_return(&tsi_request_id);
	hdr.request_id = cpu_to_le64(tsk->control_request_id);
	/* Network connect can take longer than local control accounting. */
	if (port == TSI_CONNECT && tsk->vsocket->type == SOCK_STREAM)
		timeo = min_t(long, sock_sndtimeo(sk_tsi(tsk), false), 120 * HZ);
	tsk->control_deadline = jiffies + timeo;
	if (READ_ONCE(tsk->connect_pending) &&
	    time_after(tsk->control_deadline, tsk->connect_deadline))
		tsk->control_deadline = tsk->connect_deadline;
	err = kernel_sendmsg(tsk->csocket, &msg, iov, ARRAY_SIZE(iov),
			     sizeof(hdr) + data_len);
	if (err >= 0 && err != sizeof(hdr) + data_len)
		return -EIO;
	return err;
}

static int tsi_control_recvmsg_nowait(struct tsi_sock *tsk, int port, void *data,
				      int data_len)
{
	struct {
		struct tsi_control_hdr hdr;
		u8 body[TSI_CONTROL_MAX];
	} frame;
	struct sockaddr_vm addr;
	int err;

	for (;;) {
		struct msghdr msg = {
			.msg_name = &addr,
			.msg_namelen = sizeof(addr),
		};
		struct kvec iov = { &frame, sizeof(frame) };

		if (tsi_connect_cancelled(tsk))
			return -ECANCELED;
		if (time_after_eq(jiffies, tsk->control_deadline))
			return -ETIMEDOUT;
		err = kernel_recvmsg(tsk->csocket, &msg, &iov, 1, sizeof(frame),
				     MSG_DONTWAIT | MSG_TRUNC);
		if (err < 0)
			return err;
		/* Unrelated or late replies cannot satisfy this operation. */
		if (msg.msg_namelen != sizeof(addr) ||
		    addr.svm_family != AF_VSOCK ||
		    addr.svm_cid != VMADDR_CID_HOST || addr.svm_port != port)
			continue;
		if (err < sizeof(frame.hdr))
			return -EPROTO;
		if (le64_to_cpu(frame.hdr.request_id) != tsk->control_request_id)
			continue;
		if (le32_to_cpu(frame.hdr.version) != TSI_VERSION)
			return -EPROTONOSUPPORT;
		if (le32_to_cpu(frame.hdr.operation) != port ||
		    le32_to_cpu(frame.hdr.flags) != TSI_CONTROL_REPLY ||
		    le32_to_cpu(frame.hdr.payload_len) != data_len ||
		    err != sizeof(frame.hdr) + data_len)
			return -EPROTO;
		if ((s32)get_unaligned_le32(frame.body) > 0 ||
		    (s32)get_unaligned_le32(frame.body) < -MAX_ERRNO)
			return -EPROTO;
		memcpy(data, frame.body, data_len);
		return data_len;
	}
}

static int tsi_control_recvmsg_wait(struct tsi_sock *tsk, int port, void *data,
				    int data_len, bool interruptible)
{
	struct sk_buff_head *queue = &tsk->csocket->sk->sk_receive_queue;
	wait_queue_head_t *wq = sk_sleep(tsk->csocket->sk);
	long left;
	int err;

	for (;;) {
		err = tsi_control_recvmsg_nowait(tsk, port, data, data_len);
		if (err != -EAGAIN)
			break;
		left = (long)(tsk->control_deadline - jiffies);
		if (left <= 0) {
			err = -ETIMEDOUT;
			break;
		}
		/* Native metadata queries do not expose ordinary signals as EINTR. */
		if (interruptible && (port == TSI_GETNAME || port == TSI_GETOPT))
			err = wait_event_killable_timeout(*wq,
							  !skb_queue_empty(queue) ||
							  tsi_connect_cancelled(tsk),
							  left);
		else if (interruptible)
			err = wait_event_interruptible_timeout(*wq,
							       !skb_queue_empty(queue) ||
							       tsi_connect_cancelled(tsk),
							       left);
		else
			err = wait_event_timeout(*wq,
						 !skb_queue_empty(queue) ||
						 tsi_connect_cancelled(tsk),
						 left);
		if (err < 0) {
			err = -EINTR;
			break;
		}
	}
	if (err < 0 && port != TSI_GETNAME && port != TSI_GETOPT)
		/* Host state is uncertain: require close instead of reusing it. */
		tsi_control_failed(tsk);
	return err;
}

static int tsi_control_recvmsg(struct tsi_sock *tsk, int port, void *data,
			       int data_len)
{
	bool interruptible = port == TSI_GETNAME || port == TSI_GETOPT ||
		(port == TSI_CONNECT && tsk->vsocket->type == SOCK_STREAM);

	return tsi_control_recvmsg_wait(tsk, port, data, data_len, interruptible);
}

static int tsi_accept_reply(struct tsi_sock *tsk, struct tsi_accept_rsp *rsp)
{
	int err;

	/* Post-accept accounting is bounded, but cannot be interrupted. */
	err = tsi_control_recvmsg(tsk, TSI_ACCEPT, rsp, sizeof(*rsp));
	if (err < 0)
		return err;
	return (s32)le32_to_cpu(rsp->result);
}

static int tsi_release_proxy(struct tsi_sock *tsk)
{
	struct tsi_proxy_release req;
	int err;

	if (!tsk->svm_port)
		return 0;
	req.svm_port = cpu_to_le32(tsk->svm_port);
	req.svm_peer_port = cpu_to_le32(tsk->svm_peer_port);
	err = tsi_control_sendmsg(tsk, TSI_PROXY_RELEASE, &req,
				  sizeof(req));
	if (err < 0)
		return err;
	tsk->svm_port = 0;
	return 0;
}

static int tsi_release(struct socket *sock)
{
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	struct sock *sk;
	int err;

	pr_debug("%s: socket=%p\n", __func__, sock);
	if (!sock) {
		pr_debug("%s: no sock\n", __func__);
	}

	if (!sock->sk) {
		pr_debug("%s: no sock->sk\n", __func__);
		return 0;
	} else {
		pr_debug("%s: sock->sk\n", __func__);
	}

	tsk = tsi_sk(sock->sk);
	isocket = tsk->isocket;
	vsocket = tsk->vsocket;
	sk = sock->sk;

	tsi_cancel_connect(tsk);
	lock_sock(sk);

	pr_debug("%s: tsk=%p vsocket=%p isocket=%p\n", __func__, tsk, vsocket,
		 isocket);

	if (!vsocket) {
		pr_debug("%s: no vsocket\n", __func__);
	} else {
		err = tsi_release_proxy(tsk);

		sock_release(vsocket);
	}

	if (!isocket) {
		pr_debug("%s: no isocket\n", __func__);
	} else {
		sock_release(isocket);
	}
	if (tsk->csocket)
		sock_release(tsk->csocket);
	kfree(tsk->bound_addr);
	kfree(tsk->sendto_addr);

	sock_orphan(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;
	skb_queue_purge(&sk->sk_receive_queue);
	release_sock(sk);
	sock_put(sk);
	sock->sk = NULL;
	sock->state = SS_FREE;

	return 0;
}

static int tsi_bind(struct socket *sock, struct sockaddr_unsized *addr, int addr_len)
{
	struct sock *sk = sock->sk;
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	struct sockaddr_vm addr_vsock;
	struct sockaddr *bound_addr = NULL;
	bool ping_socket, freebind = false;
	int bound_addr_len, err;

	lock_sock(sk);
	if (tsi_sk(sk)->connect_pending) {
		release_sock(sk);
		return -EINVAL;
	}
	tsk = tsi_sk(sock->sk);
	isocket = tsk->isocket;
	vsocket = tsk->vsocket;

	pr_debug("%s: vsocket=%p\n", __func__, vsocket);
	if (tsk->control_broken) {
		err = -EIO;
		goto release;
	}

	err = tsi_check_addr_len(tsk, addr_len);
	if (err != 0) {
		pr_debug("%s: invalid addr_len: %d\n", __func__, addr_len);
		err = -EINVAL;
		goto release;
	}

	if (!isocket) {
		pr_debug("%s: no isocket\n", __func__);
		err = -EINVAL;
		goto release;
	}

	bound_addr = kmalloc(TSI_ADDR_LEN, GFP_KERNEL);
	if (!bound_addr) {
		err = -ENOMEM;
		goto release;
	}
	ping_socket = sock->type == SOCK_DGRAM &&
		      ((tsk->family == AF_INET && tsk->protocol == IPPROTO_ICMP) ||
		       (tsk->family == AF_INET6 && tsk->protocol == IPPROTO_ICMPV6));
	if (ping_socket) {
		/* iputils binds the source IP selected by a host route probe. */
		lock_sock(isocket->sk);
		freebind = inet_test_bit(FREEBIND, isocket->sk);
		inet_set_bit(FREEBIND, isocket->sk);
		release_sock(isocket->sk);
	}
	err = isocket->ops->bind(isocket, addr, addr_len);
	if (ping_socket && !freebind) {
		lock_sock(isocket->sk);
		inet_clear_bit(FREEBIND, isocket->sk);
		release_sock(isocket->sk);
	}
	if (err != 0) {
		pr_debug("%s: error binding isocket: %d\n", __func__, err);
		goto release;
	}
	/* The guest allocator owns the port, including bind(0). */
	err = isocket->ops->getname(isocket, bound_addr, 0);
	if (err < 0)
		goto release;
	bound_addr_len = err;

	if (!vsocket) {
		pr_debug("%s: no vsocket\n", __func__);
		err = -EINVAL;
		goto release;
	}

	memset(&addr_vsock, 0, sizeof(addr_vsock));
	addr_vsock.svm_family = AF_VSOCK;
	addr_vsock.svm_cid = VMADDR_CID_ANY;
	addr_vsock.svm_port = VMADDR_PORT_ANY;

	err = vsocket->ops->bind(vsocket, (struct sockaddr_unsized *)&addr_vsock,
				 sizeof(addr_vsock));
	if (err) {
		pr_debug("%s: error setting up vsock listener: %d\n", __func__,
			 err);
		goto release;
	}

	kfree(tsk->bound_addr);
	tsk->bound_addr = bound_addr;
	tsk->bound_addr_len = bound_addr_len;
	bound_addr = NULL;
	if (sock->type == SOCK_DGRAM && tsk->family != AF_UNIX) {
		/* Keep a published bind(0) port when native AF_UNSPEC disconnects. */
		lock_sock(isocket->sk);
		isocket->sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
		release_sock(isocket->sk);
		err = tsi_udp_bind_proxy(tsk);
		if (err)
			/* The native endpoint is bound; require close after partial setup. */
			tsi_control_failed(tsk);
	}

release:
	kfree(bound_addr);
	release_sock(sk);
	return err;
}

static const struct {
	int level;
	int name;
} tsi_options[TSI_OPTION_COUNT] = {
	{ SOL_SOCKET, SO_REUSEADDR },
	{ SOL_SOCKET, SO_REUSEPORT },
	{ SOL_SOCKET, SO_KEEPALIVE },
	{ SOL_SOCKET, SO_BROADCAST },
	{ SOL_SOCKET, SO_SNDBUF },
	{ SOL_SOCKET, SO_RCVBUF },
	{ IPPROTO_TCP, TCP_NODELAY },
	{ IPPROTO_IPV6, IPV6_V6ONLY },
};

static int tsi_option_index(struct tsi_sock *tsk, int level, int name)
{
	int i;

	for (i = 0; i < TSI_OPTION_COUNT; i++) {
		if (tsi_options[i].level != level || tsi_options[i].name != name)
			continue;
		if (level == IPPROTO_TCP &&
		    (tsk->family == AF_UNIX || sk_tsi(tsk)->sk_socket->type != SOCK_STREAM ||
		     (tsk->protocol && tsk->protocol != IPPROTO_TCP)))
			return -1;
		if (level == IPPROTO_IPV6 && tsk->family != AF_INET6)
			return -1;
		if (name == SO_REUSEPORT && level == SOL_SOCKET && tsk->family == AF_UNIX)
			return -1;
		return i;
	}
	return -1;
}

static int tsi_proxy_option(struct tsi_sock *tsk, int level, int name,
			    int *value, bool set)
{
	struct tsi_option_req req = {
		.svm_port = cpu_to_le32(tsk->svm_port),
		.svm_peer_port = cpu_to_le32(tsk->svm_peer_port),
		.level = cpu_to_le32(level),
		.optname = cpu_to_le32(name),
		.value = cpu_to_le32(set ? *value : 0),
	};
	struct tsi_option_rsp rsp = {};
	int port = set ? TSI_SETOPT : TSI_GETOPT;
	int err;

	err = tsi_control_sendmsg(tsk, port, &req, set ? sizeof(req) : sizeof(req) - 4);
	if (err < 0)
		return err;
	if (!set && level == SOL_SOCKET && name == SO_ERROR)
		/* This read clears the host error: finish the bounded accounting. */
		err = tsi_control_recvmsg_wait(tsk, port, &rsp, sizeof(rsp), false);
	else
		err = tsi_control_recvmsg(tsk, port, &rsp, set ? 4 : sizeof(rsp));
	if (err < 0)
		return err;
	err = (s32)le32_to_cpu(rsp.result);
	if (!err && !set)
		*value = (s32)le32_to_cpu(rsp.value);
	return err;
}

static int tsi_create_proxy(struct tsi_sock *tsk, int type)
{
	struct socket *vsocket = tsk->vsocket;
	struct sockaddr_vm vm_addr;
	struct tsi_proxy_create tpc;
	__le32 result;
	int err, i;

	memset(&vm_addr, 0, sizeof(struct sockaddr_vm));
	vm_addr.svm_family = AF_VSOCK;
	vm_addr.svm_port = VMADDR_PORT_ANY;
	vm_addr.svm_cid = VMADDR_CID_ANY;

	err = kernel_bind(vsocket, (struct sockaddr_unsized *)&vm_addr,
			  sizeof(struct sockaddr_vm));
	if (err) {
		pr_debug("%s: error binding port: %d\n", __func__, err);
	}

	err = vsocket->ops->getname(vsocket, (struct sockaddr *)&vm_addr, 0);
	if (err < 0) {
		pr_debug("%s: error in getname: %d\n", __func__, err);
		return err;
	}

	tpc.svm_port = cpu_to_le32(vm_addr.svm_port);
	tpc.family = cpu_to_le16(tsk->family);
	tpc.type = cpu_to_le16(type);
	tpc.protocol = cpu_to_le32(tsk->protocol);
	/* Retain identity for close-time cleanup if the reply is lost. */
	tsk->svm_port = vm_addr.svm_port;

	pr_debug("%s: type=%d\n", __func__, tpc.type);

	err = tsi_control_sendmsg(tsk, TSI_PROXY_CREATE, (void *)&tpc,
				  sizeof(struct tsi_proxy_create));
	if (err < 0) {
		pr_debug("%s: error sending proxy request\n", __func__);
		tsk->svm_port = 0;
		return err;
	}
	err = tsi_control_recvmsg(tsk, TSI_PROXY_CREATE, &result,
				  sizeof(result));
	if (err < 0)
		return err;
	if (err != sizeof(result))
		return -EPROTO;
	err = (s32)le32_to_cpu(result);
	if (err) {
		tsk->svm_port = 0;
		return err;
	}
	/* Replay user options before the host can bind, listen or connect. */
	for (i = 0; i < TSI_OPTION_COUNT; i++) {
		if (!(tsk->option_mask & BIT(i)))
			continue;
		err = tsi_proxy_option(tsk, tsi_options[i].level, tsi_options[i].name,
				       &tsk->option_values[i], true);
		if (err) {
			tsi_control_failed(tsk);
			return err;
		}
	}
	if (type == SOCK_DGRAM && tsk->family != AF_UNIX) {
		vm_addr.svm_cid = VMADDR_CID_HOST;
		vm_addr.svm_port = TSI_DATAGRAM;
		err = kernel_connect(vsocket, (struct sockaddr_unsized *)&vm_addr,
				     sizeof(vm_addr), 0);
		if (err) {
			tsi_release_proxy(tsk);
			return err;
		}
	}

	return 0;
}

static int tsi_udp_bind_proxy(struct tsi_sock *tsk)
{
	struct tsi_connect_req req = {};
	__le32 result;
	int err;

	if (!tsk->svm_port) {
		err = tsi_create_proxy(tsk, SOCK_DGRAM);
		if (err)
			return err;
	}
	req.svm_port = cpu_to_le32(tsk->svm_port);
	req.addr_len = cpu_to_le32(tsk->bound_addr_len);
	memcpy(req.addr, tsk->bound_addr, tsk->bound_addr_len);
	err = tsi_control_sendmsg(tsk, TSI_BIND, &req, sizeof(req));
	if (err < 0)
		return err;
	err = tsi_control_recvmsg(tsk, TSI_BIND, &result, sizeof(result));
	return err < 0 ? err : (s32)le32_to_cpu(result);
}

static int tsi_connect_blocking(struct socket *sock, struct sockaddr_unsized *addr,
				int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	int err;

	lock_sock(sk);
	if (tsi_sk(sk)->connect_pending) {
		release_sock(sk);
		return -EALREADY;
	}
	if (tsi_sk(sk)->control_broken) {
		release_sock(sk);
		return -EIO;
	}
	tsk = tsi_sk(sock->sk);
	if (sock->type == SOCK_STREAM && sock->state == SS_CONNECTED) {
		err = -EISCONN;
		goto release;
	}
	tsk->connect_error = 0;
	isocket = tsk->isocket;
	vsocket = tsk->vsocket;

	pr_debug("%s: vsocket=%p isocket=%p\n", __func__, vsocket, isocket);

	if (addr->sa_family != tsk->family) {
		pr_debug(
			"%s: rejecting mismatched family addr->sa_family=%d tsk->family=%d\n",
			__func__, addr->sa_family, tsk->family);
		err = -EINVAL;
		goto release;
	}

	err = tsi_check_addr_len(tsk, addr_len);
	if (err != 0) {
		pr_debug("%s: invalid addr_len: %d\n", __func__, addr_len);
		err = -EINVAL;
		goto release;
	}

	if (isocket) {
		/* We can't honor O_NONBLOCK semantics here as we need to know
		 * whether this request can be fulfilled from INET or we need
		 * to fall back to VSOCK.
		 */
		err = isocket->ops->connect(isocket, addr, addr_len,
					    flags & ~O_NONBLOCK);
		if (err == 0 || err == -EALREADY) {
			tsk->status = S_INET;
			pr_debug("%s: switching to CONNECTED_INET\n", __func__);
			goto release;
		} else if (err == -EINPROGRESS) {
			/* This shouldn't happen, as we've cleared O_NONBLOCK */
			tsk->status = S_INET;
			pr_warn("%s: received -EINPROGRESS for isocket\n",
				__func__);
			goto release;
		}
	}

	if (vsocket) {
		struct sockaddr_vm vm_addr;
		struct tsi_connect_req tc_req = {};
		struct tsi_connect_rsp tc_rsp;

		if (!tsk->svm_port) {
			err = tsi_create_proxy(tsk, vsocket->type);
			if (err)
				goto release;
		}

		tc_req.svm_port = cpu_to_le32(tsk->svm_port);
		tc_req.addr_len = cpu_to_le32(addr_len);
		memcpy(&tc_req.addr, addr, addr_len);

		pr_debug("%s: sending connection request id=%u\n", __func__,
			 tc_req.svm_port);

		err = tsi_control_sendmsg(tsk, TSI_CONNECT,
					  (void *)&tc_req,
					  sizeof(struct tsi_connect_req));
		if (err < 0) {
			pr_debug("%s: error sending connection request\n",
				 __func__);
			goto release;
		}

		err = tsi_control_recvmsg(tsk, TSI_CONNECT,
					  (void *)&tc_rsp,
					  sizeof(struct tsi_connect_rsp));
		if (err < 0) {
			pr_debug(
				"%s: error receiving connection request answer\n",
				__func__);
			goto release;
		}

		pr_debug("%s: response result: %d\n", __func__,
			 (s32)le32_to_cpu(tc_rsp.result));

		if ((s32)le32_to_cpu(tc_rsp.result) != 0) {
			err = (s32)le32_to_cpu(tc_rsp.result);
			goto release;
		}

		memset(&vm_addr, 0, sizeof(struct sockaddr_vm));
		vm_addr.svm_family = AF_VSOCK;
		vm_addr.svm_cid = VMADDR_CID_HOST;
		if (vsocket->type == SOCK_DGRAM)
			vm_addr.svm_port = le32_to_cpu(tc_req.svm_port);
		else
			vm_addr.svm_port = TSI_DEFAULT_PORT;

		err = kernel_connect(vsocket, (struct sockaddr_unsized *)&vm_addr,
				     sizeof(struct sockaddr_vm), 0);
		if (err < 0) {
			pr_debug("%s: error connecting vsock endpoint: %d\n",
				 __func__, err);
			goto release;
		}

		if (!tsk->sendto_addr) {
			tsk->sendto_addr = kmalloc(addr_len, GFP_KERNEL);
			tsk->sendto_addr_len = addr_len;
		}
		memcpy(tsk->sendto_addr, addr, addr_len);

		tsk->status = S_VSOCK;
	}

release:
	release_sock(sk);
	return err;
}

static void tsi_connect_timer(struct timer_list *timer)
{
	struct tsi_sock *tsk = timer_container_of(tsk, timer, connect_timer);

	tsi_queue_connect(tsk);
}

static void tsi_connect_complete(struct tsi_sock *tsk, int err)
{
	struct sock *sk = sk_tsi(tsk);

	lock_sock(sk);
	if (READ_ONCE(tsk->connect_cancelled))
		err = -ECANCELED;
	tsk->connect_error = err;
	put_cred(tsk->connect_cred);
	tsk->connect_cred = NULL;
	WRITE_ONCE(sk->sk_err, -err);
	sk->sk_socket->state = err ? SS_UNCONNECTED : SS_CONNECTED;
	WRITE_ONCE(sk->sk_state, err ? TCP_CLOSE : TCP_ESTABLISHED);
	timer_delete(&tsk->connect_timer);
	WRITE_ONCE(tsk->connect_pending, false);
	release_sock(sk);
	sk->sk_state_change(sk);
}

static void tsi_connect_work(struct work_struct *work)
{
	struct tsi_sock *tsk = container_of(work, struct tsi_sock, connect_work);
	struct sockaddr_unsized *addr = (struct sockaddr_unsized *)&tsk->connect_addr;
	struct tsi_connect_req req = {};
	struct tsi_connect_rsp rsp;
	struct sockaddr_vm vm_addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = VMADDR_CID_HOST,
		.svm_port = TSI_DEFAULT_PORT,
	};
	const struct cred *old_cred;
	struct sockaddr *peer;
	int err;

	/* A late transport notification may already have queued this work. */
	if (!smp_load_acquire(&tsk->connect_pending))
		return;
	old_cred = override_creds(tsk->connect_cred);
	if (tsi_connect_cancelled(tsk)) {
		err = -ECANCELED;
		goto complete;
	}
	if (time_after_eq(jiffies, tsk->connect_deadline)) {
		tsi_control_failed(tsk);
		err = -ETIMEDOUT;
		goto complete;
	}

	if (tsk->connect_phase == TSI_CONNECT_NATIVE) {
		err = tsk->isocket->ops->connect(tsk->isocket, addr,
						 tsk->connect_addr_len, O_NONBLOCK);
		if (err == -EINPROGRESS || err == -EALREADY)
			goto pending;
		if (!err || err == -EISCONN) {
			tsk->status = S_INET;
			err = 0;
			goto complete;
		}
		if (!tsk->svm_port) {
			err = tsi_create_proxy(tsk, SOCK_STREAM);
			if (err)
				goto complete;
		}
		if (tsi_connect_cancelled(tsk)) {
			err = -ECANCELED;
			goto complete;
		}
		req.svm_port = cpu_to_le32(tsk->svm_port);
		req.addr_len = cpu_to_le32(tsk->connect_addr_len);
		memcpy(req.addr, &tsk->connect_addr, tsk->connect_addr_len);
		tsk->connect_phase = TSI_CONNECT_HOST;
		err = tsi_control_sendmsg(tsk, TSI_CONNECT, &req, sizeof(req));
		if (err < 0)
			goto complete;
	}
	if (tsk->connect_phase == TSI_CONNECT_HOST) {
		err = tsi_control_recvmsg_nowait(tsk, TSI_CONNECT, &rsp, sizeof(rsp));
		if (err == -EAGAIN)
			goto pending;
		if (err < 0) {
			tsi_control_failed(tsk);
			goto complete;
		}
		err = (s32)le32_to_cpu(rsp.result);
		if (err)
			goto complete;
		tsk->connect_phase = TSI_CONNECT_DATA;
	}
	err = tsk->vsocket->ops->connect(tsk->vsocket,
			(struct sockaddr_unsized *)&vm_addr, sizeof(vm_addr), O_NONBLOCK);
	if (err == -EINPROGRESS || err == -EALREADY)
		goto pending;
	if (err && err != -EISCONN)
		goto complete;
	peer = kmemdup(&tsk->connect_addr, tsk->connect_addr_len, GFP_KERNEL);
	if (!peer) {
		err = -ENOMEM;
		goto complete;
	}
	kfree(tsk->sendto_addr);
	tsk->sendto_addr = peer;
	tsk->sendto_addr_len = tsk->connect_addr_len;
	tsk->status = S_VSOCK;
	err = 0;
complete:
	revert_creds(old_cred);
	tsi_connect_complete(tsk, err);
	return;
pending:
	revert_creds(old_cred);
}

static int tsi_connect(struct socket *sock, struct sockaddr_unsized *addr,
		       int addr_len, int flags)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	long timeo;
	int err;

	if (!(flags & O_NONBLOCK) || sock->type != SOCK_STREAM ||
	    tsk->family == AF_UNIX)
		return tsi_connect_blocking(sock, addr, addr_len, flags);
	lock_sock(sock->sk);
	if (tsk->connect_pending) {
		err = -EALREADY;
		goto out;
	}
	if (tsk->control_broken) {
		err = -EIO;
		goto out;
	}
	if (sock->state == SS_CONNECTED) {
		err = -EISCONN;
		goto out;
	}
	err = tsi_check_addr_len(tsk, addr_len);
	if (err || addr->sa_family != tsk->family) {
		err = -EINVAL;
		goto out;
	}
	memcpy(&tsk->connect_addr, addr, addr_len);
	tsk->connect_addr_len = addr_len;
	tsk->connect_phase = TSI_CONNECT_NATIVE;
	tsk->connect_cred = get_current_cred();
	tsk->connect_error = 0;
	WRITE_ONCE(sock->sk->sk_err, 0);
	WRITE_ONCE(tsk->connect_cancelled, false);
	timeo = min_t(long, sock_sndtimeo(sock->sk, false), 120 * HZ);
	tsk->connect_deadline = jiffies + timeo;
	tsi_watch_connect(tsk, &tsk->inet_watch, tsk->isocket);
	tsi_watch_connect(tsk, &tsk->vsock_watch, tsk->vsocket);
	write_lock_bh(&tsk->csocket->sk->sk_callback_lock);
	rcu_assign_sk_user_data(tsk->csocket->sk, tsk);
	write_unlock_bh(&tsk->csocket->sk->sk_callback_lock);
	sock->state = SS_CONNECTING;
	WRITE_ONCE(sock->sk->sk_state, TCP_SYN_SENT);
	mod_timer(&tsk->connect_timer, tsk->connect_deadline);
	/* Publish credentials/state even if a late callback already queued work. */
	smp_store_release(&tsk->connect_pending, true);
	queue_work(system_unbound_wq, &tsk->connect_work);
	err = -EINPROGRESS;
out:
	release_sock(sock->sk);
	return err;
}

static int tsi_socketpair(struct socket *socka, struct socket *sockb)
{
	struct sock *ska = socka->sk;
	struct sock *skb = sockb->sk;
	struct tsi_sock *tska;
	struct tsi_sock *tskb;
	struct socket *isocketa;
	struct socket *isocketb;
	int err;

	lock_sock(ska);
	lock_sock(skb);
	tska = tsi_sk(ska);
	tskb = tsi_sk(skb);
	isocketa = tska->isocket;
	isocketb = tskb->isocket;

	if (tska->family != PF_UNIX || tskb->family != PF_UNIX) {
		err = -EOPNOTSUPP;
		goto release;
	}

	err = isocketa->ops->socketpair(isocketa, isocketb);
	if (err == 0) {
		pr_debug("%s: switching to S_INET\n", __func__);
		tska->status = tskb->status = S_INET;
	}

release:
	release_sock(ska);
	release_sock(skb);
	return err;
}

static int tsi_transport_wake(struct wait_queue_entry *entry, unsigned int mode,
			      int sync, void *key)
{
	/* Both transport queues wake the same wait_woken() entry. */
	return woken_wake_function(entry->private, mode, sync, key);
}

static int tsi_try_accept(struct socket *socket, struct socket **newsock,
			  struct proto_accept_arg *arg)
{
	struct socket *nsock;
	int err;

	nsock = sock_alloc();
	if (!nsock)
		return -ENOMEM;
	nsock->type = socket->type;
	nsock->ops = socket->ops;
	__module_get(nsock->ops->owner);
	err = socket->ops->accept(socket, nsock, arg);
	if (err < 0)
		sock_release(nsock);
	else
		*newsock = nsock;
	return err;
}

static int tsi_accept_transport(struct tsi_sock *tsk, struct socket **transports,
				int count, struct socket **newsock,
				struct socket **selected,
				struct proto_accept_arg *arg, long timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	DEFINE_WAIT_FUNC(other, tsi_transport_wake);
	struct proto_accept_arg nonblock = *arg;
	struct sock *sk = sk_tsi(tsk);
	int i, err;

	nonblock.flags |= O_NONBLOCK;
	nonblock.kern = true;
	other.private = &wait;
	add_wait_queue(sk_sleep(transports[0]->sk), &wait);
	if (count == 2)
		add_wait_queue(sk_sleep(transports[1]->sk), &other);

	for (;;) {
		if (READ_ONCE(tsk->control_broken)) {
			err = -EIO;
			break;
		}
		if (READ_ONCE(sk->sk_shutdown) & RCV_SHUTDOWN) {
			err = -EINVAL;
			break;
		}
		for (i = 0; i < count; i++) {
			err = tsi_try_accept(transports[i], newsock, &nonblock);
			if (!err) {
				*selected = transports[i];
				goto done;
			}
			if (err != -EAGAIN)
				goto done;
			err = sock_error(transports[i]->sk);
			if (err)
				goto done;
		}
		err = -EAGAIN;
		if (!timeo)
			break;
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}
		timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
	}

done:
	if (count == 2)
		remove_wait_queue(sk_sleep(transports[1]->sk), &other);
	remove_wait_queue(sk_sleep(transports[0]->sk), &wait);
	/* One empty queue cannot establish that a hybrid listener is empty. */
	arg->is_empty = count == 1 ? nonblock.is_empty : 0;
	arg->err = err;
	return err;
}

static int tsi_ack_accept(struct tsi_sock *tsk)
{
	struct tsi_accept_req ta_req;
	struct tsi_accept_rsp ta_rsp;
	int err;

	ta_req.svm_port = cpu_to_le32(tsk->svm_port);
	/*
	 * The vsock connection is already accepted. Its host notification
	 * precedes this request, so this exchange never waits for a new client.
	 */
	ta_req.flags = cpu_to_le32(0);

	err = tsi_control_sendmsg(tsk, TSI_ACCEPT, (void *)&ta_req,
				  sizeof(struct tsi_accept_req));
	if (err < 0) {
		pr_debug("%s: error sending accept request\n", __func__);
		return err;
	}

	return tsi_accept_reply(tsk, &ta_rsp);
}

static int tsi_accept(struct socket *sock, struct socket *newsock,
		      struct proto_accept_arg *arg)
{
	struct sock *listener = sock->sk;
	struct sockaddr_vm vm_addr;
	struct socket *isocket;
	struct socket *csocket;
	struct socket *transport = NULL;
	struct socket *transports[2];
	struct tsi_sock *tsk;
	struct tsi_sock *newtsk;
	struct socket *nsock = NULL;
	struct tsi_proxy_release accepted_proxy = {};
	struct sock *sk;
	bool inet;
	int count = 1;
	long timeo;
	int err;

	if (sock->type != SOCK_STREAM)
		return -EOPNOTSUPP;
	lock_sock(listener);
	if (tsi_sk(listener)->connect_pending) {
		release_sock(listener);
		return -EINVAL;
	}
	if (tsi_sk(listener)->control_broken) {
		release_sock(listener);
		return -EIO;
	}
	tsk = tsi_sk(sock->sk);
	isocket = tsk->isocket;
	if (listener->sk_state != TCP_LISTEN) {
		err = -EINVAL;
		goto release;
	}
	transports[0] = isocket;
	if (tsk->status == S_HYBRID) {
		count = 2;
		/* Alternate queue preference, including concurrent acceptors. */
		transports[tsk->accept_inet_first] = tsk->vsocket;
		transports[!tsk->accept_inet_first] = isocket;
		tsk->accept_inet_first = !tsk->accept_inet_first;
	}
	timeo = sock_rcvtimeo(isocket->sk, arg->flags & O_NONBLOCK);

	pr_debug("%s: socket=%p newsock=%p st=%d\n", __func__, sock, newsock,
		 tsk->status);

	if (tsk->family == PF_INET) {
		sk = sk_alloc(current->nsproxy->net_ns, AF_TSI, GFP_KERNEL,
			      &tsi_in4_proto, 0);
	} else if (tsk->family == PF_INET6) {
		sk = sk_alloc(current->nsproxy->net_ns, AF_TSI6, GFP_KERNEL,
			      &tsi_in6_proto, 0);
	} else if (tsk->family == PF_UNIX) {
		sk = sk_alloc(current->nsproxy->net_ns, AF_TSIU, GFP_KERNEL,
			      &tsi_un_proto, 0);
	} else {
		panic("Unsupported family in tsk->family=%d", tsk->family);
	}
	if (!sk) {
		err = -ENOMEM;
		goto release;
	}

	sock_init_data(newsock, sk);
	/* We need to use our own setsockopt functions */
	set_bit(SOCK_CUSTOM_SOCKOPT, &sk->sk_socket->flags);
	set_bit(SOCK_CUSTOM_GETSOCKOPT, &sk->sk_socket->flags);

	newtsk = tsi_sk(newsock->sk);
	tsi_init_connect(newtsk);
	newtsk->family = tsk->family;
	newtsk->protocol = tsk->protocol;
	newtsk->option_mask = tsk->option_mask;
	memcpy(newtsk->option_values, tsk->option_values, sizeof(tsk->option_values));

	/*
	 * As with stream receive, the caller pins the listener and transport.
	 * Only the short control exchange needs the outer TSI lock.
	 */
	release_sock(listener);
	err = tsi_accept_transport(tsk, transports, count, &nsock, &transport,
				   arg, timeo);
	lock_sock(listener);
	if (err < 0)
		goto error;
	if (transport == tsk->vsocket) {
		err = nsock->ops->getname(nsock, (struct sockaddr *)&vm_addr, 0);
		if (err < 0)
			goto error;
		accepted_proxy.svm_port = cpu_to_le32(vm_addr.svm_port);
		err = nsock->ops->getname(nsock, (struct sockaddr *)&vm_addr, 1);
		if (err < 0)
			goto error;
		accepted_proxy.svm_peer_port = cpu_to_le32(vm_addr.svm_port);
	}
	if (tsk->control_broken) {
		err = -EIO;
		goto error;
	}
	if (listener->sk_shutdown & RCV_SHUTDOWN) {
		err = -EINVAL;
		goto error;
	}
	inet = transport == isocket;
	if (!inet) {
		err = tsi_ack_accept(tsk);
		if (err < 0)
			goto error;

		newtsk->svm_port = le32_to_cpu(accepted_proxy.svm_port);
		newtsk->svm_peer_port = le32_to_cpu(accepted_proxy.svm_peer_port);
		newtsk->bound_addr = kmemdup(tsk->bound_addr, tsk->bound_addr_len,
					     GFP_KERNEL);
		if (!newtsk->bound_addr) {
			err = -ENOMEM;
			goto error;
		}
		newtsk->bound_addr_len = tsk->bound_addr_len;
	}

	err = tsi_create_control_socket(&csocket);
	if (err)
		goto error;

	newtsk->csocket = csocket;
	if (inet) {
		newtsk->status = S_INET;
		newtsk->isocket = nsock;
	} else {
		newtsk->status = S_VSOCK;
		newtsk->vsocket = nsock;
		/* VSOCK children do not inherit the listener's wait timeouts. */
		WRITE_ONCE(nsock->sk->sk_rcvtimeo, READ_ONCE(listener->sk_rcvtimeo));
		WRITE_ONCE(nsock->sk->sk_sndtimeo, READ_ONCE(listener->sk_sndtimeo));
	}
	WRITE_ONCE(sk->sk_rcvtimeo, READ_ONCE(nsock->sk->sk_rcvtimeo));
	WRITE_ONCE(sk->sk_sndtimeo, READ_ONCE(nsock->sk->sk_sndtimeo));
	newsock->state = SS_CONNECTED;
	WRITE_ONCE(newtsk->sk.sk_state, TCP_ESTABLISHED);

release:
	release_sock(listener);
	return err;

error:
	if (nsock) {
		/* No child descriptor will own this proxy after a failed accept. */
		if (accepted_proxy.svm_port && accepted_proxy.svm_peer_port)
			tsi_control_sendmsg(tsk, TSI_PROXY_RELEASE, &accepted_proxy,
					    sizeof(accepted_proxy));
		sock_release(nsock);
	}
	release_sock(listener);
	return err;
}

static int vsock_proxy_getname(struct tsi_sock *tsk, struct sockaddr *addr,
			       int peer)
{
	struct tsi_getname_req gn_req = {};
	struct tsi_getname_rsp gn_rsp;
	int err;

	gn_req.svm_port = cpu_to_le32(tsk->svm_port);
	gn_req.svm_peer_port = cpu_to_le32(tsk->svm_peer_port);
	gn_req.peer = cpu_to_le32(!!peer);

	err = tsi_control_sendmsg(tsk, TSI_GETNAME, (void *)&gn_req,
				  sizeof(struct tsi_getname_req));
	if (err < 0) {
		pr_debug("%s: error sending getname request\n", __func__);
		return err;
	}

	err = tsi_control_recvmsg(tsk, TSI_GETNAME, (void *)&gn_rsp,
				  sizeof(struct tsi_getname_rsp));
	if (err < 0) {
		pr_debug("%s: error receiving getname answer\n", __func__);
		return err;
	}

	if ((s32)le32_to_cpu(gn_rsp.result))
		return (s32)le32_to_cpu(gn_rsp.result);

	err = tsi_check_addr_len(tsk, le32_to_cpu(gn_rsp.addr_len));
	if (err != 0) {
		pr_debug("%s: invalid addr_len: %d\n", __func__,
			 le32_to_cpu(gn_rsp.addr_len));
		return -EINVAL;
	}

	if (get_unaligned_le16(gn_rsp.addr) != tsk->family)
		return -EPROTO;
	memcpy(addr, gn_rsp.addr, le32_to_cpu(gn_rsp.addr_len));
	/* Explicit guest binds retain their logical port across host mappings. */
	if (!peer && tsk->bound_addr) {
		if (tsk->family == AF_INET)
			((struct sockaddr_in *)addr)->sin_port =
				((struct sockaddr_in *)tsk->bound_addr)->sin_port;
		else if (tsk->family == AF_INET6)
			((struct sockaddr_in6 *)addr)->sin6_port =
				((struct sockaddr_in6 *)tsk->bound_addr)->sin6_port;
	}

	return le32_to_cpu(gn_rsp.addr_len);
}

static int tsi_getname(struct socket *sock, struct sockaddr *addr, int peer)
{
	struct sock *sk = sock->sk;
	struct tsi_sock *tsk;
	struct socket *isocket;
	int err;

	lock_sock(sk);
	if (tsi_sk(sk)->connect_pending) {
		isocket = tsi_sk(sk)->isocket;
		err = peer ? -ENOTCONN : isocket->ops->getname(isocket, addr, 0);
		release_sock(sk);
		return err;
	}
	if (tsi_sk(sk)->control_broken) {
		release_sock(sk);
		return -EIO;
	}
	tsk = tsi_sk(sock->sk);
	isocket = tsk->isocket;

	pr_debug("%s: s=%p is=%p st=%d svm_port=%u peer=%d\n", __func__, sock,
		 isocket, tsk->status, tsk->svm_port, peer);

	switch (tsk->status) {
	case S_HYBRID:
	case S_INET:
		err = isocket->ops->getname(isocket, addr, peer);
		break;
	case S_VSOCK:
		if (!peer && tsk->family == AF_UNIX && tsk->bound_addr) {
			err = tsk->bound_addr_len;
			memcpy(addr, tsk->bound_addr, err);
		} else {
			err = vsock_proxy_getname(tsk, addr, peer);
		}
		break;
	}

	release_sock(sk);
	return err;
}

static __poll_t tsi_poll(struct file *file, struct socket *sock,
			 poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	__poll_t events = 0;

	lock_sock(sk);
	tsk = tsi_sk(sk);
	poll_wait(file, sk_sleep(sk), wait);
	if (tsi_sk(sk)->connect_pending)
		goto out;
	if (tsi_sk(sk)->connect_error) {
		events = EPOLLOUT | EPOLLWRNORM | EPOLLHUP;
		if (READ_ONCE(sk->sk_err))
			events |= EPOLLERR;
		goto out;
	}
	tsk = tsi_sk(sock->sk);
	isocket = tsk->isocket;
	vsocket = tsk->vsocket;

	pr_debug("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock, vsocket,
		 isocket, tsk->status);

	if (sock->type == SOCK_DGRAM && tsk->family != AF_UNIX &&
	    !tsk->udp_peer_len) {
		events = isocket->ops->poll(file, isocket, wait) |
			 vsocket->ops->poll(file, vsocket, wait);
		goto out;
	}

	switch (tsk->status) {
	case S_INET:
		events = isocket->ops->poll(file, isocket, wait);
		break;
	case S_VSOCK:
		events = vsocket->ops->poll(file, vsocket, wait);
		break;
	default:
		if (sock->type == SOCK_STREAM) {
			events = isocket->ops->poll(file, isocket, wait) |
				 vsocket->ops->poll(file, vsocket, wait);
		} else {
			if (vsocket)
				events |= vsocket->ops->poll(file, vsocket, wait);
			if (events)
				tsk->status = S_VSOCK;
		}
	}

out:
	if (!tsk->connect_pending && tsk->control_broken)
		events |= EPOLLERR;
	release_sock(sk);
	return events;
}

static int tsi_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	int err;

	lock_sock(sk);
	if (tsi_sk(sk)->connect_pending) {
		release_sock(sk);
		return -EAGAIN;
	}
	tsk = tsi_sk(sock->sk);
	isocket = tsk->isocket;
	vsocket = tsk->vsocket;

	switch (tsk->status) {
	case S_HYBRID:
	case S_INET:
		if (isocket) {
			err = isocket->ops->ioctl(isocket, cmd, arg);
		} else {
			err = -EOPNOTSUPP;
		}
		break;
	case S_VSOCK:
		if (vsocket) {
			err = vsocket->ops->ioctl(vsocket, cmd, arg);
		} else {
			err = -EOPNOTSUPP;
		}
		break;
	}

	release_sock(sk);
	return err;
}

static int tsi_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	struct sockaddr_vm vm_addr;
	struct tsi_listen_req lreq = {};
	struct tsi_listen_rsp lrsp;
	bool local_only;
	int err;

	lock_sock(sk);
	if (tsi_sk(sk)->connect_pending) {
		release_sock(sk);
		return -EINVAL;
	}
	if (tsi_sk(sk)->control_broken) {
		release_sock(sk);
		return -EIO;
	}
	tsk = tsi_sk(sock->sk);
	isocket = tsk->isocket;
	vsocket = tsk->vsocket;

	pr_debug("%s: vsocket=%p\n", __func__, vsocket);

	if (!tsk->bound_addr) {
		err = -EINVAL;
		goto release;
	}
	/* Relative paths and abstract names belong to the guest namespace. */
	local_only = tsk->status == S_INET ||
		(tsk->family == AF_UNIX &&
		 ((struct sockaddr_un *)tsk->bound_addr)->sun_path[0] != '/');
	if (local_only)
		goto local;

	err = vsocket->ops->listen(vsocket, backlog);
	if (err != 0) {
		pr_debug("%s: vsock listen error: %d\n", __func__, err);
		goto release;
	}

	err = vsocket->ops->getname(vsocket, (struct sockaddr *)&vm_addr, 0);
	if (err < 0) {
		pr_debug("%s: error in getname: %d\n", __func__, err);
		goto release;
	}

	if (!tsk->svm_port) {
		err = tsi_create_proxy(tsk, SOCK_STREAM);
		if (err)
			goto release;
	}

	lreq.svm_port = cpu_to_le32(tsk->svm_port);
	lreq.addr_len = cpu_to_le32(tsk->bound_addr_len);
	memcpy(&lreq.addr, tsk->bound_addr, tsk->bound_addr_len);
	lreq.vm_port = cpu_to_le32(vm_addr.svm_port);
	lreq.backlog = cpu_to_le32(backlog);

	err = tsi_control_sendmsg(tsk, TSI_LISTEN, (void *)&lreq,
				  sizeof(struct tsi_listen_req));
	if (err < 0) {
		pr_debug("%s: error sending listen request: %d\n", __func__,
			 err);
		goto release;
	}

	err = tsi_control_recvmsg(tsk, TSI_LISTEN, (void *)&lrsp,
				  sizeof(struct tsi_listen_rsp));
	if (err < 0) {
		pr_debug("%s: error receiving listen request answer\n",
			 __func__);
		goto release;
	}

	pr_debug("%s: listen result=%d", __func__, (s32)le32_to_cpu(lrsp.result));

	err = (s32)le32_to_cpu(lrsp.result);
	if (le32_to_cpu(lrsp.flags) & ~TSI_LISTEN_STRICT) {
		tsi_control_failed(tsk);
		err = -EPROTO;
		goto release;
	}

	if (!err) {
		tsk->svm_peer_port = TSI_DEFAULT_PORT;
	} else if (tsk->family == AF_UNIX ||
		   (!(le32_to_cpu(lrsp.flags) & TSI_LISTEN_STRICT) &&
		    (err == -EPERM || err == -EADDRINUSE || err == -EADDRNOTAVAIL))) {
		/* Host policy, addresses or paths may require guest-only service. */
		tsi_release_proxy(tsk);
		local_only = true;
	} else {
		goto release;
	}

local:
	err = isocket->ops->listen(isocket, backlog);
	if (err) {
		tsi_release_proxy(tsk);
		goto release;
	}
	tsk->status = local_only ? S_INET : S_HYBRID;
	WRITE_ONCE(sk->sk_shutdown, 0);
	WRITE_ONCE(sk->sk_state, TCP_LISTEN);

release:
	release_sock(sk);
	return err;
}

static int tsi_shutdown(struct socket *sock, int mode)
{
	struct sock *sk = sock->sk;
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	int err;

	if (mode < SHUT_RD || mode > SHUT_RDWR)
		return -EINVAL;
	lock_sock(sk);
	if (tsi_sk(sk)->connect_pending) {
		release_sock(sk);
		return -ENOTCONN;
	}
	tsk = tsi_sk(sock->sk);
	isocket = tsk->isocket;
	vsocket = tsk->vsocket;
	if (sock->type == SOCK_DGRAM && tsk->family != AF_UNIX) {
		err = isocket->ops->shutdown(isocket, mode);
		vsocket->ops->shutdown(vsocket, mode);
		if (tsk->udp_peer_len)
			err = 0;
		goto release;
	}
	if (sk->sk_state == TCP_LISTEN) {
		WRITE_ONCE(sk->sk_shutdown, sk->sk_shutdown | (mode + 1));
		err = 0;
		if ((mode + 1) & RCV_SHUTDOWN) {
			err = isocket->ops->shutdown(isocket, mode);
			if (tsk->status == S_HYBRID) {
				int proxy_err = tsi_release_proxy(tsk);

				if (!err)
					err = proxy_err;
			}
			WRITE_ONCE(sk->sk_state, TCP_CLOSE);
		}
		wake_up_interruptible_all(sk_sleep(isocket->sk));
		wake_up_interruptible_all(sk_sleep(vsocket->sk));
		goto release;
	}

	pr_debug("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock, vsocket,
		 isocket, tsk->status);

	switch (tsk->status) {
	case S_HYBRID:
		err = -ENOTCONN;
		break;
	case S_INET:
		err = isocket->ops->shutdown(isocket, mode);
		break;
	case S_VSOCK:
		err = vsocket->ops->shutdown(vsocket, mode);
		break;
	}

release:
	release_sock(sk);
	return err;
}

static bool tsi_is_timeout_opt(int level, int optname)
{
	if (level != SOL_SOCKET)
		return false;

	return optname == SO_RCVTIMEO_OLD || optname == SO_RCVTIMEO_NEW ||
	       optname == SO_SNDTIMEO_OLD || optname == SO_SNDTIMEO_NEW;
}

static int tsi_set_timeout(struct socket *sock, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *transports[] = { tsk->isocket, tsk->vsocket };
	bool receive = optname == SO_RCVTIMEO_OLD || optname == SO_RCVTIMEO_NEW;
	long timeo;
	int i, err;

	/* Parse once on the wrapper that SOL_SOCKET getsockopt reads. */
	err = sock_setsockopt(sock, level, optname, optval, optlen);
	if (err)
		return err;
	timeo = receive ? READ_ONCE(sock->sk->sk_rcvtimeo) :
			  READ_ONCE(sock->sk->sk_sndtimeo);
	for (i = 0; i < ARRAY_SIZE(transports); i++) {
		if (!transports[i])
			continue;
		if (receive)
			WRITE_ONCE(transports[i]->sk->sk_rcvtimeo, timeo);
		else
			WRITE_ONCE(transports[i]->sk->sk_sndtimeo, timeo);
	}
	return 0;
}

static bool tsi_local_option(int level, int name)
{
	return level == SOL_SOCKET &&
		(name == SO_BINDTODEVICE || name == SO_BINDTOIFINDEX);
}

static int tsi_native_setsockopt(struct tsi_sock *tsk, int level, int name,
				 sockptr_t value, unsigned int len)
{
	struct socket *native = tsk->isocket;

	if (!native)
		return -ENOPROTOOPT;
	if (level == SOL_SOCKET)
		return sock_setsockopt(native, level, name, value, len);
	if (!native->ops->setsockopt)
		return -ENOPROTOOPT;
	return native->ops->setsockopt(native, level, name, value, len);
}

static int tsi_setsockopt(struct socket *sock, int level, int name,
			  sockptr_t optval, unsigned int optlen)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	int index, value, err;

	lock_sock(sock->sk);
	if (tsi_is_timeout_opt(level, name)) {
		err = tsi_set_timeout(sock, level, name, optval, optlen);
		goto out;
	}
	if (tsk->connect_pending) {
		err = -EAGAIN;
		goto out;
	}
	if (tsk->control_broken) {
		err = -EIO;
		goto out;
	}
	if (tsi_local_option(level, name)) {
		err = tsi_native_setsockopt(tsk, level, name, optval, optlen);
		goto out;
	}
	index = tsi_option_index(tsk, level, name);
	if (index < 0) {
		/* Local socket tuning must not disable transparent host networking. */
		err = tsi_native_setsockopt(tsk, level, name, optval, optlen);
		goto out;
	}
	err = copy_safe_from_sockptr(&value, sizeof(value), optval, optlen);
	if (err)
		goto out;
	/* These integer options need no privilege; validate the bind-only case. */
	if (level == IPPROTO_IPV6 && name == IPV6_V6ONLY && tsk->isocket &&
	    inet_sk(tsk->isocket->sk)->inet_num) {
		err = -EINVAL;
		goto out;
	}
	if (tsk->svm_port) {
		err = tsi_proxy_option(tsk, level, name, &value, true);
		if (err)
			goto out;
	}
	if (tsk->isocket) {
		err = tsi_native_setsockopt(tsk, level, name, KERNEL_SOCKPTR(&value),
					    sizeof(value));
		if (err) {
			if (tsk->svm_port) {
				/* The host applied this change; guest state is uncertain. */
				tsi_control_failed(tsk);
			}
			goto out;
		}
	}
	if (level == SOL_SOCKET && (name == SO_SNDBUF || name == SO_RCVBUF) &&
	    tsk->vsocket) {
		err = sock_setsockopt(tsk->vsocket, level, name,
				      KERNEL_SOCKPTR(&value), sizeof(value));
		if (err) {
			tsi_control_failed(tsk);
			goto out;
		}
	}
	tsk->option_values[index] = value;
	tsk->option_mask |= BIT(index);
	err = 0;
out:
	release_sock(sock->sk);
	return err;
}

static int tsi_copy_int(char __user *optval, int __user *optlen, int value)
{
	int len;

	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;
	len = min_t(int, len, sizeof(value));
	if (copy_to_user(optval, &value, len) || put_user(len, optlen))
		return -EFAULT;
	return 0;
}

static int tsi_getsockopt(struct socket *sock, int level, int name,
			  char __user *optval, int __user *optlen)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *native = tsk->isocket;
	int index, value = 0, other, err = 0, len;

	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;
	lock_sock(sock->sk);
	if (tsi_is_timeout_opt(level, name)) {
		err = sk_getsockopt(sock->sk, level, name, USER_SOCKPTR(optval),
				    USER_SOCKPTR(optlen));
		goto out;
	}
	if (level == SOL_SOCKET) {
		switch (name) {
		case SO_TYPE:
			value = sock->type;
			goto copy;
		case SO_DOMAIN:
			value = tsk->family;
			goto copy;
		case SO_PROTOCOL:
			value = tsk->protocol;
			if (!value && tsk->family != AF_UNIX)
				value = sock->type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
			goto copy;
		case SO_ACCEPTCONN:
			value = sock->sk->sk_state == TCP_LISTEN;
			goto copy;
		case SO_ERROR:
			if (tsk->connect_pending)
				goto copy;
			value = -sock_error(sock->sk);
			if (value || tsk->connect_error)
				goto copy;
			if (tsk->control_broken)
				goto copy;
			if (tsk->status == S_VSOCK || (tsk->status == S_HYBRID && tsk->svm_port)) {
				err = tsi_proxy_option(tsk, level, name, &value, false);
				if (err)
					goto out;
				other = -sock_error(tsk->vsocket->sk);
				if (other && value && other != value)
					WRITE_ONCE(sock->sk->sk_err, other);
				if (!value)
					value = other;
			} else if (native) {
				value = -sock_error(native->sk);
			}
			goto copy;
		}
	}
	if (!tsk->connect_pending && tsk->control_broken) {
		err = -EIO;
		goto out;
	}
	if (tsi_local_option(level, name) && native) {
		err = sk_getsockopt(native->sk, level, name, USER_SOCKPTR(optval),
				    USER_SOCKPTR(optlen));
		goto out;
	}
	index = tsi_option_index(tsk, level, name);
	if (!tsk->connect_pending && index >= 0 && tsk->svm_port &&
	    (tsk->status == S_VSOCK || tsk->status == S_HYBRID)) {
		err = tsi_proxy_option(tsk, level, name, &value, false);
		if (!err)
			goto copy;
		goto out;
	}
	if (!native) {
		err = -ENOPROTOOPT;
		goto out;
	}
	if (level == SOL_SOCKET) {
		err = sk_getsockopt(native->sk, level, name, USER_SOCKPTR(optval),
				    USER_SOCKPTR(optlen));
	} else if (native->ops->getsockopt) {
		err = native->ops->getsockopt(native, level, name, optval, optlen);
	} else {
		err = -ENOPROTOOPT;
	}
	goto out;
copy:
	err = tsi_copy_int(optval, optlen, value);
out:
	release_sock(sock->sk);
	return err;
}

static int tsi_stream_sendmsg(struct socket *sock, struct msghdr *msg,
			      size_t len)
{
	struct sock *sk = sock->sk;
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	int err;

	lock_sock(sk);
	if (tsi_sk(sk)->connect_pending) {
		release_sock(sk);
		return -EAGAIN;
	}
	if (tsi_sk(sk)->control_broken) {
		release_sock(sk);
		return -EIO;
	}
	tsk = tsi_sk(sock->sk);
	isocket = tsk->isocket;
	vsocket = tsk->vsocket;

	pr_debug("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock, vsocket,
		 isocket, tsk->status);

	switch (tsk->status) {
	case S_HYBRID:
		err = -EINVAL;
		break;
	case S_INET:
		err = isocket->ops->sendmsg(isocket, msg, len);
		break;
	case S_VSOCK:
		err = vsocket->ops->sendmsg(vsocket, msg, len);
		pr_debug("%s: s=%p vs=%p is=%p st=%d exit\n", __func__, sock,
			 vsocket, isocket, tsk->status);
		break;
	}

	release_sock(sk);
	return err;
}

/*
 * UDP requires a guest listener. ICMP echo is answered by the guest kernel
 * itself when the destination address is local to this network namespace.
 */
static bool tsi_has_native_dgram_peer(struct sock *sk, struct sockaddr *addr,
				      int addr_len, const u8 *source)
{
	struct tsi_sock *tsk;
	struct net *net;
	struct sock *listener;
	bool found;

	tsk = tsi_sk(sk);

	if (WARN_ON_ONCE(sk->sk_type != SOCK_DGRAM))
		return false;

	if (!addr)
		return false;

	net = sock_net(sk);

	if (tsk->family == PF_INET) {
		struct sockaddr_in *sin;
		__be32 daddr, saddr;
		__be16 dport;

		if (addr_len < sizeof(struct sockaddr_in))
			return false;

		sin = (struct sockaddr_in *)addr;
		if (sin->sin_family != AF_INET)
			return false;

		daddr = sin->sin_addr.s_addr;
		dport = sin->sin_port;
		if (tsk->protocol == IPPROTO_ICMP)
			return inet_addr_type(net, daddr) == RTN_LOCAL;
		saddr = inet_sk(tsk->isocket->sk)->inet_saddr;
		if (source)
			memcpy(&saddr, source, sizeof(saddr));
		if (!saddr) {
			struct flowi4 fl4 = {
				.daddr = daddr,
				.flowi4_proto = IPPROTO_UDP,
				.flowi4_oif = tsk->isocket->sk->sk_bound_dev_if,
				.flowi4_mark = READ_ONCE(tsk->isocket->sk->sk_mark),
				.flowi4_uid = sock_net_uid(net, tsk->isocket->sk),
			};
			struct rtable *route = ip_route_output_key(net, &fl4);

			if (!IS_ERR(route)) {
				saddr = fl4.saddr;
				ip_rt_put(route);
			}
		}

		rcu_read_lock();
		listener = __udp4_lib_lookup(net,
					      saddr,
					      inet_sk(tsk->isocket->sk)->inet_sport,
					      daddr, dport,
					      0, 0,
					      NULL);

		found = !!listener;
		rcu_read_unlock();
		return found;
	} else if (tsk->family == PF_INET6) {
		struct sockaddr_in6 *sin6;
		const struct in6_addr *daddr;
		struct in6_addr saddr;
		__be16 dport;

		if (addr_len < sizeof(struct sockaddr_in6))
			return false;

		sin6 = (struct sockaddr_in6 *)addr;
		if (sin6->sin6_family != AF_INET6)
			return false;

		daddr = &sin6->sin6_addr;
		dport = sin6->sin6_port;
		if (tsk->protocol == IPPROTO_ICMPV6)
			return ipv6_chk_addr(net, daddr, NULL, 0);
		saddr = tsk->isocket->sk->sk_v6_rcv_saddr;
		if (source)
			memcpy(&saddr, source, sizeof(saddr));
		if (ipv6_addr_any(&saddr)) {
			struct flowi6 fl6 = {
				.daddr = *daddr,
				.flowi6_proto = IPPROTO_UDP,
				.flowi6_oif = tsk->isocket->sk->sk_bound_dev_if,
				.flowi6_mark = READ_ONCE(tsk->isocket->sk->sk_mark),
				.flowi6_uid = sock_net_uid(net, tsk->isocket->sk),
			};
			struct dst_entry *route;

			route = ip6_dst_lookup_flow(net, tsk->isocket->sk, &fl6, NULL);
			if (!IS_ERR(route)) {
				saddr = fl6.saddr;
				dst_release(route);
			}
		}

		rcu_read_lock();
		listener = __udp6_lib_lookup(net,
					      &saddr,
					      inet_sk(tsk->isocket->sk)->inet_sport,
					      daddr, dport,
					      0, 0,
					      NULL);

		found = !!listener;
		rcu_read_unlock();
		return found;
	}

	return false;
}

/* The TSI lock serializes host peer changes and data operations. */
static int tsi_udp_proxy_connect(struct tsi_sock *tsk, struct sockaddr *addr,
				 int addr_len)
{
	struct tsi_connect_req req = {};
	struct tsi_connect_rsp rsp;
	int err;

	if (!tsk->svm_port) {
		err = tsi_create_proxy(tsk, SOCK_DGRAM);
		if (err)
			return err;
	}
	req.svm_port = cpu_to_le32(tsk->svm_port);
	req.addr_len = cpu_to_le32(addr_len);
	memcpy(req.addr, addr, addr_len);
	err = tsi_control_sendmsg(tsk, TSI_CONNECT, &req, sizeof(req));
	if (err < 0)
		return err;
	err = tsi_control_recvmsg(tsk, TSI_CONNECT, &rsp, sizeof(rsp));
	if (err < 0)
		return err;
	if (err != sizeof(rsp))
		return -EPROTO;
	if ((s32)le32_to_cpu(rsp.result))
		return (s32)le32_to_cpu(rsp.result);

	tsk->udp_proxy_connected = true;
	return 0;
}

static int tsi_udp_proxy_disconnect(struct tsi_sock *tsk)
{
	__le32 port = cpu_to_le32(tsk->svm_port);
	struct tsi_connect_rsp rsp;
	int err;

	if (!tsk->svm_port)
		return 0;
	err = tsi_control_sendmsg(tsk, TSI_DISCONNECT, &port, sizeof(port));
	if (err < 0)
		return err;
	err = tsi_control_recvmsg(tsk, TSI_DISCONNECT, &rsp, sizeof(rsp));
	if (err < 0)
		return err;
	err = (s32)le32_to_cpu(rsp.result);
	if (err)
		return err;
	tsk->udp_proxy_connected = false;
	tsk->udp_proxy_synced = false;
	return 0;
}

static int tsi_udp_connect(struct socket *sock, struct sockaddr_unsized *addr,
			   int addr_len, int flags)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct sockaddr unspec = { .sa_family = AF_UNSPEC };
	int native_err, err;
	bool local;

	if (tsk->family == AF_UNIX)
		return tsi_connect(sock, addr, addr_len, flags);
	lock_sock(sock->sk);
	if (tsi_sk(sock->sk)->control_broken) {
		release_sock(sock->sk);
		return -EIO;
	}
	if (addr_len < sizeof(addr->sa_family)) {
		err = -EINVAL;
		goto out;
	}
	if (addr->sa_family == AF_UNSPEC) {
		err = tsi_udp_proxy_disconnect(tsk);
		if (err)
			goto out;
		err = tsk->isocket->ops->connect(tsk->isocket, addr, addr_len, flags);
		if (!err) {
			tsk->udp_peer_len = 0;
			tsk->status = S_HYBRID;
			sock->state = SS_UNCONNECTED;
			WRITE_ONCE(sock->sk->sk_state, TCP_CLOSE);
		}
		goto out;
	}
	err = tsi_check_addr_len(tsk, addr_len);
	if (err)
		goto out;
	if (addr->sa_family != tsk->family) {
		err = -EAFNOSUPPORT;
		goto out;
	}

	native_err = tsk->isocket->ops->connect(tsk->isocket, addr, addr_len, flags);
	local = tsi_has_native_dgram_peer(sock->sk, (struct sockaddr *)addr,
					  addr_len, NULL);
	if (local) {
		err = native_err;
		if (!err && tsk->udp_proxy_connected)
			err = tsi_udp_proxy_disconnect(tsk);
	} else if (native_err && native_err != -ENETUNREACH &&
		   native_err != -EHOSTUNREACH && native_err != -ENODEV &&
		   native_err != -ENETDOWN && native_err != -EADDRNOTAVAIL) {
		err = native_err;
	} else {
		err = tsi_udp_proxy_connect(tsk, (struct sockaddr *)addr, addr_len);
	}
	if (err) {
		/* A failed reconnect must not replace the previous native peer. */
		if (tsk->udp_peer_len)
			tsk->isocket->ops->connect(tsk->isocket,
				(struct sockaddr_unsized *)&tsk->udp_peer,
				tsk->udp_peer_len, flags);
		else
			tsk->isocket->ops->connect(tsk->isocket,
				(struct sockaddr_unsized *)&unspec, sizeof(unspec), flags);
		goto out;
	}
	memcpy(&tsk->udp_peer, addr, addr_len);
	tsk->udp_peer_len = addr_len;
	tsk->udp_proxy_synced = !local;
	tsk->status = local ? S_INET : S_VSOCK;
	sock->state = SS_CONNECTED;
	WRITE_ONCE(sock->sk->sk_state, TCP_ESTABLISHED);

out:
	release_sock(sock->sk);
	return err;
}

static int tsi_udp_getname(struct socket *sock, struct sockaddr *addr, int peer)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	int err;

	if (tsk->family == AF_UNIX)
		return tsi_getname(sock, addr, peer);
	lock_sock(sock->sk);
	if (tsk->control_broken)
		err = -EIO;
	else if (peer && !tsk->udp_peer_len)
		err = -ENOTCONN;
	else if (!peer && tsk->bound_addr)
		err = tsk->isocket->ops->getname(tsk->isocket, addr, 0);
	else if (tsk->status == S_VSOCK)
		err = vsock_proxy_getname(tsk, addr, peer);
	else
		err = tsk->isocket->ops->getname(tsk->isocket, addr, peer);
	release_sock(sock->sk);
	return err;
}

static unsigned int tsi_udp_ifindex(struct tsi_sock *tsk, const u8 *address)
{
	struct sock *sk = tsk->isocket->sk;
	struct net *net = sock_net(sk);
	struct net_device *dev;
	unsigned int ifindex = sk->sk_bound_dev_if;

	if (ifindex)
		return ifindex;
	if (tsk->family == AF_INET) {
		__be32 addr;

		memcpy(&addr, address, sizeof(addr));
		dev = ip_dev_find(net, addr);
		if (dev) {
			ifindex = dev->ifindex;
			dev_put(dev);
		}
	} else if (IS_REACHABLE(CONFIG_IPV6)) {
		struct in6_addr addr;

		memcpy(&addr, address, sizeof(addr));
		rcu_read_lock();
		dev = ipv6_dev_find(net, &addr, NULL);
		if (dev)
			ifindex = dev->ifindex;
		rcu_read_unlock();
	}
	/* Proxy ingress is local to the guest, not a host interface mirror. */
	return ifindex ? ifindex : net->loopback_dev->ifindex;
}

static int tsi_udp_send_pktinfo(struct tsi_sock *tsk, struct msghdr *msg,
				struct tsi_dgram_hdr *hdr, bool proxy)
{
	struct cmsghdr *cmsg;
	bool seen = false;

	if (msg->msg_controllen && !CMSG_FIRSTHDR(msg))
		return -EINVAL;
	for_each_cmsghdr(cmsg, msg) {
		unsigned int ifindex;
		bool any;

		if (!CMSG_OK(msg, cmsg) || (proxy && seen))
			return -EINVAL;
		if (tsk->family == AF_INET && cmsg->cmsg_level == SOL_IP &&
		    cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo info;

			if (cmsg->cmsg_len != CMSG_LEN(sizeof(info)))
				return -EINVAL;
			memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
			if (info.ipi_ifindex < 0)
				return -EINVAL;
			ifindex = info.ipi_ifindex;
			memcpy(hdr->local_addr, &info.ipi_spec_dst, sizeof(info.ipi_spec_dst));
		} else if (tsk->family == AF_INET6 && cmsg->cmsg_level == SOL_IPV6 &&
			   cmsg->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo info;

			if (cmsg->cmsg_len != CMSG_LEN(sizeof(info)))
				return -EINVAL;
			memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
			if (proxy && (ipv6_addr_type(&info.ipi6_addr) & IPV6_ADDR_LINKLOCAL))
				return -EOPNOTSUPP;
			ifindex = info.ipi6_ifindex;
			memcpy(hdr->local_addr, &info.ipi6_addr, sizeof(info.ipi6_addr));
		} else {
			if (proxy)
				return -EOPNOTSUPP;
			continue;
		}
		any = !memchr_inv(hdr->local_addr, 0, sizeof(hdr->local_addr));
		if (proxy && ifindex &&
		    (any || ifindex != tsi_udp_ifindex(tsk, hdr->local_addr)))
			return -EOPNOTSUPP;
		hdr->flags = cpu_to_le32(any ? 0 : TSI_DGRAM_PKTINFO);
		seen = true;
	}
	return 0;
}

static int tsi_udp_proxy_send(struct tsi_sock *tsk, struct msghdr *msg,
			      struct sockaddr *addr, int addr_len, size_t len)
{
	struct sockaddr_vm vm_addr = {
		.svm_family = AF_VSOCK,
		.svm_port = TSI_DATAGRAM,
		.svm_cid = VMADDR_CID_HOST,
	};
	struct msghdr wire_msg = {
		.msg_name = &vm_addr,
		.msg_namelen = sizeof(vm_addr),
		.msg_flags = msg->msg_flags & (MSG_DONTWAIT | MSG_NOSIGNAL),
	};
	struct tsi_dgram_hdr *hdr;
	struct kvec iov;
	int err;

	if (len > TSI_DGRAM_MAX_SIZE - sizeof(*hdr))
		return -EMSGSIZE;
	if (msg->msg_flags & (MSG_MORE | MSG_ZEROCOPY | MSG_OOB))
		return -EOPNOTSUPP;
	hdr = kvzalloc(sizeof(*hdr) + len, GFP_KERNEL);
	if (!hdr)
		return -ENOMEM;
	hdr->version = cpu_to_le32(TSI_VERSION);
	hdr->addr_len = cpu_to_le32(addr_len);
	hdr->data_len = cpu_to_le32(len);
	err = tsi_udp_send_pktinfo(tsk, msg, hdr, true);
	if (err)
		goto out;
	memcpy(hdr->addr, addr, addr_len);
	if (tsk->family == AF_INET)
		memset(((struct sockaddr_in *)hdr->addr)->sin_zero, 0,
		       sizeof(((struct sockaddr_in *)hdr->addr)->sin_zero));
	if (!copy_from_iter_full(hdr + 1, len, &msg->msg_iter)) {
		err = -EFAULT;
		goto out;
	}
	iov.iov_base = hdr;
	iov.iov_len = sizeof(*hdr) + len;
	err = kernel_sendmsg(tsk->vsocket, &wire_msg, &iov, 1, iov.iov_len);
	if (err >= 0) {
		if (err == iov.iov_len)
			err = len;
		else
			err = -EIO;
	}

out:
	kvfree(hdr);
	return err;
}

static int tsi_udp_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct sockaddr *addr = msg->msg_name;
	struct tsi_dgram_hdr hint = {};
	const u8 *source = NULL;
	int addr_len = msg->msg_namelen;
	int err;
	bool local;

	lock_sock(sock->sk);
	if (tsi_sk(sock->sk)->control_broken) {
		release_sock(sock->sk);
		return -EIO;
	}
	if (!addr) {
		if (!tsk->udp_peer_len) {
			err = -EDESTADDRREQ;
			goto out;
		}
		addr = (struct sockaddr *)&tsk->udp_peer;
		addr_len = tsk->udp_peer_len;
	}
	err = tsi_check_addr_len(tsk, addr_len);
	if (err)
		goto out;
	if (addr->sa_family != tsk->family) {
		err = -EAFNOSUPPORT;
		goto out;
	}
	/* A sendto override chooses its own transport, not a new default peer. */
	if (msg->msg_controllen && !tsi_udp_send_pktinfo(tsk, msg, &hint, false) &&
	    (hint.flags & cpu_to_le32(TSI_DGRAM_PKTINFO)))
		source = hint.local_addr;
	local = msg->msg_name ? tsi_has_native_dgram_peer(sock->sk, addr, addr_len, source) :
			       tsk->status == S_INET;
	if (local) {
		err = tsk->isocket->ops->sendmsg(tsk->isocket, msg, len);
		if (err >= 0 && !tsk->udp_peer_len)
			tsk->status = S_INET;
		goto out;
	}
	if (tsk->isocket->sk->sk_shutdown & SEND_SHUTDOWN) {
		err = -EPIPE;
		goto out;
	}
	if (tsk->udp_peer_len && !tsk->udp_proxy_synced) {
		err = tsi_udp_proxy_connect(tsk, (struct sockaddr *)&tsk->udp_peer,
					    tsk->udp_peer_len);
		if (err)
			goto out;
		tsk->udp_proxy_synced = true;
	}
	if (!tsk->svm_port) {
		err = tsi_create_proxy(tsk, SOCK_DGRAM);
		if (err)
			goto out;
	}
	err = tsi_udp_proxy_send(tsk, msg, addr, addr_len, len);
	if (err >= 0 && !tsk->udp_peer_len)
		tsk->status = S_VSOCK;

out:
	release_sock(sock->sk);
	return err;
}

static int tsi_dgram_sendmsg(struct socket *sock, struct msghdr *msg,
			     size_t len)
{
	struct sock *sk = sock->sk;
	struct tsi_sendto_addr sa_req = {};
	struct sockaddr_vm *svm;
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	int err;

	if (tsi_sk(sk)->family != AF_UNIX)
		return tsi_udp_sendmsg(sock, msg, len);

	lock_sock(sk);
	if (tsi_sk(sk)->control_broken) {
		release_sock(sk);
		return -EIO;
	}
	tsk = tsi_sk(sock->sk);
	isocket = tsk->isocket;
	vsocket = tsk->vsocket;

	pr_debug("%s: s=%p vs=%p is=%p st=%d family=%d\n", __func__, sock,
		 vsocket, isocket, tsk->status, tsk->family);

	switch (tsk->status) {
	case S_INET:
		err = isocket->ops->sendmsg(isocket, msg, len);
		break;
	case S_HYBRID:
	case S_VSOCK:
		if (msg->msg_name) {
			pr_debug("%s: fixing msg_name for vsock proxy\n",
				 __func__);
			err = tsi_check_addr_len(tsk, msg->msg_namelen);
			if (err != 0)
				goto release;

			if (!tsk->sendto_addr) {
				tsk->sendto_addr =
					kmalloc(msg->msg_namelen, GFP_KERNEL);
				tsk->sendto_addr_len = msg->msg_namelen;
			}
			memcpy(tsk->sendto_addr, msg->msg_name,
			       msg->msg_namelen);

			if (tsk->svm_port == 0) {
				err = tsi_create_proxy(tsk, SOCK_DGRAM);
				if (err)
					goto release;
			}

			sa_req.svm_port = cpu_to_le32(tsk->svm_port);
			sa_req.addr_len = cpu_to_le32(msg->msg_namelen);
			memcpy(&sa_req.addr, msg->msg_name, msg->msg_namelen);

			err = tsi_control_sendmsg(
				tsk, TSI_SENDTO_ADDR, (void *)&sa_req,
				sizeof(struct tsi_sendto_addr));
			if (err < 0) {
				pr_debug(
					"%s: error sending connection request: %d\n",
					__func__, err);
				goto release;
			}

			svm = (struct sockaddr_vm *)msg->msg_name;
			svm->svm_family = AF_VSOCK;
			svm->svm_port = TSI_SENDTO_DATA;
			svm->svm_cid = VMADDR_CID_HOST;
			svm->svm_flags = 0;
		}

		err = vsocket->ops->sendmsg(vsocket, msg, len);
		if (err > 0)
			tsk->status = S_VSOCK;
		break;
	}

release:
	release_sock(sk);
	return err;
}

static int tsi_stream_recvmsg(struct socket *sock, struct msghdr *msg,
			      size_t len, int flags)
{
	struct sock *sk = sock->sk;
	struct tsi_sock *tsk;
	struct socket *transport;

	lock_sock(sk);
	if (tsi_sk(sk)->connect_pending) {
		release_sock(sk);
		return -EAGAIN;
	}
	if (tsi_sk(sk)->control_broken) {
		release_sock(sk);
		return -EIO;
	}
	tsk = tsi_sk(sock->sk);

	switch (tsk->status) {
	case S_INET:
		transport = tsk->isocket;
		break;
	case S_VSOCK:
		transport = tsk->vsocket;
		break;
	default:
		release_sock(sk);
		return -ENOTCONN;
	}

	release_sock(sk);

	/*
	 * The caller keeps the TSI socket alive, so tsi_release() cannot
	 * release its transport sockets while recvmsg() is waiting.
	 */
	return transport->ops->recvmsg(transport, msg, len, flags);
}

static void tsi_udp_recv_pktinfo(struct tsi_sock *tsk, struct msghdr *msg,
				 const struct tsi_dgram_hdr *hdr)
{
	struct sock *sk = tsk->isocket->sk;
	u8 address[16] = {};

	if (le32_to_cpu(hdr->flags) & TSI_DGRAM_PKTINFO) {
		memcpy(address, hdr->local_addr, sizeof(address));
	} else if (tsk->bound_addr) {
		if (tsk->family == AF_INET)
			memcpy(address, &((struct sockaddr_in *)tsk->bound_addr)->sin_addr, 4);
		else
			memcpy(address, &((struct sockaddr_in6 *)tsk->bound_addr)->sin6_addr, 16);
	}
	if (!memchr_inv(address, 0, sizeof(address)))
		return;
	if (tsk->family == AF_INET) {
		struct in_pktinfo info = {};

		if (!(inet_cmsg_flags(inet_sk(sk)) & IP_CMSG_PKTINFO))
			return;
		info.ipi_ifindex = tsi_udp_ifindex(tsk, address);
		memcpy(&info.ipi_addr, address, sizeof(info.ipi_addr));
		info.ipi_spec_dst = info.ipi_addr;
		put_cmsg(msg, SOL_IP, IP_PKTINFO, sizeof(info), &info);
	} else if (IS_REACHABLE(CONFIG_IPV6)) {
		struct in6_pktinfo info = {};

		if (!ipv6_sk_rxinfo(sk))
			return;
		info.ipi6_ifindex = tsi_udp_ifindex(tsk, address);
		memcpy(&info.ipi6_addr, address, sizeof(info.ipi6_addr));
		put_cmsg(msg, SOL_IPV6, IPV6_PKTINFO, sizeof(info), &info);
	}
}

static int tsi_udp_proxy_recv(struct tsi_sock *tsk, struct msghdr *msg,
			      size_t len, int flags)
{
	struct msghdr wire_msg = {};
	struct tsi_dgram_hdr *hdr;
	struct kvec iov;
	u32 addr_len, data_len, wire_flags;
	size_t available, copied;
	int err;

	if (flags & MSG_ERRQUEUE)
		return -EOPNOTSUPP;
	hdr = kvmalloc(TSI_DGRAM_MAX_SIZE, GFP_KERNEL);
	if (!hdr)
		return -ENOMEM;
	iov.iov_base = hdr;
	iov.iov_len = TSI_DGRAM_MAX_SIZE;
	err = kernel_recvmsg(tsk->vsocket, &wire_msg, &iov, 1, iov.iov_len,
			     (flags & ~MSG_TRUNC) | MSG_DONTWAIT);
	if (err < 0)
		goto out;
	if (err < sizeof(*hdr) || (wire_msg.msg_flags & MSG_TRUNC) ||
	    le32_to_cpu(hdr->version) != TSI_VERSION) {
		err = -EPROTO;
		goto out;
	}
	addr_len = le32_to_cpu(hdr->addr_len);
	data_len = le32_to_cpu(hdr->data_len);
	wire_flags = le32_to_cpu(hdr->flags);
	available = err - sizeof(*hdr);
	if (tsi_check_addr_len(tsk, addr_len) ||
	    ((struct sockaddr *)hdr->addr)->sa_family != tsk->family ||
	    (wire_flags & ~(TSI_DGRAM_TRUNC | TSI_DGRAM_PKTINFO | TSI_DGRAM_HOPLIMIT)) ||
	    ((wire_flags & TSI_DGRAM_HOPLIMIT) &&
	     (!(wire_flags & TSI_DGRAM_PKTINFO) || le32_to_cpu(hdr->hop_limit) > 255)) ||
	    (!(wire_flags & TSI_DGRAM_HOPLIMIT) && hdr->hop_limit) || data_len > 65535 ||
	    available > data_len ||
	    (!(wire_flags & TSI_DGRAM_TRUNC) && available != data_len)) {
		err = -EPROTO;
		goto out;
	}
	if (wire_flags & TSI_DGRAM_PKTINFO) {
		if (!memchr_inv(hdr->local_addr, 0, sizeof(hdr->local_addr)) ||
		    (tsk->family == AF_INET && memchr_inv(hdr->local_addr + 4, 0, 12))) {
			err = -EPROTO;
			goto out;
		}
	} else if (hdr->ifindex || memchr_inv(hdr->local_addr, 0, sizeof(hdr->local_addr))) {
		err = -EPROTO;
		goto out;
	}
	copied = min(len, available);
	if (copy_to_iter(hdr + 1, copied, &msg->msg_iter) != copied) {
		err = -EFAULT;
		goto out;
	}
	if (copied < data_len || (wire_flags & TSI_DGRAM_TRUNC))
		msg->msg_flags |= MSG_TRUNC;
	if (msg->msg_name) {
		memcpy(msg->msg_name, hdr->addr, addr_len);
		msg->msg_namelen = addr_len;
	} else {
		msg->msg_namelen = 0;
	}
	tsi_udp_recv_pktinfo(tsk, msg, hdr);
	if (wire_flags & TSI_DGRAM_HOPLIMIT) {
		struct sock *native = tsk->isocket->sk;
		int hop_limit = le32_to_cpu(hdr->hop_limit);

		if (tsk->family == AF_INET &&
		    (inet_cmsg_flags(inet_sk(native)) & IP_CMSG_TTL))
			put_cmsg(msg, SOL_IP, IP_TTL, sizeof(hop_limit), &hop_limit);
		else if (tsk->family == AF_INET6 && IS_REACHABLE(CONFIG_IPV6) &&
			 inet6_sk(native)->rxopt.bits.rxhlim)
			put_cmsg(msg, SOL_IPV6, IPV6_HOPLIMIT, sizeof(hop_limit), &hop_limit);
	}
	err = flags & MSG_TRUNC ? data_len : copied;

out:
	kvfree(hdr);
	return err;
}

static int tsi_udp_recvmsg(struct socket *sock, struct msghdr *msg,
			   size_t len, int flags)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	DEFINE_WAIT_FUNC(other, tsi_transport_wake);
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	int original_namelen = msg->msg_namelen;
	unsigned int original_flags = msg->msg_flags;
	struct socket *transports[2];
	long timeo;
	int count, i, err;

	if (READ_ONCE(tsi_sk(sock->sk)->control_broken))
		return -EIO;

	/* The syscall pins the wrapper and both private transport sockets. */
	other.private = &wait;
	add_wait_queue(sk_sleep(tsk->isocket->sk), &wait);
	add_wait_queue(sk_sleep(tsk->vsocket->sk), &other);
	timeo = sock_rcvtimeo(tsk->isocket->sk, flags & MSG_DONTWAIT);
	for (;;) {
		lock_sock(sock->sk);
		if (tsk->control_broken) {
			err = -EIO;
			release_sock(sock->sk);
			break;
		}
		count = tsk->udp_peer_len || (flags & MSG_ERRQUEUE) ? 1 : 2;
		if (count == 2)
			transports[0] = tsk->udp_recv_inet_first ? tsk->isocket : tsk->vsocket;
		else
			transports[0] = tsk->status == S_VSOCK ? tsk->vsocket : tsk->isocket;
		transports[1] = transports[0] == tsk->isocket ? tsk->vsocket : tsk->isocket;
		for (i = 0; i < count; i++) {
			msg->msg_namelen = original_namelen;
			msg->msg_flags = original_flags;
			if (transports[i] == tsk->vsocket)
				err = tsi_udp_proxy_recv(tsk, msg, len, flags);
			else
				err = transports[i]->ops->recvmsg(transports[i], msg, len,
							  flags | MSG_DONTWAIT);
			if (err == -EAGAIN)
				continue;
			if (err >= 0 && count == 2)
				tsk->udp_recv_inet_first = transports[i] != tsk->isocket;
			release_sock(sock->sk);
			goto out;
		}
		/* Nonblocking inner reads do not translate receive shutdown to EOF. */
		if (!(flags & (MSG_DONTWAIT | MSG_ERRQUEUE)) &&
		    (tsk->isocket->sk->sk_shutdown & RCV_SHUTDOWN)) {
			err = 0;
			msg->msg_namelen = 0;
			release_sock(sock->sk);
			goto out;
		}
		release_sock(sock->sk);
		err = -EAGAIN;
		if (!timeo)
			break;
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}
		timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
	}

out:
	remove_wait_queue(sk_sleep(tsk->vsocket->sk), &other);
	remove_wait_queue(sk_sleep(tsk->isocket->sk), &wait);
	return err;
}

static int tsi_dgram_recvmsg(struct socket *sock, struct msghdr *msg,
			     size_t len, int flags)
{
	struct sock *sk = sock->sk;
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	int err;

	if (tsi_sk(sk)->family != AF_UNIX)
		return tsi_udp_recvmsg(sock, msg, len, flags);

	lock_sock(sk);
	if (tsi_sk(sk)->control_broken) {
		release_sock(sk);
		return -EIO;
	}
	tsk = tsi_sk(sock->sk);
	isocket = tsk->isocket;
	vsocket = tsk->vsocket;

	pr_debug("%s: s=%p vs=%p is=%p st=%d family=%d\n", __func__, sock,
		 vsocket, isocket, tsk->status, tsk->family);

	switch (tsk->status) {
	case S_HYBRID:
	case S_INET:
		err = isocket->ops->recvmsg(isocket, msg, len, flags);
		break;
	case S_VSOCK:
		err = vsocket->ops->recvmsg(vsocket, msg, len, flags);
		if (err > 0 && msg && msg->msg_name && tsk->sendto_addr) {
			pr_debug(
				"%s: msg_name=%p sendto_addr=%p, msg_len=%d addr_len=%d\n",
				__func__, msg->msg_name, tsk->sendto_addr,
				msg->msg_namelen, tsk->sendto_addr_len);
			memcpy(msg->msg_name, tsk->sendto_addr,
			       tsk->sendto_addr_len);
			msg->msg_namelen = tsk->sendto_addr_len;
		}
		break;
	}

	release_sock(sk);
	return err;
}

static const struct proto_ops tsi_stream_ops = {
	.family = PF_TSI,
	.owner = THIS_MODULE,
	.release = tsi_release,
	.bind = tsi_bind,
	.connect = tsi_connect,
	.socketpair = tsi_socketpair,
	.accept = tsi_accept,
	.getname = tsi_getname,
	.poll = tsi_poll,
	.ioctl = tsi_ioctl,
	.listen = tsi_listen,
	.shutdown = tsi_shutdown,
	.setsockopt = tsi_setsockopt,
	.getsockopt = tsi_getsockopt,
	.sendmsg = tsi_stream_sendmsg,
	.recvmsg = tsi_stream_recvmsg,
	.mmap = sock_no_mmap,
};

static const struct proto_ops tsi_dgram_ops = {
	.family = PF_TSI,
	.owner = THIS_MODULE,
	.release = tsi_release,
	.bind = tsi_bind,
	.connect = tsi_udp_connect,
	.socketpair = tsi_socketpair,
	.accept = tsi_accept,
	.getname = tsi_udp_getname,
	.poll = tsi_poll,
	.ioctl = tsi_ioctl,
	.listen = tsi_listen,
	.shutdown = tsi_shutdown,
	.setsockopt = tsi_setsockopt,
	.getsockopt = tsi_getsockopt,
	.sendmsg = tsi_dgram_sendmsg,
	.recvmsg = tsi_dgram_recvmsg,
	.mmap = sock_no_mmap,
};

static int tsi_create_common(struct net *net, struct socket *sock, int protocol,
			     int kern, int family)
{
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	struct socket *csocket;
	struct sock *sk;
	int err;

	pr_debug("%s: socket=%p family=%d\n", __func__, sock, family);

	if (!sock)
		return -EINVAL;

	switch (sock->type) {
	case SOCK_STREAM:
		sock->ops = &tsi_stream_ops;
		break;
	case SOCK_DGRAM:
		sock->ops = &tsi_dgram_ops;
		break;
	default:
		return -ESOCKTNOSUPPORT;
	}

	if (family == PF_INET) {
		sk = sk_alloc(net, AF_TSI, GFP_KERNEL, &tsi_in4_proto, kern);
	} else if (family == PF_INET6) {
		sk = sk_alloc(net, AF_TSI6, GFP_KERNEL, &tsi_in6_proto, kern);
	} else if (family == PF_UNIX) {
		sk = sk_alloc(net, AF_TSIU, GFP_KERNEL, &tsi_un_proto, kern);
	} else {
		return -EPROTONOSUPPORT;
	}
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);
	/* We need to use our own setsockopt functions */
	set_bit(SOCK_CUSTOM_SOCKOPT, &sk->sk_socket->flags);
	set_bit(SOCK_CUSTOM_GETSOCKOPT, &sk->sk_socket->flags);

	tsk = tsi_sk(sk);
	tsi_init_connect(tsk);

	isocket = NULL;
	err = __sock_create(current->nsproxy->net_ns, family, sock->type,
			    protocol, &isocket, 1);
	if (err) {
		pr_debug("%s (%d): problem creating inet socket\n", __func__,
			 task_pid_nr(current));
		return err;
	}

	vsocket = NULL;
	err = __sock_create(current->nsproxy->net_ns, PF_VSOCK, sock->type,
			    PF_VSOCK, &vsocket, 1);
	if (err) {
		pr_debug("%s (%d): problem creating vsock socket\n", __func__,
			 task_pid_nr(current));
		goto free_isocket;
	}

	err = tsi_create_control_socket(&csocket);
	if (err) {
		pr_debug("%s (%d): problem creating control socket\n", __func__,
			 task_pid_nr(current));
		goto free_vsocket;
	}

	pr_debug("isocket: %p\n", isocket);
	pr_debug("vsocket: %p\n", vsocket);
	tsk->isocket = isocket;
	tsk->vsocket = vsocket;
	tsk->csocket = csocket;
	sock->state = SS_UNCONNECTED;
	tsk->svm_port = 0;
	tsk->svm_peer_port = TSI_DEFAULT_PORT;
	tsk->sendto_addr = NULL;
	tsk->bound_addr = NULL;
	tsk->family = family;
	tsk->protocol = protocol;
	tsk->udp_peer_len = 0;
	tsk->udp_proxy_connected = false;
	tsk->udp_proxy_synced = false;
	tsk->udp_recv_inet_first = true;

	return 0;

free_vsocket:
	sock_release(vsocket);
free_isocket:
	sock_release(isocket);
	return err;
}

static int tsi_create_in4(struct net *net, struct socket *sock, int protocol,
			  int kern)
{
	return tsi_create_common(net, sock, protocol, kern, AF_INET);
}

static int tsi_create_in6(struct net *net, struct socket *sock, int protocol,
			  int kern)
{
	return tsi_create_common(net, sock, protocol, kern, AF_INET6);
}

static int tsi_create_un(struct net *net, struct socket *sock, int protocol,
			 int kern)
{
	return tsi_create_common(net, sock, protocol, kern, AF_UNIX);
}

static const struct net_proto_family tsi_family_in4_ops = {
	.family = AF_TSI,
	.create = tsi_create_in4,
	.owner = THIS_MODULE,
};

static const struct net_proto_family tsi_family_in6_ops = {
	.family = AF_TSI6,
	.create = tsi_create_in6,
	.owner = THIS_MODULE,
};

static const struct net_proto_family tsi_family_un_ops = {
	.family = AF_TSIU,
	.create = tsi_create_un,
	.owner = THIS_MODULE,
};

static int __init tsi_init(void)
{
	int err;

	err = proto_register(&tsi_in4_proto, 1);
	if (err) {
		pr_err("Could not register tsi protocol\n");
		goto err_do_nothing;
	}
	err = sock_register(&tsi_family_in4_ops);
	if (err) {
		pr_err("Could not register af_tsi (%d) address family: %d\n",
		       AF_TSI, err);
		goto err_unregister_in4_proto;
	}

	err = proto_register(&tsi_in6_proto, 1);
	if (err) {
		pr_err("Could not register tsi6 protocol\n");
		goto err_unregister_in4_sock;
	}

	err = sock_register(&tsi_family_in6_ops);
	if (err) {
		pr_err("Could not register af_tsi6 (%d) address family: %d\n",
		       AF_TSI6, err);
		goto err_unregister_in6_proto;
	}

	err = proto_register(&tsi_un_proto, 1);
	if (err) {
		pr_debug("Could not register tsiu protocol\n");
		goto err_unregister_in6_sock;
	}

	err = sock_register(&tsi_family_un_ops);
	if (err) {
		pr_debug("Could not register af_tsiu (%d) address family: %d\n",
			 AF_TSIU, err);
		goto err_unregister_un_proto;
	}

	return 0;

err_unregister_un_proto:
	proto_unregister(&tsi_un_proto);
err_unregister_in6_sock:
	sock_unregister(AF_TSI6);
err_unregister_in6_proto:
	proto_unregister(&tsi_in6_proto);
err_unregister_in4_sock:
	sock_unregister(AF_TSI);
err_unregister_in4_proto:
	proto_unregister(&tsi_in4_proto);
err_do_nothing:
	return err;
}

static void __exit tsi_exit(void)
{
	sock_unregister(AF_TSI);
	proto_unregister(&tsi_in4_proto);
	sock_unregister(AF_TSI6);
	proto_unregister(&tsi_in6_proto);
}

module_init(tsi_init);
module_exit(tsi_exit);

MODULE_AUTHOR("Red Hat, Inc.");
MODULE_DESCRIPTION("Transparent Socket Impersonation Sockets");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
