// SPDX-License-Identifier: GPL-2.0-only
/* Datagram feature tests for vsock. */

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/sockios.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "control.h"
#include "timeout.h"
#include "vsock_test_dgram.h"

#define MAX_DGRAM (64 * 1024)

static void fail(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "\nFAIL: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}

static void check(int ret, const char *operation)
{
	if (ret < 0)
		fail("%s: %s", operation, strerror(errno));
}

static void expect_error(ssize_t ret, int error, const char *operation)
{
	if (ret != -1 || errno != error)
		fail("%s: expected %s, got %zd (%s)", operation,
		     strerror(error), ret, ret == -1 ? strerror(errno) : "success");
}

static int64_t now_ms(void)
{
	struct timespec ts;

	check(clock_gettime(CLOCK_MONOTONIC, &ts), "clock_gettime");
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static short poll_fd(int fd, short events, int milliseconds)
{
	struct pollfd pfd = { .fd = fd, .events = events };
	int ret;

	do {
		ret = poll(&pfd, 1, milliseconds);
	} while (ret < 0 && errno == EINTR);
	check(ret, "poll");
	if (pfd.revents & (POLLERR | POLLNVAL))
		fail("unexpected poll events %#x", pfd.revents);
	return pfd.revents;
}

static void wait_readable(int fd)
{
	if (!(poll_fd(fd, POLLIN, TIMEOUT * 1000) & POLLIN))
		fail("waiting for socket readability timed out");
}

static struct sockaddr_vm address(unsigned int cid, unsigned int port)
{
	return (struct sockaddr_vm) {
		.svm_family = AF_VSOCK,
		.svm_cid = cid,
		.svm_port = port,
	};
}

static struct sockaddr_vm sock_name(int fd, bool peer)
{
	struct sockaddr_vm addr;
	socklen_t len = sizeof(addr);
	int ret;

	if (peer)
		ret = getpeername(fd, (struct sockaddr *)&addr, &len);
	else
		ret = getsockname(fd, (struct sockaddr *)&addr, &len);
	check(ret, peer ? "getpeername" : "getsockname");
	if (len != sizeof(addr) || addr.svm_family != AF_VSOCK)
		fail("invalid socket address");
	return addr;
}

static unsigned int local_cid(void)
{
	unsigned int cid;
	int fd;

	fd = open("/dev/vsock", O_RDONLY | O_CLOEXEC);
	check(fd, "open /dev/vsock");
	check(ioctl(fd, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid), "get local CID");
	close(fd);
	if (cid == VMADDR_CID_ANY || cid <= VMADDR_CID_LOCAL)
		fail("a virtio or vhost transport is required (local CID %u)", cid);
	return cid;
}

static void bind_fd(int fd, unsigned int cid, unsigned int port)
{
	struct sockaddr_vm addr = address(cid, port);

	check(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), "bind");
}

static int dgram_socket(void)
{
	int fd = socket(AF_VSOCK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	int rcvbuf = 1024 * 1024;

	check(fd, "socket(AF_VSOCK, SOCK_DGRAM): check transport/feature support");
	check(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)), "SO_RCVBUF");
	return fd;
}

enum dgram_capability {
	DGRAM_SOCKET = 1 << 0,
	DGRAM_VIRTIO = 1 << 1,
	DGRAM_VMCI = 1 << 2,
	DGRAM_LOOPBACK = 1 << 3,
	DGRAM_PEER = 1 << 4,
};

static bool dgram_unavailable(int error)
{
	return error == EAFNOSUPPORT || error == EPROTONOSUPPORT ||
	       error == ESOCKTNOSUPPORT || error == ENODEV;
}

static unsigned int dgram_capabilities(const struct test_opts *opts,
				       unsigned int needs)
{
	unsigned int caps = DGRAM_SOCKET;
	struct sockaddr_vm peer;
	int fd, local_fd;

	fd = socket(AF_VSOCK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		if (dgram_unavailable(errno))
			return 0;
		check(fd, "probe datagram socket");
	}
	/* VMCI registers the dedicated datagram transport when loaded. */
	if (!access("/sys/module/vmw_vsock_vmci_transport", F_OK))
		caps |= DGRAM_VMCI;
	else
		caps |= DGRAM_VIRTIO;

	if ((needs & DGRAM_PEER) && (caps & DGRAM_VIRTIO)) {
		bind_fd(fd, opts->bind_cid, VMADDR_PORT_ANY);
		peer = address(opts->peer_cid, opts->peer_port);
		if (opts->to_host)
			peer.svm_flags = VMADDR_FLAG_TO_HOST;
		if (!connect(fd, (struct sockaddr *)&peer, sizeof(peer)))
			caps |= DGRAM_PEER;
		else if (!dgram_unavailable(errno) && errno != EINVAL)
			check(-1, "probe peer datagram route");
	}
	close(fd);

	if ((needs & DGRAM_LOOPBACK) && (caps & DGRAM_VIRTIO)) {
		/* Binding a stream socket to CID_LOCAL probes registration of
		 * the loopback transport without sending a packet to the host.
		 */
		local_fd = vsock_bind_try(VMADDR_CID_LOCAL, VMADDR_PORT_ANY, SOCK_STREAM);
		if (local_fd >= 0) {
			caps |= DGRAM_LOOPBACK;
			close(local_fd);
		} else if (errno != EADDRNOTAVAIL) {
			check(local_fd, "probe loopback transport");
		}
	}
	return caps;
}

static const char *dgram_check(const struct test_opts *opts, unsigned int needs)
{
	unsigned int local = dgram_capabilities(opts, needs);
	unsigned int both = local;

	/* run_tests() has already synchronized explicit --pick/--skip
	 * selection. Both peers can now safely exchange capabilities.
	 */
	if (!opts->local) {
		control_writeulong(local);
		both &= control_readulong();
	}
	if (!(both & DGRAM_SOCKET))
		return local & DGRAM_SOCKET ?
			"datagrams unavailable at peer" : "datagrams unavailable locally";
	if ((needs & DGRAM_VIRTIO) && !(both & DGRAM_VIRTIO))
		return "requires virtio/vhost datagram transports on both peers";
	if ((needs & DGRAM_VMCI) && !(both & DGRAM_VMCI))
		return "requires VMCI datagram transports on both peers";
	if ((needs & DGRAM_LOOPBACK) && !(both & DGRAM_LOOPBACK))
		return "load vsock_loopback on both peers";
	if ((needs & DGRAM_PEER) && !(both & DGRAM_PEER))
		return "peer route does not support datagrams";
	return NULL;
}

const char *vsock_dgram_check_local(const struct test_opts *opts)
{
	return dgram_check(opts, DGRAM_VIRTIO | DGRAM_LOOPBACK);
}

const char *vsock_dgram_check_peer(const struct test_opts *opts)
{
	return dgram_check(opts, DGRAM_VIRTIO | DGRAM_PEER);
}

const char *vsock_dgram_check_routes(const struct test_opts *opts)
{
	return dgram_check(opts, DGRAM_VIRTIO | DGRAM_PEER | DGRAM_LOOPBACK);
}

const char *vsock_dgram_check_vmci(const struct test_opts *opts)
{
	return dgram_check(opts, DGRAM_VMCI);
}

static int bound_socket(unsigned int cid)
{
	int fd = dgram_socket();

	bind_fd(fd, cid, VMADDR_PORT_ANY);
	return fd;
}

static struct sockaddr_vm local_address(int fd)
{
	struct sockaddr_vm addr = sock_name(fd, false);

	addr.svm_cid = VMADDR_CID_LOCAL;
	return addr;
}

static void connect_fd(int fd, const struct sockaddr_vm *addr)
{
	check(connect(fd, (const struct sockaddr *)addr, sizeof(*addr)), "connect");
}

static void disconnect_fd(int fd)
{
	struct sockaddr_vm addr = { .svm_family = AF_UNSPEC };
	socklen_t len = sizeof(addr);

	check(connect(fd, (struct sockaddr *)&addr, sizeof(addr)), "disconnect");
	expect_error(getpeername(fd, (struct sockaddr *)&addr, &len),
		     ENOTCONN, "getpeername after disconnect");
}

static int queue_bytes(int fd, unsigned long op)
{
	int bytes;

	check(ioctl(fd, op, &bytes), "queue ioctl");
	if (bytes < 0)
		fail("negative queue length: %d", bytes);
	return bytes;
}

static void expect_inq(int fd, int expected)
{
	int actual = queue_bytes(fd, SIOCINQ);

	if (actual != expected)
		fail("SIOCINQ: expected %d, got %d", expected, actual);
}

static void wait_sent(int fd)
{
	int64_t deadline = now_ms() + TIMEOUT * 1000;

	while (queue_bytes(fd, SIOCOUTQ)) {
		if (now_ms() >= deadline)
			fail("SIOCOUTQ did not return to zero");
		usleep(1000);
	}
}

static void send_packet(int fd, const struct sockaddr_vm *addr,
			const void *buf, size_t len)
{
	int64_t deadline = now_ms() + TIMEOUT * 1000;
	ssize_t ret;

	for (;;) {
		ret = sendto(fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL,
			     (const struct sockaddr *)addr, addr ? sizeof(*addr) : 0);
		if (ret >= 0)
			break;
		if (errno != EAGAIN && errno != EINTR)
			fail("sendto(%zu bytes): %s", len, strerror(errno));
		if (now_ms() >= deadline)
			fail("sendto(%zu bytes) timed out", len);
		poll_fd(fd, POLLOUT, 1);
	}
	if (ret != len)
		fail("partial datagram send: %zd/%zu", ret, len);
}

static struct sockaddr_vm recv_packet(int fd, void *buf, size_t capacity,
				      int flags, size_t expected, bool truncated)
{
	struct sockaddr_vm src = { 0 };
	struct iovec iov = { .iov_base = buf, .iov_len = capacity };
	struct msghdr msg = {
		.msg_name = &src,
		.msg_namelen = sizeof(src),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	ssize_t ret;

	wait_readable(fd);
	ret = recvmsg(fd, &msg, flags | MSG_DONTWAIT);
	check(ret, "recvmsg");
	if (ret != expected || !!(msg.msg_flags & MSG_TRUNC) != truncated)
		fail("recvmsg: expected %zu bytes, trunc=%d; got %zd, flags=%#x",
		     expected, truncated, ret, msg.msg_flags);
	if (msg.msg_namelen != sizeof(src) || src.svm_family != AF_VSOCK)
		fail("invalid recvmsg source address");
	return src;
}

static void expect_empty(int fd)
{
	char byte;

	if (poll_fd(fd, POLLIN, 0) & POLLIN)
		fail("unexpected queued datagram");
	expect_error(recv(fd, &byte, 1, MSG_DONTWAIT), EAGAIN, "empty recv");
	expect_inq(fd, 0);
}

void test_dgram_bind(const struct test_opts *opts)
{
	int rx = bound_socket(VMADDR_CID_ANY);
	struct sockaddr_vm dest = local_address(rx);
	int tx = dgram_socket();
	int other = dgram_socket();
	struct sockaddr_vm src;
	char byte;

	dest.svm_cid = VMADDR_CID_ANY;
	expect_error(bind(other, (struct sockaddr *)&dest, sizeof(dest)),
		     EADDRINUSE, "duplicate bind");
	send_packet(tx, &dest, "A", 1);
	src = recv_packet(rx, &byte, 1, 0, 1, false);
	if (byte != 'A' || src.svm_port != sock_name(tx, false).svm_port ||
	    src.svm_cid != VMADDR_CID_LOCAL || src.svm_port < 1024)
		fail("autobind or wildcard destination returned an invalid source");
	close(rx);
	bind_fd(other, VMADDR_CID_ANY, dest.svm_port);
	close(other);
	close(tx);
}

void test_dgram_receive(const struct test_opts *opts)
{
	int rx = bound_socket(VMADDR_CID_ANY);
	int tx = bound_socket(VMADDR_CID_ANY);
	struct sockaddr_vm dest = local_address(rx);
	char buf[80];
	char first[31], second[79];

	memset(first, 'A', sizeof(first));
	memset(second, 'B', sizeof(second));
	expect_empty(rx);
	if (!(poll_fd(tx, POLLOUT, 0) & POLLOUT))
		fail("new socket is not writable");
	if (queue_bytes(tx, SIOCOUTQ))
		fail("new socket has pending output");
	send_packet(tx, &dest, first, sizeof(first));
	send_packet(tx, &dest, second, sizeof(second));
	wait_readable(rx);
	expect_inq(rx, sizeof(first));
	recv_packet(rx, buf, 5, MSG_PEEK, 5, true);
	if (memcmp(buf, first, 5))
		fail("MSG_PEEK payload mismatch");
	expect_inq(rx, sizeof(first));
	recv_packet(rx, buf, 5, MSG_TRUNC, sizeof(first), true);
	wait_readable(rx);
	expect_inq(rx, sizeof(second));
	recv_packet(rx, buf, sizeof(buf), 0, sizeof(second), false);
	if (memcmp(buf, second, sizeof(second)))
		fail("datagram boundary or payload mismatch");
	send_packet(tx, &dest, "", 0);
	wait_readable(rx);
	expect_inq(rx, 0);
	recv_packet(rx, buf, sizeof(buf), MSG_PEEK, 0, false);
	recv_packet(rx, buf, sizeof(buf), 0, 0, false);
	send_packet(tx, &dest, first, sizeof(first));
	recv_packet(rx, buf, 0, MSG_TRUNC, sizeof(first), true);
	expect_empty(rx);
	wait_sent(tx);
	close(tx);
	close(rx);
}

void test_dgram_receive_flags(const struct test_opts *opts)
{
	int rx = bound_socket(VMADDR_CID_ANY);
	int tx = bound_socket(VMADDR_CID_ANY);
	struct sockaddr_vm dest = local_address(rx);
	const int flags[] = { MSG_OOB, MSG_ERRQUEUE };
	char byte;
	size_t i;

	send_packet(tx, &dest, "A", 1);
	wait_readable(rx);
	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		expect_error(recv(rx, &byte, 1, flags[i] | MSG_DONTWAIT),
			     EOPNOTSUPP, "unsupported receive flag");
		expect_inq(rx, 1);
	}
	recv_packet(rx, &byte, 1, 0, 1, false);
	if (byte != 'A')
		fail("unsupported flags consumed the normal packet");
	close(tx);
	close(rx);
}

void test_dgram_vmci_inq(const struct test_opts *opts)
{
	int rx = bound_socket(VMADDR_CID_ANY);
	int tx = bound_socket(VMADDR_CID_ANY);
	struct sockaddr_vm dest = sock_name(rx, false);
	char first[31], second[79], buf[80];

	memset(first, 'A', sizeof(first));
	memset(second, 'B', sizeof(second));
	/* CID_ANY is resolved by the dedicated transport to its local CID. */
	dest.svm_cid = VMADDR_CID_ANY;
	send_packet(tx, &dest, first, sizeof(first));
	send_packet(tx, &dest, second, sizeof(second));
	wait_readable(rx);
	expect_inq(rx, sizeof(first));
	recv_packet(rx, buf, sizeof(buf), 0, sizeof(first), false);
	if (memcmp(buf, first, sizeof(first)))
		fail("VMCI first payload mismatch");
	wait_readable(rx);
	expect_inq(rx, sizeof(second));
	recv_packet(rx, buf, sizeof(buf), 0, sizeof(second), false);
	if (memcmp(buf, second, sizeof(second)))
		fail("VMCI second payload mismatch");
	send_packet(tx, &dest, "", 0);
	wait_readable(rx);
	expect_inq(rx, 0);
	recv_packet(rx, buf, sizeof(buf), 0, 0, false);
	expect_empty(rx);
	close(tx);
	close(rx);
}

void test_dgram_filter(const struct test_opts *opts)
{
	struct sock_filter insn[] = { BPF_STMT(BPF_RET | BPF_K, 7) };
	struct sock_fprog prog = { .len = ARRAY_SIZE(insn), .filter = insn };
	int rx = bound_socket(VMADDR_CID_ANY);
	int tx = bound_socket(VMADDR_CID_ANY);
	struct sockaddr_vm dest = local_address(rx);
	char data[100], buf[100];

	memset(data, 'F', sizeof(data));
	check(setsockopt(rx, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)),
	      "SO_ATTACH_FILTER");
	send_packet(tx, &dest, data, sizeof(data));
	wait_readable(rx);
	expect_inq(rx, 7);
	recv_packet(rx, buf, 1, MSG_PEEK | MSG_TRUNC, 7, true);
	expect_inq(rx, 7);
	memset(buf, 0, sizeof(buf));
	recv_packet(rx, buf, sizeof(buf), MSG_TRUNC, 7, false);
	if (memcmp(buf, data, 7) || buf[7])
		fail("filtered receive copied beyond the filtered payload");
	send_packet(tx, &dest, data, sizeof(data));
	recv_packet(rx, buf, 1, MSG_TRUNC, 7, true);
	expect_empty(rx);
	close(tx);
	close(rx);
}

static void check_peer_filter(int rx, int allowed, int stray)
{
	struct sockaddr_vm dest = local_address(rx);
	char byte;

	/* Both packets use the same ordered loopback worker. */
	send_packet(stray, &dest, "B", 1);
	send_packet(allowed, &dest, "A", 1);
	recv_packet(rx, &byte, 1, 0, 1, false);
	if (byte != 'A')
		fail("connected socket accepted a different peer");
	expect_empty(rx);
}

void test_dgram_connect(const struct test_opts *opts)
{
	int rx = bound_socket(VMADDR_CID_ANY);
	int allowed = bound_socket(VMADDR_CID_ANY);
	int stray = bound_socket(VMADDR_CID_ANY);
	struct sockaddr_vm peer = local_address(allowed);
	struct sockaddr_vm dest = local_address(rx);
	char byte;

	connect_fd(rx, &peer);
	check_peer_filter(rx, allowed, stray);
	disconnect_fd(rx);
	send_packet(stray, &dest, "B", 1);
	recv_packet(rx, &byte, 1, 0, 1, false);
	if (byte != 'B')
		fail("disconnect did not remove peer filtering");
	connect_fd(rx, &peer);
	check(shutdown(rx, SHUT_WR), "shutdown SHUT_WR");
	if (poll_fd(rx, POLLOUT, 0) & POLLOUT)
		fail("write-shutdown socket is still writable");
	check_peer_filter(rx, allowed, stray);
	check(shutdown(rx, SHUT_RD), "shutdown SHUT_RD");
	if (!(poll_fd(rx, POLLIN | POLLRDHUP, 0) & POLLRDHUP))
		fail("read shutdown did not report POLLRDHUP");
	close(stray);
	close(allowed);
	close(rx);
}

void test_dgram_source_cid(const struct test_opts *opts)
{
	unsigned int cids[] = { VMADDR_CID_LOCAL, local_cid() };
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cids); i++) {
		int rx = bound_socket(VMADDR_CID_ANY);
		int tx = bound_socket(cids[i]);
		struct sockaddr_vm dest = local_address(rx);
		struct sockaddr_vm src;
		char byte;

		send_packet(tx, &dest, "A", 1);
		src = recv_packet(rx, &byte, 1, 0, 1, false);
		if (src.svm_cid != cids[i] || src.svm_flags ||
		    src.svm_port != sock_name(tx, false).svm_port)
			fail("explicit loopback source CID %u was not preserved", cids[i]);
		send_packet(rx, &src, "R", 1);
		recv_packet(tx, &byte, 1, 0, 1, false);
		if (byte != 'R')
			fail("reply to explicit source CID failed");
		close(tx);
		close(rx);
	}
}

void test_dgram_bound_lookup(const struct test_opts *opts)
{
	const int types[] = { SOCK_STREAM, SOCK_SEQPACKET };
	unsigned int cid = local_cid();
	size_t i;

	for (i = 0; i < ARRAY_SIZE(types); i++) {
		int listener = vsock_bind(VMADDR_CID_ANY, VMADDR_PORT_ANY, types[i]);
		int stream = vsock_bind(VMADDR_CID_LOCAL, VMADDR_PORT_ANY, types[i]);
		struct sockaddr_vm listen_addr = local_address(listener);
		struct sockaddr_vm src = sock_name(stream, false);
		struct sockaddr_vm dest;
		int accepted, tx, rx;
		char byte;

		check(listen(listener, 1), "listen");
		if (vsock_connect_fd(stream, listen_addr.svm_cid, listen_addr.svm_port))
			fail("%s loopback connect: %s",
			     types[i] == SOCK_STREAM ? "stream" : "seqpacket", strerror(errno));
		wait_readable(listener);
		accepted = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
		check(accepted, "accept");
		if (sock_name(accepted, true).svm_cid != VMADDR_CID_LOCAL ||
		    sock_name(accepted, true).svm_port != src.svm_port)
			fail("unexpected accepted loopback peer");
		close(listener);
		rx = dgram_socket();
		bind_fd(rx, cid, src.svm_port);
		dest = sock_name(rx, false);
		tx = dgram_socket();
		/* Reuse the listener's port for the datagram source. The receive
		 * socket uses the stream client's port at another local CID.
		 * Connected lookup ignores the destination CID, so it would find
		 * the stream client before the bound datagram socket.
		 */
		bind_fd(tx, VMADDR_CID_LOCAL, listen_addr.svm_port);
		send_packet(tx, &dest, "D", 1);
		recv_packet(rx, &byte, 1, 0, 1, false);
		if (byte != 'D' || (poll_fd(stream, POLLIN, 0) & POLLIN) ||
		    (poll_fd(accepted, POLLIN, 0) & POLLIN))
			fail("connected socket shadowed the reused datagram port");
		send_byte(stream, 1, 0);
		wait_readable(accepted);
		recv_byte(accepted, 1, 0);
		send_byte(accepted, 1, 0);
		wait_readable(stream);
		recv_byte(stream, 1, 0);
		close(tx);
		close(rx);
		close(accepted);
		close(stream);
	}
}

void test_dgram_sockmap(const struct test_opts *opts)
{
	const int types[] = { BPF_MAP_TYPE_SOCKMAP, BPF_MAP_TYPE_SOCKHASH };
	int fd = bound_socket(VMADDR_CID_ANY);
	struct sockaddr_vm addr = local_address(fd);
	uint64_t value = fd;
	uint32_t key = 0;
	size_t i;

	connect_fd(fd, &addr);
	for (i = 0; i < ARRAY_SIZE(types); i++) {
		union bpf_attr attr = {
			.map_type = types[i],
			.key_size = sizeof(key),
			.value_size = sizeof(value),
			.max_entries = 1,
		};
		int map = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));

		check(map, "BPF_MAP_CREATE (requires BPF privileges and CONFIG_BPF_SYSCALL)");
		memset(&attr, 0, sizeof(attr));
		attr.map_fd = map;
		attr.key = (uintptr_t)&key;
		attr.value = (uintptr_t)&value;
		attr.flags = BPF_ANY;
		expect_error(syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)),
			     EOPNOTSUPP, "datagram sockmap admission");
		close(map);
	}
	close(fd);
}

void test_dgram_nested_source(const struct test_opts *opts)
{
	int rx, tx;
	struct sockaddr_vm dest;

	if (local_cid() <= VMADDR_CID_HOST)
		fail("this test requires both a guest frontend and vhost_vsock");
	rx = bound_socket(VMADDR_CID_LOCAL);
	tx = bound_socket(VMADDR_CID_HOST);
	dest = local_address(rx);
	expect_error(sendto(tx, "A", 1, MSG_NOSIGNAL,
			    (struct sockaddr *)&dest, sizeof(dest)),
		     EADDRNOTAVAIL, "nested CID_HOST loopback send");
	expect_error(connect(tx, (struct sockaddr *)&dest, sizeof(dest)),
		     EADDRNOTAVAIL, "nested CID_HOST loopback connect");
	if (queue_bytes(tx, SIOCOUTQ))
		fail("rejected route left pending output");
	expect_empty(rx);
	close(tx);
	close(rx);
}

static int peer_socket(const struct test_opts *opts, struct sockaddr_vm *peer)
{
	int fd = bound_socket(opts->bind_cid);

	control_writeulong(sock_name(fd, false).svm_port);
	*peer = address(opts->peer_cid, control_readulong());
	if (opts->to_host)
		peer->svm_flags = VMADDR_FLAG_TO_HOST;
	return fd;
}

static void check_source(const struct test_opts *opts,
			 const struct sockaddr_vm *peer, const struct sockaddr_vm *src)
{
	bool upstream = opts->expect_to_host || opts->peer_cid == VMADDR_CID_HOST;

	if (src->svm_cid != peer->svm_cid || src->svm_port != peer->svm_port ||
	    src->svm_flags != (upstream ? VMADDR_FLAG_TO_HOST : 0))
		fail("source expected %u:%u flags=%u, got %u:%u flags=%u",
		     peer->svm_cid, peer->svm_port, upstream ? VMADDR_FLAG_TO_HOST : 0,
		     src->svm_cid, src->svm_port, src->svm_flags);
}

static void fill_payload(char *buf, size_t len, unsigned int seed)
{
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = (i * 131 + seed) & 0xff;
}

void test_dgram_sizes(const struct test_opts *opts)
{
	const size_t sizes[] = { 0, 1, 7, 255, 4095, 4096, 4097,
				8192, 32768, 65535, MAX_DGRAM };
	char *data = malloc(MAX_DGRAM + 1);
	char *buf = malloc(MAX_DGRAM + 1);
	struct sockaddr_vm peer, src;
	unsigned int round;
	int fd;
	size_t i;

	if (!data || !buf)
		fail("malloc");
	fd = peer_socket(opts, &peer);
	fill_payload(data, MAX_DGRAM + 1, 0);
	expect_error(sendto(fd, data, MAX_DGRAM + 1, MSG_NOSIGNAL,
			    (struct sockaddr *)&peer, sizeof(peer)),
		     EMSGSIZE, "oversized datagram");
	if (queue_bytes(fd, SIOCOUTQ))
		fail("oversized datagram left pending output");
	/* More than a default RX ring's worth, including on small rings. */
	for (round = 0; round < 32; round++) {
		for (i = 0; i < ARRAY_SIZE(sizes); i++) {
			fill_payload(data, sizes[i], round * ARRAY_SIZE(sizes) + i);
			if (opts->mode == TEST_MODE_CLIENT)
				send_packet(fd, &peer, data, sizes[i]);
			src = recv_packet(fd, buf, MAX_DGRAM + 1, 0, sizes[i], false);
			check_source(opts, &peer, &src);
			if (memcmp(data, buf, sizes[i]))
				fail("payload mismatch: size %zu, round %u", sizes[i], round);
			if (opts->mode == TEST_MODE_SERVER)
				send_packet(fd, &src, buf, sizes[i]);
		}
	}
	wait_sent(fd);
	expect_empty(fd);
	close(fd);
	free(buf);
	free(data);
}

void test_dgram_routes(const struct test_opts *opts)
{
	struct sockaddr_vm peer, src, stored, local;
	int fd = peer_socket(opts, &peer);
	int aux = bound_socket(VMADDR_CID_ANY);
	unsigned int round;
	char byte;

	connect_fd(fd, &peer);
	stored = sock_name(fd, true);
	local = local_address(aux);
	for (round = 0; round < 32; round++) {
		send_packet(fd, &local, "L", 1);
		recv_packet(aux, &byte, 1, 0, 1, false);
		if (byte != 'L')
			fail("sendto on a connected socket did not use loopback");
		src = sock_name(fd, true);
		if (src.svm_cid != stored.svm_cid || src.svm_port != stored.svm_port ||
		    src.svm_flags != stored.svm_flags)
			fail("per-message route changed the connected peer");
		send_packet(fd, NULL, "P", 1);
		src = recv_packet(fd, &byte, 1, 0, 1, false);
		check_source(opts, &peer, &src);
		if (byte != 'P')
			fail("connected send did not retain the peer route");
	}
	wait_sent(fd);
	close(aux);
	close(fd);
}

void test_dgram_peer_filter(const struct test_opts *opts)
{
	struct sockaddr_vm peer, src;
	int fd = peer_socket(opts, &peer);
	int stray = bound_socket(opts->bind_cid);
	char byte;

	connect_fd(fd, &peer);
	control_writeln("CONNECTED");
	control_expectln("CONNECTED");
	send_packet(stray, &peer, "B", 1);
	send_packet(fd, NULL, "A", 1);
	src = recv_packet(fd, &byte, 1, 0, 1, false);
	check_source(opts, &peer, &src);
	if (byte != 'A')
		fail("connected socket accepted a different peer port");
	disconnect_fd(fd);
	control_writeln("DISCONNECTED");
	control_expectln("DISCONNECTED");
	send_packet(stray, &peer, "B", 1);
	src = recv_packet(fd, &byte, 1, 0, 1, false);
	if (byte != 'B' || src.svm_cid != peer.svm_cid || src.svm_port == peer.svm_port)
		fail("disconnected socket did not accept the new peer");
	close(stray);
	close(fd);
}
