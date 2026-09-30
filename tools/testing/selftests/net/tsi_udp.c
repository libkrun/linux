// SPDX-License-Identifier: GPL-2.0-only
/* VMM INET impersonation enabled, guest tsi_hijack=0. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include "../kselftest_harness.h"
#include "tsi_test.h"

FIXTURE(tsi_udp)
{
	int client;
	int receiver;
	int other;
	struct sockaddr_storage addr;
	struct sockaddr_storage addr2;
	socklen_t addr_len;
};

FIXTURE_VARIANT(tsi_udp)
{
	int family;
	bool tsi;
	bool proxy;
	bool receiver_tsi;
};

FIXTURE_VARIANT_ADD(tsi_udp, native_ipv4) { .family = AF_INET };
FIXTURE_VARIANT_ADD(tsi_udp, native_ipv6) { .family = AF_INET6 };
FIXTURE_VARIANT_ADD(tsi_udp, tsi_ipv4) { .family = AF_INET, .tsi = true };
FIXTURE_VARIANT_ADD(tsi_udp, tsi_ipv6) { .family = AF_INET6, .tsi = true };
FIXTURE_VARIANT_ADD(tsi_udp, ipc_ipv4) {
	.family = AF_INET, .tsi = true, .receiver_tsi = true,
};
FIXTURE_VARIANT_ADD(tsi_udp, ipc_ipv6) {
	.family = AF_INET6, .tsi = true, .receiver_tsi = true,
};
FIXTURE_VARIANT_ADD(tsi_udp, proxy_ipv4) {
	.family = AF_INET, .tsi = true, .proxy = true,
};
FIXTURE_VARIANT_ADD(tsi_udp, proxy_ipv6) {
	.family = AF_INET6, .tsi = true, .proxy = true,
};

FIXTURE_SETUP(tsi_udp)
{
	struct sockaddr_in6 *addr6 = (void *)&self->addr;
	struct sockaddr_in *addr4 = (void *)&self->addr;
	int family = variant->family;
	FILE *param;

	self->client = -1;
	self->receiver = -1;
	self->other = -1;
	param = fopen("/sys/module/kernel/parameters/tsi_hijack", "r");
	if (param) {
		int enabled = fgetc(param);

		fclose(param);
		if (enabled == 'Y' || enabled == '1')
			SKIP(return, "native controls require tsi_hijack=0");
	}
	if (variant->tsi)
		family = family == AF_INET ? AF_TSI : AF_TSI6;
	self->client = socket(family, SOCK_DGRAM, 0);
	if (self->client < 0 && errno == EAFNOSUPPORT)
		SKIP(return, "socket family unavailable");
	ASSERT_GE(self->client, 0);
	self->receiver = socket(variant->receiver_tsi ? family : variant->family,
				SOCK_DGRAM, 0);
	ASSERT_GE(self->receiver, 0);
	if (variant->family == AF_INET) {
		addr4->sin_family = AF_INET;
		addr4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		self->addr_len = sizeof(*addr4);
	} else {
		addr6->sin6_family = AF_INET6;
		addr6->sin6_addr = in6addr_loopback;
		self->addr_len = sizeof(*addr6);
	}
	ASSERT_EQ(bind(self->receiver, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(getsockname(self->receiver, (void *)&self->addr,
			      &self->addr_len), 0);
	self->addr2 = self->addr;
	if (variant->family == AF_INET)
		((struct sockaddr_in *)&self->addr2)->sin_port = 0;
	else
		((struct sockaddr_in6 *)&self->addr2)->sin6_port = 0;
	self->other = socket(variant->receiver_tsi ? family : variant->family,
			     SOCK_DGRAM, 0);
	ASSERT_GE(self->other, 0);
	ASSERT_EQ(bind(self->other, (void *)&self->addr2, self->addr_len), 0);
	ASSERT_EQ(getsockname(self->other, (void *)&self->addr2,
			      &self->addr_len), 0);
	if (variant->proxy) {
		unsigned int ports[4], base = variant->family == AF_INET ? 0 : 2;
		const char *env = getenv("TSI_UDP_PORTS");
		int parsed;

		if (!env)
			SKIP(return, "set TSI_UDP_PORTS from the VMM host tsi_udp_server");
		parsed = sscanf(env, "%u,%u,%u,%u", &ports[0], &ports[1],
				&ports[2], &ports[3]);
		ASSERT_EQ(parsed, 4);
		if (variant->family == AF_INET) {
			((struct sockaddr_in *)&self->addr)->sin_port = htons(ports[base]);
			((struct sockaddr_in *)&self->addr2)->sin_port = htons(ports[base + 1]);
		} else {
			((struct sockaddr_in6 *)&self->addr)->sin6_port = htons(ports[base]);
			((struct sockaddr_in6 *)&self->addr2)->sin6_port = htons(ports[base + 1]);
		}
	}
}

FIXTURE_TEARDOWN(tsi_udp)
{
	if (self->client >= 0)
		close(self->client);
	if (self->receiver >= 0)
		close(self->receiver);
	if (self->other >= 0)
		close(self->other);
}

TEST_F_TIMEOUT(tsi_udp, repeated_sendto, 5)
{
	struct pollfd pfd = { .fd = self->receiver, .events = POLLIN };
	unsigned char data[] = { 0, 'U' }, received[2];
	int i;

	if (variant->proxy)
		pfd.fd = self->client;
	/* Repeated lookups must not consume the receiver's socket reference. */
	for (i = 0; i < 100; i++) {
		ASSERT_EQ(sendto(self->client, data, sizeof(data), 0,
				 (void *)&self->addr, self->addr_len), (ssize_t)sizeof(data));
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recv(pfd.fd, received, sizeof(received), 0),
			  (ssize_t)sizeof(received));
		EXPECT_EQ(memcmp(data, received, sizeof(data)), 0);
	}
}

static void delivered_from(struct __test_metadata *_metadata, int client,
			   int receiver, int reply_socket, int destination,
			   struct sockaddr_storage *expected, socklen_t expected_len)
{
	struct sockaddr_storage source;
	socklen_t len = sizeof(source);
	struct pollfd pfd = { .events = POLLIN };
	unsigned char data[2];

	if (receiver >= 0) {
		pfd.fd = receiver;
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recvfrom(receiver, data, sizeof(data), 0,
				   (void *)&source, &len), (ssize_t)sizeof(data));
		data[0] = destination;
		ASSERT_EQ(sendto(reply_socket, data, sizeof(data), 0,
				 (void *)&source, len), (ssize_t)sizeof(data));
	}
	pfd.fd = client;
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	len = sizeof(source);
	ASSERT_EQ(recvfrom(client, data, sizeof(data), 0,
			   (void *)&source, &len), (ssize_t)sizeof(data));
	EXPECT_EQ(data[0], destination);
	EXPECT_EQ(data[1], 'U');
	if (expected) {
		EXPECT_EQ(len, expected_len);
		EXPECT_EQ(memcmp(&source, expected, expected_len), 0);
	}
}

static void delivered(struct __test_metadata *_metadata, int client,
		      int receiver, int reply_socket, int destination)
{
	delivered_from(_metadata, client, receiver, reply_socket, destination, NULL, 0);
}

static void peer_is(struct __test_metadata *_metadata, int fd,
		    struct sockaddr_storage *expected, socklen_t expected_len)
{
	struct sockaddr_storage addr = {};
	socklen_t len = sizeof(addr);

	ASSERT_EQ(getpeername(fd, (void *)&addr, &len), 0);
	EXPECT_EQ(len, expected_len);
	EXPECT_EQ(memcmp(&addr, expected, expected_len), 0);
}

TEST_F_TIMEOUT(tsi_udp, connected_send, 5)
{
	unsigned char data[] = { 0, 'U' };

	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	peer_is(_metadata, self->client, &self->addr, self->addr_len);
	ASSERT_EQ(send(self->client, data, sizeof(data), 0), (ssize_t)sizeof(data));
	delivered(_metadata, self->client, variant->proxy ? -1 : self->receiver,
		  self->receiver, 0);
}

TEST_F_TIMEOUT(tsi_udp, connected_write, 5)
{
	unsigned char data[] = { 0, 'U' };

	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(write(self->client, data, sizeof(data)), (ssize_t)sizeof(data));
	delivered(_metadata, self->client, variant->proxy ? -1 : self->receiver,
		  self->receiver, 0);
}

TEST_F_TIMEOUT(tsi_udp, sendto_preserves_default, 5)
{
	unsigned char data[] = { 0, 'U' };

	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(sendto(self->client, data, sizeof(data), 0,
			 (void *)&self->addr2, self->addr_len), (ssize_t)sizeof(data));
	delivered_from(_metadata, self->client, variant->proxy ? -1 : self->other,
		       self->receiver, 1, &self->addr, self->addr_len);
	peer_is(_metadata, self->client, &self->addr, self->addr_len);
	ASSERT_EQ(send(self->client, data, sizeof(data), 0), (ssize_t)sizeof(data));
	delivered(_metadata, self->client, variant->proxy ? -1 : self->receiver,
		  self->receiver, 0);
}

TEST_F_TIMEOUT(tsi_udp, sendto_does_not_connect, 5)
{
	struct sockaddr_storage peer;
	socklen_t len = sizeof(peer);
	unsigned char data[] = { 0, 'U' };

	ASSERT_EQ(sendto(self->client, data, sizeof(data), 0,
			 (void *)&self->addr, self->addr_len), (ssize_t)sizeof(data));
	delivered(_metadata, self->client, variant->proxy ? -1 : self->receiver,
		  self->receiver, 0);
	EXPECT_EQ(getpeername(self->client, (void *)&peer, &len), -1);
	EXPECT_EQ(errno, ENOTCONN);
	EXPECT_EQ(send(self->client, data, sizeof(data), 0), -1);
	EXPECT_EQ(errno, EDESTADDRREQ);
}

TEST_F_TIMEOUT(tsi_udp, reconnect, 5)
{
	unsigned char data[] = { 0, 'U' };

	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(send(self->client, data, sizeof(data), 0), (ssize_t)sizeof(data));
	delivered(_metadata, self->client, variant->proxy ? -1 : self->receiver,
		  self->receiver, 0);
	ASSERT_EQ(connect(self->client, (void *)&self->addr2, self->addr_len), 0);
	peer_is(_metadata, self->client, &self->addr2, self->addr_len);
	data[0] = 1;
	ASSERT_EQ(send(self->client, data, sizeof(data), 0), (ssize_t)sizeof(data));
	delivered(_metadata, self->client, variant->proxy ? -1 : self->other,
		  self->other, 1);
}

TEST_F_TIMEOUT(tsi_udp, failed_reconnect_preserves_peer, 5)
{
	struct sockaddr_storage invalid = self->addr2;
	unsigned char data[] = { 0, 'U' };

	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	invalid.ss_family = AF_UNIX;
	EXPECT_EQ(connect(self->client, (void *)&invalid, self->addr_len), -1);
	peer_is(_metadata, self->client, &self->addr, self->addr_len);
	EXPECT_EQ(connect(self->client, (void *)&self->addr2, 1), -1);
	peer_is(_metadata, self->client, &self->addr, self->addr_len);
	ASSERT_EQ(send(self->client, data, sizeof(data), 0), (ssize_t)sizeof(data));
	delivered(_metadata, self->client, variant->proxy ? -1 : self->receiver,
		  self->receiver, 0);
}

TEST_F_TIMEOUT(tsi_udp, zero_length_sendto, 5)
{
	struct pollfd pfd = { .fd = self->client, .events = POLLIN };
	struct sockaddr_storage source;
	socklen_t len = sizeof(source);
	unsigned char byte;

	ASSERT_EQ(sendto(self->client, "", 0, 0, (void *)&self->addr,
			 self->addr_len), 0);
	if (!variant->proxy) {
		pfd.fd = self->receiver;
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recvfrom(self->receiver, &byte, 1, 0,
				   (void *)&source, &len), 0);
		ASSERT_EQ(sendto(self->receiver, "", 0, 0, (void *)&source, len), 0);
	}
	pfd.fd = self->client;
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	len = sizeof(source);
	ASSERT_EQ(recvfrom(self->client, &byte, 1, 0, (void *)&source, &len), 0);
	EXPECT_EQ(len, self->addr_len);
	EXPECT_EQ(memcmp(&source, &self->addr, len), 0);
}

static void echo_guest(struct __test_metadata *_metadata, int receiver)
{
	struct sockaddr_storage source;
	socklen_t len = sizeof(source);
	struct pollfd pfd = { .fd = receiver, .events = POLLIN };
	unsigned char data[2];

	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_EQ(recvfrom(receiver, data, sizeof(data), 0,
			   (void *)&source, &len), (ssize_t)sizeof(data));
	ASSERT_EQ(sendto(receiver, data, sizeof(data), 0,
			 (void *)&source, len), (ssize_t)sizeof(data));
}

TEST_F_TIMEOUT(tsi_udp, two_peer_senders, 5)
{
	struct sockaddr_storage *peers[] = { &self->addr, &self->addr2 };
	int receivers[] = { self->receiver, self->other };
	struct pollfd pfd = { .fd = self->client, .events = POLLIN };
	int order, i;

	for (order = 0; order < 2; order++) {
		for (i = 0; i < 2; i++) {
			int peer = i ^ order;
			unsigned char data[] = { peer, 'U' };

			ASSERT_EQ(sendto(self->client, data, sizeof(data), 0,
					 (void *)peers[peer], self->addr_len),
				  (ssize_t)sizeof(data));
			if (!variant->proxy)
				echo_guest(_metadata, receivers[peer]);
			ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		}
		for (i = 0; i < 2; i++) {
			struct sockaddr_storage source;
			socklen_t len = sizeof(source);
			unsigned char data[2];
			int peer = i ^ order;

			ASSERT_EQ(poll(&pfd, 1, 1000), 1);
			ASSERT_EQ(recvfrom(self->client, data, sizeof(data), 0,
					   (void *)&source, &len), (ssize_t)sizeof(data));
			EXPECT_EQ(data[0], peer);
			EXPECT_EQ(data[1], 'U');
			EXPECT_EQ(len, self->addr_len);
			EXPECT_EQ(memcmp(&source, peers[peer], len), 0);
		}
	}
}

TEST_F_TIMEOUT(tsi_udp, peek_and_truncate, 5)
{
	struct sockaddr_storage source;
	struct pollfd pfd = { .fd = self->client, .events = POLLIN };
	unsigned char data[] = { 0, 'U' }, byte;
	struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
	struct msghdr msg = { .msg_name = &source, .msg_iov = &iov, .msg_iovlen = 1 };
	int i;

	ASSERT_EQ(sendto(self->client, data, sizeof(data), 0,
			 (void *)&self->addr, self->addr_len), (ssize_t)sizeof(data));
	if (!variant->proxy)
		echo_guest(_metadata, self->receiver);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	for (i = 0; i < 3; i++) {
		int flags = i < 2 ? MSG_PEEK : 0;

		if (i)
			flags |= MSG_TRUNC;
		if (i == 2)
			iov.iov_len = 0;
		msg.msg_namelen = sizeof(source);
		msg.msg_flags = 0;
		ASSERT_EQ(recvmsg(self->client, &msg, flags), i ? 2 : 1);
		EXPECT_TRUE(msg.msg_flags & MSG_TRUNC);
		EXPECT_EQ(msg.msg_namelen, self->addr_len);
		EXPECT_EQ(memcmp(&source, &self->addr, self->addr_len), 0);
	}
	EXPECT_EQ(recv(self->client, &byte, 1, MSG_DONTWAIT), -1);
	EXPECT_EQ(errno, EAGAIN);
}

TEST_F_TIMEOUT(tsi_udp, datagram_size_limit, 5)
{
	const size_t limit = 65536 - 168;
	unsigned char *data = malloc(limit + 1), *received = malloc(limit + 1);
	struct pollfd pfd = { .events = POLLIN };
	struct sockaddr_storage source;
	socklen_t addr_len;
	size_t len;

	ASSERT_NE(data, NULL);
	ASSERT_NE(received, NULL);
	memset(data, 'U', limit + 1);
	data[0] = 0;
	for (len = limit; len <= limit + 1; len++) {
		if (variant->proxy && len > limit) {
			EXPECT_EQ(sendto(self->client, data, len, 0,
					 (void *)&self->addr, self->addr_len), -1);
			EXPECT_EQ(errno, EMSGSIZE);
			continue;
		}
		ASSERT_EQ(sendto(self->client, data, len, 0,
				 (void *)&self->addr, self->addr_len), (ssize_t)len);
		if (!variant->proxy) {
			pfd.fd = self->receiver;
			ASSERT_EQ(poll(&pfd, 1, 1000), 1);
			addr_len = sizeof(source);
			ASSERT_EQ(recvfrom(self->receiver, received, len, 0,
					   (void *)&source, &addr_len), (ssize_t)len);
			ASSERT_EQ(sendto(self->receiver, received, len, 0,
					 (void *)&source, addr_len), (ssize_t)len);
		}
		pfd.fd = self->client;
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recv(self->client, received, len, 0), (ssize_t)len);
		EXPECT_EQ(memcmp(data, received, len), 0);
	}
	free(received);
	free(data);
}

TEST_F_TIMEOUT(tsi_udp, connected_receiver, 5)
{
	struct sockaddr_storage local, source;
	socklen_t len = sizeof(local);
	unsigned char data[] = { 0, 'U' };

	/* Use the guest receiver even for variants with host peers available. */
	ASSERT_EQ(getsockname(self->receiver, (void *)&local, &len), 0);
	ASSERT_EQ(connect(self->client, (void *)&local, len), 0);
	len = sizeof(source);
	ASSERT_EQ(getsockname(self->client, (void *)&source, &len), 0);
	ASSERT_EQ(connect(self->receiver, (void *)&source, len), 0);
	ASSERT_EQ(connect(self->client, (void *)&local, len), 0);
	ASSERT_EQ(send(self->client, data, sizeof(data), 0), (ssize_t)sizeof(data));
	delivered(_metadata, self->client, self->receiver, self->receiver, 0);
}

TEST_F_TIMEOUT(tsi_udp, local_send_error, 5)
{
	struct sockaddr_storage local;
	socklen_t len = sizeof(local);
	unsigned char data[] = { 0, 'U' };

	ASSERT_EQ(getsockname(self->receiver, (void *)&local, &len), 0);
	ASSERT_EQ(tsi_force_proxy(self->client), 0);
	/* A guest delivery error must not be retried on the host. */
	EXPECT_EQ(sendto(self->client, data, sizeof(data), 0,
			 (void *)&local, len), -1);
}

TEST_F_TIMEOUT(tsi_udp, host_then_guest, 5)
{
	struct sockaddr_storage local, host = self->addr;
	socklen_t len = sizeof(local);
	unsigned char data[] = { 0, 'U' };
	int i;

	ASSERT_EQ(getsockname(self->receiver, (void *)&local, &len), 0);
	/* Native controls use two guest sockets; TSI variants use both stacks. */
	if (!variant->proxy)
		host = self->addr2;
	for (i = 0; i < 4; i++) {
		bool remote = variant->proxy && !(i % 2);
		struct sockaddr_storage *addr = i % 2 ? &local : &host;
		int receiver = i % 2 ? self->receiver : self->other;

		if (variant->proxy && !(i % 2))
			receiver = -1;
		ASSERT_EQ(sendto(self->client, data, sizeof(data), 0,
				 (void *)addr, len), (ssize_t)sizeof(data));
		delivered(_metadata, self->client, receiver,
			  i % 2 ? self->receiver : self->other,
			  remote || i % 2 ? 0 : 1);
	}
}

TEST_F_TIMEOUT(tsi_udp, queued_guest_and_host, 5)
{
	struct sockaddr_storage local, client_addr, remote = self->addr;
	struct pollfd pfd = { .events = POLLIN };
	socklen_t len = sizeof(local);
	unsigned char data[] = { 0, 'U' };
	int i, seen = 0;

	ASSERT_EQ(getsockname(self->receiver, (void *)&local, &len), 0);
	client_addr = local;
	if (variant->family == AF_INET)
		((struct sockaddr_in *)&client_addr)->sin_port = 0;
	else
		((struct sockaddr_in6 *)&client_addr)->sin6_port = 0;
	ASSERT_EQ(bind(self->client, (void *)&client_addr, len), 0);
	ASSERT_EQ(getsockname(self->client, (void *)&client_addr, &len), 0);
	if (!variant->proxy)
		remote = self->addr2;
	ASSERT_EQ(sendto(self->client, data, sizeof(data), 0,
			 (void *)&remote, len), (ssize_t)sizeof(data));
	if (!variant->proxy) {
		pfd.fd = self->other;
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recv(self->other, data, sizeof(data), 0), (ssize_t)sizeof(data));
		ASSERT_EQ(sendto(self->other, data, sizeof(data), 0,
				 (void *)&client_addr, len), (ssize_t)sizeof(data));
	}
	data[0] = 1;
	ASSERT_EQ(sendto(self->receiver, data, sizeof(data), 0,
			 (void *)&client_addr, len), (ssize_t)sizeof(data));
	pfd.fd = self->client;
	for (i = 0; i < 2; i++) {
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recv(self->client, data, sizeof(data), 0), (ssize_t)sizeof(data));
		ASSERT_LT(data[0], 2);
		EXPECT_EQ(data[1], 'U');
		seen |= 1 << data[0];
	}
	EXPECT_EQ(seen, 3);
}

struct receiver_thread {
	int fd;
	ssize_t result;
	pid_t tid;
	unsigned char data[2];
	pthread_barrier_t barrier;
};

static void *receive_reply(void *arg)
{
	struct receiver_thread *reader = arg;

	reader->tid = gettid();
	pthread_barrier_wait(&reader->barrier);
	reader->result = recv(reader->fd, reader->data, sizeof(reader->data), 0);
	return NULL;
}

static void reader_waiting(struct __test_metadata *_metadata, pid_t tid)
{
	char path[80];
	FILE *file;
	long nr = -1;
	int i;

	snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", tid);
	for (i = 0; i < 1000; i++) {
		file = fopen(path, "r");
		ASSERT_NE(file, NULL);
		if (fscanf(file, "%ld", &nr) != 1)
			nr = -1;
		fclose(file);
		if (nr == SYS_recvfrom)
			return;
		usleep(1000);
	}
	ASSERT_EQ(nr, SYS_recvfrom);
}

TEST_F_TIMEOUT(tsi_udp, receive_allows_send, 5)
{
	struct receiver_thread reader = { .fd = self->client };
	struct pollfd pfd = { .fd = self->receiver, .events = POLLIN };
	struct sockaddr_storage source;
	socklen_t len = sizeof(source);
	unsigned char data[] = { 0, 'U' };
	pthread_t thread;

	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(pthread_barrier_init(&reader.barrier, NULL, 2), 0);
	ASSERT_EQ(pthread_create(&thread, NULL, receive_reply, &reader), 0);
	pthread_barrier_wait(&reader.barrier);
	reader_waiting(_metadata, reader.tid);
	ASSERT_EQ(send(self->client, data, sizeof(data), 0), (ssize_t)sizeof(data));
	if (!variant->proxy) {
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recvfrom(self->receiver, data, sizeof(data), 0,
				   (void *)&source, &len), (ssize_t)sizeof(data));
		ASSERT_EQ(sendto(self->receiver, data, sizeof(data), 0,
				 (void *)&source, len), (ssize_t)sizeof(data));
	}
	ASSERT_EQ(pthread_join(thread, NULL), 0);
	EXPECT_EQ(reader.result, (ssize_t)sizeof(data));
	EXPECT_EQ(memcmp(reader.data, data, sizeof(data)), 0);
	pthread_barrier_destroy(&reader.barrier);
}

TEST_F_TIMEOUT(tsi_udp, shutdown_wakes_receive, 5)
{
	struct receiver_thread reader = { .fd = self->client };
	pthread_t thread;

	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(pthread_barrier_init(&reader.barrier, NULL, 2), 0);
	ASSERT_EQ(pthread_create(&thread, NULL, receive_reply, &reader), 0);
	pthread_barrier_wait(&reader.barrier);
	reader_waiting(_metadata, reader.tid);
	ASSERT_EQ(shutdown(self->client, SHUT_RD), 0);
	ASSERT_EQ(pthread_join(thread, NULL), 0);
	EXPECT_EQ(reader.result, 0);
	pthread_barrier_destroy(&reader.barrier);
}

TEST_F_TIMEOUT(tsi_udp, write_shutdown, 5)
{
	unsigned char data[] = { 0, 'U' };

	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(shutdown(self->client, SHUT_WR), 0);
	EXPECT_EQ(send(self->client, data, sizeof(data), MSG_NOSIGNAL), -1);
	EXPECT_EQ(errno, EPIPE);
}

TEST_F_TIMEOUT(tsi_udp, timeout_after_connect, 3)
{
	struct timeval timeout = { .tv_usec = 100000 }, observed = {};
	socklen_t len = sizeof(observed);
	char byte;

	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(setsockopt(self->client, SOL_SOCKET, SO_RCVTIMEO,
			     &timeout, sizeof(timeout)), 0);
	ASSERT_EQ(getsockopt(self->client, SOL_SOCKET, SO_RCVTIMEO,
			     &observed, &len), 0);
	EXPECT_EQ(observed.tv_sec, timeout.tv_sec);
	EXPECT_EQ(observed.tv_usec, timeout.tv_usec);
	ASSERT_EQ(setsockopt(self->client, SOL_SOCKET, SO_SNDTIMEO,
			     &timeout, sizeof(timeout)), 0);
	len = sizeof(observed);
	ASSERT_EQ(getsockopt(self->client, SOL_SOCKET, SO_SNDTIMEO,
			     &observed, &len), 0);
	EXPECT_EQ(observed.tv_sec, timeout.tv_sec);
	EXPECT_EQ(observed.tv_usec, timeout.tv_usec);
	EXPECT_EQ(recv(self->client, &byte, sizeof(byte), 0), -1);
	EXPECT_EQ(errno, EAGAIN);
}

static void check_udp_local_name(struct __test_metadata *_metadata,
				int client, int receiver,
				struct sockaddr_storage *destination,
				socklen_t addr_len, bool connected)
{
	unsigned char data[2 + sizeof(struct sockaddr_in6)] = { 0, 'N' };
	struct sockaddr_storage observed = {}, local = {};
	socklen_t len = sizeof(local);
	struct pollfd pfd = { .events = POLLIN };
	ssize_t size = 2 + addr_len;
	uint16_t observed_port, local_port;

	if (connected) {
		ASSERT_EQ(connect(client, (void *)destination, addr_len), 0);
		ASSERT_EQ(send(client, data, size, 0), size);
	} else {
		ASSERT_EQ(sendto(client, data, size, 0,
				 (void *)destination, addr_len), size);
	}
	if (receiver >= 0) {
		pfd.fd = receiver;
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recvfrom(receiver, data, sizeof(data), 0,
				   (void *)&observed, &len), size);
		memcpy(data + 2, &observed, len);
		ASSERT_EQ(sendto(receiver, data, size, 0, (void *)&observed, len), size);
	}
	pfd.fd = client;
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_EQ(recv(client, data, sizeof(data), 0), size);
	memcpy(&observed, data + 2, addr_len);
	len = sizeof(local);
	ASSERT_EQ(getsockname(client, (void *)&local, &len), 0);
	ASSERT_EQ(len, addr_len);
	if (connected) {
		EXPECT_EQ(memcmp(&local, &observed, len), 0);
	} else {
		if (local.ss_family == AF_INET) {
			local_port = ((struct sockaddr_in *)&local)->sin_port;
			observed_port = ((struct sockaddr_in *)&observed)->sin_port;
		} else {
			local_port = ((struct sockaddr_in6 *)&local)->sin6_port;
			observed_port = ((struct sockaddr_in6 *)&observed)->sin6_port;
		}
		EXPECT_NE(local_port, 0);
		EXPECT_EQ(local_port, observed_port);
	}
}

TEST_F_TIMEOUT(tsi_udp, connected_local_name, 5)
{
	check_udp_local_name(_metadata, self->client,
		variant->proxy ? -1 : self->receiver,
		&self->addr, self->addr_len, true);
}

TEST_F_TIMEOUT(tsi_udp, unconnected_local_name, 5)
{
	check_udp_local_name(_metadata, self->client,
		variant->proxy ? -1 : self->receiver,
		&self->addr, self->addr_len, false);
}

TEST_F_TIMEOUT(tsi_udp, disconnect, 5)
{
	struct sockaddr unspec = { .sa_family = AF_UNSPEC };
	struct sockaddr_storage peer;
	socklen_t len = sizeof(peer);
	unsigned char data[] = { 0, 'U' };

	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(connect(self->client, &unspec, sizeof(unspec)), 0);
	EXPECT_EQ(getpeername(self->client, (void *)&peer, &len), -1);
	EXPECT_EQ(errno, ENOTCONN);
	EXPECT_EQ(send(self->client, data, sizeof(data), 0), -1);
	EXPECT_EQ(errno, EDESTADDRREQ);
	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(send(self->client, data, sizeof(data), 0), (ssize_t)sizeof(data));
	delivered(_metadata, self->client, variant->proxy ? -1 : self->receiver,
		  self->receiver, 0);
}

TEST_F_TIMEOUT(tsi_udp, disconnect_then_sendto, 5)
{
	struct sockaddr unspec = { .sa_family = AF_UNSPEC };
	unsigned char data[] = { 1, 'U' };

	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(connect(self->client, &unspec, sizeof(unspec)), 0);
	ASSERT_EQ(sendto(self->client, data, sizeof(data), 0,
			 (void *)&self->addr2, self->addr_len), (ssize_t)sizeof(data));
	/* An unconnected host socket accepts the response from the other peer. */
	delivered_from(_metadata, self->client, variant->proxy ? -1 : self->other,
		       self->other, 1, &self->addr2, self->addr_len);
	data[0] = 0;
	ASSERT_EQ(sendto(self->client, data, sizeof(data), 0,
			 (void *)&self->addr, self->addr_len), (ssize_t)sizeof(data));
	delivered(_metadata, self->client, variant->proxy ? -1 : self->receiver,
		  self->receiver, 0);
}

TEST_F_TIMEOUT(tsi_udp, disconnect_twice, 5)
{
	struct sockaddr unspec = { .sa_family = AF_UNSPEC };
	unsigned char data[] = { 0, 'U' };
	int i;

	for (i = 0; i < 3; i++) {
		ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
		ASSERT_EQ(connect(self->client, &unspec, sizeof(unspec)), 0);
		ASSERT_EQ(connect(self->client, &unspec, sizeof(unspec)), 0);
	}
	ASSERT_EQ(sendto(self->client, data, sizeof(data), 0,
			 (void *)&self->addr, self->addr_len), (ssize_t)sizeof(data));
	delivered(_metadata, self->client, variant->proxy ? -1 : self->receiver,
		  self->receiver, 0);
}

TEST_F_TIMEOUT(tsi_udp, connect_host_then_guest_disconnect, 5)
{
	struct sockaddr_storage local;
	struct sockaddr unspec = { .sa_family = AF_UNSPEC };
	socklen_t len = sizeof(local);
	unsigned char data[] = { 0, 'U' };

	ASSERT_EQ(getsockname(self->receiver, (void *)&local, &len), 0);
	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(connect(self->client, (void *)&local, len), 0);
	peer_is(_metadata, self->client, &local, len);
	ASSERT_EQ(send(self->client, data, sizeof(data), 0), (ssize_t)sizeof(data));
	delivered(_metadata, self->client, self->receiver, self->receiver, 0);
	ASSERT_EQ(connect(self->client, &unspec, sizeof(unspec)), 0);
	data[0] = 1;
	ASSERT_EQ(sendto(self->client, data, sizeof(data), 0,
			 (void *)&self->addr2, self->addr_len), (ssize_t)sizeof(data));
	delivered(_metadata, self->client, variant->proxy ? -1 : self->other,
		  self->other, 1);
}

static void receive_packet_info(struct __test_metadata *_metadata,
				FIXTURE_DATA(tsi_udp) *self,
				const FIXTURE_VARIANT(tsi_udp) *variant,
				bool enabled, bool short_control, int bind_mode)
{
	struct sockaddr_storage local = self->addr, peer;
	union {
		struct cmsghdr align;
		char data[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	} control;
	unsigned char data[] = { 0, 'U' }, received[2];
	struct iovec iov = { .iov_base = received, .iov_len = sizeof(received) };
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control.data,
		.msg_controllen = short_control ? 1 : sizeof(control),
	};
	struct pollfd pfd = { .events = POLLIN };
	int level = variant->family == AF_INET ? SOL_IP : SOL_IPV6;
	int option = variant->family == AF_INET ? IP_PKTINFO : IPV6_RECVPKTINFO;
	struct cmsghdr *cmsg;
	socklen_t len;
	int value = enabled;

	if (variant->family == AF_INET)
		((struct sockaddr_in *)&local)->sin_port = 0;
	else
		((struct sockaddr_in6 *)&local)->sin6_port = 0;
	if (bind_mode == 1) {
		if (variant->family == AF_INET)
			((struct sockaddr_in *)&local)->sin_addr.s_addr = INADDR_ANY;
		else
			((struct sockaddr_in6 *)&local)->sin6_addr = in6addr_any;
	}
	if (bind_mode != 2)
		ASSERT_EQ(bind(self->client, (void *)&local, self->addr_len), 0);
	ASSERT_EQ(setsockopt(self->client, level, option, &value, sizeof(value)), 0);
	ASSERT_EQ(sendto(self->client, data, sizeof(data), 0,
			 (void *)&self->addr, self->addr_len), (ssize_t)sizeof(data));
	if (!variant->proxy) {
		pfd.fd = self->receiver;
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		len = sizeof(peer);
		ASSERT_EQ(recvfrom(self->receiver, received, sizeof(received), 0,
				   (void *)&peer, &len), (ssize_t)sizeof(received));
		ASSERT_EQ(sendto(self->receiver, received, sizeof(received), 0,
				 (void *)&peer, len), (ssize_t)sizeof(received));
	}
	pfd.fd = self->client;
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_EQ(recvmsg(self->client, &msg, 0), (ssize_t)sizeof(received));
	EXPECT_EQ(memcmp(data, received, sizeof(data)), 0);
	EXPECT_EQ(!!(msg.msg_flags & MSG_CTRUNC), enabled && short_control);
	if (!enabled || short_control) {
		EXPECT_EQ(msg.msg_controllen, (size_t)0);
		return;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	ASSERT_NE(cmsg, NULL);
	EXPECT_EQ(cmsg->cmsg_level, level);
	if (variant->family == AF_INET) {
		struct in_pktinfo *info = (void *)CMSG_DATA(cmsg);

		ASSERT_EQ(cmsg->cmsg_type, IP_PKTINFO);
		ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(*info)));
		EXPECT_EQ(info->ipi_addr.s_addr, htonl(INADDR_LOOPBACK));
		EXPECT_EQ(info->ipi_spec_dst.s_addr, htonl(INADDR_LOOPBACK));
		EXPECT_EQ(info->ipi_ifindex, (int)if_nametoindex("lo"));
	} else {
		struct in6_pktinfo *info = (void *)CMSG_DATA(cmsg);

		ASSERT_EQ(cmsg->cmsg_type, IPV6_PKTINFO);
		ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(*info)));
		EXPECT_EQ(memcmp(&info->ipi6_addr, &in6addr_loopback,
				 sizeof(in6addr_loopback)), 0);
		EXPECT_EQ(info->ipi6_ifindex, if_nametoindex("lo"));
	}
	EXPECT_EQ(CMSG_NXTHDR(&msg, cmsg), NULL);
}

TEST_F_TIMEOUT(tsi_udp, packet_info, 5)
{
	receive_packet_info(_metadata, self, variant, true, false, 0);
}

TEST_F_TIMEOUT(tsi_udp, packet_info_disabled, 5)
{
	receive_packet_info(_metadata, self, variant, false, false, 0);
}

TEST_F_TIMEOUT(tsi_udp, packet_info_short_control, 5)
{
	receive_packet_info(_metadata, self, variant, true, true, 0);
}

TEST_F_TIMEOUT(tsi_udp, wildcard_packet_info, 5)
{
	receive_packet_info(_metadata, self, variant, true, false, 1);
}

TEST_F_TIMEOUT(tsi_udp, wildcard_packet_info_short_control, 5)
{
	receive_packet_info(_metadata, self, variant, true, true, 1);
}

TEST_F_TIMEOUT(tsi_udp, implicit_packet_info, 5)
{
	receive_packet_info(_metadata, self, variant, true, false, 2);
}

static void send_packet_info(struct __test_metadata *_metadata,
			     FIXTURE_DATA(tsi_udp) *self,
			     const FIXTURE_VARIANT(tsi_udp) *variant,
			     bool guest_interface, bool malformed)
{
	union {
		struct cmsghdr align;
		char data[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	} control = {};
	unsigned char data[2 + sizeof(struct sockaddr_in6)] = { 0, 'N' };
	struct sockaddr_storage peer = {}, observed = {};
	struct iovec iov = { .iov_base = data, .iov_len = 2 + self->addr_len };
	struct msghdr msg = {
		.msg_name = &self->addr,
		.msg_namelen = self->addr_len,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control.data,
	};
	struct cmsghdr *cmsg = (void *)control.data;
	struct pollfd pfd = { .events = POLLIN };
	socklen_t len = sizeof(peer);
	int ifindex = guest_interface ? if_nametoindex("lo") : 0;

	if (variant->family == AF_INET) {
		struct in_pktinfo *info = (void *)CMSG_DATA(cmsg);

		cmsg->cmsg_level = SOL_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*info));
		info->ipi_ifindex = ifindex;
		info->ipi_spec_dst.s_addr = htonl(0x7f000002);
	} else {
		struct in6_pktinfo *info = (void *)CMSG_DATA(cmsg);

		cmsg->cmsg_level = SOL_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*info));
		info->ipi6_ifindex = ifindex;
		info->ipi6_addr = in6addr_loopback;
	}
	msg.msg_controllen = cmsg->cmsg_len;
	if (malformed) {
		cmsg->cmsg_len--;
		msg.msg_controllen--;
		EXPECT_EQ(sendmsg(self->client, &msg, 0), -1);
		EXPECT_EQ(errno, EINVAL);
		cmsg->cmsg_len++;
		msg.msg_controllen++;
	}
	ASSERT_EQ(sendmsg(self->client, &msg, 0), (ssize_t)iov.iov_len);
	if (!variant->proxy) {
		pfd.fd = self->receiver;
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recvfrom(self->receiver, data, sizeof(data), 0,
				   (void *)&peer, &len), (ssize_t)iov.iov_len);
		memcpy(data + 2, &peer, len);
		ASSERT_EQ(sendto(self->receiver, data, iov.iov_len, 0,
				 (void *)&peer, len), (ssize_t)iov.iov_len);
	}
	pfd.fd = self->client;
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_EQ(recv(self->client, data, sizeof(data), 0), (ssize_t)iov.iov_len);
	memcpy(&observed, data + 2, self->addr_len);
	if (variant->family == AF_INET) {
		EXPECT_EQ(((struct sockaddr_in *)&observed)->sin_addr.s_addr, htonl(0x7f000002));
	} else {
		EXPECT_EQ(memcmp(&((struct sockaddr_in6 *)&observed)->sin6_addr,
				 &in6addr_loopback, sizeof(in6addr_loopback)), 0);
	}
}

TEST_F_TIMEOUT(tsi_udp, send_packet_info, 5)
{
	send_packet_info(_metadata, self, variant, false, false);
}

TEST_F_TIMEOUT(tsi_udp, send_packet_info_guest_interface, 5)
{
	send_packet_info(_metadata, self, variant, true, false);
}

TEST_F_TIMEOUT(tsi_udp, malformed_packet_info_length, 5)
{
	send_packet_info(_metadata, self, variant, false, true);
}

static void wildcard_guest_reply(struct __test_metadata *_metadata,
				 FIXTURE_DATA(tsi_udp) *self,
				 const FIXTURE_VARIANT(tsi_udp) *variant,
				 bool packet_info)
{
	struct sockaddr_storage server = self->addr, peer;
	union {
		struct cmsghdr align;
		char data[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	} control;
	unsigned char data[] = { 0, 'U' }, received[2];
	struct iovec iov = { .iov_base = received, .iov_len = sizeof(received) };
	struct msghdr msg = {
		.msg_name = &peer,
		.msg_namelen = sizeof(peer),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = packet_info ? control.data : NULL,
		.msg_controllen = packet_info ? sizeof(control) : 0,
	};
	struct pollfd pfd = { .events = POLLIN };
	socklen_t len = sizeof(server);
	int value = 1;
	int level = variant->family == AF_INET ? SOL_IP : SOL_IPV6;
	int option = variant->family == AF_INET ? IP_PKTINFO : IPV6_RECVPKTINFO;

	if (variant->family == AF_INET) {
		((struct sockaddr_in *)&server)->sin_addr.s_addr = INADDR_ANY;
		((struct sockaddr_in *)&server)->sin_port = 0;
	} else {
		((struct sockaddr_in6 *)&server)->sin6_addr = in6addr_any;
		((struct sockaddr_in6 *)&server)->sin6_port = 0;
	}
	ASSERT_EQ(bind(self->client, (void *)&server, self->addr_len), 0);
	ASSERT_EQ(getsockname(self->client, (void *)&server, &len), 0);
	if (variant->family == AF_INET)
		((struct sockaddr_in *)&server)->sin_addr.s_addr =
			htonl(packet_info ? 0x7f000002 : INADDR_LOOPBACK);
	else
		((struct sockaddr_in6 *)&server)->sin6_addr = in6addr_loopback;
	if (packet_info)
		ASSERT_EQ(setsockopt(self->client, level, option, &value, sizeof(value)), 0);
	ASSERT_EQ(connect(self->receiver, (void *)&server, len), 0);
	ASSERT_EQ(send(self->receiver, data, sizeof(data), 0), (ssize_t)sizeof(data));
	pfd.fd = self->client;
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_EQ(recvmsg(self->client, &msg, 0), (ssize_t)sizeof(data));
	if (packet_info)
		ASSERT_NE(CMSG_FIRSTHDR(&msg), NULL);
	msg.msg_flags = 0;
	ASSERT_EQ(sendmsg(self->client, &msg, 0), (ssize_t)sizeof(data));
	pfd.fd = self->receiver;
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_EQ(recv(self->receiver, received, sizeof(received), 0), (ssize_t)sizeof(data));
	EXPECT_EQ(memcmp(data, received, sizeof(data)), 0);
}

TEST_F_TIMEOUT(tsi_udp, wildcard_reply_to_connected_guest, 5)
{
	wildcard_guest_reply(_metadata, self, variant, false);
}

TEST_F_TIMEOUT(tsi_udp, wildcard_pktinfo_reply_to_connected_guest, 5)
{
	wildcard_guest_reply(_metadata, self, variant, true);
}

TEST_F_TIMEOUT(tsi_udp, small_datagram_burst, 5)
{
	unsigned char request[2] = { 0, 'Q' }, data[256] = { 0, 'Q' }, received[256];
	struct sockaddr_storage peer, local = self->addr;
	socklen_t len = sizeof(peer);
	struct pollfd pfd = { .events = POLLIN };
	int i, buffer = 16384, bind_result, bind_error;

	if (variant->family == AF_INET)
		((struct sockaddr_in *)&local)->sin_port = 0;
	else
		((struct sockaddr_in6 *)&local)->sin6_port = 0;
	bind_result = bind(self->client, (void *)&local, self->addr_len);
	bind_error = errno;
	ASSERT_EQ(bind_result, 0) {
		TH_LOG("UDP bind failed: family=%d proxy=%d errno=%d (%s)",
		       variant->family, variant->proxy, bind_error,
		       strerror(bind_error));
	}
	ASSERT_EQ(setsockopt(self->client, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer)), 0);

	ASSERT_EQ(sendto(self->client, request, sizeof(request), 0,
			 (void *)&self->addr, self->addr_len), (ssize_t)sizeof(request));
	if (!variant->proxy) {
		pfd.fd = self->receiver;
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recvfrom(self->receiver, received, sizeof(received), 0,
				   (void *)&peer, &len), (ssize_t)sizeof(request));
		for (i = 0; i < 16; i++) {
			data[0] = i;
			ASSERT_EQ(sendto(self->receiver, data, sizeof(data), 0,
					 (void *)&peer, len), (ssize_t)sizeof(data));
		}
	}
	/* Let the entire burst queue before reading, as native UDP permits. */
	usleep(200000);
	pfd.fd = self->client;
	for (i = 0; i < 16; i++) {
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recv(self->client, received, sizeof(received), 0),
			  (ssize_t)sizeof(received));
		EXPECT_EQ(received[0], i);
		EXPECT_EQ(received[1], 'Q');
	}
}

TEST_HARNESS_MAIN
