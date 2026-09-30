// SPDX-License-Identifier: GPL-2.0-only
/* VMM INET impersonation enabled; guest automatic hijacking disabled. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../kselftest_harness.h"
#include "tsi_test.h"

FIXTURE(tsi_sockopt)
{
	int client;
	int listener;
	int accepted;
	struct sockaddr_storage addr;
	socklen_t addr_len;
};

FIXTURE_VARIANT(tsi_sockopt)
{
	int family;
	int type;
	bool tsi;
	bool proxy;
};

FIXTURE_VARIANT_ADD(tsi_sockopt, native_tcp4) {
	.family = AF_INET, .type = SOCK_STREAM,
};
FIXTURE_VARIANT_ADD(tsi_sockopt, native_tcp6) {
	.family = AF_INET6, .type = SOCK_STREAM,
};
FIXTURE_VARIANT_ADD(tsi_sockopt, native_udp4) {
	.family = AF_INET, .type = SOCK_DGRAM,
};
FIXTURE_VARIANT_ADD(tsi_sockopt, native_udp6) {
	.family = AF_INET6, .type = SOCK_DGRAM,
};
FIXTURE_VARIANT_ADD(tsi_sockopt, local_tcp4) {
	.family = AF_INET, .type = SOCK_STREAM, .tsi = true,
};
FIXTURE_VARIANT_ADD(tsi_sockopt, local_tcp6) {
	.family = AF_INET6, .type = SOCK_STREAM, .tsi = true,
};
FIXTURE_VARIANT_ADD(tsi_sockopt, local_udp4) {
	.family = AF_INET, .type = SOCK_DGRAM, .tsi = true,
};
FIXTURE_VARIANT_ADD(tsi_sockopt, local_udp6) {
	.family = AF_INET6, .type = SOCK_DGRAM, .tsi = true,
};
FIXTURE_VARIANT_ADD(tsi_sockopt, proxy_tcp4) {
	.family = AF_INET, .type = SOCK_STREAM, .tsi = true, .proxy = true,
};
FIXTURE_VARIANT_ADD(tsi_sockopt, proxy_tcp6) {
	.family = AF_INET6, .type = SOCK_STREAM, .tsi = true, .proxy = true,
};
FIXTURE_VARIANT_ADD(tsi_sockopt, proxy_udp4) {
	.family = AF_INET, .type = SOCK_DGRAM, .tsi = true, .proxy = true,
};
FIXTURE_VARIANT_ADD(tsi_sockopt, proxy_udp6) {
	.family = AF_INET6, .type = SOCK_DGRAM, .tsi = true, .proxy = true,
};

FIXTURE_SETUP(tsi_sockopt)
{
	struct sockaddr_in *in = (void *)&self->addr;
	struct sockaddr_in6 *in6 = (void *)&self->addr;
	int family = variant->family;

	self->client = -1;
	self->listener = -1;
	self->accepted = -1;
	if (variant->tsi)
		family = family == AF_INET ? AF_TSI : AF_TSI6;
	self->client = socket(family, variant->type, 0);
	if (self->client < 0 && errno == EAFNOSUPPORT)
		SKIP(return, "TSI family unavailable");
	ASSERT_GE(self->client, 0);
	self->listener = socket(variant->tsi && variant->type == SOCK_STREAM ?
				family : variant->family, variant->type, 0);
	ASSERT_GE(self->listener, 0);
	if (variant->family == AF_INET) {
		in->sin_family = AF_INET;
		in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		self->addr_len = sizeof(*in);
	} else {
		in6->sin6_family = AF_INET6;
		in6->sin6_addr = in6addr_loopback;
		self->addr_len = sizeof(*in6);
	}
	ASSERT_EQ(bind(self->listener, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(getsockname(self->listener, (void *)&self->addr, &self->addr_len), 0);
	if (variant->proxy && variant->type == SOCK_DGRAM) {
		unsigned int ports[4], base = variant->family == AF_INET ? 0 : 2;
		int parsed;
		const char *env = getenv("TSI_UDP_PORTS");

		if (!env)
			SKIP(return, "host UDP fixture unavailable");
		parsed = sscanf(env, "%u,%u,%u,%u", &ports[0], &ports[1],
				&ports[2], &ports[3]);
		ASSERT_EQ(parsed, 4);
		if (variant->family == AF_INET)
			in->sin_port = htons(ports[base]);
		else
			in6->sin6_port = htons(ports[base]);
	}
}

FIXTURE_TEARDOWN(tsi_sockopt)
{
	if (self->accepted >= 0)
		close(self->accepted);
	if (self->client >= 0)
		close(self->client);
	if (self->listener >= 0)
		close(self->listener);
}

static void connect_client(struct __test_metadata *_metadata,
			   struct _test_data_tsi_sockopt *self,
			   const struct _fixture_variant_tsi_sockopt *variant)
{
	struct pollfd pfd = { .fd = self->listener, .events = POLLIN };

	if (variant->type == SOCK_STREAM) {
		ASSERT_EQ(listen(self->listener, 8), 0);
		if (variant->proxy)
			ASSERT_EQ(tsi_force_proxy(self->client), 0);
	}
	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	if (variant->type == SOCK_STREAM) {
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		self->accepted = accept(self->listener, NULL, NULL);
		ASSERT_GE(self->accepted, 0);
	}
}

static int get_int(struct __test_metadata *_metadata, int fd, int level, int name)
{
	int value = -1;
	socklen_t len = sizeof(value);

	ASSERT_EQ(getsockopt(fd, level, name, &value, &len), 0);
	EXPECT_EQ(len, sizeof(value));
	return value;
}

static void set_int(struct __test_metadata *_metadata, int fd, int level,
		    int name, int value)
{
	ASSERT_EQ(setsockopt(fd, level, name, &value, sizeof(value)), 0);
}

TEST_F_TIMEOUT(tsi_sockopt, before_connect, 5)
{
	int names[] = { SO_REUSEADDR, SO_REUSEPORT, SO_KEEPALIVE, SO_BROADCAST };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		set_int(_metadata, self->client, SOL_SOCKET, names[i], 1);
		EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, names[i]), 1);
	}
	connect_client(_metadata, self, variant);
	for (i = 0; i < ARRAY_SIZE(names); i++)
		EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, names[i]), 1);
}

TEST_F_TIMEOUT(tsi_sockopt, after_connect, 5)
{
	int names[] = { SO_REUSEADDR, SO_REUSEPORT, SO_KEEPALIVE, SO_BROADCAST };
	unsigned int i;

	connect_client(_metadata, self, variant);
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		set_int(_metadata, self->client, SOL_SOCKET, names[i], 1);
		EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, names[i]), 1);
		set_int(_metadata, self->client, SOL_SOCKET, names[i], 0);
		EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, names[i]), 0);
	}
}

TEST_F_TIMEOUT(tsi_sockopt, buffers, 5)
{
	int names[] = { SO_SNDBUF, SO_RCVBUF };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		set_int(_metadata, self->client, SOL_SOCKET, names[i], 32768);
		EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, names[i]), 65536);
	}
	connect_client(_metadata, self, variant);
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, names[i]), 65536);
		set_int(_metadata, self->client, SOL_SOCKET, names[i], 65536);
		EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, names[i]), 131072);
	}
}

TEST_F_TIMEOUT(tsi_sockopt, accepted_or_peer_options, 5)
{
	struct timeval timeout = { .tv_usec = 100000 }, observed;
	socklen_t len = sizeof(observed);
	char byte;

	ASSERT_EQ(setsockopt(self->listener, SOL_SOCKET, SO_RCVTIMEO,
			     &timeout, sizeof(timeout)), 0);
	ASSERT_EQ(setsockopt(self->listener, SOL_SOCKET, SO_SNDTIMEO,
			     &timeout, sizeof(timeout)), 0);
	set_int(_metadata, self->listener, SOL_SOCKET, SO_KEEPALIVE, 1);
	if (variant->type == SOCK_STREAM)
		set_int(_metadata, self->listener, IPPROTO_TCP, TCP_NODELAY, 1);
	connect_client(_metadata, self, variant);
	EXPECT_EQ(get_int(_metadata, self->listener, SOL_SOCKET, SO_KEEPALIVE), 1);
	if (variant->type == SOCK_STREAM) {
		ASSERT_EQ(getsockopt(self->accepted, SOL_SOCKET, SO_RCVTIMEO,
				     &observed, &len), 0);
		ASSERT_EQ(observed.tv_sec, timeout.tv_sec);
		ASSERT_EQ(observed.tv_usec, timeout.tv_usec);
		ASSERT_EQ(getsockopt(self->accepted, SOL_SOCKET, SO_SNDTIMEO,
				     &observed, &len), 0);
		ASSERT_EQ(observed.tv_sec, timeout.tv_sec);
		ASSERT_EQ(observed.tv_usec, timeout.tv_usec);
		EXPECT_EQ(recv(self->accepted, &byte, 1, 0), -1);
		EXPECT_EQ(errno, EAGAIN);
		EXPECT_EQ(get_int(_metadata, self->accepted, IPPROTO_TCP, TCP_NODELAY), 1);
		EXPECT_EQ(get_int(_metadata, self->accepted, SOL_SOCKET, SO_KEEPALIVE), 1);
		if (variant->family == AF_INET6) {
			int previous = get_int(_metadata, self->accepted, IPPROTO_IPV6, IPV6_V6ONLY);
			int changed = !previous;

			EXPECT_EQ(setsockopt(self->accepted, IPPROTO_IPV6, IPV6_V6ONLY,
					     &changed, sizeof(changed)), -1);
			EXPECT_EQ(errno, EINVAL);
			EXPECT_EQ(get_int(_metadata, self->accepted, IPPROTO_IPV6, IPV6_V6ONLY), previous);
		}
		set_int(_metadata, self->accepted, SOL_SOCKET, SO_KEEPALIVE, 0);
		EXPECT_EQ(get_int(_metadata, self->accepted, SOL_SOCKET, SO_KEEPALIVE), 0);
		EXPECT_EQ(get_int(_metadata, self->listener, SOL_SOCKET, SO_ACCEPTCONN), 1);
		EXPECT_EQ(get_int(_metadata, self->accepted, SOL_SOCKET, SO_ACCEPTCONN), 0);
	}
}

TEST_F_TIMEOUT(tsi_sockopt, local_option_keeps_networking, 5)
{
	int value = 42;

	set_int(_metadata, self->client, IPPROTO_IP, IP_TTL, value);
	connect_client(_metadata, self, variant);
	EXPECT_EQ(get_int(_metadata, self->client, IPPROTO_IP, IP_TTL), value);
	set_int(_metadata, self->client, IPPROTO_IP, IP_TTL, ++value);
	EXPECT_EQ(get_int(_metadata, self->client, IPPROTO_IP, IP_TTL), value);
	set_int(_metadata, self->client, SOL_SOCKET, SO_KEEPALIVE, 1);
	EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, SO_KEEPALIVE), 1);
}

TEST_F_TIMEOUT(tsi_sockopt, metadata_and_bad_option, 5)
{
	int value = 1;

	connect_client(_metadata, self, variant);
	EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, SO_TYPE), variant->type);
	EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, SO_PROTOCOL),
		  variant->type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
	EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, SO_ERROR), 0);
	EXPECT_EQ(setsockopt(self->client, SOL_SOCKET, 0x7fff, &value, sizeof(value)), -1);
	EXPECT_EQ(errno, ENOPROTOOPT);
}

TEST_F_TIMEOUT(tsi_sockopt, short_get_and_bad_set, 5)
{
	unsigned char value = 0xa5;
	socklen_t len = 1;
	int one = 1;

	connect_client(_metadata, self, variant);
	set_int(_metadata, self->client, SOL_SOCKET, SO_KEEPALIVE, one);
	ASSERT_EQ(getsockopt(self->client, SOL_SOCKET, SO_KEEPALIVE, &value, &len), 0);
	EXPECT_EQ(len, 1U);
	EXPECT_EQ(value, 1);
	EXPECT_EQ(setsockopt(self->client, SOL_SOCKET, SO_KEEPALIVE, &one, 1), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, SO_KEEPALIVE), 1);
}

TEST_F_TIMEOUT(tsi_sockopt, transport_option, 5)
{
	int level = variant->type == SOCK_STREAM ? IPPROTO_TCP : SOL_SOCKET;
	int name = variant->type == SOCK_STREAM ? TCP_NODELAY : SO_BROADCAST;

	if (variant->family == AF_INET6) {
		set_int(_metadata, self->client, IPPROTO_IPV6, IPV6_V6ONLY, 1);
		EXPECT_EQ(get_int(_metadata, self->client, IPPROTO_IPV6, IPV6_V6ONLY), 1);
	}
	set_int(_metadata, self->client, level, name, 1);
	EXPECT_EQ(get_int(_metadata, self->client, level, name), 1);
	connect_client(_metadata, self, variant);
	if (variant->family == AF_INET6) {
		int zero = 0;

		EXPECT_EQ(get_int(_metadata, self->client, IPPROTO_IPV6, IPV6_V6ONLY), 1);
		EXPECT_EQ(setsockopt(self->client, IPPROTO_IPV6, IPV6_V6ONLY,
				     &zero, sizeof(zero)), -1);
		EXPECT_EQ(errno, EINVAL);
	}
	EXPECT_EQ(get_int(_metadata, self->client, level, name), 1);
	set_int(_metadata, self->client, level, name, 0);
	EXPECT_EQ(get_int(_metadata, self->client, level, name), 0);
}

TEST_F_TIMEOUT(tsi_sockopt, pending_error_clears, 5)
{
	unsigned char data[2 + sizeof(struct sockaddr_in6)] = { 0, 'E' };
	struct sockaddr_storage target = self->addr;
	struct pollfd pfd = { .fd = self->client, .events = POLLIN };
	int size = 2 + self->addr_len;

	connect_client(_metadata, self, variant);
	if (variant->type == SOCK_STREAM) {
		EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, SO_ERROR), 0);
		return;
	}
	if (variant->proxy) {
		ASSERT_EQ(send(self->client, data, size, 0), size);
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recv(self->client, data, sizeof(data), 0), size);
		memcpy(&target, data + 2, self->addr_len);
		ASSERT_EQ(connect(self->client, (void *)&target, self->addr_len), 0);
	} else {
		close(self->listener);
		self->listener = -1;
	}
	ASSERT_EQ(send(self->client, "U", 1, 0), 1);
	usleep(100000);
	if (variant->proxy) {
		unsigned char trigger[] = { 0, 'J' };
		int i;

		/* A broker send can consume the pending ICMP error before GETOPT. */
		for (i = 0; i < 2; i++)
			ASSERT_EQ(sendto(self->client, trigger, sizeof(trigger), 0,
					 (void *)&self->addr, self->addr_len), 2);
		usleep(100000);
	}
	EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, SO_ERROR), ECONNREFUSED);
	EXPECT_EQ(get_int(_metadata, self->client, SOL_SOCKET, SO_ERROR), 0);
	if (variant->proxy) {
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recv(self->client, data, sizeof(data), 0), 1);
		EXPECT_EQ(data[0], 'C');
	}
}

TEST_HARNESS_MAIN
