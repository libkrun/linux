// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include "../kselftest_harness.h"
#include "tsi_test.h"

FIXTURE(tsi_udp_bind)
{
	int fd;
	int control;
	struct sockaddr_storage local;
	struct sockaddr_storage host;
	socklen_t len;
	unsigned int ports[4];
};
FIXTURE_VARIANT(tsi_udp_bind)
{
	int family;
	bool wildcard;
};
FIXTURE_VARIANT_ADD(tsi_udp_bind, loopback4) { .family = AF_INET };
FIXTURE_VARIANT_ADD(tsi_udp_bind, loopback6) { .family = AF_INET6 };
FIXTURE_VARIANT_ADD(tsi_udp_bind, wildcard4) { .family = AF_INET, .wildcard = true };
FIXTURE_VARIANT_ADD(tsi_udp_bind, wildcard6) { .family = AF_INET6, .wildcard = true };

static void port(struct sockaddr_storage *addr, unsigned int value)
{
	if (addr->ss_family == AF_INET)
		((struct sockaddr_in *)addr)->sin_port = htons(value);
	else
		((struct sockaddr_in6 *)addr)->sin6_port = htons(value);
}
static unsigned int get_port(struct sockaddr_storage *addr)
{
	return ntohs(addr->ss_family == AF_INET ? ((struct sockaddr_in *)addr)->sin_port :
	      ((struct sockaddr_in6 *)addr)->sin6_port);
}
FIXTURE_SETUP(tsi_udp_bind)
{
	const char *env = getenv("TSI_UDP_PORTS");
	int base = variant->family == AF_INET ? 0 : 2;
	int domain = variant->family == AF_INET ? AF_TSI : AF_TSI6;
	int parsed;

	self->fd = -1;
	self->control = -1;
	if (!env)
		SKIP(return, "host UDP helper unavailable");
	parsed = sscanf(env, "%u,%u,%u,%u", &self->ports[0], &self->ports[1],
			&self->ports[2], &self->ports[3]);
	ASSERT_EQ(parsed, 4);
	self->len = variant->family == AF_INET ? sizeof(struct sockaddr_in) :
					sizeof(struct sockaddr_in6);
	self->local.ss_family = variant->family;
	if (variant->family == AF_INET)
		((struct sockaddr_in *)&self->local)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	else
		((struct sockaddr_in6 *)&self->local)->sin6_addr = in6addr_loopback;
	self->host = self->local;
	port(&self->host, self->ports[base]);
	if (variant->wildcard) {
		if (variant->family == AF_INET)
			((struct sockaddr_in *)&self->local)->sin_addr.s_addr = INADDR_ANY;
		else
			((struct sockaddr_in6 *)&self->local)->sin6_addr = in6addr_any;
	}
	self->fd = socket(domain, SOCK_DGRAM, 0);
	if (self->fd < 0 && errno == EAFNOSUPPORT)
		SKIP(return, "TSI family unavailable");
	ASSERT_GE(self->fd, 0);
	self->control = socket(domain, SOCK_DGRAM, 0);
	ASSERT_GE(self->control, 0);
	ASSERT_EQ(tsi_force_proxy(self->control), 0);
}
FIXTURE_TEARDOWN(tsi_udp_bind)
{
	if (self->fd >= 0)
		close(self->fd);
	if (self->control >= 0)
		close(self->control);
}
TEST_F_TIMEOUT(tsi_udp_bind, incoming_before_send, 5)
{
	struct sockaddr_storage target = self->host, sender;
	unsigned char request[2 + sizeof(struct sockaddr_in6)] = { 0, 'B' };
	unsigned char data[2];
	struct pollfd pfd = { .fd = self->fd, .events = POLLIN };
	socklen_t len;
	int native;
	int seen = 0, count, base = variant->family == AF_INET ? 0 : 2;

	ASSERT_EQ(bind(self->fd, (void *)&self->local, self->len), 0);
	ASSERT_EQ(getsockname(self->fd, (void *)&self->local, &self->len), 0);
	ASSERT_GT(get_port(&self->local), 0U);
	port(&target, get_port(&self->local));
	memcpy(request + 2, &target, self->len);
	ASSERT_EQ(sendto(self->control, request, self->len + 2, 0,
		  (void *)&self->host, self->len), self->len + 2);
	for (int i = 0; i < 3; i++) {
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		len = sizeof(sender);
		count = recvfrom(self->fd, data, sizeof(data), 0, (void *)&sender, &len);
		ASSERT_GE(count, 0);
		EXPECT_EQ(len, self->len);
		if (!count) {
			seen |= 4;
			EXPECT_EQ(get_port(&sender), self->ports[base]);
		} else {
			ASSERT_EQ(count, 2);
			ASSERT_LE(data[0], 1);
			EXPECT_EQ(data[1], 'B');
			EXPECT_EQ(get_port(&sender), self->ports[base + data[0]]);
			seen |= 1 << data[0];
		}
	}
	EXPECT_EQ(seen, 7);
	request[1] = 'N';
	memset(request + 2, 0, self->len);
	ASSERT_EQ(sendto(self->fd, request, self->len + 2, 0,
		  (void *)&self->host, self->len), self->len + 2);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_EQ(recv(self->fd, request, sizeof(request), 0), self->len + 2);
	memcpy(&sender, request + 2, self->len);
	EXPECT_EQ(get_port(&sender), get_port(&self->local));
	len = sizeof(sender);
	ASSERT_EQ(getsockname(self->fd, (void *)&sender, &len), 0);
	EXPECT_EQ(memcmp(&sender, &self->local, self->len), 0);
	/* Host publication must retain guest-local request/reply delivery. */
	native = socket(variant->family, SOCK_DGRAM, 0);

	ASSERT_GE(native, 0);
	ASSERT_EQ(sendto(native, "L", 1, 0, (void *)&target, self->len), 1);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	len = sizeof(sender);
	ASSERT_EQ(recvfrom(self->fd, data, sizeof(data), 0, (void *)&sender, &len), 1);
	EXPECT_EQ(data[0], 'L');
	ASSERT_EQ(sendto(self->fd, "R", 1, 0, (void *)&sender, len), 1);
	pfd.fd = native;
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_EQ(recv(native, data, sizeof(data), 0), 1);
	EXPECT_EQ(data[0], 'R');
	close(native);
}
TEST_F_TIMEOUT(tsi_udp_bind, host_conflict, 5)
{
	port(&self->local, get_port(&self->host));
	EXPECT_EQ(bind(self->fd, (void *)&self->local, self->len), -1);
	EXPECT_EQ(errno, EADDRINUSE);
}
TEST_F_TIMEOUT(tsi_udp_bind, repeated_close_rebind, 5)
{
	int domain = variant->family == AF_INET ? AF_TSI : AF_TSI6;

	for (int i = 0; i < 20; i++) {
		ASSERT_EQ(bind(self->fd, (void *)&self->local, self->len), 0);
		ASSERT_EQ(getsockname(self->fd, (void *)&self->local, &self->len), 0);
		close(self->fd);
		self->fd = socket(domain, SOCK_DGRAM, 0);
		ASSERT_GE(self->fd, 0);
	}
}

TEST_F_TIMEOUT(tsi_udp_bind, bound_connect_disconnect, 5)
{
	struct sockaddr unspec = { .sa_family = AF_UNSPEC };
	struct sockaddr_storage observed, target = self->host;
	struct pollfd pfd = { .fd = self->fd, .events = POLLIN };
	unsigned char request[2 + sizeof(struct sockaddr_in6)] = { 0, 'N' };
	socklen_t len = sizeof(observed);

	ASSERT_EQ(bind(self->fd, (void *)&self->local, self->len), 0);
	ASSERT_EQ(getsockname(self->fd, (void *)&self->local, &self->len), 0);
	ASSERT_EQ(connect(self->fd, (void *)&self->host, self->len), 0);
	ASSERT_EQ(send(self->fd, request, self->len + 2, 0), self->len + 2);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_EQ(recv(self->fd, request, sizeof(request), 0), self->len + 2);
	memcpy(&observed, request + 2, self->len);
	EXPECT_EQ(get_port(&observed), get_port(&self->local));
	ASSERT_EQ(connect(self->fd, &unspec, sizeof(unspec)), 0);
	ASSERT_EQ(getsockname(self->fd, (void *)&observed, &len), 0);
	EXPECT_EQ(get_port(&observed), get_port(&self->local));
	port(&target, get_port(&self->local));
	request[1] = 'B';
	memcpy(request + 2, &target, self->len);
	ASSERT_EQ(sendto(self->control, request, self->len + 2, 0,
			 (void *)&self->host, self->len), self->len + 2);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_EQ(recv(self->fd, request, sizeof(request), 0), 2);
}

TEST_HARNESS_MAIN
