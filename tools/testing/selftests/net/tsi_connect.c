// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../kselftest_harness.h"
#include "tsi_test.h"

static long elapsed_ms(struct timespec start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start.tv_sec) * 1000 +
	       (now.tv_nsec - start.tv_nsec) / 1000000;
}

static void loopback(struct sockaddr_storage *addr, int family)
{
	if (family == AF_INET) {
		struct sockaddr_in *in = (void *)addr;

		in->sin_family = AF_INET;
		in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	} else {
		struct sockaddr_in6 *in = (void *)addr;

		in->sin6_family = AF_INET6;
		in->sin6_addr = in6addr_loopback;
	}
}

FIXTURE(tsi_connect)
{
	int listener;
	int filler;
	int client;
	struct sockaddr_storage addr;
	socklen_t len;
};

FIXTURE_VARIANT(tsi_connect)
{
	int family;
	bool tsi;
};
FIXTURE_VARIANT_ADD(tsi_connect, native4) { .family = AF_INET };
FIXTURE_VARIANT_ADD(tsi_connect, native6) { .family = AF_INET6 };
FIXTURE_VARIANT_ADD(tsi_connect, tsi4) { .family = AF_INET, .tsi = true };
FIXTURE_VARIANT_ADD(tsi_connect, tsi6) { .family = AF_INET6, .tsi = true };

static int client_socket(int family, bool tsi)
{
	struct timeval timeout = { .tv_sec = 2 };
	int domain = tsi ? (family == AF_INET ? AF_TSI : AF_TSI6) : family;
	int fd = socket(domain, SOCK_STREAM | SOCK_NONBLOCK, 0);

	if (fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
				 &timeout, sizeof(timeout))) {
		close(fd);
		return -1;
	}
	return fd;
}

static int proxy_socket(int family)
{
	int fd = client_socket(family, true);
	int zero = 0;

	if (fd < 0)
		return fd;
	if ((family == AF_INET6 &&
	     setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero))) ||
	    tsi_force_proxy(fd)) {
		close(fd);
		return -1;
	}
	return fd;
}

FIXTURE_SETUP(tsi_connect)
{
	self->listener = -1;
	self->filler = -1;
	self->client = -1;
	self->len = variant->family == AF_INET ? sizeof(struct sockaddr_in) :
						 sizeof(struct sockaddr_in6);
	loopback(&self->addr, variant->family);
	self->listener = socket(variant->family, SOCK_STREAM, 0);
	ASSERT_GE(self->listener, 0);
	ASSERT_EQ(bind(self->listener, (void *)&self->addr, self->len), 0);
	ASSERT_EQ(getsockname(self->listener, (void *)&self->addr, &self->len), 0);
	ASSERT_EQ(listen(self->listener, 0), 0);
	self->filler = socket(variant->family, SOCK_STREAM, 0);
	ASSERT_GE(self->filler, 0);
	ASSERT_EQ(connect(self->filler, (void *)&self->addr, self->len), 0);
	self->client = client_socket(variant->family, variant->tsi);
	if (self->client < 0 && errno == EAFNOSUPPORT)
		SKIP(return, "TSI family unavailable");
	ASSERT_GE(self->client, 0);
}

FIXTURE_TEARDOWN(tsi_connect)
{
	if (self->client >= 0)
		close(self->client);
	if (self->filler >= 0)
		close(self->filler);
	if (self->listener >= 0)
		close(self->listener);
}

TEST_F_TIMEOUT(tsi_connect, pending_and_completion, 10)
{
	struct pollfd pfd = { .fd = self->client, .events = POLLOUT };
	struct sockaddr_storage peer;
	socklen_t len = sizeof(peer);
	struct timespec started;
	int value, accepted, result;
	char byte;

	clock_gettime(CLOCK_MONOTONIC, &started);
	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->len), -1);
	ASSERT_EQ(errno, EINPROGRESS);
	ASSERT_LT(elapsed_ms(started), 100);
	ASSERT_EQ(poll(&pfd, 1, 40), 0);
	len = sizeof(value);
	ASSERT_EQ(getsockopt(self->client, SOL_SOCKET, SO_ERROR, &value, &len), 0);
	EXPECT_EQ(value, 0);
	EXPECT_EQ(connect(self->client, (void *)&self->addr, self->len), -1);
	EXPECT_EQ(errno, EALREADY);
	EXPECT_EQ(send(self->client, "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL), -1);
	EXPECT_EQ(errno, EAGAIN);
	EXPECT_EQ(recv(self->client, &byte, 1, MSG_DONTWAIT), -1);
	EXPECT_EQ(errno, EAGAIN);
	len = sizeof(peer);
	EXPECT_EQ(getpeername(self->client, (void *)&peer, &len), -1);
	EXPECT_EQ(errno, ENOTCONN);
	accepted = accept(self->listener, NULL, NULL);
	ASSERT_GE(accepted, 0);
	close(accepted);
	ASSERT_EQ(poll(&pfd, 1, 3000), 1);
	EXPECT_TRUE(pfd.revents & POLLOUT);
	EXPECT_FALSE(pfd.revents & POLLERR);
	len = sizeof(value);
	ASSERT_EQ(getsockopt(self->client, SOL_SOCKET, SO_ERROR, &value, &len), 0);
	ASSERT_EQ(value, 0);
	accepted = accept(self->listener, NULL, NULL);
	ASSERT_GE(accepted, 0);
	ASSERT_EQ(send(self->client, "x", 1, MSG_NOSIGNAL), 1);
	ASSERT_EQ(recv(accepted, &byte, 1, 0), 1);
	EXPECT_EQ(byte, 'x');
	close(accepted);
	len = sizeof(peer);
	EXPECT_EQ(getpeername(self->client, (void *)&peer, &len), 0);
	result = connect(self->client, (void *)&self->addr, self->len);
	EXPECT_TRUE(result == 0 || (result == -1 && errno == EISCONN));
}

TEST_F_TIMEOUT(tsi_connect, close_pending, 10)
{
	struct timespec started;
	int fd, accepted, result, error;

	for (int i = 0; i < 20; i++) {
		fd = client_socket(variant->family, variant->tsi);
		ASSERT_GE(fd, 0);
		clock_gettime(CLOCK_MONOTONIC, &started);
		result = connect(fd, (void *)&self->addr, self->len);
		error = errno;
		close(fd);
		ASSERT_EQ(result, -1);
		ASSERT_EQ(error, EINPROGRESS);
		ASSERT_LT(elapsed_ms(started), 100);
	}
	accepted = accept(self->listener, NULL, NULL);
	ASSERT_GE(accepted, 0);
	close(accepted);
	usleep(100000);
	ASSERT_EQ(fcntl(self->listener, F_SETFL, O_NONBLOCK), 0);
	EXPECT_EQ(accept(self->listener, NULL, NULL), -1);
	EXPECT_EQ(errno, EAGAIN);
}

FIXTURE(tsi_connect_proxy)
{
	int fd;
	struct sockaddr_storage addr;
	socklen_t len;
};
FIXTURE_VARIANT(tsi_connect_proxy) { int family; };
FIXTURE_VARIANT_ADD(tsi_connect_proxy, ipv4) { .family = AF_INET };
FIXTURE_VARIANT_ADD(tsi_connect_proxy, ipv6_mapped) { .family = AF_INET6 };

FIXTURE_SETUP(tsi_connect_proxy)
{
	struct timeval timeout = { .tv_usec = 200000 };
	const char *port = getenv("TSI_CONTROL_PORT");

	self->fd = -1;
	if (!port)
		SKIP(return, "host TCP queue fixture unavailable");
	self->len = variant->family == AF_INET ? sizeof(struct sockaddr_in) :
						 sizeof(struct sockaddr_in6);
	loopback(&self->addr, variant->family);
	if (variant->family == AF_INET) {
		((struct sockaddr_in *)&self->addr)->sin_port = htons(atoi(port));
	} else {
		struct sockaddr_in6 *in = (void *)&self->addr;

		in->sin6_port = htons(atoi(port));
		ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &in->sin6_addr), 1);
	}
	self->fd = proxy_socket(variant->family);
	if (self->fd < 0 && errno == EAFNOSUPPORT)
		SKIP(return, "TSI family unavailable");
	ASSERT_GE(self->fd, 0);
	ASSERT_EQ(setsockopt(self->fd, SOL_SOCKET, SO_SNDTIMEO,
			     &timeout, sizeof(timeout)), 0);
}
FIXTURE_TEARDOWN(tsi_connect_proxy)
{
	if (self->fd >= 0)
		close(self->fd);
}

TEST_F_TIMEOUT(tsi_connect_proxy, timeout_error_clears, 5)
{
	struct pollfd pfd = { .fd = self->fd, .events = POLLOUT };
	struct timespec started;
	socklen_t len;
	int value;

	clock_gettime(CLOCK_MONOTONIC, &started);
	ASSERT_EQ(connect(self->fd, (void *)&self->addr, self->len), -1);
	ASSERT_EQ(errno, EINPROGRESS);
	ASSERT_LT(elapsed_ms(started), 100);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	EXPECT_TRUE(pfd.revents & POLLOUT);
	EXPECT_TRUE(pfd.revents & POLLERR);
	len = sizeof(value);
	ASSERT_EQ(getsockopt(self->fd, SOL_SOCKET, SO_ERROR, &value, &len), 0);
	EXPECT_EQ(value, ETIMEDOUT);
	ASSERT_EQ(getsockopt(self->fd, SOL_SOCKET, SO_ERROR, &value, &len), 0);
	EXPECT_EQ(value, 0);
}

TEST_F_TIMEOUT(tsi_connect_proxy, refused_error_clears, 5)
{
	struct pollfd pfd = { .fd = self->fd, .events = POLLOUT };
	socklen_t len;
	int value;

	/* A TCP listener cannot own destination port zero. */
	if (variant->family == AF_INET)
		((struct sockaddr_in *)&self->addr)->sin_port = 0;
	else
		((struct sockaddr_in6 *)&self->addr)->sin6_port = 0;
	ASSERT_EQ(connect(self->fd, (void *)&self->addr, self->len), -1);
	ASSERT_EQ(errno, EINPROGRESS);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	EXPECT_TRUE(pfd.revents & POLLOUT);
	EXPECT_TRUE(pfd.revents & POLLERR);
	len = sizeof(value);
	ASSERT_EQ(getsockopt(self->fd, SOL_SOCKET, SO_ERROR, &value, &len), 0);
	EXPECT_EQ(value, ECONNREFUSED);
	ASSERT_EQ(getsockopt(self->fd, SOL_SOCKET, SO_ERROR, &value, &len), 0);
	EXPECT_EQ(value, 0);
}

TEST_F_TIMEOUT(tsi_connect_proxy, close_pending_repeatedly, 5)
{
	struct timespec started;

	for (int i = 0; i < 20; i++) {
		ASSERT_EQ(connect(self->fd, (void *)&self->addr, self->len), -1);
		ASSERT_EQ(errno, EINPROGRESS);
		usleep(10000);
		clock_gettime(CLOCK_MONOTONIC, &started);
		close(self->fd);
		self->fd = -1;
		ASSERT_LT(elapsed_ms(started), 100);
		if (i != 19) {
			self->fd = proxy_socket(variant->family);
			ASSERT_GE(self->fd, 0);
		}
	}
}

TEST_HARNESS_MAIN
