// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "../kselftest_harness.h"
#include "tsi_test.h"

enum command {
	CONNECT = 1, SEND, RECEIVE, CLOSE, TIME_WAIT, LISTENING, RESET, ALLOCATE,
	OCCUPY, UNBLOCK,
};

FIXTURE(tsi_tcp_restart)
{
	int listener;
	int accepted;
	int control;
	int domain;
	bool native;
	struct sockaddr_storage addr;
	socklen_t len;
	unsigned int port;
	uint32_t sequence;
};

FIXTURE_VARIANT(tsi_tcp_restart)
{
	int family;
	bool reuseaddr;
	int reuseport;
};

FIXTURE_VARIANT_ADD(tsi_tcp_restart, ipv4_default) {
	.family = AF_INET, .reuseport = -1,
};
FIXTURE_VARIANT_ADD(tsi_tcp_restart, ipv4_addr) {
	.family = AF_INET, .reuseaddr = true, .reuseport = -1,
};
FIXTURE_VARIANT_ADD(tsi_tcp_restart, ipv4_port_off) {
	.family = AF_INET, .reuseaddr = true, .reuseport = 0,
};
FIXTURE_VARIANT_ADD(tsi_tcp_restart, ipv4_port_on) {
	.family = AF_INET, .reuseaddr = true, .reuseport = 1,
};
FIXTURE_VARIANT_ADD(tsi_tcp_restart, ipv6_default) {
	.family = AF_INET6, .reuseport = -1,
};
FIXTURE_VARIANT_ADD(tsi_tcp_restart, ipv6_addr) {
	.family = AF_INET6, .reuseaddr = true, .reuseport = -1,
};
FIXTURE_VARIANT_ADD(tsi_tcp_restart, ipv6_port_off) {
	.family = AF_INET6, .reuseaddr = true, .reuseport = 0,
};
FIXTURE_VARIANT_ADD(tsi_tcp_restart, ipv6_port_on) {
	.family = AF_INET6, .reuseaddr = true, .reuseport = 1,
};

static long elapsed_ms(struct timespec start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start.tv_sec) * 1000 +
	       (now.tv_nsec - start.tv_nsec) / 1000000;
}

static int host(struct __test_metadata *_metadata,
		struct _test_data_tsi_tcp_restart *self, enum command command,
		unsigned int slot, unsigned int value, unsigned int *output)
{
	uint32_t request[] = {
		htonl(++self->sequence), htonl(command), htonl(self->port),
		htonl(slot), htonl(value),
	};
	uint32_t reply[3];
	ssize_t count;

	ASSERT_EQ(send(self->control, request, sizeof(request), 0), (ssize_t)sizeof(request));
	count = recv(self->control, reply, sizeof(reply), 0);
	ASSERT_EQ(count, (ssize_t)sizeof(reply));
	ASSERT_EQ(ntohl(reply[0]), self->sequence);
	if (output)
		*output = ntohl(reply[2]);
	return (int32_t)ntohl(reply[1]);
}

static int bound_socket(struct _test_data_tsi_tcp_restart *self,
			const struct _fixture_variant_tsi_tcp_restart *variant)
{
	struct timeval timeout = { .tv_sec = 2 };
	int one = 1, fd = socket(self->domain, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;
	if ((variant->reuseaddr && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
					    &one, sizeof(one))) ||
	    (variant->reuseport >= 0 && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
						 &variant->reuseport, sizeof(int))) ||
	    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
	    bind(fd, (void *)&self->addr, self->len)) {
		int error = errno;

		close(fd);
		errno = error;
		return -1;
	}
	return fd;
}

static int new_listener(struct _test_data_tsi_tcp_restart *self,
			const struct _fixture_variant_tsi_tcp_restart *variant)
{
	int fd = bound_socket(self, variant);

	if (fd >= 0 && listen(fd, 8)) {
		int error = errno;

		close(fd);
		errno = error;
		return -1;
	}
	return fd;
}

FIXTURE_SETUP(tsi_tcp_restart)
{
	struct sockaddr_storage control_addr = {};
	struct timeval timeout = { .tv_sec = 2 };
	const char *ports = getenv("TSI_TCP_RESTART_PORTS");
	unsigned int port4, port6;
	unsigned int low, high;
	socklen_t len = sizeof(int);
	int parsed, addr, port;
	FILE *range;

	self->listener = -1;
	self->accepted = -1;
	self->control = -1;
	if (!ports)
		SKIP(return, "set TSI_TCP_RESTART_PORTS from the host peer");
	parsed = sscanf(ports, "%u,%u", &port4, &port6);
	ASSERT_EQ(parsed, 2);
	self->native = getenv("TSI_TCP_RESTART_NATIVE") != NULL;
	self->domain = self->native ? variant->family :
		      variant->family == AF_INET ? AF_TSI : AF_TSI6;
	self->control = socket(self->domain, SOCK_DGRAM, 0);
	if (self->control < 0 && errno == EAFNOSUPPORT)
		SKIP(return, "TSI family unavailable");
	ASSERT_GE(self->control, 0);
	if (!self->native)
		ASSERT_EQ(tsi_force_proxy(self->control), 0);
	self->addr.ss_family = variant->family;
	if (variant->family == AF_INET) {
		struct sockaddr_in *addr = (void *)&self->addr;

		addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		self->len = sizeof(*addr);
		control_addr = self->addr;
		((struct sockaddr_in *)&control_addr)->sin_port = htons(port4);
	} else {
		struct sockaddr_in6 *addr = (void *)&self->addr;

		addr->sin6_addr = in6addr_loopback;
		self->len = sizeof(*addr);
		control_addr = self->addr;
		((struct sockaddr_in6 *)&control_addr)->sin6_port = htons(port6);
	}
	ASSERT_EQ(setsockopt(self->control, SOL_SOCKET, SO_RCVTIMEO,
			     &timeout, sizeof(timeout)), 0);
	ASSERT_EQ(connect(self->control, (void *)&control_addr, self->len), 0);
	range = fopen("/proc/sys/net/ipv4/ip_local_port_range", "r");
	ASSERT_NE(range, NULL);
	parsed = fscanf(range, "%u %u", &low, &high);
	fclose(range);
	ASSERT_EQ(parsed, 2);
	ASSERT_EQ(host(_metadata, self, ALLOCATE, low, high, &self->port), 0);
	if (variant->family == AF_INET)
		((struct sockaddr_in *)&self->addr)->sin_port = htons(self->port);
	else
		((struct sockaddr_in6 *)&self->addr)->sin6_port = htons(self->port);
	self->listener = new_listener(self, variant);
	ASSERT_GE(self->listener, 0);
	ASSERT_EQ(getsockopt(self->listener, SOL_SOCKET, SO_REUSEADDR, &addr, &len), 0);
	ASSERT_EQ(getsockopt(self->listener, SOL_SOCKET, SO_REUSEPORT, &port, &len), 0);
	TH_LOG("%s listener port=%u effective reuseaddr=%d reuseport=%d",
	       self->native ? "native" : "TSI", self->port, addr, port);
}

FIXTURE_TEARDOWN(tsi_tcp_restart)
{
	if (self->accepted >= 0)
		close(self->accepted);
	if (self->listener >= 0)
		close(self->listener);
	if (self->control >= 0) {
		host(_metadata, self, RESET, 0, 0, NULL);
		close(self->control);
	}
}

static int accept_host(struct __test_metadata *_metadata,
		       struct _test_data_tsi_tcp_restart *self, unsigned int slot,
		       unsigned int *peer)
{
	struct pollfd pfd = { .fd = self->listener, .events = POLLIN };
	int accepted;

	ASSERT_EQ(host(_metadata, self, CONNECT, slot, 0, peer), 0);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	accepted = accept(self->listener, NULL, NULL);
	ASSERT_GE(accepted, 0);
	return accepted;
}

static void exchange(struct __test_metadata *_metadata,
		     struct _test_data_tsi_tcp_restart *self, int accepted,
		     unsigned int slot, unsigned char tag)
{
	struct pollfd pfd = { .fd = accepted, .events = POLLIN };
	unsigned int value;
	unsigned char byte;

	ASSERT_EQ(host(_metadata, self, SEND, slot, tag, NULL), 0);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_EQ(recv(accepted, &byte, 1, 0), 1);
	ASSERT_EQ(byte, tag);
	ASSERT_EQ(send(accepted, &tag, 1, MSG_NOSIGNAL), 1);
	ASSERT_EQ(host(_metadata, self, RECEIVE, slot, 0, &value), 1);
	ASSERT_EQ(value, tag);
}

static void restart(struct __test_metadata *_metadata,
		    struct _test_data_tsi_tcp_restart *self,
		    const struct _fixture_variant_tsi_tcp_restart *variant,
		    bool old_connection)
{
	struct timespec start;
	unsigned int listening = 1;
	int accepted, error;

	clock_gettime(CLOCK_MONOTONIC, &start);
	ASSERT_EQ(close(self->listener), 0);
	self->listener = -1;
	do {
		ASSERT_EQ(host(_metadata, self, LISTENING, 0, 0, &listening), 0);
		if (!listening)
			break;
		usleep(1000);
	} while (elapsed_ms(start) < 1000);
	ASSERT_EQ(listening, 0U);
	self->listener = new_listener(self, variant);
	error = errno;
	TH_LOG("replacement after %ld ms: fd=%d errno=%d", elapsed_ms(start),
	       self->listener, self->listener < 0 ? error : 0);
	/* Native controls without either reuse flag must report port ownership. */
	if (self->native && old_connection && !variant->reuseaddr) {
		ASSERT_EQ(self->listener, -1);
		ASSERT_EQ(error, EADDRINUSE);
		return;
	}
	ASSERT_GE(self->listener, 0);
	ASSERT_LT(elapsed_ms(start), 1000);
	for (int i = 0; i < 8; i++) {
		accepted = accept_host(_metadata, self, 1, NULL);
		exchange(_metadata, self, accepted, 1, 'A' + i);
		ASSERT_EQ(host(_metadata, self, CLOSE, 1, 0, NULL), 0);
		close(accepted);
	}
}

TEST_F_TIMEOUT(tsi_tcp_restart, idle_listener, 10)
{
	restart(_metadata, self, variant, false);
}

static void interrupted(int sig)
{
	(void)sig;
}

struct accept_worker {
	int listener;
	int result;
	int error;
	pid_t tid;
	pthread_barrier_t barrier;
};

static void *blocked_accept(void *arg)
{
	struct accept_worker *worker = arg;

	worker->tid = gettid();
	pthread_barrier_wait(&worker->barrier);
	worker->result = accept(worker->listener, NULL, NULL);
	worker->error = errno;
	return NULL;
}

TEST_F_TIMEOUT(tsi_tcp_restart, interrupted_accept, 10)
{
	struct sigaction action = { .sa_handler = interrupted };
	struct accept_worker worker = { .listener = self->listener };
	pthread_t thread;
	char path[80];
	long nr = -1;
	FILE *file;

	ASSERT_EQ(sigaction(SIGUSR1, &action, NULL), 0);
	ASSERT_EQ(pthread_barrier_init(&worker.barrier, NULL, 2), 0);
	ASSERT_EQ(pthread_create(&thread, NULL, blocked_accept, &worker), 0);
	pthread_barrier_wait(&worker.barrier);
	snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", worker.tid);
	for (int i = 0; i < 1000; i++) {
		file = fopen(path, "r");
		ASSERT_NE(file, NULL);
		if (fscanf(file, "%ld", &nr) != 1)
			nr = -1;
		fclose(file);
		if (nr == SYS_accept)
			break;
		usleep(1000);
	}
	ASSERT_EQ(nr, SYS_accept);
	ASSERT_EQ(pthread_kill(thread, SIGUSR1), 0);
	ASSERT_EQ(pthread_join(thread, NULL), 0);
	ASSERT_EQ(worker.result, -1);
	ASSERT_EQ(worker.error, EINTR);
	ASSERT_EQ(pthread_barrier_destroy(&worker.barrier), 0);
	restart(_metadata, self, variant, false);
}

TEST_F_TIMEOUT(tsi_tcp_restart, accepted_connection_survives, 10)
{
	self->accepted = accept_host(_metadata, self, 0, NULL);
	exchange(_metadata, self, self->accepted, 0, 'O');
	restart(_metadata, self, variant, true);
	exchange(_metadata, self, self->accepted, 0, 'S');
}

TEST_F_TIMEOUT(tsi_tcp_restart, host_time_wait, 10)
{
	struct pollfd pfd;
	struct timespec start;
	unsigned int peer, waiting = 0;
	char byte;

	self->accepted = accept_host(_metadata, self, 0, &peer);
	exchange(_metadata, self, self->accepted, 0, 'T');
	ASSERT_EQ(shutdown(self->accepted, SHUT_WR), 0);
	ASSERT_EQ(host(_metadata, self, RECEIVE, 0, 0, NULL), 0);
	ASSERT_EQ(host(_metadata, self, CLOSE, 0, 0, NULL), 0);
	pfd = (struct pollfd) { .fd = self->accepted, .events = POLLIN };
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_EQ(recv(self->accepted, &byte, 1, 0), 0);
	close(self->accepted);
	self->accepted = -1;
	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		ASSERT_EQ(host(_metadata, self, TIME_WAIT, 0, peer, &waiting), 0);
		if (waiting)
			break;
		usleep(1000);
	} while (elapsed_ms(start) < 1000);
	ASSERT_EQ(waiting, 1U);
	TH_LOG("host TIME_WAIT verified for server=%u client=%u", self->port, peer);
	restart(_metadata, self, variant, true);
}

TEST_F_TIMEOUT(tsi_tcp_restart, publication_failure_policy, 10)
{
	bool strict = getenv("TSI_TCP_PUBLICATION_STRICT") != NULL;
	struct pollfd pfd;
	struct timespec start;
	unsigned int listening;
	socklen_t len = sizeof(int);
	int value, client, accepted;
	char byte;

	if (self->native)
		SKIP(return, "publication policy requires separate guest/host port spaces");
	ASSERT_EQ(close(self->listener), 0);
	self->listener = -1;
	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		ASSERT_EQ(host(_metadata, self, LISTENING, 0, 0, &listening), 0);
		if (!listening)
			break;
		usleep(1000);
	} while (elapsed_ms(start) < 1000);
	ASSERT_EQ(listening, 0U);
	ASSERT_EQ(host(_metadata, self, OCCUPY, 0, 0, NULL), 0);
	self->listener = bound_socket(self, variant);
	ASSERT_GE(self->listener, 0);
	if (strict) {
		ASSERT_EQ(listen(self->listener, 8), -1);
		ASSERT_EQ(errno, EADDRINUSE);
		ASSERT_EQ(getsockopt(self->listener, SOL_SOCKET, SO_ACCEPTCONN, &value, &len), 0);
		EXPECT_EQ(value, 0);
		client = socket(variant->family, SOCK_STREAM, 0);
		ASSERT_GE(client, 0);
		EXPECT_EQ(connect(client, (void *)&self->addr, self->len), -1);
		EXPECT_EQ(errno, ECONNREFUSED);
		close(client);
	} else {
		ASSERT_EQ(listen(self->listener, 8), 0);
		ASSERT_EQ(getsockopt(self->listener, SOL_SOCKET, SO_ACCEPTCONN, &value, &len), 0);
		EXPECT_EQ(value, 1);
		client = socket(variant->family, SOCK_STREAM, 0);
		ASSERT_GE(client, 0);
		ASSERT_EQ(connect(client, (void *)&self->addr, self->len), 0);
		accepted = accept(self->listener, NULL, NULL);
		ASSERT_GE(accepted, 0);
		ASSERT_EQ(send(accepted, "L", 1, MSG_NOSIGNAL), 1);
		pfd = (struct pollfd) { .fd = client, .events = POLLIN };
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recv(client, &byte, 1, 0), 1);
		EXPECT_EQ(byte, 'L');
		close(client);
		pfd.fd = accepted;
		ASSERT_EQ(poll(&pfd, 1, 1000), 1);
		ASSERT_EQ(recv(accepted, &byte, 1, 0), 0);
		close(accepted);
	}
	ASSERT_EQ(host(_metadata, self, UNBLOCK, 0, 0, NULL), 0);
	if (!strict) {
		ASSERT_EQ(host(_metadata, self, LISTENING, 0, 0, &listening), 0);
		EXPECT_EQ(listening, 0U);
		close(self->listener);
		self->listener = bound_socket(self, variant);
		ASSERT_GE(self->listener, 0);
	}
	/* Strict failure can be retried after the conflict is removed. */
	ASSERT_EQ(listen(self->listener, 8), 0);
	self->accepted = accept_host(_metadata, self, 0, NULL);
	exchange(_metadata, self, self->accepted, 0, 'P');
}

TEST_HARNESS_MAIN
