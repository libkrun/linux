// SPDX-License-Identifier: GPL-2.0-only
/* Run with VMM INET impersonation enabled and guest tsi_hijack=0. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include "../kselftest_harness.h"
#include "tsi_test.h"

FIXTURE(tsi_accept)
{
	int listener;
	struct sockaddr_storage addr;
	socklen_t addr_len;
};

FIXTURE_VARIANT(tsi_accept)
{
	int family;
	bool tsi;
};

FIXTURE_VARIANT_ADD(tsi_accept, native_ipv4) { .family = AF_INET };
FIXTURE_VARIANT_ADD(tsi_accept, native_ipv6) { .family = AF_INET6 };
FIXTURE_VARIANT_ADD(tsi_accept, tsi_ipv4) { .family = AF_INET, .tsi = true };
FIXTURE_VARIANT_ADD(tsi_accept, tsi_ipv6) { .family = AF_INET6, .tsi = true };

static void interrupted(int sig)
{
	(void)sig;
}

FIXTURE_SETUP(tsi_accept)
{
	struct sockaddr_in6 *addr6 = (void *)&self->addr;
	struct sockaddr_in *addr4 = (void *)&self->addr;
	struct sigaction action = { .sa_handler = interrupted };
	int family, probe, one = 1;
	FILE *param;

	self->listener = -1;
	param = fopen("/sys/module/kernel/parameters/tsi_hijack", "r");
	if (param) {
		int enabled = fgetc(param);

		fclose(param);
		if (enabled == 'Y' || enabled == '1')
			SKIP(return, "native controls require tsi_hijack=0");
	}
	family = variant->family;
	if (variant->tsi)
		family = family == AF_INET ? AF_TSI : AF_TSI6;
	self->listener = socket(family, SOCK_STREAM, 0);
	if (self->listener < 0 && errno == EAFNOSUPPORT)
		SKIP(return, "socket family unavailable");
	ASSERT_GE(self->listener, 0);
	ASSERT_EQ(sigaction(SIGUSR1, &action, NULL), 0);

	if (variant->family == AF_INET) {
		addr4->sin_family = AF_INET;
		addr4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		self->addr_len = sizeof(*addr4);
	} else {
		addr6->sin6_family = AF_INET6;
		addr6->sin6_addr = in6addr_loopback;
		self->addr_len = sizeof(*addr6);
	}
	probe = socket(variant->family, SOCK_STREAM, 0);
	ASSERT_GE(probe, 0);
	ASSERT_EQ(bind(probe, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(getsockname(probe, (void *)&self->addr, &self->addr_len), 0);
	close(probe);
	ASSERT_EQ(setsockopt(self->listener, SOL_SOCKET, SO_REUSEADDR, &one,
			     sizeof(one)), 0);
	ASSERT_EQ(bind(self->listener, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(listen(self->listener, 16), 0);
}

FIXTURE_TEARDOWN(tsi_accept)
{
	if (self->listener >= 0)
		close(self->listener);
}

enum operation {
	ACCEPT,
	GETNAME,
	GETPEERNAME,
	SHUTDOWN,
};

struct worker {
	int fd;
	int flags;
	int result;
	int error;
	int done[2];
	pid_t tid;
	enum operation operation;
	pthread_t thread;
	pthread_barrier_t barrier;
};

static void *operate(void *data)
{
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	struct worker *worker = data;

	worker->tid = gettid();
	pthread_barrier_wait(&worker->barrier);
	switch (worker->operation) {
	case ACCEPT:
		worker->result = accept4(worker->fd, NULL, NULL, worker->flags);
		break;
	case GETNAME:
		worker->result = getsockname(worker->fd, (void *)&addr, &len);
		break;
	case GETPEERNAME:
		worker->result = getpeername(worker->fd, (void *)&addr, &len);
		break;
	case SHUTDOWN:
		worker->result = shutdown(worker->fd, SHUT_RD);
		break;
	}
	worker->error = errno;
	write(worker->done[1], "D", 1);
	return NULL;
}

static void start_worker(struct __test_metadata *_metadata, struct worker *worker,
			 int fd, enum operation operation)
{
	worker->fd = fd;
	worker->operation = operation;
	ASSERT_EQ(pipe(worker->done), 0);
	ASSERT_EQ(pthread_barrier_init(&worker->barrier, NULL, 2), 0);
	ASSERT_EQ(pthread_create(&worker->thread, NULL, operate, worker), 0);
	pthread_barrier_wait(&worker->barrier);
}

static void wait_accept(struct __test_metadata *_metadata, struct worker *worker)
{
	char path[80];
	FILE *file;
	long nr = -1;
	int i;

	snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", worker->tid);
	for (i = 0; i < 1000; i++) {
		file = fopen(path, "r");
		ASSERT_NE(file, NULL);
		if (fscanf(file, "%ld", &nr) != 1)
			nr = -1;
		fclose(file);
		if (nr == SYS_accept4)
			return;
		usleep(1000);
	}
	ASSERT_EQ(nr, SYS_accept4);
}

static bool ready(int fd, int timeout)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	return poll(&pfd, 1, timeout) == 1 && (pfd.revents & POLLIN);
}

static void join_worker(struct __test_metadata *_metadata, struct worker *worker)
{
	ASSERT_EQ(pthread_join(worker->thread, NULL), 0);
	pthread_barrier_destroy(&worker->barrier);
	close(worker->done[0]);
	close(worker->done[1]);
}

static int connect_client(struct __test_metadata *_metadata, int family,
			 struct sockaddr_storage *addr, socklen_t addr_len)
{
	int fd = socket(family, SOCK_STREAM, 0);

	ASSERT_GE(fd, 0);
	if ((family == AF_TSI || family == AF_TSI6) &&
	    !getenv("TSI_TEST_LOCAL_ONLY"))
		ASSERT_EQ(tsi_force_proxy(fd), 0);
	ASSERT_EQ(connect(fd, (void *)addr, addr_len), 0);
	return fd;
}

TEST_F_TIMEOUT(tsi_accept, concurrent_getsockname, 5)
{
	struct worker acceptor = {}, name = {};
	bool completed;

	start_worker(_metadata, &acceptor, self->listener, ACCEPT);
	wait_accept(_metadata, &acceptor);
	start_worker(_metadata, &name, self->listener, GETNAME);
	completed = ready(name.done[0], 1000);
	ASSERT_EQ(pthread_kill(acceptor.thread, SIGUSR1), 0);
	join_worker(_metadata, &acceptor);
	join_worker(_metadata, &name);
	EXPECT_TRUE(completed);
	EXPECT_EQ(name.result, 0);
	EXPECT_EQ(acceptor.result, -1);
	EXPECT_EQ(acceptor.error, EINTR);
}

TEST_F_TIMEOUT(tsi_accept, shutdown_wakes_accept, 5)
{
	struct worker acceptor = {}, shutdown = {};
	bool completed, woke = false;

	start_worker(_metadata, &acceptor, self->listener, ACCEPT);
	wait_accept(_metadata, &acceptor);
	start_worker(_metadata, &shutdown, self->listener, SHUTDOWN);
	completed = ready(shutdown.done[0], 1000);
	if (completed)
		woke = ready(acceptor.done[0], 1000);
	if (!woke)
		ASSERT_EQ(pthread_kill(acceptor.thread, SIGUSR1), 0);
	join_worker(_metadata, &acceptor);
	join_worker(_metadata, &shutdown);
	EXPECT_TRUE(completed);
	EXPECT_TRUE(woke);
	EXPECT_EQ(shutdown.result, 0);
	EXPECT_EQ(acceptor.result, -1);
	EXPECT_EQ(acceptor.error, EINVAL);
}

TEST_F_TIMEOUT(tsi_accept, nonblocking_empty, 5)
{
	ASSERT_EQ(fcntl(self->listener, F_SETFL, O_NONBLOCK), 0);
	EXPECT_EQ(accept4(self->listener, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EAGAIN);
}

TEST_F_TIMEOUT(tsi_accept, listening_state, 5)
{
	socklen_t len = sizeof(int);
	int value;

	ASSERT_EQ(getsockopt(self->listener, SOL_SOCKET, SO_ACCEPTCONN,
			     &value, &len), 0);
	EXPECT_EQ(value, 1);
}

TEST_F_TIMEOUT(tsi_accept, receive_timeout, 5)
{
	struct timeval timeout = { .tv_usec = 100000 };

	ASSERT_EQ(setsockopt(self->listener, SOL_SOCKET, SO_RCVTIMEO,
			     &timeout, sizeof(timeout)), 0);
	EXPECT_EQ(accept4(self->listener, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EAGAIN);
}

TEST_F_TIMEOUT(tsi_accept, signal_with_timeout, 5)
{
	struct sigaction action = { .sa_handler = interrupted,
				    .sa_flags = SA_RESTART };
	struct timeval timeout = { .tv_sec = 10 };
	struct worker acceptor = {};
	bool completed;

	ASSERT_EQ(sigaction(SIGUSR1, &action, NULL), 0);
	ASSERT_EQ(setsockopt(self->listener, SOL_SOCKET, SO_RCVTIMEO,
			     &timeout, sizeof(timeout)), 0);
	start_worker(_metadata, &acceptor, self->listener, ACCEPT);
	wait_accept(_metadata, &acceptor);
	ASSERT_EQ(pthread_kill(acceptor.thread, SIGUSR1), 0);
	completed = ready(acceptor.done[0], 1000);
	if (!completed) {
		action.sa_flags = 0;
		ASSERT_EQ(sigaction(SIGUSR1, &action, NULL), 0);
		ASSERT_EQ(pthread_kill(acceptor.thread, SIGUSR1), 0);
	}
	join_worker(_metadata, &acceptor);
	EXPECT_TRUE(completed);
	EXPECT_EQ(acceptor.result, -1);
	EXPECT_EQ(acceptor.error, EINTR);
}

TEST_F_TIMEOUT(tsi_accept, concurrent_getpeername, 5)
{
	struct worker acceptor = {}, name = {};
	int family = variant->family, client, accepted;
	bool completed;

	if (variant->tsi)
		family = family == AF_INET ? AF_TSI : AF_TSI6;
	/* Poll a pending connection to exercise the proxied getname path. */
	client = connect_client(_metadata, family, &self->addr, self->addr_len);
	ASSERT_TRUE(ready(self->listener, 1000));
	accepted = accept4(self->listener, NULL, NULL, 0);
	ASSERT_GE(accepted, 0);
	close(accepted);
	close(client);
	start_worker(_metadata, &acceptor, self->listener, ACCEPT);
	wait_accept(_metadata, &acceptor);
	start_worker(_metadata, &name, self->listener, GETPEERNAME);
	completed = ready(name.done[0], 1000);
	ASSERT_EQ(pthread_kill(acceptor.thread, SIGUSR1), 0);
	join_worker(_metadata, &acceptor);
	join_worker(_metadata, &name);
	EXPECT_TRUE(completed);
	EXPECT_EQ(name.result, -1);
	EXPECT_EQ(name.error, ENOTCONN);
}

TEST_F_TIMEOUT(tsi_accept, nonblocking_drain, 5)
{
	int family = variant->family, client, accepted;

	if (variant->tsi)
		family = family == AF_INET ? AF_TSI : AF_TSI6;
	ASSERT_EQ(fcntl(self->listener, F_SETFL, O_NONBLOCK), 0);
	client = connect_client(_metadata, family, &self->addr, self->addr_len);
	ASSERT_TRUE(ready(self->listener, 1000));
	accepted = accept4(self->listener, NULL, NULL, 0);
	ASSERT_GE(accepted, 0);
	EXPECT_EQ(accept4(self->listener, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EAGAIN);
	close(accepted);
	close(client);
}

TEST_F_TIMEOUT(tsi_accept, accepted_nonblock_flag, 5)
{
	struct worker acceptor = { .flags = SOCK_NONBLOCK };
	int family = variant->family, client;

	if (variant->tsi)
		family = family == AF_INET ? AF_TSI : AF_TSI6;
	start_worker(_metadata, &acceptor, self->listener, ACCEPT);
	wait_accept(_metadata, &acceptor);
	EXPECT_FALSE(ready(acceptor.done[0], 0));
	client = connect_client(_metadata, family, &self->addr, self->addr_len);
	join_worker(_metadata, &acceptor);
	ASSERT_GE(acceptor.result, 0);
	EXPECT_NE(fcntl(acceptor.result, F_GETFL) & O_NONBLOCK, 0);
	close(acceptor.result);
	close(client);
}

TEST_F_TIMEOUT(tsi_accept, interrupted_retry, 5)
{
	struct worker acceptor = {};
	int family = variant->family, client, accepted, i;

	if (variant->tsi)
		family = family == AF_INET ? AF_TSI : AF_TSI6;
	for (i = 0; i < 2; i++) {
		start_worker(_metadata, &acceptor, self->listener, ACCEPT);
		wait_accept(_metadata, &acceptor);
		ASSERT_EQ(pthread_kill(acceptor.thread, SIGUSR1), 0);
		join_worker(_metadata, &acceptor);
		EXPECT_EQ(acceptor.result, -1);
		EXPECT_EQ(acceptor.error, EINTR);
	}
	client = connect_client(_metadata, family, &self->addr, self->addr_len);
	accepted = accept4(self->listener, NULL, NULL, 0);
	ASSERT_GE(accepted, 0);
	close(accepted);
	close(client);
}

TEST_F_TIMEOUT(tsi_accept, interrupted_close_rebind, 10)
{
	struct worker acceptor = {};
	int family = variant->family, client, accepted, one = 1, i;
	int received = 0;

	if (variant->tsi)
		family = family == AF_INET ? AF_TSI : AF_TSI6;
	start_worker(_metadata, &acceptor, self->listener, ACCEPT);
	wait_accept(_metadata, &acceptor);
	ASSERT_EQ(pthread_kill(acceptor.thread, SIGUSR1), 0);
	join_worker(_metadata, &acceptor);
	ASSERT_EQ(acceptor.result, -1);
	ASSERT_EQ(acceptor.error, EINTR);
	ASSERT_EQ(close(self->listener), 0);
	self->listener = socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	ASSERT_GE(self->listener, 0);
	ASSERT_EQ(setsockopt(self->listener, SOL_SOCKET, SO_REUSEADDR, &one,
			     sizeof(one)), 0);
	ASSERT_EQ(bind(self->listener, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(listen(self->listener, 16), 0);
	for (i = 0; i < 16; i++) {
		client = connect_client(_metadata, family, &self->addr, self->addr_len);
		if (ready(self->listener, 100)) {
			accepted = accept4(self->listener, NULL, NULL, 0);
			if (accepted >= 0) {
				received++;
				close(accepted);
			}
		}
		close(client);
	}
	EXPECT_EQ(received, 16);
}

TEST_F_TIMEOUT(tsi_accept, concurrent_acceptors, 5)
{
	struct worker acceptors[3] = {};
	int family = variant->family, clients[3], i;

	if (variant->tsi)
		family = family == AF_INET ? AF_TSI : AF_TSI6;
	for (i = 0; i < 3; i++) {
		start_worker(_metadata, &acceptors[i], self->listener, ACCEPT);
		wait_accept(_metadata, &acceptors[i]);
	}
	for (i = 0; i < 3; i++)
		clients[i] = connect_client(_metadata, family, &self->addr, self->addr_len);
	for (i = 0; i < 3; i++) {
		join_worker(_metadata, &acceptors[i]);
		ASSERT_GE(acceptors[i].result, 0);
		close(acceptors[i].result);
		close(clients[i]);
	}
}

TEST_HARNESS_MAIN
