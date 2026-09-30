// SPDX-License-Identifier: GPL-2.0-only
/*
 * Run with INET impersonation allowed by the VMM and tsi_hijack=0 in the
 * guest. Explicit TSI families keep native controls in the same kernel.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include "../kselftest_harness.h"
#include "tsi_test.h"

FIXTURE(tsi_stream)
{
	int fd[2];
};

FIXTURE_VARIANT(tsi_stream)
{
	int family;
	bool client_tsi;
	bool listener_tsi;
};

FIXTURE_VARIANT_ADD(tsi_stream, native_ipv4)
{
	.family = AF_INET,
};

FIXTURE_VARIANT_ADD(tsi_stream, native_ipv6)
{
	.family = AF_INET6,
};

FIXTURE_VARIANT_ADD(tsi_stream, local_ipv4)
{
	.family = AF_INET,
	.client_tsi = true,
};

FIXTURE_VARIANT_ADD(tsi_stream, local_ipv6)
{
	.family = AF_INET6,
	.client_tsi = true,
};

FIXTURE_VARIANT_ADD(tsi_stream, proxied_ipv4)
{
	.family = AF_INET,
	.client_tsi = true,
	.listener_tsi = true,
};

FIXTURE_VARIANT_ADD(tsi_stream, proxied_ipv6)
{
	.family = AF_INET6,
	.client_tsi = true,
	.listener_tsi = true,
};

FIXTURE_SETUP(tsi_stream)
{
	struct sockaddr_storage addr = {};
	struct sockaddr_in6 *addr6 = (void *)&addr;
	struct sockaddr_in *addr4 = (void *)&addr;
	socklen_t addr_len;
	int family, listener, probe, one = 1;
	FILE *param;
	int hijack;

	self->fd[0] = -1;
	self->fd[1] = -1;
	param = fopen("/sys/module/kernel/parameters/tsi_hijack", "r");
	if (param) {
		hijack = fgetc(param);
		fclose(param);
		if (hijack == 'Y' || hijack == '1')
			SKIP(return, "native controls require tsi_hijack=0");
	}
	family = variant->family == AF_INET ? AF_TSI : AF_TSI6;
	self->fd[0] = socket(variant->client_tsi ? family : variant->family,
			     SOCK_STREAM, 0);
	if (self->fd[0] < 0 && errno == EAFNOSUPPORT)
		SKIP(return, "socket family unavailable");
	ASSERT_GE(self->fd[0], 0) {
		TH_LOG("socket: %s", strerror(errno));
	}
	if (variant->listener_tsi && !getenv("TSI_TEST_LOCAL_ONLY"))
		ASSERT_EQ(tsi_force_proxy(self->fd[0]), 0);

	if (variant->family == AF_INET) {
		addr4->sin_family = AF_INET;
		addr4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_len = sizeof(*addr4);
	} else {
		addr6->sin6_family = AF_INET6;
		addr6->sin6_addr = in6addr_loopback;
		addr_len = sizeof(*addr6);
	}

	/* Choose a concrete port: TSI bind(0) is a separate regression. */
	probe = socket(variant->family, SOCK_STREAM, 0);
	ASSERT_GE(probe, 0);
	ASSERT_EQ(bind(probe, (void *)&addr, addr_len), 0);
	ASSERT_EQ(getsockname(probe, (void *)&addr, &addr_len), 0);
	close(probe);

	listener = socket(variant->listener_tsi ? family : variant->family,
			  SOCK_STREAM, 0);
	ASSERT_GE(listener, 0);
	ASSERT_EQ(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one,
			     sizeof(one)), 0);
	ASSERT_EQ(bind(listener, (void *)&addr, addr_len), 0);
	ASSERT_EQ(listen(listener, 4), 0);
	ASSERT_EQ(connect(self->fd[0], (void *)&addr, addr_len), 0);
	self->fd[1] = accept(listener, NULL, NULL);
	ASSERT_GE(self->fd[1], 0);
	close(listener);
}

FIXTURE_TEARDOWN(tsi_stream)
{
	if (self->fd[0] >= 0)
		close(self->fd[0]);
	if (self->fd[1] >= 0)
		close(self->fd[1]);
}

struct io_worker {
	int fd;
	int done_fd;
	bool shutdown;
	pid_t tid;
	pthread_barrier_t *barrier;
	ssize_t result;
	char byte;
};

static void *receive_byte(void *data)
{
	struct io_worker *worker = data;

	worker->tid = gettid();
	pthread_barrier_wait(worker->barrier);
	worker->result = recv(worker->fd, &worker->byte, 1, 0);
	return NULL;
}

static void *send_or_shutdown(void *data)
{
	struct io_worker *worker = data;

	if (worker->shutdown)
		worker->result = shutdown(worker->fd, SHUT_RD);
	else
		worker->result = send(worker->fd, "S", 1, MSG_NOSIGNAL);
	write(worker->done_fd, "D", 1);
	return NULL;
}

static bool receiver_waiting(pid_t tid)
{
	char path[80];
	FILE *file;
	long nr;
	int ret, i;

	snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", tid);
	for (i = 0; i < 1000; i++) {
		file = fopen(path, "r");
		if (!file)
			return false;
		ret = fscanf(file, "%ld", &nr);
		fclose(file);
		if (ret == 1 && nr == SYS_recvfrom)
			return true;
		usleep(1000);
	}
	return false;
}

static void start_receiver(struct __test_metadata *_metadata,
			   struct io_worker *reader, pthread_t *thread,
			   pthread_barrier_t *barrier)
{
	ASSERT_EQ(pthread_barrier_init(barrier, NULL, 2), 0);
	reader->barrier = barrier;
	ASSERT_EQ(pthread_create(thread, NULL, receive_byte, reader), 0);
	pthread_barrier_wait(barrier);
	ASSERT_TRUE(receiver_waiting(reader->tid));
}

static void receive_concurrently(struct __test_metadata *_metadata,
				int *fds, int endpoint, bool shut, bool close_fd)
{
	struct io_worker reader = { .fd = fds[endpoint] };
	struct io_worker operation = { .fd = fds[endpoint],
				       .shutdown = shut };
	int peer = fds[!endpoint], done[2];
	pthread_t receive_thread, operation_thread;
	pthread_barrier_t barrier;
	struct pollfd pfd;
	bool completed;
	char byte;

	ASSERT_EQ(pipe(done), 0);
	operation.done_fd = done[1];
	start_receiver(_metadata, &reader, &receive_thread, &barrier);
	if (close_fd) {
		fds[endpoint] = dup(reader.fd);
		ASSERT_GE(fds[endpoint], 0);
		ASSERT_EQ(close(reader.fd), 0);
		operation.fd = fds[endpoint];
	}
	ASSERT_EQ(pthread_create(&operation_thread, NULL, send_or_shutdown,
				 &operation), 0);
	pfd = (struct pollfd) { .fd = done[0], .events = POLLIN };
	ASSERT_GE(poll(&pfd, 1, 1000), 0);
	completed = pfd.revents & POLLIN;

	/* Release the receiver even when the operation was blocked by its lock. */
	if (!shut || !completed)
		ASSERT_EQ(send(peer, "R", 1, MSG_NOSIGNAL), 1);
	ASSERT_EQ(pthread_join(receive_thread, NULL), 0);
	ASSERT_EQ(pthread_join(operation_thread, NULL), 0);
	pthread_barrier_destroy(&barrier);
	close(done[0]);
	close(done[1]);

	EXPECT_TRUE(completed);
	EXPECT_EQ(operation.result, shut ? 0 : 1);
	if (!shut) {
		ASSERT_EQ(recv(peer, &byte, 1, 0), 1);
		EXPECT_EQ(byte, 'S');
		EXPECT_EQ(reader.result, 1);
		EXPECT_EQ(reader.byte, 'R');
	} else if (completed) {
		EXPECT_EQ(reader.result, 0);
	}
}

static void receive_last_close(struct __test_metadata *_metadata,
			       int *fds, int endpoint)
{
	struct io_worker reader = { .fd = fds[endpoint] };
	pthread_barrier_t barrier;
	pthread_t thread;

	start_receiver(_metadata, &reader, &thread, &barrier);
	ASSERT_EQ(close(fds[endpoint]), 0);
	fds[endpoint] = -1;
	ASSERT_EQ(send(fds[!endpoint], "R", 1, MSG_NOSIGNAL), 1);
	ASSERT_EQ(pthread_join(thread, NULL), 0);
	pthread_barrier_destroy(&barrier);
	EXPECT_EQ(reader.result, 1);
	EXPECT_EQ(reader.byte, 'R');
}

TEST_F_TIMEOUT(tsi_stream, client_receive_send, 5)
{
	receive_concurrently(_metadata, self->fd, 0, false, false);
}

TEST_F_TIMEOUT(tsi_stream, timeout_after_connect, 3)
{
	struct timeval timeout = { .tv_usec = 100000 }, observed = {};
	socklen_t len;
	int i;
	char byte;

	for (i = 0; i < 2; i++) {
		ASSERT_EQ(setsockopt(self->fd[i], SOL_SOCKET, SO_RCVTIMEO,
				     &timeout, sizeof(timeout)), 0);
		len = sizeof(observed);
		ASSERT_EQ(getsockopt(self->fd[i], SOL_SOCKET, SO_RCVTIMEO,
				     &observed, &len), 0);
		EXPECT_EQ(observed.tv_sec, timeout.tv_sec);
		EXPECT_EQ(observed.tv_usec, timeout.tv_usec);
		ASSERT_EQ(setsockopt(self->fd[i], SOL_SOCKET, SO_SNDTIMEO,
				     &timeout, sizeof(timeout)), 0);
		len = sizeof(observed);
		ASSERT_EQ(getsockopt(self->fd[i], SOL_SOCKET, SO_SNDTIMEO,
				     &observed, &len), 0);
		EXPECT_EQ(observed.tv_sec, timeout.tv_sec);
		EXPECT_EQ(observed.tv_usec, timeout.tv_usec);
		EXPECT_EQ(recv(self->fd[i], &byte, sizeof(byte), 0), -1);
		EXPECT_EQ(errno, EAGAIN);
	}
}

TEST_F_TIMEOUT(tsi_stream, accepted_receive_send, 5)
{
	receive_concurrently(_metadata, self->fd, 1, false, false);
}

TEST_F_TIMEOUT(tsi_stream, client_receive_shutdown, 5)
{
	receive_concurrently(_metadata, self->fd, 0, true, false);
}

TEST_F_TIMEOUT(tsi_stream, accepted_receive_shutdown, 5)
{
	receive_concurrently(_metadata, self->fd, 1, true, false);
}

TEST_F_TIMEOUT(tsi_stream, client_receive_close_send, 5)
{
	receive_concurrently(_metadata, self->fd, 0, false, true);
}

TEST_F_TIMEOUT(tsi_stream, accepted_receive_close_shutdown, 5)
{
	receive_concurrently(_metadata, self->fd, 1, true, true);
}

TEST_F_TIMEOUT(tsi_stream, client_receive_last_close, 5)
{
	receive_last_close(_metadata, self->fd, 0);
}

TEST_F_TIMEOUT(tsi_stream, accepted_receive_last_close, 5)
{
	receive_last_close(_metadata, self->fd, 1);
}

TEST_HARNESS_MAIN
