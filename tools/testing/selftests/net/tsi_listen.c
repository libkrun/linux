// SPDX-License-Identifier: GPL-2.0-only
/*
 * VMM INET and UNIX impersonation enabled, guest automatic hijacking disabled,
 * CONFIG_NETDEVICES=y. Use -f tsi_ipc to select guest-local IPC cases only.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "../kselftest_harness.h"
#include "tsi_test.h"

FIXTURE(tsi_port)
{
	int listener;
	int client;
	struct sockaddr_storage addr;
	socklen_t addr_len;
};

FIXTURE_VARIANT(tsi_port)
{
	int family;
	bool tsi;
};

FIXTURE_VARIANT_ADD(tsi_port, native_ipv4) { .family = AF_INET };
FIXTURE_VARIANT_ADD(tsi_port, native_ipv6) { .family = AF_INET6 };
FIXTURE_VARIANT_ADD(tsi_port, tsi_ipv4) { .family = AF_INET, .tsi = true };
FIXTURE_VARIANT_ADD(tsi_port, tsi_ipv6) { .family = AF_INET6, .tsi = true };

FIXTURE_SETUP(tsi_port)
{
	struct sockaddr_in6 *addr6 = (void *)&self->addr;
	struct sockaddr_in *addr4 = (void *)&self->addr;
	int family = variant->family;
	FILE *param;

	self->listener = -1;
	self->client = -1;
	param = fopen("/sys/module/kernel/parameters/tsi_hijack", "r");
	if (param) {
		int enabled = fgetc(param);

		fclose(param);
		if (enabled == 'Y' || enabled == '1')
			SKIP(return, "native controls require tsi_hijack=0");
	}
	if (variant->tsi)
		family = family == AF_INET ? AF_TSI : AF_TSI6;
	self->listener = socket(family, SOCK_STREAM, 0);
	if (self->listener < 0 && errno == EAFNOSUPPORT)
		SKIP(return, "socket family unavailable");
	ASSERT_GE(self->listener, 0);
	if (variant->family == AF_INET) {
		addr4->sin_family = AF_INET;
		addr4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		self->addr_len = sizeof(*addr4);
	} else {
		addr6->sin6_family = AF_INET6;
		addr6->sin6_addr = in6addr_loopback;
		self->addr_len = sizeof(*addr6);
	}
	ASSERT_EQ(bind(self->listener, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(getsockname(self->listener, (void *)&self->addr,
			      &self->addr_len), 0);
	ASSERT_NE(variant->family == AF_INET ? addr4->sin_port : addr6->sin6_port, 0);
	self->client = socket(family, SOCK_STREAM, 0);
	ASSERT_GE(self->client, 0);
	if (variant->tsi)
		ASSERT_EQ(tsi_force_proxy(self->client), 0);
}

FIXTURE_TEARDOWN(tsi_port)
{
	if (self->client >= 0)
		close(self->client);
	if (self->listener >= 0)
		close(self->listener);
}

TEST_F_TIMEOUT(tsi_port, advertised_port_accepts, 5)
{
	struct sockaddr_storage after = {};
	socklen_t len = sizeof(after);
	struct pollfd pfd = { .fd = self->listener, .events = POLLIN };
	int accepted;
	char byte;

	ASSERT_EQ(listen(self->listener, 4), 0);
	ASSERT_EQ(getsockname(self->listener, (void *)&after, &len), 0);
	ASSERT_EQ(len, self->addr_len);
	ASSERT_EQ(memcmp(&after, &self->addr, len), 0);
	/* Updating the backlog must preserve the allocated guest/host port. */
	ASSERT_EQ(listen(self->listener, 8), 0);
	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_TRUE(pfd.revents & POLLIN);
	accepted = accept(self->listener, NULL, NULL);
	ASSERT_GE(accepted, 0);
	ASSERT_EQ(send(self->client, "P", 1, MSG_NOSIGNAL), 1);
	ASSERT_EQ(recv(accepted, &byte, 1, 0), 1);
	EXPECT_EQ(byte, 'P');
	close(accepted);
}

static void check_connection(struct __test_metadata *_metadata, int listener,
			     int client, const struct sockaddr_storage *addr,
			     socklen_t addr_len)
{
	struct sockaddr_storage local = {};
	struct pollfd pfd = { .fd = listener, .events = POLLIN };
	socklen_t len = sizeof(local);
	int accepted;
	char byte;

	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_TRUE(pfd.revents & POLLIN);
	accepted = accept(listener, NULL, NULL);
	ASSERT_GE(accepted, 0);
	ASSERT_EQ(getsockname(accepted, (void *)&local, &len), 0);
	EXPECT_EQ(len, addr_len);
	EXPECT_EQ(memcmp(&local, addr, addr_len), 0);
	ASSERT_EQ(send(client, "C", 1, MSG_NOSIGNAL), 1);
	ASSERT_EQ(recv(accepted, &byte, 1, 0), 1);
	EXPECT_EQ(byte, 'C');
	ASSERT_EQ(send(accepted, "A", 1, MSG_NOSIGNAL), 1);
	ASSERT_EQ(recv(client, &byte, 1, 0), 1);
	EXPECT_EQ(byte, 'A');
	close(accepted);
}

TEST_F_TIMEOUT(tsi_port, accepted_name, 5)
{
	ASSERT_EQ(listen(self->listener, 8), 0);
	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	check_connection(_metadata, self->listener, self->client,
			 &self->addr, self->addr_len);
}

TEST_F_TIMEOUT(tsi_port, endpoint_names_match, 5)
{
	struct sockaddr_storage client_local = {}, server_peer = {};
	struct sockaddr_storage server_local = {}, client_peer = {};
	socklen_t cl = sizeof(client_local), sp = sizeof(server_peer);
	socklen_t sl = sizeof(server_local), cp = sizeof(client_peer);
	struct pollfd pfd = { .fd = self->listener, .events = POLLIN };
	int accepted;

	ASSERT_EQ(listen(self->listener, 8), 0);
	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	accepted = accept(self->listener, NULL, NULL);
	ASSERT_GE(accepted, 0);
	ASSERT_EQ(getsockname(self->client, (void *)&client_local, &cl), 0);
	ASSERT_EQ(getpeername(accepted, (void *)&server_peer, &sp), 0);
	ASSERT_EQ(getsockname(accepted, (void *)&server_local, &sl), 0);
	ASSERT_EQ(getpeername(self->client, (void *)&client_peer, &cp), 0);
	EXPECT_EQ(cl, sp);
	EXPECT_EQ(memcmp(&client_local, &server_peer, cl), 0);
	EXPECT_EQ(sl, cp);
	EXPECT_EQ(memcmp(&server_local, &client_peer, sl), 0);
	close(accepted);
}

TEST_F_TIMEOUT(tsi_port, wildcard_accept_name, 5)
{
	struct sockaddr_storage bound = self->addr, peer, local;
	socklen_t len = sizeof(local);
	struct pollfd pfd = { .events = POLLIN };
	int family = variant->family;
	int accepted;

	close(self->listener);
	self->listener = -1;
	if (variant->tsi)
		family = family == AF_INET ? AF_TSI : AF_TSI6;
	self->listener = socket(family, SOCK_STREAM, 0);
	ASSERT_GE(self->listener, 0);
	if (variant->family == AF_INET) {
		((struct sockaddr_in *)&bound)->sin_addr.s_addr = htonl(INADDR_ANY);
		((struct sockaddr_in *)&bound)->sin_port = 0;
	} else {
		((struct sockaddr_in6 *)&bound)->sin6_addr = in6addr_any;
		((struct sockaddr_in6 *)&bound)->sin6_port = 0;
	}
	ASSERT_EQ(bind(self->listener, (void *)&bound, self->addr_len), 0);
	len = sizeof(bound);
	ASSERT_EQ(getsockname(self->listener, (void *)&bound, &len), 0);
	ASSERT_EQ(listen(self->listener, 8), 0);
	peer = bound;
	if (variant->family == AF_INET)
		((struct sockaddr_in *)&peer)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	else
		((struct sockaddr_in6 *)&peer)->sin6_addr = in6addr_loopback;
	ASSERT_EQ(connect(self->client, (void *)&peer, len), 0);
	pfd.fd = self->listener;
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	accepted = accept(self->listener, NULL, NULL);
	ASSERT_GE(accepted, 0);
	memset(&local, 0, sizeof(local));
	len = sizeof(local);
	ASSERT_EQ(getsockname(accepted, (void *)&local, &len), 0);
	EXPECT_EQ(len, self->addr_len);
	EXPECT_EQ(memcmp(&local, &peer, len), 0);
	/* Accepting must not replace the listener's wildcard bind identity. */
	len = sizeof(local);
	ASSERT_EQ(getsockname(self->listener, (void *)&local, &len), 0);
	EXPECT_EQ(memcmp(&local, &bound, len), 0);
	close(accepted);
}

TEST_F_TIMEOUT(tsi_port, explicit_bind_keeps_port, 5)
{
	struct sockaddr_storage bound = self->addr, actual = {}, expected;
	socklen_t len = self->addr_len;
	struct pollfd pfd = { .fd = self->listener, .events = POLLIN };
	int accepted, any = 0;

	if (variant->family == AF_INET) {
		((struct sockaddr_in *)&bound)->sin_addr.s_addr = htonl(INADDR_ANY);
		((struct sockaddr_in *)&bound)->sin_port = 0;
	} else {
		((struct sockaddr_in6 *)&bound)->sin6_addr = in6addr_any;
		((struct sockaddr_in6 *)&bound)->sin6_port = 0;
	}
	if (variant->tsi)
		ASSERT_EQ(setsockopt(self->client, SOL_SOCKET, SO_BINDTOIFINDEX,
				     &any, sizeof(any)), 0);
	ASSERT_EQ(bind(self->client, (void *)&bound, len), 0);
	ASSERT_EQ(getsockname(self->client, (void *)&bound, &len), 0);
	if (variant->tsi)
		ASSERT_EQ(tsi_force_proxy(self->client), 0);
	ASSERT_EQ(listen(self->listener, 8), 0);
	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	accepted = accept(self->listener, NULL, NULL);
	ASSERT_GE(accepted, 0);
	ASSERT_EQ(getsockname(self->client, (void *)&actual, &len), 0);
	expected = bound;
	if (variant->family == AF_INET)
		((struct sockaddr_in *)&expected)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	else
		((struct sockaddr_in6 *)&expected)->sin6_addr = in6addr_loopback;
	EXPECT_EQ(memcmp(&actual, &expected, len), 0);
	close(accepted);
}

TEST_F_TIMEOUT(tsi_port, local_name_after_shutdown, 10)
{
	struct sockaddr_storage client_expected = {}, local = {};
	socklen_t len = sizeof(client_expected);
	struct pollfd pfd = { .fd = self->listener, .events = POLLIN };
	int accepted;

	ASSERT_EQ(listen(self->listener, 8), 0);
	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	accepted = accept(self->listener, NULL, NULL);
	ASSERT_GE(accepted, 0);
	ASSERT_EQ(getpeername(accepted, (void *)&client_expected, &len), 0);
	ASSERT_EQ(shutdown(self->client, SHUT_RDWR), 0);
	ASSERT_EQ(shutdown(accepted, SHUT_RDWR), 0);
	/* Exceed the old host's five-second deferred-removal interval. */
	sleep(6);
	len = sizeof(local);
	ASSERT_EQ(getsockname(self->client, (void *)&local, &len), 0);
	EXPECT_EQ(len, self->addr_len);
	EXPECT_EQ(memcmp(&local, &client_expected, len), 0);
	len = sizeof(local);
	ASSERT_EQ(getsockname(accepted, (void *)&local, &len), 0);
	EXPECT_EQ(memcmp(&local, &self->addr, len), 0);
	close(accepted);
}

TEST_F_TIMEOUT(tsi_port, timeout_before_connect, 3)
{
	struct timeval timeout = { .tv_usec = 100000 }, observed = {};
	socklen_t len = sizeof(observed);
	int accepted;
	char byte;

	ASSERT_EQ(setsockopt(self->client, SOL_SOCKET, SO_RCVTIMEO,
			     &timeout, sizeof(timeout)), 0);
	ASSERT_EQ(listen(self->listener, 8), 0);
	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	accepted = accept(self->listener, NULL, NULL);
	ASSERT_GE(accepted, 0);
	ASSERT_EQ(getsockopt(self->client, SOL_SOCKET, SO_RCVTIMEO,
			     &observed, &len), 0);
	EXPECT_EQ(observed.tv_sec, timeout.tv_sec);
	EXPECT_EQ(observed.tv_usec, timeout.tv_usec);
	EXPECT_EQ(recv(self->client, &byte, sizeof(byte), 0), -1);
	EXPECT_EQ(errno, EAGAIN);
	close(accepted);
}

TEST_F_TIMEOUT(tsi_port, mixed_poll, 10)
{
	struct epoll_event event = { .events = EPOLLIN | EPOLLET };
	struct pollfd pfd = { .fd = self->listener, .events = POLLIN };
	int epfd, client, i;

	ASSERT_EQ(listen(self->listener, 8), 0);
	epfd = epoll_create1(0);
	ASSERT_GE(epfd, 0);
	ASSERT_EQ(epoll_ctl(epfd, EPOLL_CTL_ADD, self->listener, &event), 0);
	for (i = 0; i < 8; i++) {
		/* Alternate native guest clients and forced host-proxy clients. */
		client = self->client;
		if (!(i % 2)) {
			client = socket(variant->family, SOCK_STREAM, 0);
			ASSERT_GE(client, 0);
		} else if (i > 1) {
			int family = variant->family;

			if (variant->tsi)
				family = family == AF_INET ? AF_TSI : AF_TSI6;
			self->client = socket(family, SOCK_STREAM, 0);
			client = self->client;
			ASSERT_GE(client, 0);
			if (variant->tsi)
				ASSERT_EQ(tsi_force_proxy(client), 0);
		}
		ASSERT_EQ(connect(client, (void *)&self->addr, self->addr_len), 0);
		ASSERT_EQ(epoll_wait(epfd, &event, 1, 1000), 1);
		ASSERT_NE(event.events & EPOLLIN, 0U);
		check_connection(_metadata, self->listener, client,
				 &self->addr, self->addr_len);
		close(client);
		if (i % 2)
			self->client = -1;
		EXPECT_EQ(poll(&pfd, 1, 0), 0);
	}
	ASSERT_EQ(fcntl(self->listener, F_SETFL, O_NONBLOCK), 0);
	EXPECT_EQ(accept(self->listener, NULL, NULL), -1);
	EXPECT_EQ(errno, EAGAIN);
	close(epfd);
}

struct accept_worker {
	int listener;
	int accepted;
	int error;
	pid_t tid;
	pthread_barrier_t barrier;
};

static void *blocking_accept(void *arg)
{
	struct accept_worker *worker = arg;

	worker->tid = gettid();
	pthread_barrier_wait(&worker->barrier);
	worker->accepted = accept(worker->listener, NULL, NULL);
	worker->error = errno;
	return NULL;
}

static void wait_accept(struct __test_metadata *_metadata, pid_t tid)
{
	char path[80];
	long nr = -1;
	FILE *file;
	int i;

	snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", tid);
	for (i = 0; i < 1000; i++) {
		file = fopen(path, "r");
		ASSERT_NE(file, NULL);
		if (fscanf(file, "%ld", &nr) != 1)
			nr = -1;
		fclose(file);
		if (nr == SYS_accept)
			return;
		usleep(1000);
	}
	ASSERT_EQ(nr, SYS_accept);
}

TEST_F_TIMEOUT(tsi_port, mixed_blocking_accept, 5)
{
	struct accept_worker worker = { .listener = self->listener };
	pthread_t thread;
	int client, i;
	char byte;

	ASSERT_EQ(listen(self->listener, 8), 0);
	for (i = 0; i < 2; i++) {
		ASSERT_EQ(pthread_barrier_init(&worker.barrier, NULL, 2), 0);
		ASSERT_EQ(pthread_create(&thread, NULL, blocking_accept, &worker), 0);
		pthread_barrier_wait(&worker.barrier);
		wait_accept(_metadata, worker.tid);
		client = self->client;
		if (!i) {
			client = socket(variant->family, SOCK_STREAM, 0);
			ASSERT_GE(client, 0);
		}
		ASSERT_EQ(connect(client, (void *)&self->addr, self->addr_len), 0);
		ASSERT_EQ(pthread_join(thread, NULL), 0);
		ASSERT_GE(worker.accepted, 0);
		ASSERT_EQ(send(client, "B", 1, MSG_NOSIGNAL), 1);
		ASSERT_EQ(recv(worker.accepted, &byte, 1, 0), 1);
		EXPECT_EQ(byte, 'B');
		close(worker.accepted);
		if (!i)
			close(client);
		pthread_barrier_destroy(&worker.barrier);
	}
}

TEST_F_TIMEOUT(tsi_port, concurrent_mixed_accept, 5)
{
	struct accept_worker workers[2] = {
		{ .listener = self->listener }, { .listener = self->listener },
	};
	pthread_t threads[2];
	int client, i, seen = 0;
	char byte;

	ASSERT_EQ(listen(self->listener, 8), 0);
	for (i = 0; i < 2; i++) {
		ASSERT_EQ(pthread_barrier_init(&workers[i].barrier, NULL, 2), 0);
		ASSERT_EQ(pthread_create(&threads[i], NULL, blocking_accept,
					 &workers[i]), 0);
		pthread_barrier_wait(&workers[i].barrier);
		wait_accept(_metadata, workers[i].tid);
	}
	client = socket(variant->family, SOCK_STREAM, 0);
	ASSERT_GE(client, 0);
	ASSERT_EQ(connect(client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(send(client, "L", 1, MSG_NOSIGNAL), 1);
	ASSERT_EQ(connect(self->client, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(send(self->client, "P", 1, MSG_NOSIGNAL), 1);
	for (i = 0; i < 2; i++) {
		ASSERT_EQ(pthread_join(threads[i], NULL), 0);
		ASSERT_GE(workers[i].accepted, 0);
		ASSERT_EQ(recv(workers[i].accepted, &byte, 1, 0), 1);
		ASSERT_TRUE(byte == 'L' || byte == 'P');
		seen |= byte == 'L' ? 1 : 2;
		close(workers[i].accepted);
		pthread_barrier_destroy(&workers[i].barrier);
	}
	EXPECT_EQ(seen, 3);
	close(client);
}

FIXTURE(tsi_ipc)
{
	int listener;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	char directory[80];
};

FIXTURE_VARIANT(tsi_ipc)
{
	int family;
	bool tsi;
	bool relative;
	bool abstract;
	bool guest_path;
};

FIXTURE_VARIANT_ADD(tsi_ipc, native_ipv4) { .family = AF_INET };
FIXTURE_VARIANT_ADD(tsi_ipc, native_ipv6) { .family = AF_INET6 };
FIXTURE_VARIANT_ADD(tsi_ipc, tsi_ipv4) { .family = AF_INET, .tsi = true };
FIXTURE_VARIANT_ADD(tsi_ipc, tsi_ipv6) { .family = AF_INET6, .tsi = true };
FIXTURE_VARIANT_ADD(tsi_ipc, native_unix) { .family = AF_UNIX };
FIXTURE_VARIANT_ADD(tsi_ipc, tsi_unix) { .family = AF_UNIX, .tsi = true };
FIXTURE_VARIANT_ADD(tsi_ipc, native_guest_path) {
	.family = AF_UNIX, .guest_path = true,
};
FIXTURE_VARIANT_ADD(tsi_ipc, tsi_guest_path) {
	.family = AF_UNIX, .guest_path = true, .tsi = true,
};
FIXTURE_VARIANT_ADD(tsi_ipc, native_relative) {
	.family = AF_UNIX, .relative = true,
};
FIXTURE_VARIANT_ADD(tsi_ipc, tsi_relative) {
	.family = AF_UNIX, .relative = true, .tsi = true,
};
FIXTURE_VARIANT_ADD(tsi_ipc, native_abstract) {
	.family = AF_UNIX, .abstract = true,
};
FIXTURE_VARIANT_ADD(tsi_ipc, tsi_abstract) {
	.family = AF_UNIX, .abstract = true, .tsi = true,
};

FIXTURE_SETUP(tsi_ipc)
{
	struct sockaddr_in6 *addr6 = (void *)&self->addr;
	struct sockaddr_in *addr4 = (void *)&self->addr;
	struct sockaddr_un *un = (void *)&self->addr;
	int family = variant->family;
	FILE *param;

	self->listener = -1;
	param = fopen(variant->family == AF_UNIX ?
		      "/sys/module/kernel/parameters/tsi_hijack_unix" :
		      "/sys/module/kernel/parameters/tsi_hijack", "r");
	if (param) {
		int enabled = fgetc(param);

		fclose(param);
		if (enabled == 'Y' || enabled == '1')
			SKIP(return, "native controls require automatic hijacking disabled");
	}
	if (variant->tsi) {
		family = family == AF_INET ? AF_TSI :
			 family == AF_INET6 ? AF_TSI6 : AF_TSIU;
	}
	self->listener = socket(family, SOCK_STREAM, 0);
	if (self->listener < 0 && errno == EAFNOSUPPORT)
		SKIP(return, "socket family unavailable");
	ASSERT_GE(self->listener, 0);
	if (variant->family == AF_INET) {
		addr4->sin_family = AF_INET;
		addr4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		self->addr_len = sizeof(*addr4);
	} else if (variant->family == AF_INET6) {
		addr6->sin6_family = AF_INET6;
		addr6->sin6_addr = in6addr_loopback;
		self->addr_len = sizeof(*addr6);
	} else {
		mkdir("/tmp", 0777);
		snprintf(self->directory, sizeof(self->directory), "/tmp/tsi-ipc-XXXXXX");
		ASSERT_NE(mkdtemp(self->directory), NULL);
		un->sun_family = AF_UNIX;
		if (variant->relative) {
			ASSERT_EQ(chdir("/tmp"), 0);
			snprintf(un->sun_path, sizeof(un->sun_path), "%s/socket",
				 self->directory + strlen("/tmp/"));
		} else if (variant->abstract) {
			snprintf(un->sun_path + 1, sizeof(un->sun_path) - 1,
				 "%s", self->directory);
		} else if (variant->guest_path) {
			snprintf(un->sun_path, sizeof(un->sun_path), "%s/socket",
				 self->directory);
		} else {
			snprintf(un->sun_path, sizeof(un->sun_path), "%s.sock",
				 self->directory);
		}
		self->addr_len = offsetof(struct sockaddr_un, sun_path) +
			strlen(un->sun_path + variant->abstract) + 1;
	}
	ASSERT_EQ(bind(self->listener, (void *)&self->addr, self->addr_len), 0);
	ASSERT_EQ(getsockname(self->listener, (void *)&self->addr,
			      &self->addr_len), 0);
	ASSERT_EQ(listen(self->listener, 8), 0);
}

FIXTURE_TEARDOWN(tsi_ipc)
{
	struct sockaddr_un *un = (void *)&self->addr;

	if (self->listener >= 0)
		close(self->listener);
	if (variant->family == AF_UNIX) {
		if (!variant->abstract)
			unlink(un->sun_path);
		chdir("/");
		rmdir(self->directory);
	}
}

static void pass_fd(struct __test_metadata *_metadata, int client, int accepted)
{
	union {
		struct cmsghdr align;
		char bytes[CMSG_SPACE(sizeof(int))];
	} control = {};
	char byte = 'F';
	struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control.bytes, .msg_controllen = sizeof(control) };
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	int pipefd[2], received;

	ASSERT_EQ(pipe(pipefd), 0);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &pipefd[0], sizeof(int));
	ASSERT_EQ(sendmsg(client, &msg, MSG_NOSIGNAL), 1);
	memset(&control, 0, sizeof(control));
	ASSERT_EQ(recvmsg(accepted, &msg, 0), 1);
	ASSERT_EQ(byte, 'F');
	cmsg = CMSG_FIRSTHDR(&msg);
	ASSERT_NE(cmsg, NULL);
	ASSERT_EQ(cmsg->cmsg_level, SOL_SOCKET);
	ASSERT_EQ(cmsg->cmsg_type, SCM_RIGHTS);
	memcpy(&received, CMSG_DATA(cmsg), sizeof(received));
	ASSERT_EQ(write(pipefd[1], "R", 1), 1);
	ASSERT_EQ(read(received, &byte, 1), 1);
	EXPECT_EQ(byte, 'R');
	close(received);
	close(pipefd[0]);
	close(pipefd[1]);
}

static void local_connect(struct __test_metadata *_metadata, int listener,
			  struct sockaddr_storage *addr, socklen_t addr_len,
			  int family)
{
	struct pollfd pfd = { .fd = listener, .events = POLLIN };
	int client, accepted;
	char byte;

	client = socket(family, SOCK_STREAM, 0);
	ASSERT_GE(client, 0);
	ASSERT_EQ(connect(client, (void *)addr, addr_len), 0);
	ASSERT_EQ(poll(&pfd, 1, 1000), 1);
	ASSERT_TRUE(pfd.revents & POLLIN);
	accepted = accept(listener, NULL, NULL);
	ASSERT_GE(accepted, 0);
	ASSERT_EQ(send(client, "L", 1, MSG_NOSIGNAL), 1);
	ASSERT_EQ(recv(accepted, &byte, 1, 0), 1);
	EXPECT_EQ(byte, 'L');
	if (addr->ss_family == AF_UNIX) {
		pass_fd(_metadata, client, accepted);
		pass_fd(_metadata, accepted, client);
	}
	close(client);
	close(accepted);
}

TEST_F_TIMEOUT(tsi_ipc, native_client, 5)
{
	local_connect(_metadata, self->listener, &self->addr, self->addr_len,
		      variant->family);
}

TEST_F_TIMEOUT(tsi_ipc, tsi_client, 5)
{
	int family = variant->family;

	if (variant->tsi)
		family = family == AF_INET ? AF_TSI :
			 family == AF_INET6 ? AF_TSI6 : AF_TSIU;
	local_connect(_metadata, self->listener, &self->addr, self->addr_len, family);
}

TEST_F_TIMEOUT(tsi_ipc, shutdown_wakes_accept, 5)
{
	struct accept_worker worker = { .listener = self->listener };
	pthread_t thread;

	ASSERT_EQ(pthread_barrier_init(&worker.barrier, NULL, 2), 0);
	ASSERT_EQ(pthread_create(&thread, NULL, blocking_accept, &worker), 0);
	pthread_barrier_wait(&worker.barrier);
	wait_accept(_metadata, worker.tid);
	ASSERT_EQ(shutdown(self->listener, SHUT_RD), 0);
	ASSERT_EQ(pthread_join(thread, NULL), 0);
	EXPECT_EQ(worker.accepted, -1);
	EXPECT_EQ(worker.error, EINVAL);
	pthread_barrier_destroy(&worker.barrier);
}

TEST_HARNESS_MAIN
