// SPDX-License-Identifier: GPL-2.0-only
/* Requires a libkrun host built with krun-devices/tsi-fault-injection. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../kselftest_harness.h"
#include "tsi_test.h"

#define FAULT_PORT 0x54534946U
#define CREATE 1024
#define CONNECT 1025
#define GETNAME 1026
#define LISTEN 1029
#define ACCEPT 1030
#define DISCONNECT 1033
#define SETOPT 1034
#define GETOPT 1035
#define BIND 1036

enum fault {
	BAD_VERSION = 1, BAD_OPERATION, BAD_FLAGS, SHORT_HEADER, SHORT_BODY,
	TRAILING, PAYLOAD_LENGTH, POSITIVE_RESULT, INVALID_ERROR, OVERSIZED,
	WRONG_ID, WRONG_PORT, WRONG_CID, DUPLICATE, DROP, HOLD,
	LISTEN_FLAGS, ADDRESS_LENGTH, ADDRESS_FAMILY,
	WRONG_ID_ONLY, WRONG_PORT_ONLY, WRONG_CID_ONLY,
	RELEASE_HELD, CORRUPT_HELD,
};

static double seconds(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec + now.tv_nsec / 1e9;
}

static void command(struct __test_metadata *_metadata, int fd, int operation,
		    int fault, uint32_t *stats)
{
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_HOST,
		.svm_port = FAULT_PORT,
	};
	uint32_t request[] = { htole32(1), htole32(operation), htole32(fault), 0 };
	socklen_t len = sizeof(addr);

	ASSERT_EQ(sendto(fd, request, sizeof(request), 0,
			 (void *)&addr, sizeof(addr)), (ssize_t)sizeof(request));
	ASSERT_EQ(recvfrom(fd, stats, 20, MSG_TRUNC, (void *)&addr, &len), 20);
	ASSERT_EQ(len, sizeof(addr));
	ASSERT_EQ(addr.svm_cid, (unsigned int)VMADDR_CID_HOST);
	ASSERT_EQ(addr.svm_port, FAULT_PORT);
	for (int i = 0; i < 5; i++)
		stats[i] = le32toh(stats[i]);
	ASSERT_EQ(stats[0], 1U);
	ASSERT_EQ(stats[1], 0U);
}

static int probe(void)
{
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_HOST,
		.svm_port = FAULT_PORT,
	};
	struct timeval timeout = { .tv_usec = 200000 };
	uint32_t request[] = { htole32(1), 0, 0, 0 }, reply[5];
	int fd = socket(AF_VSOCK, SOCK_DGRAM, 0);

	if (fd < 0)
		return -1;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
	    sendto(fd, request, sizeof(request), 0, (void *)&addr, sizeof(addr)) < 0 ||
	    recv(fd, reply, sizeof(reply), MSG_TRUNC) != sizeof(reply) ||
	    le32toh(reply[0]) != 1 || reply[1]) {
		close(fd);
		return -1;
	}
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
		close(fd);
		return -1;
	}
	return fd;
}

static void cleanup_proxies(struct __test_metadata *_metadata, int control)
{
	uint32_t stats[5];
	double deadline = seconds() + 7;

	do {
		command(_metadata, control, 0, 0, stats);
		if (!stats[4])
			return;
		usleep(10000);
	} while (seconds() < deadline);
	ASSERT_EQ(stats[4], 0U);
}

static struct sockaddr_in host_address(struct __test_metadata *_metadata)
{
	const char *env = getenv("TSI_UDP_PORTS");
	struct sockaddr_in addr = {
		.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	unsigned int ports[4];
	int parsed;

	ASSERT_NE(env, NULL);
	parsed = sscanf(env, "%u,%u,%u,%u", &ports[0], &ports[1],
			&ports[2], &ports[3]);
	ASSERT_EQ(parsed, 4);
	ASSERT_GT(ports[0], 0U);
	ASSERT_LE(ports[0], 65535U);
	addr.sin_port = htons(ports[0]);
	return addr;
}

static int udp_socket(struct __test_metadata *_metadata, bool connected)
{
	struct sockaddr_in host = host_address(_metadata);
	struct timeval timeout = { .tv_sec = 1 };
	int fd = socket(AF_TSI, SOCK_DGRAM, 0);

	ASSERT_GE(fd, 0);
	ASSERT_EQ(tsi_force_proxy(fd), 0);
	ASSERT_EQ(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), 0);
	if (connected)
		ASSERT_EQ(connect(fd, (void *)&host, sizeof(host)), 0);
	return fd;
}

static void echo(struct __test_metadata *_metadata, int fd)
{
	unsigned char data[] = { 0, 'F', 0x39, 0xa7 }, reply[sizeof(data)];

	ASSERT_EQ(send(fd, data, sizeof(data), MSG_NOSIGNAL), (ssize_t)sizeof(data));
	ASSERT_EQ(recv(fd, reply, sizeof(reply), MSG_TRUNC), (ssize_t)sizeof(reply));
	ASSERT_EQ(memcmp(data, reply, sizeof(data)), 0);
}

static int read_control(int fd, int operation)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int value = -1;

	if (operation == GETNAME) {
		if (getsockname(fd, (void *)&addr, &len))
			return -1;
		if (len != sizeof(addr) || addr.sin_family != AF_INET || !addr.sin_port) {
			errno = EINVAL;
			return -1;
		}
	} else {
		len = sizeof(value);
		if (getsockopt(fd, SOL_SOCKET, SO_BROADCAST, &value, &len))
			return -1;
		if (len != sizeof(value) || value) {
			errno = EINVAL;
			return -1;
		}
	}
	return 0;
}

FIXTURE(tsi_control_fault)
{
	int control;
	int fd;
};

FIXTURE_VARIANT(tsi_control_fault)
{
	int operation;
	int fault;
	int error;
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_version) {
	.operation = GETNAME, .fault = BAD_VERSION, .error = EPROTONOSUPPORT,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_operation) {
	.operation = GETNAME, .fault = BAD_OPERATION, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_flags) {
	.operation = GETNAME, .fault = BAD_FLAGS, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_short_header) {
	.operation = GETNAME, .fault = SHORT_HEADER, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_short_body) {
	.operation = GETNAME, .fault = SHORT_BODY, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_trailing) {
	.operation = GETNAME, .fault = TRAILING, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_length) {
	.operation = GETNAME, .fault = PAYLOAD_LENGTH, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_positive_result) {
	.operation = GETNAME, .fault = POSITIVE_RESULT, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_invalid_errno) {
	.operation = GETNAME, .fault = INVALID_ERROR, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_oversized) {
	.operation = GETNAME, .fault = OVERSIZED, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_wrong_id) {
	.operation = GETNAME, .fault = WRONG_ID, .error = 0,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_wrong_port) {
	.operation = GETNAME, .fault = WRONG_PORT, .error = 0,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_wrong_cid) {
	.operation = GETNAME, .fault = WRONG_CID, .error = 0,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_duplicate) {
	.operation = GETNAME, .fault = DUPLICATE, .error = 0,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_drop) {
	.operation = GETNAME, .fault = DROP, .error = ETIMEDOUT,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_late) {
	.operation = GETNAME, .fault = HOLD, .error = ETIMEDOUT,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_only_wrong_id) {
	.operation = GETNAME, .fault = WRONG_ID_ONLY, .error = ETIMEDOUT,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_only_wrong_port) {
	.operation = GETNAME, .fault = WRONG_PORT_ONLY, .error = ETIMEDOUT,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_only_wrong_cid) {
	.operation = GETNAME, .fault = WRONG_CID_ONLY, .error = ETIMEDOUT,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_version) {
	.operation = GETOPT, .fault = BAD_VERSION, .error = EPROTONOSUPPORT,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_operation) {
	.operation = GETOPT, .fault = BAD_OPERATION, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_flags) {
	.operation = GETOPT, .fault = BAD_FLAGS, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_short_header) {
	.operation = GETOPT, .fault = SHORT_HEADER, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_short_body) {
	.operation = GETOPT, .fault = SHORT_BODY, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_trailing) {
	.operation = GETOPT, .fault = TRAILING, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_length) {
	.operation = GETOPT, .fault = PAYLOAD_LENGTH, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_positive_result) {
	.operation = GETOPT, .fault = POSITIVE_RESULT, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_invalid_errno) {
	.operation = GETOPT, .fault = INVALID_ERROR, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_oversized) {
	.operation = GETOPT, .fault = OVERSIZED, .error = EPROTO,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_wrong_id) {
	.operation = GETOPT, .fault = WRONG_ID, .error = 0,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_wrong_port) {
	.operation = GETOPT, .fault = WRONG_PORT, .error = 0,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_wrong_cid) {
	.operation = GETOPT, .fault = WRONG_CID, .error = 0,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_duplicate) {
	.operation = GETOPT, .fault = DUPLICATE, .error = 0,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_drop) {
	.operation = GETOPT, .fault = DROP, .error = ETIMEDOUT,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_late) {
	.operation = GETOPT, .fault = HOLD, .error = ETIMEDOUT,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_only_wrong_id) {
	.operation = GETOPT, .fault = WRONG_ID_ONLY, .error = ETIMEDOUT,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_only_wrong_port) {
	.operation = GETOPT, .fault = WRONG_PORT_ONLY, .error = ETIMEDOUT,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, option_only_wrong_cid) {
	.operation = GETOPT, .fault = WRONG_CID_ONLY, .error = ETIMEDOUT,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_address_length) {
	.operation = GETNAME, .fault = ADDRESS_LENGTH, .error = EINVAL,
};

FIXTURE_VARIANT_ADD(tsi_control_fault, name_address_family) {
	.operation = GETNAME, .fault = ADDRESS_FAMILY, .error = EPROTO,
};

FIXTURE_SETUP(tsi_control_fault)
{
	self->fd = -1;
	self->control = probe();
	if (self->control < 0)
		SKIP(return, "libkrun test-only control injector unavailable");
	if (!getenv("TSI_UDP_PORTS"))
		SKIP(return, "host UDP fixture unavailable");
	cleanup_proxies(_metadata, self->control);
	self->fd = udp_socket(_metadata, true);
}

FIXTURE_TEARDOWN(tsi_control_fault)
{
	if (self->fd >= 0)
		close(self->fd);
	if (self->control >= 0) {
		cleanup_proxies(_metadata, self->control);
		close(self->control);
	}
}

TEST_F_TIMEOUT(tsi_control_fault, read_failure_is_recoverable, 15)
{
	uint32_t stats[5];
	double start, elapsed;
	int result, error, other;

	command(_metadata, self->control, variant->operation, variant->fault, stats);
	start = seconds();
	result = read_control(self->fd, variant->operation);
	error = errno;
	elapsed = seconds() - start;
	ASSERT_EQ(result, variant->error ? -1 : 0);
	if (variant->error)
		ASSERT_EQ(error, variant->error);
	if (variant->error == ETIMEDOUT)
		EXPECT_GE(elapsed, 4.0);
	EXPECT_LT(elapsed, 8.0);
	ASSERT_EQ(read_control(self->fd, variant->operation), 0);
	echo(_metadata, self->fd);
	other = udp_socket(_metadata, true);
	echo(_metadata, other);
	close(other);
	command(_metadata, self->control, 0, 0, stats);
	EXPECT_GE(stats[2], 2U);
	EXPECT_EQ(stats[3], variant->fault == HOLD ? 2U : 1U);
}

struct interrupted_read {
	int fd;
	int operation;
	int result;
	int error;
	atomic_bool done;
};

static void *reader(void *arg)
{
	struct interrupted_read *read = arg;

	read->result = read_control(read->fd, read->operation);
	read->error = errno;
	atomic_store(&read->done, true);
	return NULL;
}

static void interrupt(int signal)
{
	(void)signal;
}

TEST(metadata_signal_wait_and_stale_close_reuse)
{
	struct sigaction action = { .sa_handler = interrupt };
	uint32_t stats[5];
	int control = probe();

	if (control < 0)
		SKIP(return, "libkrun test-only control injector unavailable");
	ASSERT_EQ(sigaction(SIGUSR1, &action, NULL), 0);
	for (int i = 0; i < 66; i++) {
		struct interrupted_read read = {
			.fd = udp_socket(_metadata, true),
			.operation = i % 2 ? GETOPT : GETNAME,
		};
		struct timespec deadline;
		pthread_t thread;
		double until = seconds() + 2;

		command(_metadata, control, read.operation, HOLD, stats);
		ASSERT_EQ(pthread_create(&thread, NULL, reader, &read), 0);
		do {
			command(_metadata, control, 0, 0, stats);
			if (stats[3])
				break;
			usleep(1000);
		} while (seconds() < until);
		ASSERT_EQ(stats[3], 1U);
		ASSERT_EQ(pthread_kill(thread, SIGUSR1), 0);
		usleep(50000);
		EXPECT_FALSE(atomic_load(&read.done));
		command(_metadata, control, 0, i < 2 ? RELEASE_HELD : CORRUPT_HELD, stats);
		clock_gettime(CLOCK_REALTIME, &deadline);
		deadline.tv_sec += 2;
		ASSERT_EQ(pthread_timedjoin_np(thread, NULL, &deadline), 0);
		ASSERT_EQ(read.result, i < 2 ? 0 : -1);
		if (i >= 2)
			ASSERT_EQ(read.error, EPROTONOSUPPORT);
		/* First recover in place, then stress 64 close/replacement cycles. */
		if (i >= 2) {
			close(read.fd);
			cleanup_proxies(_metadata, control);
			read.fd = udp_socket(_metadata, true);
		}
		ASSERT_EQ(read_control(read.fd, read.operation), 0);
		echo(_metadata, read.fd);
		command(_metadata, control, 0, 0, stats);
		EXPECT_EQ(stats[3], i < 2 ? 2U : 3U);
		close(read.fd);
		cleanup_proxies(_metadata, control);
	}
	close(control);
}

TEST(fatal_signal_metadata_read_recovery)
{
	uint32_t stats[5];
	int control = probe();

	if (control < 0)
		SKIP(return, "libkrun test-only control injector unavailable");
	for (int i = 0; i < 2; i++) {
		int fd = udp_socket(_metadata, true);
		int operation = i ? GETOPT : GETNAME;
		int status = 0;
		pid_t child, waited = 0;
		double deadline;

		command(_metadata, control, operation, HOLD, stats);
		child = fork();
		ASSERT_GE(child, 0);
		if (!child) {
			read_control(fd, operation);
			_exit(1);
		}
		deadline = seconds() + 2;
		do {
			command(_metadata, control, 0, 0, stats);
			if (stats[3])
				break;
			usleep(1000);
		} while (seconds() < deadline);
		ASSERT_EQ(stats[3], 1U);
		ASSERT_EQ(kill(child, SIGKILL), 0);
		deadline = seconds() + 2;
		do {
			waited = waitpid(child, &status, WNOHANG);
			if (waited)
				break;
			usleep(1000);
		} while (seconds() < deadline);
		ASSERT_EQ(waited, child);
		ASSERT_TRUE(WIFSIGNALED(status));
		ASSERT_EQ(WTERMSIG(status), SIGKILL);
		ASSERT_EQ(read_control(fd, operation), 0);
		echo(_metadata, fd);
		close(fd);
		cleanup_proxies(_metadata, control);
	}
	close(control);
}

FIXTURE(tsi_control_state_fault)
{
	int control;
	int fd;
	int other;
	struct sockaddr_in local;
};

FIXTURE_VARIANT(tsi_control_state_fault)
{
	int operation;
	int fault;
	bool tcp;
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, create_malformed) {
	.operation = CREATE, .fault = BAD_VERSION, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, create_dropped) {
	.operation = CREATE, .fault = DROP, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, create_late) {
	.operation = CREATE, .fault = HOLD, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, udp_connect_malformed) {
	.operation = CONNECT, .fault = BAD_VERSION, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, udp_connect_dropped) {
	.operation = CONNECT, .fault = DROP, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, udp_connect_late) {
	.operation = CONNECT, .fault = HOLD, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, disconnect_malformed) {
	.operation = DISCONNECT, .fault = BAD_VERSION, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, disconnect_dropped) {
	.operation = DISCONNECT, .fault = DROP, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, disconnect_late) {
	.operation = DISCONNECT, .fault = HOLD, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, set_option_malformed) {
	.operation = SETOPT, .fault = BAD_VERSION, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, set_option_dropped) {
	.operation = SETOPT, .fault = DROP, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, set_option_late) {
	.operation = SETOPT, .fault = HOLD, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, bind_malformed) {
	.operation = BIND, .fault = BAD_VERSION, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, bind_dropped) {
	.operation = BIND, .fault = DROP, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, bind_late) {
	.operation = BIND, .fault = HOLD, .tcp = false,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, listen_malformed) {
	.operation = LISTEN, .fault = BAD_VERSION, .tcp = true,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, listen_dropped) {
	.operation = LISTEN, .fault = DROP, .tcp = true,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, listen_late) {
	.operation = LISTEN, .fault = HOLD, .tcp = true,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, accept_malformed) {
	.operation = ACCEPT, .fault = BAD_VERSION, .tcp = true,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, accept_dropped) {
	.operation = ACCEPT, .fault = DROP, .tcp = true,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, accept_late) {
	.operation = ACCEPT, .fault = HOLD, .tcp = true,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, tcp_connect_malformed) {
	.operation = CONNECT, .fault = BAD_VERSION, .tcp = true,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, tcp_connect_dropped) {
	.operation = CONNECT, .fault = DROP, .tcp = true,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, tcp_connect_late) {
	.operation = CONNECT, .fault = HOLD, .tcp = true,
};

FIXTURE_VARIANT_ADD(tsi_control_state_fault, listen_reserved_policy) {
	.operation = LISTEN, .fault = LISTEN_FLAGS, .tcp = true,
};

static void prepare(struct __test_metadata *_metadata,
		    FIXTURE_DATA(tsi_control_state_fault) *self,
		    const FIXTURE_VARIANT(tsi_control_state_fault) *variant)
{
	struct timeval timeout = { .tv_usec = 250000 };
	struct timeval receive = { .tv_sec = 2 };
	socklen_t len = sizeof(self->local);
	int one = 1;

	self->other = -1;
	if (!variant->tcp) {
		self->fd = udp_socket(_metadata, variant->operation != CREATE &&
				      variant->operation != BIND);
		return;
	}
	self->fd = socket(AF_TSI, SOCK_STREAM, 0);
	ASSERT_GE(self->fd, 0);
	if (variant->operation == CONNECT) {
		self->other = socket(AF_TSI, SOCK_STREAM, 0);
		ASSERT_GE(self->other, 0);
		ASSERT_EQ(bind(self->other, (void *)&self->local, len), 0);
		ASSERT_EQ(getsockname(self->other, (void *)&self->local, &len), 0);
		ASSERT_EQ(setsockopt(self->other, SOL_SOCKET, SO_RCVTIMEO,
				     &receive, sizeof(receive)), 0);
		ASSERT_EQ(listen(self->other, 8), 0);
		ASSERT_EQ(tsi_force_proxy(self->fd), 0);
		ASSERT_EQ(setsockopt(self->fd, SOL_SOCKET, SO_SNDTIMEO,
				     &timeout, sizeof(timeout)), 0);
		ASSERT_EQ(fcntl(self->fd, F_SETFL, O_NONBLOCK), 0);
	} else {
		ASSERT_EQ(setsockopt(self->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)), 0);
		ASSERT_EQ(bind(self->fd, (void *)&self->local, len), 0);
		ASSERT_EQ(getsockname(self->fd, (void *)&self->local, &len), 0);
		if (variant->operation == ACCEPT) {
			ASSERT_EQ(listen(self->fd, 8), 0);
			self->other = socket(AF_TSI, SOCK_STREAM, 0);
			ASSERT_GE(self->other, 0);
			ASSERT_EQ(tsi_force_proxy(self->other), 0);
			ASSERT_EQ(connect(self->other, (void *)&self->local, len), 0);
		}
	}
}

static int change(struct __test_metadata *_metadata,
		  FIXTURE_DATA(tsi_control_state_fault) *self,
		  const FIXTURE_VARIANT(tsi_control_state_fault) *variant)
{
	struct sockaddr_in host = host_address(_metadata);
	struct sockaddr unspec = { .sa_family = AF_UNSPEC };
	struct pollfd pfd = { .fd = self->fd, .events = POLLOUT };
	socklen_t len;
	int result, error, one = 1;

	switch (variant->operation) {
	case CREATE:
	case CONNECT:
		if (!variant->tcp)
			return connect(self->fd, (void *)&host, sizeof(host));
		result = connect(self->fd, (void *)&self->local, sizeof(self->local));
		ASSERT_EQ(result, -1);
		ASSERT_EQ(errno, EINPROGRESS);
		ASSERT_EQ(poll(&pfd, 1, 2500), 1);
		len = sizeof(error);
		ASSERT_EQ(getsockopt(self->fd, SOL_SOCKET, SO_ERROR, &error, &len), 0);
		/* Consume the server child independently of the client's reply. */
		result = accept(self->other, NULL, NULL);
		ASSERT_GE(result, 0);
		close(result);
		errno = error;
		return error ? -1 : 0;
	case DISCONNECT:
		return connect(self->fd, &unspec, sizeof(unspec));
	case SETOPT:
		return setsockopt(self->fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
	case BIND:
		return bind(self->fd, (void *)&self->local, sizeof(self->local));
	case LISTEN:
		return listen(self->fd, 8);
	case ACCEPT:
		result = accept(self->fd, NULL, NULL);
		if (result >= 0) {
			close(result);
			return 0;
		}
		return -1;
	}
	return -1;
}

FIXTURE_SETUP(tsi_control_state_fault)
{
	self->fd = -1;
	self->other = -1;
	self->local.sin_family = AF_INET;
	self->local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	self->control = probe();
	if (self->control < 0)
		SKIP(return, "libkrun test-only control injector unavailable");
	if (!getenv("TSI_UDP_PORTS"))
		SKIP(return, "host UDP fixture unavailable");
	cleanup_proxies(_metadata, self->control);
	prepare(_metadata, self, variant);
}

FIXTURE_TEARDOWN(tsi_control_state_fault)
{
	if (self->fd >= 0)
		close(self->fd);
	if (self->other >= 0)
		close(self->other);
	if (self->control >= 0) {
		cleanup_proxies(_metadata, self->control);
		close(self->control);
	}
}

TEST_F_TIMEOUT(tsi_control_state_fault, failure_requires_close_and_replacement, 25)
{
	struct pollfd pfd = { .fd = self->fd, .events = POLLOUT };
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	uint32_t stats[5];
	double start, elapsed;
	int expected = variant->fault == BAD_VERSION ? EPROTONOSUPPORT :
		       variant->fault == LISTEN_FLAGS ? EPROTO : ETIMEDOUT;
	int one = 1, result, error, healthy;

	command(_metadata, self->control, variant->operation, variant->fault, stats);
	start = seconds();
	result = change(_metadata, self, variant);
	error = errno;
	elapsed = seconds() - start;
	ASSERT_EQ(result, -1);
	ASSERT_EQ(error, expected);
	if (expected == ETIMEDOUT)
		EXPECT_GE(elapsed, variant->tcp && variant->operation == CONNECT ? 0.15 : 4.0);
	EXPECT_LT(elapsed, 8.0);
	EXPECT_EQ(getsockname(self->fd, (void *)&addr, &len), -1);
	EXPECT_EQ(errno, EIO);
	EXPECT_EQ(setsockopt(self->fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)), -1);
	EXPECT_EQ(errno, EIO);
	EXPECT_EQ(send(self->fd, "x", 1, MSG_NOSIGNAL), -1);
	EXPECT_EQ(errno, EIO);
	ASSERT_EQ(poll(&pfd, 1, 0), 1);
	EXPECT_NE(pfd.revents & POLLERR, 0);
	close(self->fd);
	self->fd = -1;
	if (self->other >= 0) {
		close(self->other);
		self->other = -1;
	}
	cleanup_proxies(_metadata, self->control);
	prepare(_metadata, self, variant);
	ASSERT_EQ(change(_metadata, self, variant), 0);
	command(_metadata, self->control, 0, 0, stats);
	EXPECT_EQ(stats[3], variant->fault == HOLD ? 2U : 1U);
	healthy = udp_socket(_metadata, true);
	echo(_metadata, healthy);
	close(healthy);
}

TEST_HARNESS_MAIN
