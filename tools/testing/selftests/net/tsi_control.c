// SPDX-License-Identifier: GPL-2.0-only
/* TSIv4 wire checks: run with VMM INET impersonation enabled. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <sys/time.h>
#include <unistd.h>

#include "../kselftest_harness.h"
#include "tsi_test.h"

#define CREATE 1024
#define CONNECT 1025
#define GETNAME 1026
#define RELEASE 1031
#define SETOPT 1034
#define GETOPT 1035

struct control_header {
	uint32_t version;
	uint32_t operation;
	uint64_t request_id;
	uint32_t payload_len;
	uint32_t flags;
};

struct create_body {
	uint32_t data_port;
	uint16_t family;
	uint16_t type;
	uint32_t protocol;
};

struct control_frame {
	struct control_header header;
	uint8_t body[144];
};

_Static_assert(sizeof(struct control_header) == 24, "control header size");

FIXTURE(tsi_control)
{
	int control;
	int data;
	uint32_t data_port;
	uint64_t request_id;
	bool created;
};

FIXTURE_SETUP(tsi_control)
{
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = VMADDR_CID_ANY,
		.svm_port = VMADDR_PORT_ANY,
	};
	struct timeval timeout = { .tv_sec = 2 };
	socklen_t len = sizeof(addr);

	self->control = socket(AF_VSOCK, SOCK_DGRAM, 0);
	self->data = -1;
	if (self->control < 0 && errno == EAFNOSUPPORT)
		SKIP(return, "VSOCK datagrams unavailable");
	ASSERT_GE(self->control, 0);
	ASSERT_EQ(bind(self->control, (void *)&addr, sizeof(addr)), 0);
	ASSERT_EQ(setsockopt(self->control, SOL_SOCKET, SO_RCVTIMEO,
			     &timeout, sizeof(timeout)), 0);
	self->data = socket(AF_VSOCK, SOCK_DGRAM, 0);
	ASSERT_GE(self->data, 0);
	ASSERT_EQ(bind(self->data, (void *)&addr, sizeof(addr)), 0);
	ASSERT_EQ(getsockname(self->data, (void *)&addr, &len), 0);
	self->data_port = addr.svm_port;
	self->request_id = 0x123456789abcdef0ULL;
}

static ssize_t send_frame(int fd, unsigned int port, struct control_frame *frame,
			 size_t len)
{
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = VMADDR_CID_HOST,
		.svm_port = port,
	};

	return sendto(fd, frame, len, 0, (void *)&addr, sizeof(addr));
}

FIXTURE_TEARDOWN(tsi_control)
{
	struct control_frame frame = {
		.header = {
			.version = htole32(4),
			.operation = htole32(RELEASE),
			.payload_len = htole32(8),
			.flags = htole32(2),
		},
	};
	uint32_t ports[2] = { htole32(self->data_port), htole32(620) };

	if (self->created) {
		frame.header.request_id = htole64(++self->request_id);
		memcpy(frame.body, ports, sizeof(ports));
		send_frame(self->control, RELEASE, &frame, 32);
	}
	if (self->data >= 0)
		close(self->data);
	if (self->control >= 0)
		close(self->control);
}

static struct control_frame create_frame(uint32_t port, uint64_t id)
{
	struct control_frame frame = {
		.header = {
			.version = htole32(4),
			.operation = htole32(CREATE),
			.request_id = htole64(id),
			.payload_len = htole32(12),
		},
	};
	struct create_body body = {
		.data_port = htole32(port),
		.family = htole16(AF_INET),
		.type = htole16(SOCK_DGRAM),
		.protocol = htole32(IPPROTO_UDP),
	};

	memcpy(frame.body, &body, sizeof(body));
	return frame;
}

static int check_reply(struct __test_metadata *_metadata, int fd,
			unsigned int port, uint64_t id, int result, size_t len)
{
	struct sockaddr_vm addr = {};
	struct control_frame reply;
	socklen_t addr_len = sizeof(addr);
	int32_t actual;
	ssize_t received;

	memset(&reply, 0xa5, sizeof(reply));
	received = recvfrom(fd, &reply, sizeof(reply), MSG_TRUNC,
			    (void *)&addr, &addr_len);
	ASSERT_EQ(received, (ssize_t)len);
	EXPECT_EQ(addr_len, sizeof(addr));
	EXPECT_EQ(addr.svm_family, AF_VSOCK);
	EXPECT_EQ(addr.svm_cid, (unsigned int)VMADDR_CID_HOST);
	EXPECT_EQ(addr.svm_port, port);
	EXPECT_EQ(le32toh(reply.header.version), 4U);
	EXPECT_EQ(le32toh(reply.header.operation), port);
	EXPECT_EQ(le64toh(reply.header.request_id), id);
	EXPECT_EQ(le32toh(reply.header.payload_len), len - 24);
	EXPECT_EQ(le32toh(reply.header.flags), 1U);
	memcpy(&actual, reply.body, sizeof(actual));
	EXPECT_EQ((int32_t)le32toh(actual), result);
	if (len == 160 && result) {
		for (int i = 4; i < 136; i++)
			EXPECT_EQ(reply.body[i], 0);
	}
	if (len >= 32) {
		uint32_t value;

		memcpy(&value, reply.body + 4, sizeof(value));
		return (int32_t)le32toh(value);
	}
	return 0;
}

TEST_F(tsi_control, explicit_protocol_and_exact_reply)
{
	struct control_frame frame = create_frame(self->data_port, self->request_id);

	ASSERT_EQ(send_frame(self->control, CREATE, &frame, 36), 36);
	check_reply(_metadata, self->control, CREATE, self->request_id, 0, 28);
	self->created = true;
}

TEST_F(tsi_control, duplicate_create_preserves_existing_proxy)
{
	struct control_frame frame = create_frame(self->data_port, self->request_id);

	ASSERT_EQ(send_frame(self->control, CREATE, &frame, 36), 36);
	check_reply(_metadata, self->control, CREATE, self->request_id, 0, 28);
	self->created = true;
	frame.header.request_id = htole64(++self->request_id);
	ASSERT_EQ(send_frame(self->control, CREATE, &frame, 36), 36);
	check_reply(_metadata, self->control, CREATE, self->request_id,
		    -EADDRINUSE, 28);
}

TEST_F(tsi_control, unsupported_protocol)
{
	struct control_frame frame = create_frame(self->data_port, self->request_id);
	uint32_t protocol = htole32(IPPROTO_SCTP);

	memcpy(&frame.body[8], &protocol, sizeof(protocol));
	ASSERT_EQ(send_frame(self->control, CREATE, &frame, 36), 36);
	check_reply(_metadata, self->control, CREATE, self->request_id,
		    -EPROTONOSUPPORT, 28);
}

TEST_F(tsi_control, wrong_version)
{
	struct control_frame frame = create_frame(self->data_port, self->request_id);

	frame.header.version = htole32(3);
	ASSERT_EQ(send_frame(self->control, CREATE, &frame, 36), 36);
	check_reply(_metadata, self->control, CREATE, self->request_id,
		    -EPROTONOSUPPORT, 28);
}

TEST_F(tsi_control, operation_must_match_port)
{
	struct control_frame frame = create_frame(self->data_port, self->request_id);

	frame.header.operation = htole32(GETNAME);
	ASSERT_EQ(send_frame(self->control, CREATE, &frame, 36), 36);
	check_reply(_metadata, self->control, CREATE, self->request_id, -EPROTO, 28);
}

TEST_F(tsi_control, reject_trailing_data)
{
	struct control_frame frame = create_frame(self->data_port, self->request_id);

	ASSERT_EQ(send_frame(self->control, CREATE, &frame, 37), 37);
	check_reply(_metadata, self->control, CREATE, self->request_id, -EPROTO, 28);
}

TEST_F(tsi_control, reject_short_body)
{
	struct control_frame frame = create_frame(self->data_port, self->request_id);

	ASSERT_EQ(send_frame(self->control, CREATE, &frame, 35), 35);
	check_reply(_metadata, self->control, CREATE, self->request_id, -EPROTO, 28);
}

TEST_F(tsi_control, reject_reserved_flags)
{
	struct control_frame frame = create_frame(self->data_port, self->request_id);

	frame.header.flags = htole32(4);
	ASSERT_EQ(send_frame(self->control, CREATE, &frame, 36), 36);
	check_reply(_metadata, self->control, CREATE, self->request_id, -EPROTO, 28);
}

TEST_F(tsi_control, reject_malformed_address)
{
	struct control_frame frame = create_frame(self->data_port, self->request_id);

	frame.header.operation = htole32(CONNECT);
	frame.header.payload_len = htole32(136);
	/* The address length remains zero. */
	memset(frame.body, 0, sizeof(frame.body));
	ASSERT_EQ(send_frame(self->control, CONNECT, &frame, 160), 160);
	check_reply(_metadata, self->control, CONNECT, self->request_id, -EPROTO, 28);
}

TEST_F(tsi_control, getname_error_has_exact_zeroed_body)
{
	struct control_frame frame = create_frame(self->data_port, self->request_id);

	frame.header.operation = htole32(GETNAME);
	memset(frame.body, 0, sizeof(frame.body));
	ASSERT_EQ(send_frame(self->control, GETNAME, &frame, 36), 36);
	check_reply(_metadata, self->control, GETNAME, self->request_id, -EINVAL, 160);
}

TEST_F(tsi_control, local_name_selector)
{
	struct control_frame frame = create_frame(self->data_port, self->request_id);
	uint32_t fields[] = { htole32(self->data_port), htole32(620), 0 };

	ASSERT_EQ(send_frame(self->control, CREATE, &frame, 36), 36);
	check_reply(_metadata, self->control, CREATE, self->request_id, 0, 28);
	self->created = true;
	frame.header.operation = htole32(GETNAME);
	frame.header.request_id = htole64(++self->request_id);
	memcpy(frame.body, fields, sizeof(fields));
	ASSERT_EQ(send_frame(self->control, GETNAME, &frame, 36), 36);
	check_reply(_metadata, self->control, GETNAME, self->request_id, 0, 160);
}

TEST_F(tsi_control, socket_option_roundtrip_and_allowlist)
{
	struct control_frame frame = create_frame(self->data_port, self->request_id);
	uint32_t fields[] = { htole32(self->data_port), htole32(620),
			      htole32(SOL_SOCKET), htole32(SO_BROADCAST), htole32(1) };
	int denied[] = { SO_DEBUG, SO_SNDBUFFORCE, SO_BINDTOIFINDEX };
	unsigned int i;

	ASSERT_EQ(send_frame(self->control, CREATE, &frame, 36), 36);
	check_reply(_metadata, self->control, CREATE, self->request_id, 0, 28);
	self->created = true;
	frame.header.operation = htole32(SETOPT);
	frame.header.payload_len = htole32(20);
	frame.header.request_id = htole64(++self->request_id);
	memcpy(frame.body, fields, sizeof(fields));
	ASSERT_EQ(send_frame(self->control, SETOPT, &frame, 44), 44);
	check_reply(_metadata, self->control, SETOPT, self->request_id, 0, 28);
	for (i = 0; i < ARRAY_SIZE(denied); i++) {
		fields[3] = htole32(denied[i]);
		memcpy(frame.body, fields, sizeof(fields));
		frame.header.request_id = htole64(++self->request_id);
		ASSERT_EQ(send_frame(self->control, SETOPT, &frame, 44), 44);
		check_reply(_metadata, self->control, SETOPT, self->request_id,
			    -ENOPROTOOPT, 28);
	}
	fields[3] = htole32(SO_BROADCAST);
	memcpy(frame.body, fields, sizeof(fields));
	frame.header.operation = htole32(GETOPT);
	frame.header.payload_len = htole32(16);
	frame.header.request_id = htole64(++self->request_id);
	ASSERT_EQ(send_frame(self->control, GETOPT, &frame, 40), 40);
	EXPECT_EQ(check_reply(_metadata, self->control, GETOPT,
			      self->request_id, 0, 32), 1);
}

TEST_F(tsi_control, malformed_option_request)
{
	struct control_frame frame = create_frame(self->data_port, self->request_id);

	frame.header.operation = htole32(GETOPT);
	frame.header.payload_len = htole32(16);
	ASSERT_EQ(send_frame(self->control, GETOPT, &frame, 39), 39);
	EXPECT_EQ(check_reply(_metadata, self->control, GETOPT,
			      self->request_id, -EPROTO, 32), 0);
	frame.header.operation = htole32(SETOPT);
	frame.header.payload_len = htole32(20);
	frame.header.request_id = htole64(++self->request_id);
	ASSERT_EQ(send_frame(self->control, SETOPT, &frame, 43), 43);
	check_reply(_metadata, self->control, SETOPT, self->request_id, -EPROTO, 28);
}

TEST_F(tsi_control, asynchronous_reply_keeps_original_id)
{
	const char *port = getenv("TSI_CONTROL_PORT");
	struct control_frame frame = create_frame(self->data_port, self->request_id);
	struct control_frame connecting;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct timeval timeout = { .tv_sec = 4 };
	uint32_t fields[3];
	uint16_t type = htole16(SOCK_STREAM);
	uint32_t protocol = htole32(IPPROTO_TCP);
	uint64_t connect_id;
	int trigger;

	if (!port)
		SKIP(return, "TSI_CONTROL_PORT host fixture unavailable");
	addr.sin_port = htons(atoi(port));
	ASSERT_EQ(setsockopt(self->control, SOL_SOCKET, SO_RCVTIMEO,
			     &timeout, sizeof(timeout)), 0);
	memcpy(&frame.body[6], &type, sizeof(type));
	memcpy(&frame.body[8], &protocol, sizeof(protocol));
	ASSERT_EQ(send_frame(self->control, CREATE, &frame, 36), 36);
	check_reply(_metadata, self->control, CREATE, self->request_id, 0, 28);
	self->created = true;

	connecting = frame;
	connect_id = ++self->request_id;
	connecting.header.operation = htole32(CONNECT);
	connecting.header.request_id = htole64(connect_id);
	connecting.header.payload_len = htole32(136);
	memset(connecting.body, 0, sizeof(connecting.body));
	fields[0] = htole32(self->data_port);
	fields[1] = htole32(sizeof(addr));
	memcpy(connecting.body, fields, 8);
	memcpy(&connecting.body[8], &addr, sizeof(addr));
	ASSERT_EQ(send_frame(self->control, CONNECT, &connecting, 160), 160);

	/* A read-only RPC must not relabel the still-pending connect reply. */
	frame.header.operation = htole32(GETNAME);
	frame.header.request_id = htole64(++self->request_id);
	fields[1] = htole32(620);
	fields[2] = htole32(1);
	memcpy(frame.body, fields, sizeof(fields));
	ASSERT_EQ(send_frame(self->control, GETNAME, &frame, 36), 36);
	check_reply(_metadata, self->control, GETNAME, self->request_id,
		    -ENOTCONN, 160);

	/* A second connect is rejected without overwriting the first ID. */
	connecting.header.request_id = htole64(++self->request_id);
	ASSERT_EQ(send_frame(self->control, CONNECT, &connecting, 160), 160);
	check_reply(_metadata, self->control, CONNECT, self->request_id,
		    -EALREADY, 28);

	trigger = socket(AF_TSI, SOCK_DGRAM, IPPROTO_UDP);
	ASSERT_GE(trigger, 0);
	ASSERT_EQ(sendto(trigger, "d", 1, 0, (void *)&addr, sizeof(addr)), 1);
	close(trigger);
	check_reply(_metadata, self->control, CONNECT, connect_id, 0, 28);
}

struct pending_connect {
	int fd;
	struct sockaddr_in addr;
	int result;
	int error;
};

static void *connect_worker(void *data)
{
	struct pending_connect *worker = data;

	worker->result = connect(worker->fd, (void *)&worker->addr,
				 sizeof(worker->addr));
	worker->error = errno;
	return NULL;
}

static void interrupt_connect(int sig)
{
	(void)sig;
}

static double monotonic_seconds(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec + now.tv_nsec / 1000000000.0;
}

/* Set TSI_CONTROL_PORT to the host tsi_control_server's printed port. */
TEST(connect_timeout_requires_close)
{
	const char *port = getenv("TSI_CONTROL_PORT");
	struct timeval timeout = { .tv_usec = 200000 };
	struct pending_connect worker = {
		.addr.sin_family = AF_INET,
		.addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	double start, elapsed;

	if (!port)
		SKIP(return, "TSI_CONTROL_PORT host fixture unavailable");
	worker.addr.sin_port = htons(atoi(port));
	worker.fd = socket(AF_TSI, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_GE(worker.fd, 0);
	ASSERT_EQ(tsi_force_proxy(worker.fd), 0);
	ASSERT_EQ(setsockopt(worker.fd, SOL_SOCKET, SO_SNDTIMEO,
			     &timeout, sizeof(timeout)), 0);
	start = monotonic_seconds();
	connect_worker(&worker);
	elapsed = monotonic_seconds() - start;
	EXPECT_EQ(worker.result, -1);
	EXPECT_EQ(worker.error, ETIMEDOUT);
	EXPECT_GE(elapsed, 0.1);
	EXPECT_LT(elapsed, 2.0);
	EXPECT_EQ(connect(worker.fd, (void *)&worker.addr, sizeof(worker.addr)), -1);
	EXPECT_EQ(errno, EIO);
	EXPECT_EQ(send(worker.fd, "x", 1, MSG_NOSIGNAL), -1);
	EXPECT_EQ(errno, EIO);
	close(worker.fd);
}

TEST(connect_signal_requires_close)
{
	const char *port = getenv("TSI_CONTROL_PORT");
	struct sigaction action = { .sa_handler = interrupt_connect };
	struct pending_connect worker = {
		.addr.sin_family = AF_INET,
		.addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct timespec deadline;
	pthread_t thread;

	if (!port)
		SKIP(return, "TSI_CONTROL_PORT host fixture unavailable");
	worker.addr.sin_port = htons(atoi(port));
	ASSERT_EQ(sigaction(SIGUSR1, &action, NULL), 0);
	worker.fd = socket(AF_TSI, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_GE(worker.fd, 0);
	ASSERT_EQ(tsi_force_proxy(worker.fd), 0);
	ASSERT_EQ(pthread_create(&thread, NULL, connect_worker, &worker), 0);
	usleep(150000);
	ASSERT_EQ(pthread_kill(thread, SIGUSR1), 0);
	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 2;
	ASSERT_EQ(pthread_timedjoin_np(thread, NULL, &deadline), 0);
	EXPECT_EQ(worker.result, -1);
	EXPECT_EQ(worker.error, EINTR);
	EXPECT_EQ(connect(worker.fd, (void *)&worker.addr, sizeof(worker.addr)), -1);
	EXPECT_EQ(errno, EIO);
	close(worker.fd);
}

TEST_HARNESS_MAIN
