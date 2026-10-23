/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef VSOCK_TEST_DGRAM_H
#define VSOCK_TEST_DGRAM_H

#include "util.h"

const char *vsock_dgram_check_local(const struct test_opts *opts);
const char *vsock_dgram_check_local_cid(const struct test_opts *opts);
const char *vsock_dgram_check_no_loopback(const struct test_opts *opts);
const char *vsock_dgram_check_peer(const struct test_opts *opts);
const char *vsock_dgram_check_routes(const struct test_opts *opts);
const char *vsock_dgram_check_vmci(const struct test_opts *opts);
const char *vsock_dgram_check_vmci_host(const struct test_opts *opts);

void test_dgram_bind(const struct test_opts *opts);
void test_dgram_receive(const struct test_opts *opts);
void test_dgram_receive_flags(const struct test_opts *opts);
void test_dgram_filter(const struct test_opts *opts);
void test_dgram_connect(const struct test_opts *opts);
void test_dgram_no_loopback(const struct test_opts *opts);
void test_dgram_connected_cid(const struct test_opts *opts);
void test_dgram_source_cid(const struct test_opts *opts);
void test_dgram_bound_lookup(const struct test_opts *opts);
void test_dgram_sockmap(const struct test_opts *opts);
void test_dgram_nested_source(const struct test_opts *opts);
void test_dgram_sizes(const struct test_opts *opts);
void test_dgram_burst(const struct test_opts *opts);
void test_dgram_port_space(const struct test_opts *opts);
void test_dgram_routes(const struct test_opts *opts);
void test_dgram_peer_filter(const struct test_opts *opts);
void test_dgram_vmci_inq(const struct test_opts *opts);
void test_dgram_vmci_host_routes(const struct test_opts *opts);

#endif /* VSOCK_TEST_DGRAM_H */
