/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TSI_TEST_H
#define TSI_TEST_H

#include <limits.h>
#include <sys/socket.h>

#ifndef AF_TSI
#define AF_TSI 46
#endif
#ifndef AF_TSI6
#define AF_TSI6 47
#endif
#ifndef AF_TSIU
#define AF_TSIU 48
#endif

static inline int tsi_force_proxy(int fd)
{
	int index = INT_MAX;

	/*
	 * Bind the native socket to a nonexistent interface. Its connect fails
	 * routing, while the host proxy can still reach the loopback listener.
	 * This requires CONFIG_NETDEVICES; the option is not forwarded to the
	 * host. Without it, hybrid listeners would turn proxy tests into IPC.
	 */
	return setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX, &index, sizeof(index));
}

#endif
