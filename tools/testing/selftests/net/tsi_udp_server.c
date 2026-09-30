// SPDX-License-Identifier: GPL-2.0-only
/* Run on the VMM host; pass the printed TSI_UDP_PORTS value to the guest. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void)
{
	struct pollfd peers[4];
	unsigned int ports[4];
	struct sockaddr_storage error_probe[4], error_source[4];
	bool error_valid[4] = {};
	int i;

	/* The VM launcher can spawn this helper without leaving orphan peers. */
	prctl(PR_SET_PDEATHSIG, SIGTERM);
	for (i = 0; i < 4; i++) {
		struct sockaddr_storage addr = {};
		struct sockaddr_in *in = (void *)&addr;
		struct sockaddr_in6 *in6 = (void *)&addr;
		socklen_t len;

		peers[i].fd = socket(i < 2 ? AF_INET : AF_INET6, SOCK_DGRAM, 0);
		peers[i].events = POLLIN;
		if (peers[i].fd < 0)
			return 1;
		if (i < 2) {
			in->sin_family = AF_INET;
			in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			len = sizeof(*in);
		} else {
			in6->sin6_family = AF_INET6;
			in6->sin6_addr = in6addr_loopback;
			len = sizeof(*in6);
		}
		if (bind(peers[i].fd, (void *)&addr, len) ||
		    getsockname(peers[i].fd, (void *)&addr, &len))
			return 1;
		ports[i] = ntohs(i < 2 ? in->sin_port : in6->sin6_port);
	}
	printf("%u,%u,%u,%u\n", ports[0], ports[1], ports[2], ports[3]);
	fflush(stdout);
	for (;;) {
		if (poll(peers, 4, -1) < 0) {
			if (errno == EINTR)
				continue;
			return 1;
		}
		for (i = 0; i < 4; i++) {
			struct sockaddr_storage addr = {};
			socklen_t len = sizeof(addr);
			unsigned char data[65536];
			int count, source;

			if (!(peers[i].revents & POLLIN))
				continue;
			count = recvfrom(peers[i].fd, data, sizeof(data), 0,
					 (void *)&addr, &len);
			if (!count) {
				data[0] = i % 2;
				if (sendto(peers[i].fd, data, 0, 0, (void *)&addr, len) < 0)
					return 1;
				continue;
			}
			if (count < 2 || data[0] > 1)
				continue;
			if (data[1] == 'Q' && count == 2) {
				unsigned char packet[256] = { 0, 'Q' };
				int j;

				for (j = 0; j < 16; j++) {
					packet[0] = j;
					if (sendto(peers[i].fd, packet, sizeof(packet), 0,
						   (void *)&addr, len) != sizeof(packet))
						return 1;
				}
				continue;
			}
			if (data[1] == 'B' && count == (int)len + 2) {
				struct sockaddr_storage target = {};
				unsigned char packet[2] = { 0, 'B' };
				int j;

				memcpy(&target, data + 2, len);
				if (target.ss_family != addr.ss_family)
					continue;
				for (j = 0; j < 3; j++) {
					packet[0] = j % 2;
					if (sendto(peers[(i & ~1) + j % 2].fd,
						   packet, j == 2 ? 0 : sizeof(packet), 0,
						   (void *)&target, len) < 0)
						return 1;
				}
				continue;
			}
			if (data[1] == 'E' && count == (int)len + 2) {
				struct sockaddr_storage probe = addr;
				socklen_t probe_len = len;
				int fd = socket(addr.ss_family, SOCK_DGRAM, 0);

				if (addr.ss_family == AF_INET)
					((struct sockaddr_in *)&probe)->sin_port = 0;
				else
					((struct sockaddr_in6 *)&probe)->sin6_port = 0;
				if (fd < 0 || bind(fd, (void *)&probe, len) ||
				    getsockname(fd, (void *)&probe, &probe_len))
					return 1;
				close(fd);
				error_probe[i] = probe;
				error_source[i] = addr;
				error_valid[i] = true;
				memcpy(data + 2, &probe, len);
			} else if (data[1] == 'J' && error_valid[i] &&
				   !memcmp(&addr, &error_source[i], len)) {
				int fd = socket(addr.ss_family, SOCK_DGRAM, 0);

				if (fd < 0 || bind(fd, (void *)&error_probe[i], len) ||
				    sendto(fd, "C", 1, 0, (void *)&addr, len) != 1)
					return 1;
				close(fd);
				continue;
			}
			/* Name probes report the actual UDP sender; other payloads echo. */
			if (data[1] == 'N' && count == (int)len + 2)
				memcpy(data + 2, &addr, len);
			/* Report destination identity through the requested source. */
			source = (i & ~1) + data[0];
			data[0] = i % 2;
			if (sendto(peers[source].fd, data, count, 0,
				   (void *)&addr, len) < 0)
				return 1;
		}
	}
}
