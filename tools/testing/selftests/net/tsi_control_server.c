// SPDX-License-Identifier: GPL-2.0-only
/* A full host TCP accept queue keeps proxied connects pending. */
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t len = sizeof(addr);
	char command;
	int listener, filler, control;

	if (prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() == 1)
		return 1;
	listener = socket(AF_INET, SOCK_STREAM, 0);
	filler = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0 || filler < 0 ||
	    bind(listener, (void *)&addr, sizeof(addr)) ||
	    getsockname(listener, (void *)&addr, &len) || listen(listener, 0) ||
	    connect(filler, (void *)&addr, len))
		return 1;
	control = socket(AF_INET, SOCK_DGRAM, 0);
	if (control < 0 || bind(control, (void *)&addr, sizeof(addr)))
		return 1;
	printf("%u\n", ntohs(addr.sin_port));
	fflush(stdout);
	/* A final correlation test opens the queue after probing pending RPCs. */
	if (recv(control, &command, sizeof(command), 0) != 1 || command != 'd')
		return 1;
	for (int i = 0; i < 128; i++) {
		/* Keep peers open so completion is independent of EOF timing. */
		if (accept(listener, NULL, NULL) < 0)
			return 1;
	}
	return 1;
}
