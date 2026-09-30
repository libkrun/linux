#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host peer for tsi_tcp_restart; print its two UDP control ports."""

import errno
import random
import selectors
import socket
import struct


def tcp_state(family, port, peer, state):
    path = "/proc/net/tcp" if family == socket.AF_INET else "/proc/net/tcp6"
    with open(path, encoding="ascii") as table:
        return any(
            int(fields[1].split(":")[1], 16) == port
            and (not peer or int(fields[2].split(":")[1], 16) == peer)
            and int(fields[3], 16) == state
            for fields in (line.split() for line in table.readlines()[1:])
        )


def main():
    selector = selectors.DefaultSelector()
    peers = {}
    pools = {}
    held = {}
    controls = []
    with open("/proc/sys/net/ipv4/ip_local_port_range", encoding="ascii") as config:
        host_low, host_high = map(int, config.read().split())

    def bind_private(client, address, pool):
        # Leave the guest's ephemeral ports free for other suites in the VM.
        for port in pool:
            try:
                client.bind((address, port))
                return
            except OSError as error:
                if error.errno != errno.EADDRINUSE:
                    raise
        raise OSError(errno.EADDRINUSE, "restart peer port pool exhausted")

    for family in [socket.AF_INET, socket.AF_INET6]:
        control = socket.socket(family, socket.SOCK_DGRAM)
        control.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
        controls.append(control)
        selector.register(control, selectors.EVENT_READ)
    print(",".join(str(control.getsockname()[1]) for control in controls), flush=True)
    try:
        while True:
            for key, _ in selector.select():
                control = key.fileobj
                packet, source = control.recvfrom(128)
                if len(packet) != 20:
                    continue
                sequence, command, port, slot, value = struct.unpack("!5I", packet)
                owner = (control.family, source)
                clients = peers.setdefault(owner, {})
                result = value_out = 0
                try:
                    if command == 1:  # Connect a real host client.
                        client = socket.socket(control.family, socket.SOCK_STREAM)
                        client.settimeout(0.75)
                        try:
                            bind_private(client, source[0], pools[owner])
                            client.connect((source[0], port))
                            value_out = client.getsockname()[1]
                            clients[slot] = client
                        except OSError:
                            client.close()
                            raise
                    elif command == 2:
                        clients[slot].sendall(bytes([value]))
                    elif command == 3:
                        data = clients[slot].recv(1)
                        result = len(data)
                        value_out = data[0] if data else 0
                    elif command == 4:
                        clients.pop(slot).close()
                    elif command == 5:
                        value_out = int(tcp_state(control.family, port, value, 0x06))
                    elif command == 6:
                        value_out = int(tcp_state(control.family, port, 0, 0x0A))
                    elif command == 7:
                        for client in clients.values():
                            client.close()
                        peers.pop(owner, None)
                        pools.pop(owner, None)
                        if owner in held:
                            held.pop(owner).close()
                    elif command == 8:
                        pool = [
                            candidate for candidate in range(1024, 65536)
                            if not host_low <= candidate <= host_high
                            and not slot <= candidate <= value
                        ]
                        random.shuffle(pool)
                        pools[owner] = pool
                        with socket.socket(control.family, socket.SOCK_STREAM) as reserve:
                            bind_private(reserve, source[0], pool)
                            value_out = reserve.getsockname()[1]
                    elif command == 9:
                        listener = socket.socket(control.family, socket.SOCK_STREAM)
                        try:
                            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            listener.bind((source[0], port))
                            listener.listen(1)
                            held[owner] = listener
                        except OSError:
                            listener.close()
                            raise
                    elif command == 10:
                        held.pop(owner).close()
                    else:
                        result = -errno.EINVAL
                except TimeoutError:
                    result = -errno.ETIMEDOUT
                except OSError as error:
                    result = -(error.errno or errno.EIO)
                except KeyError:
                    result = -errno.EBADF
                control.sendto(struct.pack("!IiI", sequence, result, value_out), source)
    finally:
        for clients in peers.values():
            for client in clients.values():
                client.close()
        for control in controls:
            control.close()
        for listener in held.values():
            listener.close()
        selector.close()


if __name__ == "__main__":
    main()
