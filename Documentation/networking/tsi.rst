.. SPDX-License-Identifier: GPL-2.0-only

Transparent Socket Impersonation
================================

TSI forwards selected socket operations through VSOCK to a paired host
implementation. The TSIv4 ABI is under development for a coordinated
libkrun/libkrunfw release. It does not negotiate or fall back to TSIv3.

Linux ICMP datagram ping sockets
--------------------------------

With a Linux host proxy, ordinary iputils ping works through ICMP datagram
sockets for IPv4 and IPv6, including connected mode and explicit nonzero echo
identifiers. Guest-local echo destinations stay native; other destinations
use the host network. ICMP binds may use a host-selected source IP absent
from guest interfaces; the native endpoint temporarily permits that bind
and the host validates its own endpoint. Both guest and host must allow the socket owner's group
in net.ipv4.ping_group_range. CAP_NET_RAW is unnecessary. Echo identifiers are
managed by native ping sockets; UDP port mappings do not apply. Raw sockets,
outgoing TTL/hop-limit controls and host error-queue forwarding are unsupported.
Other host platforms return EPROTONOSUPPORT for ICMP proxy creation.

Control messages
----------------

Each control datagram starts with the following 24-byte header. All scalar
fields are little endian. The operation equals the destination VSOCK port
on a request and the source port on a reply.

======  ====  ========================================
Offset  Size  Field
======  ====  ========================================
0       4     Version, currently 4
4       4     Operation
8       8     Nonzero request ID, echoed unchanged
16      4     Payload length, excluding this header
20      4     Flags: 0 request, 1 reply, 2 one-way request
======  ====  ========================================

No other flag bits are defined. The datagram must contain exactly the
specified header and body. Replies originate at host CID 2 and the
operation's port. The guest checks source, version, operation, ID, flags
and length before using a reply. It discards unrelated and late replies
without extending the current deadline. Guest-generated IDs are distinct
across sockets and private control port reuse within a kernel boot.
Asynchronous host operations retain the originating request ID.

The current control bodies use these fixed lengths:

======  ============  =============  ====================================
Port    Request size  Reply size     Operation
======  ============  =============  ====================================
1024    12            4              Create proxy
1025    136           4              Connect: data port, address length,
                                     128-byte address
1026    12            136            Get name: data port, peer port, peer
                                     selector (0 local, 1 peer)
1027    136           none           Legacy UNIX sendto address (one-way)
1029    144           8              Listen: data port, listener port,
                                     backlog, address length, address
1030    8             4              Accept accounting: data port, flags=0
1031    8             none           Release: data port, peer port (one-way)
1033    4             4              Disconnect INET datagram: data port
1034    20            4              Set integer socket option
1035    16            8              Get integer socket option
1036    136           4              Bind INET datagram: data port, address
                                     length, 128-byte address
======  ============  =============  ====================================

Sizes exclude the common header. Fields are 32-bit unless stated
otherwise; addresses occupy 128 bytes with unused bytes zeroed. Replies
start with a signed 32-bit result: zero or a negative Linux errno.
GETNAME selects the local or peer name and appends a 32-bit address length and a 128-byte address; error
replies zero both. Unsupported versions return EPROTONOSUPPORT and
malformed requests return EPROTO when a request ID can be recovered.
Invalid one-way requests and headers too short to identify are dropped.

LISTEN appends a 32-bit policy flags word to its result. Bit 0 means
strict host publication: return the original host error instead of
activating a guest-only INET listener. Other bits are reserved and rejected.
The host selects policy; guests cannot opt out through request contents.
UNIX replies use zero policy flags. This unreleased TSIv4 reply format
requires matching guest and host implementations.

Local control operations have a five-second deadline. Blocking stream connect is
interruptible and uses the smaller of SO_SNDTIMEO and 120 seconds. GETNAME
and ordinary GETOPT wait through ordinary signals and remain killable; their
deadline is unchanged. This avoids spurious EINTR in applications that treat
metadata queries as synchronous. Late replies cannot satisfy a
later call. Create, datagram connect, listen, post-accept accounting and
SETOPT complete their bounded wait despite signals, since the host may
already have applied the change. GETOPT of SO_ERROR also waits through
signals because reading the host error clears it. A failed GETNAME or
GETOPT does not mark the control channel broken.
A failed exchange for a state-changing operation leaves host state
uncertain. The guest returns the exchange error and subsequent control and
data operations fail with EIO until close; close still releases the proxy.
This also prevents a pending connect or accept from being overwritten by
a later operation. Retrying an interrupted connect requires a new socket.
Normal host-reported errors do not mark the control channel broken.

Nonblocking INET stream connections
----------------------------------

An IPv4 or IPv6 stream connect with O_NONBLOCK returns EINPROGRESS while
connection setup proceeds in the guest. Repeating connect while it is
pending returns EALREADY. The guest first attempts its native endpoint,
then uses the host proxy if that attempt fails. Host completion and the
data VSOCK connection must both succeed before publishing proxy readiness.
This uses the existing CONNECT exchange; the wire ABI is unchanged.

poll/epoll wait on the application socket during setup. SO_ERROR returns
zero and writable readiness is withheld until completion. Success enables
ordinary transport readiness. Failure wakes waiters with writable/error
readiness and exposes the completion errno through SO_ERROR once; a second
read returns zero. A new connect on an established stream returns EISCONN.

The total setup deadline is the smaller of SO_SNDTIMEO at the start of the
attempt and 120 seconds. A timeout leaves the socket requiring close,
since host state may be uncertain. Closing a pending socket cancels guest
work and releases any host proxy; it does not wait for the remote TCP
connection deadline. Transport/control notifications and a deadline timer
drive setup without parking a worker for each outstanding TCP connection.

During setup, send/recv and ioctl return EAGAIN, getpeername returns
ENOTCONN, and getsockname reports the guest-native local endpoint. Other
socket-option setters return EAGAIN, except local receive/send timeouts;
changing those timeouts does not extend an active connect deadline.
Option getters use local values while setup owns the control channel.
bind/listen/accept return EINVAL and shutdown returns ENOTCONN. These
rules prioritize application event-loop progress over native equivalence.
UNIX streams retain their existing connection path.

Proxy creation
--------------

The 12-byte body sent to port 1024 is:

======  ====  ========================================
Offset  Size  Field
======  ====  ========================================
0       4     Guest data VSOCK port identifying the proxy
4       2     Linux socket family
6       2     Linux socket type
8       4     Linux socket protocol
======  ====  ========================================

INET stream proxies support protocol 0 or IPPROTO_TCP (6); INET datagram
proxies support 0 or IPPROTO_UDP (17). Linux hosts also support IPv4
IPPROTO_ICMP (1) and IPv6 IPPROTO_ICMPV6 (58) datagram ping sockets.
UNIX proxies support protocol 0.
Other protocols fail with EPROTONOSUPPORT instead of being mapped to TCP
or UDP. Platform family support and host impersonation permissions still
apply. Creation is acknowledged before data is sent. Duplicate creation
returns EADDRINUSE without replacing an existing proxy. The guest retains
the data port for close-time cleanup if a creation reply is lost.

INET datagrams
--------------

Explicit bind reserves the guest-native address and port, then creates the
host proxy, replays cached options and sends BIND to port 1036. The host
binds the same address and port, applying a configured guest:host port
override, and registers receive interest before acknowledging success.
No outgoing datagram is required to activate host-to-guest reception.
Host permission and bind errors are returned to the application; no
automatic host SO_REUSEPORT is enabled. Mapping entries override ports;
they do not form an allowlist.

The guest allocator chooses a nonzero port for bind(0). Explicitly bound
local names describe the guest endpoint, including when a mapping changes
the host port. That port remains reserved through AF_UNSPEC disconnect,
including when the original bind requested zero. UDP receive continues to
service both native and proxy queues while unconnected. Destination lookup
still favors a matching guest-native listener; identical host and guest
address tuples can therefore be ambiguous.

A host bind failure after native reservation requires close: TSI reports
the original error and later operations return EIO. It cannot atomically
roll back both endpoints while retaining arbitrary local socket tuning.
Closing releases the host datagram proxy immediately; no TCP-style reaper
delay applies. Implicitly bound outgoing sockets keep lazy proxy allocation
and report host names when using the proxy. UNIX datagram binding keeps its
existing path. These changes require the paired TSIv4 host implementation.

Send one complete frame to host VSOCK port 1032. Replies originate from
host CID 2, port 1032, and target the guest data port. The guest private
VSOCK endpoint connects to that tuple even for an unconnected application
socket. Host UDP socket state supplies connected peer filtering.

======  ====  ================================================================
Offset  Size  Field
======  ====  ================================================================
0       4     Version, currently 4
4       4     Peer address length: 16 for IPv4 or 28 for IPv6
8       4     Original payload length
12      4     Flags: bit 0 truncated, bit 1 packet-info, bit 2 hop-limit
16      128   Peer address followed by zero padding
144     4     Host ingress interface index; zero on guest sends
148     4     Reply TTL/hop-limit; zero without flag bit 2
152     16    Packet destination on receive; selected source on send
168     N     Payload, including N = 0 for an empty datagram
======  ====  ================================================================

The peer address is the destination on send and actual sender on receive. Its
layout follows Linux sockaddr_in or sockaddr_in6: little-endian family,
network-order port and IP bytes, network-order IPv6 flowinfo, little-endian
IPv6 scope ID. Unused address bytes and padding are zero. A send frame has
no truncation flag and its payload length equals the bytes following the header.
Packet-info requires a nonzero IP address: IPv4 occupies the first four bytes
with twelve zero bytes, and IPv6 occupies all sixteen. Without packet-info,
the interface index and IP bytes must all be zero. Hop-limit flag bit 2
requires packet-info and a value from 0 to 255. Without it, the hop-limit
word is zero. Host interface indices and hop-limit are receive metadata;
guest sends must supply zero in both fields and cannot set bit 2.

The entire frame is limited to 65536 bytes. Proxied sends larger than
65368 payload bytes fail with EMSGSIZE; guest-native delivery keeps its
native limits. A receive frame may contain fewer payload bytes than its
original length only with the truncated flag set. The original length is
limited to 65535. The receiver validates version, family, address length,
flags and payload length before exposing data to userspace.

Framing is hidden from applications. recvfrom/recvmsg return the actual
sender of each datagram, MSG_PEEK retains the complete packet, and
MSG_TRUNC reports truncation and the original payload length when available
from the host. A zero-byte payload is a datagram, not an end-of-file marker.
No synchronous acknowledgment is added to individual UDP sends.

When enabled, proxy receive supplies IP_PKTINFO or IPV6_PKTINFO with the actual
host destination IP, including for wildcard and implicitly bound sockets.
The packet-info interface index identifies a guest interface: a socket's bound
device, otherwise an interface owning that IP, otherwise guest loopback.
The host ingress interface index is never copied into the guest cmsg. This
models local proxy ingress without mirroring host interfaces into the guest.
Short control buffers set MSG_CTRUNC. If packet-info is absent from a frame,
a specifically bound guest-local address can still supply it from the bind.

Linux hosts also capture reply TTL/hop-limit. When requested with IP_RECVTTL
or IPV6_RECVHOPLIMIT, the guest receives IP_TTL or IPV6_HOPLIMIT ancillary
data. This does not add outgoing TTL/hop-limit control.

Proxy send supports IP_PKTINFO.ipi_spec_dst and IPV6_PKTINFO.ipi6_addr as source
address selection. A nonzero guest packet-info interface index must match the
logical guest interface for that source. The host applies the selected IP to
its native sendmsg; it validates whether the address is usable. Host send
errors follow the existing asynchronous UDP socket-error reporting. A zero
source and zero interface index express no preference.

Interface-only source selection, scoped IPv6 link-local source routing and
other proxy ancillary messages are unsupported. No host interface mapping is
provided for IPv6 scope IDs. Multicast and broadcast semantics are outside
this contract. Native delivery keeps its native ancillary handling; native
listener selection uses a packet-info source when present, otherwise native
route source selection for a wildcard sender. This allows replies to connected
guest-local clients without redirecting them through the host.

The 168-byte datagram header requires the coordinated updated TSIv4 host and
guest; the former 144-byte development layout is not supported. LISTEN and
control framing are unchanged.

UNIX datagram payloads still use the legacy two-message path, with their
address control message now enveloped as above. Firmware ABI checks remain
part of TSIv4 development.

UDP disconnect
--------------

Application connect(AF_UNSPEC) sends an acknowledged DISCONNECT request
before clearing the guest peer. The host dissolves the UDP association;
later sendto/connect operations reuse the proxy. Repeated disconnects are
supported. A switch to a guest-local peer also disconnects a previous
host peer. The private VSOCK data endpoint remains connected to its
canonical host tuple. Ordinary UDP sends do not acquire an acknowledgment.

Socket names
------------

GETNAME selector zero returns the host socket's local name; selector one
returns its peer. The guest normalizes Linux's internal nonzero peer
selectors to one. The address length is the concrete sockaddr size, not
the storage capacity: 16 bytes for IPv4, 28 for IPv6, or the UNIX name's
length. Unused bytes remain zero.

Proxied outgoing connections and accepted sockets use host-selected IP
addresses, including concrete local addresses for wildcard accepts.
Unconnected UDP sends expose the host-assigned local port; guest-local
operations use the native guest endpoint. A listener keeps its guest bind
identity. Explicit guest binds also retain their logical port when a host
port mapping or source-port choice differs; UNIX bind names remain guest
names. This does not add forwarding of explicit client-side binds to the
host. Hybrid sockets still have separate native and host endpoints.

Shutdown disables stream polling but retains the host socket until guest
release. A socket's local name therefore remains available after shutdown,
including after the previous five-second proxy-removal interval. Ordinary
peer-name errors still follow the state of the underlying host socket.

Socket options
--------------

SETOPT (1034) carries five 32-bit little-endian fields: guest data port,
peer port, Linux level, Linux option number and signed integer value.
GETOPT (1035) carries the first four fields. The port pair identifies an
outgoing proxy or accepted connection. SETOPT replies contain the result;
GETOPT replies append the effective signed integer value, zero on error.
The host maps Linux option numbers explicitly to native constants and
returns Linux errno values.

The initial host allowlist is:

* SOL_SOCKET: SO_REUSEADDR, SO_REUSEPORT, SO_KEEPALIVE, SO_BROADCAST,
  SO_SNDBUF and SO_RCVBUF; SO_ERROR is read-only.
* IPPROTO_TCP: TCP_NODELAY on INET streams.
* IPPROTO_IPV6: IPV6_V6ONLY on IPv6 sockets.

SO_REUSEPORT is unavailable on UNIX sockets and Windows hosts. Host wire
requests for unlisted options, including privileged buffer overrides and
host device binding, return ENOPROTOOPT. The host enforces the allowlist
independently of guest-side option handling.
Ordinary host setter errors leave the previous guest setting intact and
do not break control. If the host applied a setting but the guest cannot
apply its corresponding local setting, the socket requires close.

Before lazy proxy creation, successful native setters cache allowlisted
values. Replay occurs after creation and before host bind/listen/connect,
so IPV6_V6ONLY and reuse options take effect in the correct phase. Active
getters return effective host values, including host buffer limits and
platform-specific buffer accounting. Buffer setters also configure the
private guest transports. Boolean host values are normalized to zero or
one. Binding-only option changes retain the native host/guest errors.

Guest wait timeouts stay on the wrapper and private transports, including
accepted sockets. SO_BINDTODEVICE and SO_BINDTOIFINDEX configure only guest
routing. SO_TYPE, SO_DOMAIN, SO_PROTOCOL and SO_ACCEPTCONN describe the
application socket. Options outside the remote allowlist are applied to
and read from the private guest-native socket when it exists, including
after proxy creation. A successful local setter does not prevent host
networking. These values do not configure or describe the host endpoint;
for example, local TCP keepalive timing, maximum-segment size, user timeout
and UDP path-MTU policy are not forwarded. This best-effort policy favors
compatibility with applications that tune their sockets before connecting.
Accepted proxy-only sockets lack a guest-native endpoint and return
ENOPROTOOPT for such options. Options unsupported by the native guest
socket still fail. The host wire allowlist remains enforced.

SO_ERROR reads and clears pending errors. The broker preserves the first
pending asynchronous UDP error consumed by host I/O or Linux error
readiness, so a later guest read can retrieve it once. It does not add a
per-payload acknowledgment or relay asynchronous UDP POLLERR to the guest.
Delivery of error readiness and platform-specific socket semantics remain
limitations of this initial implementation.

Unix host INET stream proxies enable SO_REUSEADDR by default to support
rapid listener restart, and enable SO_REUSEPORT only on an explicit
application request. Explicit setters, including SO_REUSEADDR=0, override
these defaults before host bind/connect. Guest-native endpoints retain
their native defaults. UDP and UNIX stream reuse policy is unchanged.
SO_REUSEPORT is a request to share a host listening address; it does not
establish port isolation between VMs. Other host platforms retain their
native defaults and available option support.

TCP host publication policy
---------------------------

INET listeners are automatically exposed through a host proxy, applying
configured port overrides when present. Host publication defaults to best effort:
if host listen setup returns EPERM, EADDRINUSE or EADDRNOTAVAIL, TSI can
retain a guest-only listener and return success to the application.
Successful listen and SO_ACCEPTCONN therefore establish guest availability,
not host/external reachability. A port override does not make such failures
fatal. An existing host listener can keep ownership while a new guest-only
service starts successfully; it is not automatically promoted to a host
listener when the existing service exits. Close and recreate the listener
to retry publication. UNIX guest-only fallback follows its existing rules.

This default is an accepted application-compatibility limitation. Applications
can use guest-local services when host publication is unavailable, and callers
that need external reachability must verify it separately.

A VMM can enable ``TsiFlags::FAIL_ON_TCP_PUBLICATION_ERROR`` alongside
``HIJACK_INET`` (C: ``KRUN_TSI_FLAGS_FAIL_ON_TCP_PUBLICATION_ERROR``). In
that mode, an INET TCP host publication error is returned from guest listen
with its original errno. The bound native guest endpoint is not activated
as a listener, and SO_ACCEPTCONN remains false. A normal host error does
not break the control channel; listen may be retried after resolving the
conflict when the host socket state permits it. The policy applies to
mapped and unmapped ports for the VM. UNIX guest-local fallback, UDP
binding, and explicit SO_REUSEPORT behavior are unchanged.

Control reply fault coverage
----------------------------

The ``tsi_control_fault`` selftest requires a matching libkrun built with
the opt-in ``krun-devices/tsi-fault-injection`` Cargo feature. Ordinary
builds contain neither the injector nor its diagnostic VSOCK endpoint.
Build instructions and the diagnostic protocol are in libkrun's
``docs/tsi-control-faults.md``. Run the host ``tsi_udp_server`` peer and
pass its printed ports as ``TSI_UDP_PORTS``. Disable automatic INET hijacking
in the guest; the test uses explicit TSI families and native VSOCK control.

The test corrupts host replies after their operations have run. It checks
exact envelope/body lengths, version, operation, flags and errno validation;
unrelated sources and request IDs; duplicates; missing replies; and late
replies following timeout, interruption or close. Read-only GETNAME/GETOPT
failures must leave the socket usable. Uncertain CREATE, CONNECT, BIND,
LISTEN, ACCEPT, SETOPT and DISCONNECT exchanges must fail within their
deadline and require close. Nonblocking TCP connect is included.

Each state-change case checks close-time host proxy removal and replacement
socket operation. The suite also performs 64 interrupted-read/close/replacement
cycles. A held reply is retargeted to the replacement's private control port,
preserving its old request ID and carrying a detectable error. This models
control-port reuse deterministically; it does not require allocator wraparound.
Counters verify that each selected fault actually ran. An ordinary host build
skips this suite; release validation must require zero skips with the injector.
Run both TCP publication policies with the same paired TSIv4 host/kernel.

TCP listener restart coverage
----------------------------

The ``tsi_tcp_restart`` selftest exercises IPv4/IPv6 listener replacement
inside a running guest. Run its host peer first::

  python3 tools/testing/selftests/net/tsi_tcp_restart_server.py

The peer prints two comma-separated UDP control ports. Pass those to the
guest, disable automatic INET hijacking for these explicit-family tests,
and run::

  TSI_TCP_RESTART_PORTS=<port4>,<port6> ./tsi_tcp_restart

The VMM must allow INET impersonation and automatic host exposure. The
guest uses explicit TSI sockets and the peer opens real host TCP clients.
The peer requires Linux ``/proc/net/tcp`` and ``/proc/net/tcp6``. Run native
controls on the host with the same peer::

  TSI_TCP_RESTART_NATIVE=1 TSI_TCP_RESTART_PORTS=<port4>,<port6> ./tsi_tcp_restart

The peer selects server and client TCP ports outside both host and guest
ephemeral ranges, so retained connections and TIME_WAIT do not occupy ports
used by unrelated guest tests. No system port-range setting is changed.

There are 32 restart cases: four scenarios for each family and option combination.
Scenarios cover an idle listener, an interrupted blocking accept, an
accepted connection that survives replacement, and verified host-side
TIME_WAIT. Options are application defaults, SO_REUSEADDR alone, and
SO_REUSEADDR with SO_REUSEPORT explicitly disabled or enabled. Effective
values are logged without requiring a particular implicit reuse default.

Before replacement, the peer verifies that the old host listener has
disappeared. Retirement and rebind must complete within one second, and
eight host connections must exchange distinct tags through the replacement.
The surviving connection must still exchange data after replacement. The
TIME_WAIT case verifies the actual host server/client port tuple; it does
not infer TCP state from a delay or successful close. Native controls
without reuse options expect EADDRINUSE while old connections own the port.
These tests establish a restart baseline without changing publication,
cleanup or reuse policy; they do not establish isolation between VMs.

Eight additional VM-only cases occupy the host port and verify publication
failure, local service or its absence, and recovery after releasing the
conflict. Pass ``TSI_TCP_PUBLICATION_STRICT=1`` to the guest test when the
VMM enables strict publication. The flag must match host configuration;
it selects expectations, not policy. Default mode requires close/recreate
to retry a guest-only fallback; strict mode verifies retrying listen on the
same bound socket. Native controls skip these eight cross-namespace cases.
