.. SPDX-License-Identifier: GPL-2.0

Adversarial virtio-fs confinement tests
=====================================

``CONFIG_VIRTIO_FS_TEST=y`` adds ``/dev/virtiofs-test``. Guest root can use it
to send raw FUSE operation bodies through an existing virtio-fs mount. Names,
node IDs, handles and credentials bypass the guest VFS. Normal mounts do not
send adversarial traffic until the runner is explicitly invoked. The option
defaults to off. This is a private test interface, not a stable userspace ABI.

The runner and host fixture manager are one Python 3 script:
``tools/testing/selftests/filesystems/virtiofs/virtiofs_test.py``.
It uses only the standard library. Host commands run on macOS; ``run`` runs
as root in the Linux guest with the modified kernel and Python 3 installed.

Build on arm64 Linux
--------------------

Use the existing libkrunfw kernel configuration in this tree::

  scripts/config -e VIRTIO_FS_TEST --set-str LOCALVERSION '-virtiofs-test'
  make ARCH=arm64 olddefconfig
  make ARCH=arm64 -j12 Image

The kernel is ``arch/arm64/boot/Image``. Package it with libkrunfw as usual on
macOS. ``uname -r`` in the guest should contain ``-virtiofs-test`` (it may
also have a trailing ``+`` from the source version).
If starting from a fresh tree, first copy ``../config-libkrunfw_aarch64`` to
``.config``. No loadable modules are needed for this built-in configuration.

Basic run
---------

1. Copy the Python script to macOS and the guest. On macOS, create fixtures in
   the directory you actually export (a disposable writable export is best)::

     python3 virtiofs_test.py prepare --export /absolute/host/shared

   This creates a unique ``.virtiofs-test-TOKEN`` directory inside the export
   and ``.virtiofs-outside-TOKEN`` next to the export. It prints the guest
   fixture name and the host manifest path. Keep both paths. The outside
   directory contains disposable canaries that the attacks try to access or
   modify. Preparation does not change existing files in the export.

2. Start libkrun with the rebuilt firmware and enable Restricted permission
   semantics for that export in your launcher. The script does not enable
   restricted mode for you. If it is a secondary share, mount its tag::

     mkdir -p /mnt/share
     mount -t virtiofs YOUR_TAG /mnt/share

   ``--mount`` must point to the export root, not the fixture directory.
   If testing the virtio-fs root filesystem, use ``--mount /``.

3. In the guest, run as root, replacing TOKEN with the printed value::

     python3 virtiofs_test.py run --mount /mnt/share \
       --fixture .virtiofs-test-TOKEN \
       --report /tmp/virtiofs-results.json --trace /tmp/virtiofs-trace.jsonl

   ``/dev/virtiofs-test`` is created by devtmpfs. If your guest does not mount
   devtmpfs, find the major:minor numbers in
   ``/sys/class/misc/virtiofs-test/dev`` and use ``mknod`` to create the
   character device with mode 0600. An absent sysfs entry means that the test
   interface is not registered; check the running kernel and configuration.

4. After the guest run, verify on macOS using the manifest in the OUTSIDE
   directory, not its guest-visible copy::

     python3 virtiofs_test.py verify \
       --manifest /absolute/host/.virtiofs-outside-TOKEN/manifest.json

Both guest and host commands must succeed. Guest output uses TAP: each
``not ok`` is a failure; the final line gives the failure and skip counts.
Exit status is 0 on success and 1 on failure. Paste that output and the host
verification result when reporting a run. The JSON report and request/reply
trace provide details for failures. ``# RUN`` is flushed before each case to
identify a request if the backend hangs.

The suite tests invalid components on lookup and namespace mutations,
absolute paths, traversal, direct opens on symlink inode IDs, symlink parent
IDs, handle/inode mismatches, forged and released handles, forged node IDs,
spoofed credentials, hardlinks and special files. Positive read, write and
namespace controls must work before negative results are accepted. Transport
errors, malformed replies and ENOSYS do not count as confinement passes.
GETXATTR probes returning ENOSYS are reported as ``# SKIP`` in TAP and as
skipped entries in the JSON report: Restricted mode deliberately disables
xattrs, so these replies do not exercise inode confinement. ENOSYS from
other probed operations, and local ioctl failures, remain test failures.
An initial configuration check expects the current libkrun Restricted
implementation's zero lookup cache lifetimes and DIRECT_IO regular-file
opens. Failure here means the export does not match that implementation;
check the loaded libkrun library and the permission mode of the tested
export. This consistency check does not itself prove confinement.

Host mutations while the guest holds handles
--------------------------------------------

Use fresh fixtures and add ``--host-mutations`` to the guest command. The
guest opens files and a directory, writes ``handles-ready`` in the fixture,
then waits up to 300 seconds and prints a host command. In another macOS
terminal run::

  python3 virtiofs_test.py mutate \
    --manifest /absolute/host/.virtiofs-outside-TOKEN/manifest.json

The host moves a file and directory outside, creates an outside hardlink to
an open file, and unlinks/replaces another open file. The guest then retries
operations using the previously acquired inode IDs and handles. These must
fail. Release of an old handle is still allowed for cleanup.

After that run, the host verification command must include ``--mutated``::

  python3 virtiofs_test.py verify --mutated \
    --manifest /absolute/host/.virtiofs-outside-TOKEN/manifest.json

Each fixture is for one run, particularly with host mutations. Keep the
fixtures for investigation or remove the two printed directories manually
afterward. The script does not remove them automatically.

Limits and interface details
----------------------------

These are deterministic regression probes, not an exhaustive proof of
confinement. They do not exercise timing races, cross-device mounts, DAX,
virtqueue descriptor corruption, arbitrary header lengths, or the full
FUSE opcode space. Host-side path replacement races need separate stress
tests. Host verification checks the disposable outside namespace, file
contents, modes, ownership, link counts and modification times; it cannot
detect every possible read or a change that was subsequently restored.

The ioctl layout is in ``fs/fuse/virtio_fs_test.h``. It accepts a file
descriptor on the target mount, opcode, node ID, credentials, input bytes
and a reply buffer of at most 16 KiB each. The driver generates request IDs
and header lengths and preserves normal transport completion handling. It
pins the mount for the request and requires CAP_SYS_ADMIN in the initial
user namespace. INIT, DESTROY, INTERRUPT, FORGET, BATCH_FORGET and NOTIFY_REPLY
are rejected locally to avoid changing a live mount's control state. A
successful ioctl returns the host error separately from a local ioctl
failure. As with normal virtio-fs requests, a backend that stops responding
can stall the caller; there is no per-request timeout in this interface.

When FUSE_SECURITY_CTX was negotiated, the driver adds an empty security
context extension to CREATE, MKDIR, MKNOD and SYMLINK and sets total_extlen in
the FUSE header. The ioctl input contains the operation body without that
extension. This follows normal Linux request framing without requiring an
LSM context on test-created objects. It is independent of host confinement
policy; a missing negotiated extension is a protocol error, not a successful
policy rejection.
