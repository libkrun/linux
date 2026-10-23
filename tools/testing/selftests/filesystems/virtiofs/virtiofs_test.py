#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Raw virtio-fs confinement probes and disposable host fixtures (Python 3)."""

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import struct
import sys
import time
import uuid


OP = {
    "LOOKUP": 1, "GETATTR": 3, "SETATTR": 4, "READLINK": 5,
    "SYMLINK": 6, "MKNOD": 8, "MKDIR": 9, "UNLINK": 10, "RMDIR": 11,
    "RENAME": 12, "LINK": 13, "OPEN": 14, "READ": 15, "WRITE": 16,
    "RELEASE": 18, "FSYNC": 20, "SETXATTR": 21, "GETXATTR": 22,
    "FLUSH": 25, "OPENDIR": 27, "READDIR": 28, "RELEASEDIR": 29,
    "CREATE": 35, "FALLOCATE": 43, "RENAME2": 45, "LSEEK": 46,
}
ROOT = 1
ENTRY_SIZE = 128
MAX_PAYLOAD = 16384
U64_MAX = (1 << 64) - 1
# These are Linux flags, even when fixtures are prepared on macOS.
RDWR, CREAT, EXCL, TRUNC, NOFOLLOW = 2, 0o100, 0o200, 0o1000, 0o400000
DENIED = {
    errno.EPERM, errno.EACCES, errno.EINVAL, errno.ENOENT, errno.ENOTDIR,
    errno.ELOOP, errno.EBADF, errno.ESTALE, errno.EXDEV, errno.EOPNOTSUPP,
}


class Request(ctypes.Structure):
    # Keep in sync with fs/fuse/virtio_fs_test.h; identical on arm64 and x86_64.
    _fields_ = [
        ("mount_fd", ctypes.c_uint32), ("opcode", ctypes.c_uint32),
        ("nodeid", ctypes.c_uint64), ("in_ptr", ctypes.c_uint64),
        ("out_ptr", ctypes.c_uint64), ("in_len", ctypes.c_uint32),
        ("out_len", ctypes.c_uint32), ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32), ("pid", ctypes.c_uint32),
        ("error", ctypes.c_int32), ("out_actual", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]


assert ctypes.sizeof(Request) == 64
IOCTL = (3 << 30) | (ctypes.sizeof(Request) << 16) | (0xe5 << 8)


def pack(fmt, *args):
    return struct.pack("<" + fmt, *args)


def cstring(value):
    value = os.fsencode(value)
    if b"\0" in value:
        raise ValueError("embedded NUL in test name")
    return value + b"\0"


def read_arg(handle, size=512, offset=0):
    return pack("QQIIQII", handle, offset, size, 0, 0, 0, 0)


def write_arg(handle, data=b"ATTACK\n"):
    return pack("QQIIQII", handle, 0, len(data), 0, 0, RDWR, 0) + data


def setattr_arg(handle=0, valid=8, size=0):
    return pack("IIQQQQQQIIIIIIII", valid, 0, handle, size, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0)


class ProbeFailure(Exception):
    pass


class ProbeSkip(Exception):
    pass


class SuiteAbort(ProbeFailure):
    pass


def require(condition, message):
    if not condition:
        raise ProbeFailure(message)


class Reply:
    def __init__(self, error, data, op="request"):
        self.error, self.data, self.op = error, data, op

    def ok(self, minimum=0):
        require(self.error == 0, f"{self.op}: host returned {errno.errorcode.get(self.error, self.error)}")
        require(len(self.data) >= minimum,
                f"short reply: {len(self.data)} bytes, expected at least {minimum}")
        return self.data

    def denied(self):
        if self.op == "GETXATTR" and self.error == errno.ENOSYS:
            raise ProbeSkip("GETXATTR unsupported (ENOSYS); inode confinement not exercised")
        require(self.error in DENIED,
                f"expected rejection, got {errno.errorcode.get(self.error, self.error)} "
                f"data={self.data[:64].hex()}")


class Client:
    def __init__(self, mount, device, trace=None):
        self.mount_fd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.device_fd = os.open(device, os.O_RDWR)
        except BaseException:
            os.close(self.mount_fd)
            raise
        self.trace = trace
        self.label = "setup"
        self.handles = []

    def request(self, op, node, payload=b"", out=0, creds=None):
        if len(payload) > MAX_PAYLOAD or out > MAX_PAYLOAD:
            raise ValueError("test payload exceeds kernel interface limit")
        incoming = ctypes.create_string_buffer(payload or b"\0")
        outgoing = ctypes.create_string_buffer(max(out, 1))
        uid, gid, pid = creds or (os.getuid(), os.getgid(), os.getpid())
        req = Request(self.mount_fd, OP[op], node, ctypes.addressof(incoming),
                      ctypes.addressof(outgoing), len(payload), out, uid, gid, pid, 0, 0, 0)
        event = {"case": self.label, "op": op, "node": node,
                 "uid": uid, "gid": gid, "pid": pid, "input": payload.hex()}
        if self.trace:
            self.trace.write(json.dumps(dict(event, stage="send")) + "\n")
            self.trace.flush()
        wire = bytearray(req)
        # ioctl failures are local harness failures, never host policy passes.
        fcntl.ioctl(self.device_fd, IOCTL, wire, True)
        req = Request.from_buffer_copy(wire)
        require(req.out_actual <= out, "kernel returned an oversized reply")
        reply = Reply(-req.error, outgoing.raw[:req.out_actual], op)
        if self.trace:
            self.trace.write(json.dumps(dict(event, stage="reply", error=reply.error,
                                             output=reply.data.hex())) + "\n")
            self.trace.flush()
        return reply

    def lookup(self, node, name):
        data = self.request("LOOKUP", node, cstring(name), ENTRY_SIZE).ok(ENTRY_SIZE)
        result, = struct.unpack_from("<Q", data)
        require(result != 0, "negative lookup entry")
        return result

    def open(self, node, flags=0, directory=False):
        data = self.request("OPENDIR" if directory else "OPEN", node,
                            pack("II", flags, 0), 16).ok(16)
        handle, = struct.unpack_from("<Q", data)
        self.handles.append((node, handle, directory))
        return handle

    def release(self, node, handle, directory=False):
        reply = self.request("RELEASEDIR" if directory else "RELEASE", node,
                             pack("QIIQ", handle, 0, 0, 0))
        reply.ok()
        self.handles.remove((node, handle, directory))

    def contents(self, node, expected):
        handle = self.open(node)
        try:
            data = self.request("READ", node, read_arg(handle), 512).ok()
            require(data == expected, f"unexpected data: {data!r}")
        finally:
            self.release(node, handle)

    def close(self):
        for node, handle, directory in self.handles[:]:
            try:
                self.release(node, handle, directory)
            except (OSError, ProbeFailure):
                pass
        os.close(self.device_fd)
        os.close(self.mount_fd)


class Suite:
    def __init__(self, client):
        self.client = client
        self.results = []

    def case(self, name, action=None, skip=None):
        number = len(self.results) + 1
        self.client.label = name
        print(f"# RUN {number} {name}", flush=True)
        detail = ""
        passed = True
        if not skip:
            try:
                action()
            except ProbeSkip as exc:
                skip = str(exc)
            except (OSError, ProbeFailure, ValueError, TimeoutError) as exc:
                passed, detail = False, f"{type(exc).__name__}: {exc}"
        self.results.append({"name": name, "pass": passed, "detail": detail, "skip": skip})
        suffix = f" # SKIP {skip}" if skip else ""
        print(f"{'ok' if passed else 'not ok'} {number} - {name}{suffix}", flush=True)
        if detail:
            print("# " + detail, flush=True)
        return passed

    def deny(self, name, op, node, payload=b"", out=0, creds=None):
        return self.case(name, lambda: self.client.request(op, node, payload, out, creds).denied())


def snapshot(directory):
    """Do not follow symlinks or count atime changes caused by verification."""
    result = {}
    for path in sorted(Path(directory).rglob("*")):
        key = path.relative_to(directory).as_posix()
        if key == "manifest.json":
            continue
        st = path.lstat()
        item = {"mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid}
        if stat.S_ISREG(st.st_mode):
            item.update(type="file", size=st.st_size, nlink=st.st_nlink,
                        sha256=hashlib.sha256(path.read_bytes()).hexdigest(), mtime_ns=st.st_mtime_ns)
        elif stat.S_ISDIR(st.st_mode):
            item.update(type="dir")
        elif stat.S_ISLNK(st.st_mode):
            item.update(type="symlink", target=os.readlink(path))
        else:
            item.update(type="special")
        result[key] = item
    return result


def save_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n")


def prepare(args):
    root = Path(args.export).resolve(strict=True)
    require(root.is_dir() and root.parent != root, "export must be a directory below /")
    token = uuid.uuid4().hex[:12]
    fixture = root / (".virtiofs-test-" + token)
    outside = root.parent / (".virtiofs-outside-" + token)
    fixture.mkdir(mode=0o700)
    outside.mkdir(mode=0o700)
    inside_data = f"VIRTIOFS_INSIDE:{token}\n"
    outside_data = f"VIRTIOFS_OUTSIDE:{token}\n"
    (fixture / "inside").write_text(inside_data)
    (fixture / "other").write_text("OTHER\n")
    (fixture / "rename-source").write_text("RENAME_SOURCE\n")
    (fixture / "sub").mkdir()
    for name in ("movable", "hardlink-later", "unlinked-later"):
        (fixture / name).write_text(f"UNCHANGED:{name}:{token}\n")
    (fixture / "movable-dir").mkdir()
    (fixture / "movable-dir" / "child").write_text(f"UNCHANGED:child:{token}\n")
    for name in ("canary", "unlink-victim", "rename-source", "rename-dest", "hardlink-source"):
        (outside / name).write_text(outside_data)
    (outside / "empty-dir").mkdir()
    os.link(outside / "hardlink-source", fixture / "hardlink")
    links = {
        "rel-inside": "inside", "abs-inside": f"/{fixture.name}/inside",
        "chain-inside": "abs-inside", "escape-rel": f"../../{outside.name}/canary",
        "escape-abs": str(outside / "canary"), "escape-dir": f"../../{outside.name}",
        "loop": "loop",
    }
    for name, target in links.items():
        os.symlink(target, fixture / name)
    os.mkfifo(fixture / "fifo", 0o600)
    before = snapshot(outside)
    source = snapshot(fixture)
    after = dict(before)
    after["moved"] = source["movable"]
    after["moved-dir"] = source["movable-dir"]
    after["moved-dir/child"] = source["movable-dir/child"]
    after["linked-later"] = dict(source["hardlink-later"], nlink=2)
    manifest = {
        "version": 1, "token": token, "export": str(root), "fixture": fixture.name,
        "outside": str(outside), "inside_data": inside_data, "links": links,
        "expected_before": before, "expected_after": after,
        "mutation_sources": {name: value for name, value in source.items()
                             if name in {"movable", "movable-dir", "movable-dir/child",
                                         "hardlink-later", "unlinked-later"}},
    }
    save_json(outside / "manifest.json", manifest)
    save_json(fixture / "manifest.json", manifest)
    print(f"Fixture: {fixture}")
    print(f"Host manifest: {outside / 'manifest.json'}")
    print(f"Guest: python3 virtiofs_test.py run --mount /mnt/share --fixture {fixture.name}")
    print("Add --host-mutations to test objects moved, linked or unlinked by the host.")
    return 0


def load_manifest(path):
    manifest = json.loads(Path(path).read_text())
    require(manifest["version"] == 1, "unsupported fixture version")
    return manifest


def verify_snapshot(actual, expected):
    differences = [key for key in sorted(actual.keys() | expected.keys())
                   if actual.get(key) != expected.get(key)]
    require(not differences, "outside fixture changed: " + ", ".join(differences))


def mutate(args):
    manifest = load_manifest(args.manifest)
    fixture = Path(manifest["export"]) / manifest["fixture"]
    outside = Path(manifest["outside"])
    ready = json.loads((fixture / "handles-ready").read_text())
    require(ready["token"] == manifest["token"], "guest readiness marker mismatch")
    verify_snapshot(snapshot(outside), manifest["expected_before"])
    sources = snapshot(fixture)
    for key, value in manifest["mutation_sources"].items():
        require(sources.get(key) == value, f"mutation source changed: {key}")
    os.rename(fixture / "movable", outside / "moved")
    os.rename(fixture / "movable-dir", outside / "moved-dir")
    os.link(fixture / "hardlink-later", outside / "linked-later")
    (fixture / "unlinked-later").unlink()
    (fixture / "unlinked-later").write_text("REPLACEMENT\n")
    verify_snapshot(snapshot(outside), manifest["expected_after"])
    save_json(fixture / "mutations-done", {"token": manifest["token"]})
    print("Host mutations complete; guest can continue.")
    return 0


def verify(args):
    manifest = load_manifest(args.manifest)
    expected = manifest["expected_after" if args.mutated else "expected_before"]
    verify_snapshot(snapshot(manifest["outside"]), expected)
    print("PASS: outside fixture contents, metadata and namespace are unchanged.")
    return 0


def restricted_preflight(client, fixture):
    data = client.request("LOOKUP", fixture, cstring("inside"), ENTRY_SIZE).ok(ENTRY_SIZE)
    node, = struct.unpack_from("<Q", data)
    entry_seconds, attr_seconds, entry_ns, attr_ns = struct.unpack_from("<QQII", data, 16)
    require((entry_seconds, attr_seconds, entry_ns, attr_ns) == (0, 0, 0, 0),
            f"LOOKUP cache lifetimes are entry={entry_seconds}s+{entry_ns}ns, "
            f"attr={attr_seconds}s+{attr_ns}ns; current Restricted mode requires zero. "
            "Check the libkrun build and permission mode of this export")
    data = client.request("OPEN", node, pack("II", 0, 0), 16).ok(16)
    handle, flags = struct.unpack_from("<QI", data)
    client.handles.append((node, handle, False))
    client.release(node, handle)
    require(flags & 1, f"OPEN flags={flags:#x} lack DIRECT_IO; "
            "check Restricted permission mode for this export")


def positive_mutations(client, fixture):
    data = client.request("MKDIR", fixture, pack("II", 0o700, 0) + cstring("scratch"), ENTRY_SIZE).ok(ENTRY_SIZE)
    directory, = struct.unpack_from("<Q", data)
    data = client.request("CREATE", directory,
                          pack("IIII", RDWR | CREAT | EXCL, 0o100600, 0, 0) + cstring("file"), 144).ok(144)
    node, = struct.unpack_from("<Q", data)
    handle, = struct.unpack_from("<Q", data, ENTRY_SIZE)
    client.handles.append((node, handle, False))
    written = client.request("WRITE", node, write_arg(handle, b"CONTROL\n"), 8).ok(8)
    require(struct.unpack_from("<I", written)[0] == 8, "short positive WRITE")
    require(client.request("READ", node, read_arg(handle), 512).ok() == b"CONTROL\n", "positive readback failed")
    client.request("GETATTR", node, pack("IIQ", 1, 0, handle), 104).ok(104)
    client.request("SETATTR", node, setattr_arg(handle, 8 | 64, 4), 104).ok(104)
    client.request("FLUSH", node, pack("QIIQ", handle, 0, 0, 0)).ok()
    client.request("FSYNC", node, pack("QII", handle, 0, 0)).ok()
    client.request("FALLOCATE", node, pack("QQQII", handle, 0, 8, 0, 0)).ok()
    client.request("LSEEK", node, pack("QQII", handle, 0, 0, 0), 8).ok(8)
    client.release(node, handle)
    client.request("MKNOD", directory,
                   pack("IIII", 0o100600, 0, 0, 0) + cstring("regular"), ENTRY_SIZE).ok(ENTRY_SIZE)
    client.request("SYMLINK", directory, cstring("link") + cstring("regular"), ENTRY_SIZE).ok(ENTRY_SIZE)
    client.request("RENAME", directory,
                   pack("Q", directory) + cstring("file") + cstring("renamed")).ok()
    client.request("RENAME2", directory,
                   pack("QII", directory, 0, 0) + cstring("renamed") + cstring("again")).ok()
    fh = client.open(directory, directory=True)
    client.request("READDIR", directory, read_arg(fh), 512).ok(24)
    client.release(directory, fh, directory=True)
    for name in ("regular", "link", "again"):
        client.request("UNLINK", directory, cstring(name)).ok()
    client.request("RMDIR", fixture, cstring("scratch")).ok()


def name_probes(suite, fixture, manifest, inside):
    outside = Path(manifest["outside"])
    invalid = [b"", b".", b"..", b"/", b"a/b", b"inside/",
               os.fsencode(f"../{outside.name}/canary"), os.fsencode(outside / "canary")]
    for parent, label in ((ROOT, "export"), (fixture, "fixture")):
        for name in invalid:
            suite.deny(f"LOOKUP {label} component {name!r}", "LOOKUP", parent,
                       cstring(name), ENTRY_SIZE)
    # All mutations target only the disposable outside fixture if confinement fails.
    for prefix, label in ((f"../{outside.name}/", "dotdot"), (str(outside) + "/", "absolute")):
        new = lambda leaf: cstring(prefix + leaf)
        for op, payload, out in (
            ("CREATE", pack("IIII", RDWR | CREAT | EXCL, 0o100600, 0, 0) + new("created"), 144),
            ("MKNOD", pack("IIII", 0o100600, 0, 0, 0) + new("mknod"), ENTRY_SIZE),
            ("MKDIR", pack("II", 0o700, 0) + new("mkdir"), ENTRY_SIZE),
            ("SYMLINK", new("symlink") + cstring("unused"), ENTRY_SIZE),
            ("UNLINK", new("unlink-victim"), 0),
            ("RMDIR", new("empty-dir"), 0),
            ("LINK", pack("Q", inside) + new("linked"), ENTRY_SIZE),
        ):
            suite.deny(f"{op} {label} component", op, ROOT, payload, out)
        for op in ("RENAME", "RENAME2"):
            header = pack("Q", fixture) if op == "RENAME" else pack("QII", fixture, 0, 0)
            suite.deny(f"{op} {label} source", op, ROOT,
                       header + new("rename-source") + cstring("received"))
            header = pack("Q", ROOT) if op == "RENAME" else pack("QII", ROOT, 0, 0)
            suite.deny(f"{op} {label} destination", op, fixture,
                       header + cstring("rename-source") + new("rename-dest"))
    for creds in ((0, 0, 1), (0xffffffff, 0xffffffff, 0xffffffff)):
        suite.deny(f"spoofed credentials {creds}", "LOOKUP", ROOT,
                   cstring(f"../{outside.name}/canary"), ENTRY_SIZE, creds)


def handle_probes(suite, inside, other, handle):
    for node, fh, label in ((other, handle, "inode mismatch"), (inside, 0, "zero handle"),
                            (inside, U64_MAX, "forged handle")):
        for op, payload, out in (
            ("GETATTR", pack("IIQ", 1, 0, fh), 104),
            ("READ", read_arg(fh), 512),
            ("WRITE", write_arg(fh), 8),
            ("SETATTR", setattr_arg(fh, 8 | 64, 0), 104),
            ("FLUSH", pack("QIIQ", fh, 0, 0, 0), 0),
            ("FSYNC", pack("QII", fh, 0, 0), 0),
            ("FALLOCATE", pack("QQQII", fh, 0, 8, 0, 0), 0),
            ("LSEEK", pack("QQII", fh, 0, 0, 0), 8),
            ("RELEASE", pack("QIIQ", fh, 0, 0, 0), 0),
        ):
            suite.deny(f"{op} {label}", op, node, payload, out)
    for node in (0, U64_MAX):
        suite.deny(f"GETATTR forged node {node}", "GETATTR", node, pack("IIQ", 0, 0, 0), 104)
        suite.deny(f"OPEN forged node {node}", "OPEN", node, pack("II", 0, 0), 16)
        suite.deny(f"LOOKUP forged parent {node}", "LOOKUP", node, cstring("inside"), ENTRY_SIZE)


def symlink_probes(suite, fixture, manifest):
    client = suite.client
    for name in ("rel-inside", "abs-inside", "chain-inside"):
        def positive(name=name):
            node = client.lookup(fixture, name)
            target = client.request("READLINK", node, out=4096).ok()
            require(target == os.fsencode(manifest["links"][name]), "wrong symlink identity")
            client.contents(node, manifest["inside_data"].encode())
        suite.case(f"raw OPEN resolves {name} inside export", positive)
    for name in ("escape-rel", "escape-abs", "escape-dir", "loop", "rel-inside"):
        node = client.lookup(fixture, name)
        suite.deny(f"OPEN NOFOLLOW {name}", "OPEN", node, pack("II", NOFOLLOW, 0), 16)
        suite.deny(f"LOOKUP through symlink inode {name}", "LOOKUP", node, cstring("canary"), ENTRY_SIZE)
        if name != "rel-inside":
            suite.deny(f"raw OPEN external or looping symlink {name}", "OPEN", node, pack("II", 0, 0), 16)
            suite.deny(f"raw OPEN TRUNC external or looping symlink {name}", "OPEN", node,
                       pack("II", 1 | TRUNC, 0), 16)
            suite.deny(f"SETATTR size on symlink {name}", "SETATTR", node, setattr_arg(), 104)


def moved_probes(suite, fixture, fixture_path, manifest, timeout):
    client = suite.client
    held = []
    for name in ("movable", "hardlink-later", "unlinked-later", "movable-dir"):
        directory = name == "movable-dir"
        node = client.lookup(fixture, name)
        held.append((name, node, client.open(node, 0 if directory else RDWR, directory), directory))
    save_json(fixture_path / "handles-ready", {"token": manifest["token"]})
    print(f"# HOST: python3 virtiofs_test.py mutate --manifest {manifest['outside']}/manifest.json", flush=True)

    def wait_host():
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                done = json.loads((fixture_path / "mutations-done").read_text())
                require(done["token"] == manifest["token"], "host mutation marker mismatch")
                return
            except FileNotFoundError:
                time.sleep(0.25)
        raise TimeoutError("host mutation command was not completed")

    if not suite.case("host mutation handshake", wait_host):
        return
    for name, node, fh, directory in held:
        for op, payload, out in (
            ("GETATTR", pack("IIQ", 0, 0, 0), 104),
            ("GETATTR", pack("IIQ", 1, 0, fh), 104),
            ("OPEN", pack("II", 0, 0), 16),
            ("SETATTR", setattr_arg(fh, 8 | 64, 0), 104),
            ("FLUSH", pack("QIIQ", fh, 0, 0, 0), 0),
            ("FSYNC", pack("QII", fh, 0, 0), 0),
            ("GETXATTR", pack("II", 0, 0) + cstring("user.virtiofs-test"), 8),
        ):
            suite.deny(f"{op} after host change {name}", op, node, payload, out)
        if directory:
            suite.deny(f"LOOKUP moved directory {name}", "LOOKUP", node, cstring("child"), ENTRY_SIZE)
            suite.deny(f"READDIR moved directory {name}", "READDIR", node, read_arg(fh), 512)
            suite.deny(f"MKDIR moved directory {name}", "MKDIR", node,
                       pack("II", 0o700, 0) + cstring("created"), ENTRY_SIZE)
        else:
            suite.deny(f"READ after host change {name}", "READ", node, read_arg(fh), 512)
            suite.deny(f"WRITE after host change {name}", "WRITE", node, write_arg(fh), 8)
            suite.deny(f"FALLOCATE after host change {name}", "FALLOCATE", node,
                       pack("QQQII", fh, 0, 8, 0, 0))
            suite.deny(f"LSEEK after host change {name}", "LSEEK", node, pack("QQII", fh, 0, 0, 0), 8)


def run(args):
    require(sys.platform == "linux", "run the probes inside the Linux guest")
    require(platform.machine() in ("aarch64", "x86_64"), "unsupported ioctl architecture")
    mount = Path(args.mount).resolve(strict=True)
    relative = Path(args.fixture)
    require(not relative.is_absolute() and ".." not in relative.parts, "fixture must be relative to mount")
    fixture_path = mount / relative
    manifest = load_manifest(fixture_path / "manifest.json")
    require(relative.as_posix() == manifest["fixture"], "fixture name differs from manifest")
    trace = open(args.trace, "w") if args.trace else None
    client = Client(mount, args.device, trace)
    suite = Suite(client)
    print("TAP version 13", flush=True)
    print(f"# kernel={platform.release()} token={manifest['token']}", flush=True)
    try:
        fixture = client.lookup(ROOT, manifest["fixture"])
        inside = client.lookup(fixture, "inside")
        other = client.lookup(fixture, "other")
        if not suite.case("restricted export configuration", lambda: restricted_preflight(client, fixture)):
            raise SuiteAbort("export does not match the current Restricted implementation")
        if not suite.case("positive raw OPEN/READ of inside canary",
                          lambda: client.contents(inside, manifest["inside_data"].encode())):
            raise SuiteAbort("positive control failed; refusing misleading denial results")
        if not suite.case("positive file and directory mutations", lambda: positive_mutations(client, fixture)):
            raise SuiteAbort("positive mutations failed; check export is writable and restricted")
        handle = client.open(inside, RDWR)
        name_probes(suite, fixture, manifest, inside)
        symlink_probes(suite, fixture, manifest)
        handle_probes(suite, inside, other, handle)
        suite.deny("reject pre-existing hardlink", "LOOKUP", fixture, cstring("hardlink"), ENTRY_SIZE)
        suite.deny("reject FIFO", "LOOKUP", fixture, cstring("fifo"), ENTRY_SIZE)
        suite.deny("reject new hardlink", "LINK", fixture, pack("Q", inside) + cstring("new-link"), ENTRY_SIZE)
        suite.case("inside canary intact after forged requests",
                   lambda: client.contents(inside, manifest["inside_data"].encode()))
        suite.case("other inode intact after mismatched handle writes",
                   lambda: client.contents(other, b"OTHER\n"))
        stale = client.open(other)
        client.release(other, stale)
        suite.deny("READ released handle", "READ", other, read_arg(stale), 512)
        directory_handle = client.open(fixture, directory=True)
        suite.deny("READDIR mismatched inode", "READDIR", ROOT, read_arg(directory_handle), 512)
        suite.deny("RELEASEDIR mismatched inode", "RELEASEDIR", ROOT,
                   pack("QIIQ", directory_handle, 0, 0, 0))
        if args.host_mutations:
            moved_probes(suite, fixture, fixture_path, manifest, args.host_timeout)
        else:
            suite.case("host mutation probes", skip="enable --host-mutations and run host mutate command")
    except SuiteAbort as exc:
        print(f"# Stopped: {exc}", flush=True)
    except (OSError, ProbeFailure, ValueError) as exc:
        suite.case("harness setup/continuation", lambda: (_ for _ in ()).throw(ProbeFailure(str(exc))))
    finally:
        client.close()
        if trace:
            trace.close()
    failures = sum(not item["pass"] for item in suite.results)
    skipped = sum(bool(item["skip"]) for item in suite.results)
    print(f"1..{len(suite.results)}")
    print(f"# {len(suite.results)} tests, {failures} failures, {skipped} skipped")
    print("# Also run host verify; guest denials alone do not prove the canaries survived.")
    if args.report:
        save_json(args.report, {"kernel": platform.release(), "token": manifest["token"],
                                "results": suite.results})
    return bool(failures)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    host = sub.add_parser("prepare", help="create disposable fixtures on macOS")
    host.add_argument("--export", required=True, help="existing directory exported by virtio-fs")
    host.set_defaults(func=prepare)
    for command, function in (("mutate", mutate), ("verify", verify)):
        host = sub.add_parser(command, help=f"{command} fixtures on the host")
        host.add_argument("--manifest", required=True, help="host manifest in the OUTSIDE directory")
        host.set_defaults(func=function)
        if command == "verify":
            host.add_argument("--mutated", action="store_true", help="expect planned host mutations")
    guest = sub.add_parser("run", help="send adversarial requests inside the guest")
    guest.add_argument("--mount", required=True, help="virtio-fs mount point; / for a virtio-fs rootfs")
    guest.add_argument("--fixture", required=True, help="fixture directory name printed by prepare")
    guest.add_argument("--device", default="/dev/virtiofs-test")
    guest.add_argument("--trace", help="JSONL request/reply trace")
    guest.add_argument("--report", help="JSON result report")
    guest.add_argument("--host-mutations", action="store_true")
    guest.add_argument("--host-timeout", type=float, default=300)
    guest.set_defaults(func=run)
    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, ProbeFailure, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
