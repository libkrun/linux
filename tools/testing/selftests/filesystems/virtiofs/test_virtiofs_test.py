#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Regression tests for result classification; no VM or privileges needed."""

import contextlib
import errno
import io
import json
from pathlib import Path
import tempfile
import unittest

import virtiofs_test as runner


class FakeClient:
    def __init__(self, error, data=b"", local_error=None):
        self.error = error
        self.data = data
        self.local_error = local_error
        self.requests = []
        self.label = "setup"

    def request(self, op, node, payload=b"", out=0, creds=None):
        self.requests.append((op, node))
        if self.local_error is not None:
            raise OSError(self.local_error, "ioctl failed")
        return runner.Reply(self.error, self.data, op)


class ClassificationTests(unittest.TestCase):
    def deny(self, op, error, data=b"", local_error=None):
        suite = runner.Suite(FakeClient(error, data, local_error))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = suite.deny("probe", op, 123)
        return result, suite.results[0], output.getvalue()

    def test_getxattr_enosys_is_skipped_in_tap_and_json(self):
        result, record, tap = self.deny("GETXATTR", errno.ENOSYS)
        self.assertTrue(result)
        self.assertTrue(record["pass"])
        self.assertIn("GETXATTR unsupported (ENOSYS)", record["skip"])
        self.assertIn("ok 1 - probe # SKIP", tap)
        self.assertNotIn("not ok", tap)
        self.assertEqual(json.loads(json.dumps(record))["skip"], record["skip"])

    def test_enosys_is_not_a_general_denial(self):
        for op in runner.OP:
            if op == "GETXATTR":
                continue
            with self.subTest(op=op):
                result, record, tap = self.deny(op, errno.ENOSYS)
                self.assertFalse(result)
                self.assertFalse(record["skip"])
                self.assertIn("not ok 1", tap)

    def test_getxattr_rejection_still_passes(self):
        result, record, tap = self.deny("GETXATTR", errno.EBADF)
        self.assertTrue(result)
        self.assertFalse(record["skip"])
        self.assertNotIn("# SKIP", tap)

    def test_getxattr_success_or_unexpected_error_still_fails(self):
        for error, data in ((0, b"outside attribute"), (errno.EIO, b""),
                            (errno.ENODATA, b"")):
            with self.subTest(error=error):
                result, record, _ = self.deny("GETXATTR", error, data)
                self.assertFalse(result)
                self.assertFalse(record["skip"])

    def test_local_ioctl_error_is_not_skipped(self):
        result, record, _ = self.deny("GETXATTR", 0, local_error=errno.ENOSYS)
        self.assertFalse(result)
        self.assertFalse(record["skip"])
        self.assertIn("OSError", record["detail"])

    def test_positive_control_enosys_still_fails(self):
        with self.assertRaises(runner.ProbeFailure):
            runner.Reply(errno.ENOSYS, b"", "GETXATTR").ok()

    def test_host_mutation_phase_continues_with_four_skips(self):
        class MutationClient(FakeClient):
            def lookup(self, node, name):
                return {"movable": 2, "hardlink-later": 3,
                        "unlinked-later": 4, "movable-dir": 5}[name]

            def open(self, node, flags=0, directory=False):
                return node + 100

            def request(self, op, node, payload=b"", out=0, creds=None):
                self.requests.append((op, node))
                error = errno.ENOSYS if op == "GETXATTR" else errno.EBADF
                return runner.Reply(error, b"", op)

        client = MutationClient(0)
        suite = runner.Suite(client)
        with tempfile.TemporaryDirectory(prefix="virtiofs-results-test-") as tmp:
            fixture = Path(tmp)
            runner.save_json(fixture / "mutations-done", {"token": "test"})
            with contextlib.redirect_stdout(io.StringIO()):
                runner.moved_probes(suite, 1, fixture,
                                   {"token": "test", "outside": "/unused"}, 1)
        skipped = [record for record in suite.results if record["skip"]]
        self.assertEqual(len(skipped), 4)
        self.assertTrue(all(record["name"].startswith("GETXATTR ") for record in skipped))
        self.assertTrue(all(record["pass"] for record in suite.results))
        self.assertEqual(sum(op == "GETXATTR" for op, _ in client.requests), 4)
        self.assertEqual(suite.results[-1]["name"], "MKDIR moved directory movable-dir")


if __name__ == "__main__":
    unittest.main()
