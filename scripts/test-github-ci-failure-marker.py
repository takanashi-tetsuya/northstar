#!/usr/bin/env python3
"""Exercise optional first-failure publication with real supervised processes."""

from __future__ import annotations

import importlib.util
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


SOURCE = Path(__file__).with_name("github_ci_supervisor.py")
SPEC = importlib.util.spec_from_file_location("ci_failure_marker_subject", SOURCE)
assert SPEC is not None and SPEC.loader is not None
SUBJECT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SUBJECT
SPEC.loader.exec_module(SUBJECT)
OBSERVER_SPEC = importlib.util.spec_from_file_location(
    "marker_observer_reader", SOURCE.parent / "lib/listener-control-observer.py",
)
OBSERVER = importlib.util.module_from_spec(OBSERVER_SPEC)
OBSERVER_SPEC.loader.exec_module(OBSERVER)


@unittest.skipUnless(sys.platform == "linux", "requires the real Linux supervisor")
class FailureMarkerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="northstar-ci-marker.")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.root.chmod(0o700)
        self.marker = self.root / "first-failure.json"

    def environment(self, marker=True):
        environment = os.environ.copy()
        environment.pop(SUBJECT.FAILURE_MARKER_ENV, None)
        if marker:
            environment[SUBJECT.FAILURE_MARKER_ENV] = str(self.marker)
        return environment

    def command(self, script, *, timeout=None):
        args = [sys.executable, str(SOURCE), "--kill-after-seconds", "1",
                "--require-linux-subreaper", "--log-file", str(self.root / "command.log")]
        if timeout is not None:
            args += ["--timeout-seconds", str(timeout)]
        return [*args, "--", sys.executable, "-c", script]

    def run_command(self, script, *, timeout=None, environment=None):
        return subprocess.run(
            self.command(script, timeout=timeout), capture_output=True, text=True,
            env=self.environment() if environment is None else environment, timeout=12,
        )

    def record(self, cause):
        data = self.marker.read_bytes()
        self.assertLessEqual(len(data), 1024)
        record = json.loads(data)
        self.assertEqual(set(record), {"schema_version", "cause", "monotonic_ns", "realtime_ns"})
        self.assertEqual(record["schema_version"], 1)
        self.assertEqual(record["cause"], cause)
        for field in ("monotonic_ns", "realtime_ns"):
            self.assertIs(type(record[field]), int)
            self.assertGreater(record[field], 0)
        self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.root.glob(".first-failure.*.tmp")), [])
        return data

    def test_unconfigured_helper_performs_no_filesystem_operations(self):
        with mock.patch.dict(os.environ, self.environment(False), clear=True), \
                mock.patch.object(SUBJECT.os, "open", side_effect=AssertionError("unexpected open")):
            self.assertTrue(SUBJECT.publish_failure_marker("command_exit"))

    def test_success_and_unconfigured_nonzero_keep_existing_status(self):
        success = self.run_command("raise SystemExit(0)")
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertFalse(self.marker.exists())
        failure = self.run_command("raise SystemExit(7)", environment=self.environment(False))
        self.assertEqual(failure.returncode, 7, failure.stderr)
        self.assertFalse(self.marker.exists())

    def test_nonzero_marker_is_visible_before_term_and_output_drain(self):
        ready = self.root / "child-ready"
        term_seen = self.root / "term-saw-marker"
        script = f"""
import os, signal, time
from pathlib import Path
if os.fork() == 0:
    signal.signal(signal.SIGTERM, lambda *_: Path({str(term_seen)!r}).write_text(str(Path({str(self.marker)!r}).exists())))
    Path({str(ready)!r}).write_text('ready')
    time.sleep(5)
    os._exit(0)
deadline = time.monotonic() + 2
while not Path({str(ready)!r}).exists():
    if time.monotonic() >= deadline: os._exit(8)
    time.sleep(0.01)
os._exit(7)
"""
        result = self.run_command(script)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(term_seen.read_text(), "True")
        self.record("command_exit")

    def test_deadline_marker_precedes_term_and_keeps_124(self):
        term_seen = self.root / "deadline-term"
        result = self.run_command(f"""
import signal, time
from pathlib import Path
signal.signal(signal.SIGTERM, lambda *_: Path({str(term_seen)!r}).write_text(str(Path({str(self.marker)!r}).exists())))
time.sleep(5)
""", timeout=1)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertEqual(term_seen.read_text(), "True")
        self.record("deadline")

    def test_spawn_failure_preserves_127_and_emits_safe_startup_marker(self):
        args = self.command("pass")
        args = args[:args.index("--") + 1] + [str(self.root / "missing-secret-command")]
        result = subprocess.run(args, capture_output=True, text=True, env=self.environment(), timeout=8)
        self.assertEqual(result.returncode, 127, result.stderr)
        data = self.record("startup")
        self.assertNotIn(b"missing-secret-command", data)

    def test_parent_cancellation_preserves_143_and_is_distinct_from_child_failure(self):
        ready = self.root / "cancel-ready"
        process = subprocess.Popen(
            self.command(f"from pathlib import Path;import time;Path({str(ready)!r}).touch();time.sleep(4)"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.environment(),
        )
        try:
            deadline = time.monotonic() + 3
            while not ready.exists():
                self.assertLess(time.monotonic(), deadline)
                self.assertIsNone(process.poll())
                time.sleep(0.01)
            process.send_signal(signal.SIGTERM)
            _, error = process.communicate(timeout=6)
            self.assertEqual(process.returncode, 143, error)
            self.record("parent_cancel")
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=2)

    def test_bad_marker_configuration_does_not_replace_command_failure(self):
        environment = self.environment()
        environment[SUBJECT.FAILURE_MARKER_ENV] = "PRIVATE_PATH_SENTINEL/first-failure.json"
        result = self.run_command("raise SystemExit(7)", environment=environment)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertNotIn("PRIVATE_PATH_SENTINEL", result.stderr)
        self.assertIn("command_failure_marker_unavailable", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_first_record_is_not_replaced_by_later_failure(self):
        self.assertTrue(SUBJECT.publish_failure_marker("command_exit", self.marker))
        original = self.record("command_exit")
        self.assertTrue(SUBJECT.publish_failure_marker("deadline", self.marker))
        self.assertEqual(self.record("command_exit"), original)

    def test_failed_publish_removes_private_temporary_record(self):
        with mock.patch.object(SUBJECT, "_rename_noreplace", side_effect=PermissionError("PRIVATE_ERROR")):
            self.assertFalse(SUBJECT.publish_failure_marker("deadline", self.marker))
        self.assertFalse(self.marker.exists())
        self.assertEqual(list(self.root.glob(".first-failure.*.tmp")), [])

    def test_unsupported_atomic_publish_fails_without_fallback(self):
        for error in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
            with self.subTest(error=error), \
                    mock.patch.object(SUBJECT, "_rename_noreplace", side_effect=OSError(error, "unsupported")):
                self.assertFalse(SUBJECT.publish_failure_marker("deadline", self.marker))
                self.assertFalse(self.marker.exists())
                self.assertEqual(list(self.root.glob(".first-failure.*.tmp")), [])
        with mock.patch.object(SUBJECT.ctypes, "CDLL", return_value=object()):
            self.assertFalse(SUBJECT.publish_failure_marker("deadline", self.marker))
        self.assertFalse(self.marker.exists())

    def test_production_reader_spans_publication_finalization_without_ctime_change(self):
        published, reading, finished = threading.Event(), threading.Event(), threading.Event()
        rename, read = SUBJECT._rename_noreplace, os.read
        outcomes = []

        def paused_publish(*args):
            rename(*args)
            published.set()
            if not reading.wait(3):
                raise TimeoutError("reader did not start")

        def spanning_read(*args):
            # PrivateFile has taken its first fstat. Let the real publisher
            # finish all cleanup before the second fstat checks ctime.
            reading.set()
            self.assertTrue(finished.wait(3))
            return read(*args)

        def publish():
            try:
                outcomes.append(SUBJECT.publish_failure_marker("deadline", self.marker))
            finally:
                finished.set()

        reader = OBSERVER.FirstFailure(self.marker)
        self.addCleanup(reader.close)
        with mock.patch.object(SUBJECT, "_rename_noreplace", side_effect=paused_publish), \
                mock.patch.object(OBSERVER.os, "read", side_effect=spanning_read):
            worker = threading.Thread(target=publish)
            worker.start()
            try:
                self.assertTrue(published.wait(3))
                record = reader.poll()
                self.assertEqual(record["cause"], "deadline")
            finally:
                reading.set()
                worker.join(timeout=4)
            self.assertFalse(worker.is_alive())
        self.assertEqual(outcomes, [True])
        self.record("deadline")

    def test_marker_error_reporting_cannot_interrupt_cleanup_when_stderr_is_closed(self):
        with mock.patch.object(SUBJECT.sys, "stderr") as stderr:
            stderr.write.side_effect = OSError("closed stderr")
            self.assertFalse(SUBJECT.publish_failure_marker("deadline", "relative/first-failure.json"))

    def test_complete_record_is_atomic_under_competing_real_publishers(self):
        code = "import sys;sys.path.insert(0,sys.argv[1]);from github_ci_supervisor import publish_failure_marker;raise SystemExit(0 if publish_failure_marker(sys.argv[3],sys.argv[2]) else 1)"
        causes = ("command_exit", "deadline", "lifecycle", "startup")
        children = [subprocess.Popen(
            [sys.executable, "-c", code, str(SOURCE.parent), str(self.marker), cause],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        ) for cause in causes]
        try:
            deadline = time.monotonic() + 5
            while not self.marker.exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.005)
            # A reader can parse immediately after the directory entry appears.
            reader = OBSERVER.FirstFailure(self.marker)
            self.addCleanup(reader.close)
            first_record = reader.poll()
            first = self.marker.read_bytes()
            self.assertIn(first_record["cause"], causes)
            self.assertEqual(json.loads(first), first_record)
            for child in children:
                _, error = child.communicate(timeout=5)
                self.assertEqual(child.returncode, 0, error)
            self.assertEqual(self.marker.read_bytes(), first)
            self.record(json.loads(first)["cause"])
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=2)

    def test_symlink_and_nonprivate_parent_are_rejected_without_external_write(self):
        external = self.root / "external"
        external.mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(external, target_is_directory=True)
        self.assertFalse(SUBJECT.publish_failure_marker("deadline", alias / "first-failure.json"))
        self.assertFalse((external / "first-failure.json").exists())
        external.chmod(0o755)
        self.assertFalse(SUBJECT.publish_failure_marker("deadline", external / "first-failure.json"))
        self.assertFalse((external / "first-failure.json").exists())

    def test_occupied_symlink_is_never_followed_or_overwritten(self):
        external = self.root / "external-secret"
        external.write_text("PRIVATE_SENTINEL")
        self.marker.symlink_to(external)
        self.assertTrue(SUBJECT.publish_failure_marker("deadline", self.marker))
        self.assertTrue(self.marker.is_symlink())
        self.assertEqual(external.read_text(), "PRIVATE_SENTINEL")
        self.assertEqual(list(self.root.glob(".first-failure.*.tmp")), [])

    def test_expected_nested_nonzero_does_not_claim_outer_success(self):
        nested_args = [sys.executable, str(SOURCE), "--kill-after-seconds", "1",
                       "--require-linux-subreaper", "--log-file", str(self.root / "nested.log"),
                       "--", sys.executable, "-c", "raise SystemExit(9)"]
        result = self.run_command(f"""
import os, subprocess
from pathlib import Path
assert {SUBJECT.FAILURE_MARKER_ENV!r} not in os.environ
result = subprocess.run({nested_args!r}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
assert result.returncode == 9
assert not Path({str(self.marker)!r}).exists()
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
