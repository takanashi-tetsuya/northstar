#!/usr/bin/env python3
"""Offline CAS, concurrency and recovery tests; never contact a guest or DNS."""

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("local-vm-lab-dane-install.py")
SPEC = importlib.util.spec_from_file_location("lab_dane_install", SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)
OWNER = "_5269._tcp.prosody.lab.test."
BASE = ("$TTL 300\n"
        "@ IN SOA dns-ca.lab.test. hostmaster.lab.test. ( 2026092602 3600 900 604800 300 )\n"
        "@ IN NS dns-ca.lab.test.\n"
        "dns-ca IN A 192.168.197.10\n"
        "prosody IN A 192.168.197.11\n")
GOOD = f"{OWNER} 300 IN TLSA 1 1 1 {'a' * 64}"
BAD = f"{OWNER} 300 IN TLSA 1 1 1 {'b' * 64}"


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / "lab.test.zone"
        self.lock = self.root / "lock"
        self.evidence = self.root / "evidence"
        self.baseline = BASE.encode()
        self.target.write_bytes(self.baseline)
        self.target.chmod(0o640)
        self.staged = installer.zone.stage_zone(BASE, OWNER, [GOOD])[0].encode()
        self.calls = []

    def command(self, args, data):
        self.calls.append((args, data))
        return subprocess.CompletedProcess(args, 0, b"ok\n", b"")

    def apply(self, **overrides):
        arguments = dict(target=self.target, lock=self.lock, staged=self.staged,
                         base_sha256=installer.zone.sha256(self.baseline),
                         base_serial=2026092602,
                         staged_sha256=installer.zone.sha256(self.staged),
                         owner=OWNER, evidence=self.evidence, command=self.command)
        arguments.update(overrides)
        return installer.install(**arguments)

    def statuses(self):
        return [json.loads(line)["status"] for line in
                (self.evidence / "events.jsonl").read_text().splitlines()]

    def test_install_retains_evidence_and_file_metadata(self):
        original = self.target.stat()
        report = self.apply()
        self.assertEqual(self.target.read_bytes(), self.staged)
        self.assertEqual(report["new_soa_serial"], 2026092603)
        self.assertEqual(self.statuses()[-1], "completed")
        self.assertEqual((self.evidence / "original.zone").read_bytes(), self.baseline)
        self.assertEqual(stat.S_IMODE(self.evidence.stat().st_mode), 0o700)
        for path in self.evidence.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)
        self.assertEqual((self.target.stat().st_uid, self.target.stat().st_gid),
                         (original.st_uid, original.st_gid))
        self.assertNotEqual(self.target.stat().st_ino, original.st_ino)
        self.assertEqual(self.calls[-1][0], ["rndc", "reload", "lab.test"])
        self.assertEqual(self.calls[0][1], self.staged)

    def test_stale_sha_fails_before_commands(self):
        self.target.write_bytes(self.baseline + b"; concurrent update\n")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.apply()
        self.assertFalse(self.evidence.exists())
        self.assertEqual(self.calls, [])

    def test_stale_serial_fails_before_commands(self):
        with self.assertRaisesRegex(ValueError, "SOA serial"):
            self.apply(base_serial=2026092601)
        self.assertEqual(self.calls, [])

    def test_wrong_staged_pin_fails(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.apply(staged_sha256="0" * 64)
        self.assertEqual(self.target.read_bytes(), self.baseline)

    def test_unrelated_zone_edit_is_rejected_even_with_correct_pin(self):
        changed = self.staged.replace(b"192.168.197.11", b"192.168.197.12")
        with self.assertRaisesRegex(ValueError, "changes more"):
            self.apply(staged=changed, staged_sha256=installer.zone.sha256(changed))
        self.assertEqual(self.calls, [])

    def test_missing_serial_increment_is_rejected(self):
        changed = self.staged.replace(b"2026092603", b"2026092602")
        with self.assertRaisesRegex(ValueError, "changes more"):
            self.apply(staged=changed, staged_sha256=installer.zone.sha256(changed))

    def test_successive_change_requires_fresh_baseline(self):
        self.apply()
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.apply(evidence=self.root / "another-attempt")
        next_zone = installer.zone.stage_zone(self.staged.decode(), OWNER, [BAD])[0].encode()
        report = self.apply(staged=next_zone, base_sha256=installer.zone.sha256(self.staged),
                            base_serial=2026092603,
                            staged_sha256=installer.zone.sha256(next_zone),
                            evidence=self.root / "fresh-attempt")
        self.assertEqual(report["new_soa_serial"], 2026092604)
        self.assertEqual(self.target.read_bytes(), next_zone)

    def test_absent_rrset_and_other_owner_are_preserved(self):
        other = GOOD.replace("prosody", "ejabberd")
        base = BASE + GOOD + "\n" + other + "\n"
        self.baseline = base.encode()
        self.target.write_bytes(self.baseline)
        self.staged = installer.zone.stage_zone(base, OWNER, [])[0].encode()
        self.apply()
        self.assertNotIn(GOOD.encode(), self.target.read_bytes())
        self.assertIn(other.encode(), self.target.read_bytes())

    def test_named_checkzone_failure_preserves_original(self):
        def reject(args, data):
            return subprocess.CompletedProcess(args, 1, b"", b"invalid zone\n")
        with self.assertRaisesRegex(RuntimeError, "candidate_check"):
            self.apply(command=reject)
        self.assertEqual(self.target.read_bytes(), self.baseline)
        self.assertEqual(self.statuses()[-1], "failed")
        self.assertEqual((self.evidence / "candidate_check.stderr").read_bytes(), b"invalid zone\n")

    def test_rollback_validation_failure_prevents_install(self):
        def reject(args, data):
            self.command(args, data)
            return subprocess.CompletedProcess(args, int(len(self.calls) == 2), b"", b"")
        with self.assertRaisesRegex(RuntimeError, "rollback_check"):
            self.apply(command=reject)
        self.assertEqual(self.target.read_bytes(), self.baseline)

    def test_reload_failure_restores_original_rrset_with_newer_serial(self):
        def reject_first_reload(args, data):
            self.command(args, data)
            return subprocess.CompletedProcess(args, int(len(self.calls) == 3), b"", b"")
        with self.assertRaisesRegex(RuntimeError, "reload exited"):
            self.apply(command=reject_first_reload)
        self.assertEqual(self.target.read_bytes(), BASE.replace("2026092602", "2026092604").encode())
        self.assertEqual(self.statuses()[-1], "rolled_back")
        self.assertEqual(len(self.calls), 4)

    def test_reload_timeout_also_rolls_back(self):
        def timeout(args, data):
            self.command(args, data)
            if len(self.calls) == 3:
                raise subprocess.TimeoutExpired(args, 30)
            return subprocess.CompletedProcess(args, 0, b"", b"")
        with self.assertRaises(subprocess.TimeoutExpired):
            self.apply(command=timeout)
        self.assertEqual(self.statuses()[-1], "rolled_back")

    def test_rollback_failure_requires_explicit_recovery(self):
        def fail_reload(args, data):
            return subprocess.CompletedProcess(args, int(args[0] == "rndc"), b"", b"")
        with self.assertRaisesRegex(RuntimeError, "recovery required"):
            self.apply(command=fail_reload)
        self.assertEqual(self.statuses()[-1], "recovery_required")
        self.assertNotIn("completed", self.statuses())
        self.assertEqual(self.target.read_bytes(), (self.evidence / "rollback.zone").read_bytes())

    def test_preinstall_external_change_is_not_overwritten(self):
        altered = self.baseline + b"; external change\n"
        def change(args, data):
            self.target.write_bytes(altered)
            return self.command(args, data)
        with self.assertRaisesRegex(RuntimeError, "changed during validation"):
            self.apply(command=change)
        self.assertEqual(self.target.read_bytes(), altered)
        self.assertTrue(all(args[0] != "rndc" for args, _ in self.calls))

    def test_postinstall_external_change_is_not_overwritten(self):
        altered = self.staged + b"; external change\n"
        def change(args, data):
            if args[0] == "rndc":
                self.target.write_bytes(altered)
            return self.command(args, data)
        with self.assertRaisesRegex(RuntimeError, "recovery required"):
            self.apply(command=change)
        self.assertEqual(self.target.read_bytes(), altered)
        self.assertEqual(self.statuses()[-1], "recovery_required")

    def test_failure_after_rename_before_directory_sync_rolls_back(self):
        replace = installer.replace_zone
        attempts = 0
        def fail_once(*args):
            nonlocal attempts
            attempts += 1
            replace(*args)
            if attempts == 1:
                raise OSError("injected post-rename failure")
        with mock.patch.object(installer, "replace_zone", side_effect=fail_once):
            with self.assertRaisesRegex(OSError, "post-rename"):
                self.apply()
        self.assertEqual(self.statuses()[-1], "rolled_back")

    def test_interruption_after_install_rolls_back(self):
        def interrupt(args, data):
            self.command(args, data)
            if len(self.calls) == 3:
                installer.interrupted(15, None)
            return subprocess.CompletedProcess(args, 0, b"", b"")
        with self.assertRaises(InterruptedError):
            self.apply(command=interrupt)
        self.assertEqual(self.statuses()[-1], "rolled_back")

    def test_evidence_write_failure_does_not_prevent_compensation(self):
        write = installer.write_private
        def no_reload_output(path, data):
            if path.name == "reload.stdout":
                raise OSError("injected evidence disk failure")
            write(path, data)
        with mock.patch.object(installer, "write_private", side_effect=no_reload_output):
            with self.assertRaisesRegex(OSError, "evidence disk failure"):
                self.apply()
        self.assertEqual(self.statuses()[-1], "rolled_back")
        self.assertEqual(self.target.read_bytes(), (self.evidence / "rollback.zone").read_bytes())

    def test_evidence_directory_cannot_be_reused(self):
        self.evidence.mkdir()
        (self.evidence / "existing").write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            self.apply()
        self.assertEqual(self.target.read_bytes(), self.baseline)
        self.assertEqual((self.evidence / "existing").read_bytes(), b"keep")

    def test_zone_symlink_is_rejected(self):
        actual = self.target.with_name("actual")
        self.target.rename(actual)
        self.target.symlink_to(actual)
        with self.assertRaises(OSError):
            self.apply()
        self.assertEqual(actual.read_bytes(), self.baseline)

    def test_lock_symlink_is_rejected(self):
        self.lock.symlink_to(self.target)
        with self.assertRaises(OSError):
            self.apply()
        self.assertEqual(self.target.read_bytes(), self.baseline)

    def test_non_regular_zone_is_rejected_without_blocking(self):
        self.target.unlink()
        os.mkfifo(self.target)
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.apply()

    def test_lock_excludes_second_process_and_is_not_unlinked(self):
        code = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(23)
sys.exit(1)
"""
        with installer.exclusive_lock(self.lock):
            inode = self.lock.stat().st_ino
            result = subprocess.run([sys.executable, "-c", code, str(self.lock)], timeout=5)
            self.assertEqual(result.returncode, 23)
            with self.assertRaises(BlockingIOError):
                self.apply()
        self.apply()
        self.assertEqual(self.lock.stat().st_ino, inode)

    def test_guest_guard_rejects_host_and_default_routes(self):
        with mock.patch.object(installer.os, "geteuid", return_value=0):
            with mock.patch.object(installer.socket, "gethostname", return_value="host"):
                with self.assertRaisesRegex(RuntimeError, "northstar-lab-dns-ca"):
                    installer.require_guest()
            with mock.patch.object(installer.socket, "gethostname", return_value="northstar-lab-dns-ca"):
                with mock.patch.object(installer, "run_command", return_value=
                                       subprocess.CompletedProcess([], 0, b'[{}]', b"")):
                    with self.assertRaisesRegex(RuntimeError, "default route"):
                        installer.require_guest()


if __name__ == "__main__":
    unittest.main()
