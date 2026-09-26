#!/usr/bin/env python3
"""Exact local-object replay tests for crash recovery; no database is touched."""

from __future__ import annotations

import importlib.util
import hashlib
from pathlib import Path
import tempfile
import types
import unittest


PATH = Path(__file__).with_name("restore-recovery.py")
SPEC = importlib.util.spec_from_file_location("northstar_restore_recovery", PATH)
assert SPEC and SPEC.loader
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)


def write(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


class JournalFixture:
    restore_id = "1234567890abcdef1234567890abcdef"
    old_id = "11111111-1111-4111-8111-111111111111"
    new_id = "22222222-2222-4222-8222-222222222222"
    old_content = b"old upload object"
    new_content = b"new upload object"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.upload = root / "uploads"
        self.rollback = root / "rollback"
        self.backup = root / "backup"
        self.floor_parent = root / "state"
        self.cutover = self.upload / f".northstar-restore-cutover-{self.restore_id}"
        self.old_stage = self.cutover / "old"
        self.new_stage = self.cutover / "new"
        self.rollback_set = self.rollback / f"restore-20260924T000000Z-{self.restore_id}"
        self.previous = self.rollback_set / "uploads"
        for path in (self.upload, self.rollback, self.backup, self.floor_parent,
                     self.cutover, self.old_stage, self.new_stage,
                     self.rollback_set, self.previous):
            path.mkdir(mode=0o700)
        write(self.upload / ".northstar-upload-root", b"northstar-upload-root-v1\n")
        write(self.rollback / ".northstar-rollback-root", b"northstar-restore-rollback-v1\n")
        write(self.backup / "manifest.txt", b"signed fixture manifest\n")
        write(self.rollback_set / "database-before.dump", b"original dump\n")
        self.floor = self.floor_parent / "floor"
        self.old_record = (len(self.old_content), hashlib.sha256(self.old_content).hexdigest())
        self.new_record = (len(self.new_content), hashlib.sha256(self.new_content).hexdigest())
        old_manifest = (f"{self.old_id}\t{self.old_record[0]}\t{self.old_record[1]}\n").encode()
        new_manifest = (f"{self.new_id}\t{self.new_record[0]}\t{self.new_record[1]}\n").encode()
        write(self.cutover / "old-objects.tsv", old_manifest)
        write(self.cutover / "new-objects.tsv", new_manifest)
        self.records = [
            ["format", "northstar-restore-journal-v1", self.restore_id],
            ["object-manifests", "old-sha256=" + recovery.sha256(self.cutover / "old-objects.tsv"),
             "new-sha256=" + recovery.sha256(self.cutover / "new-objects.tsv")],
            ["staged", "1", str(self.new_record[0]), str(self.new_record[0])],
            ["rollback-ready", str(self.rollback_set)],
            ["restore-binding", "target-database=northstar", "target-database-oid=16384",
             "manifest-sha256=" + recovery.sha256(self.backup / "manifest.txt"),
             "rollback-state-file=" + str(self.floor), "rollback-state-pre-sha256=none",
             "backup-directory=" + str(self.backup),
             "rollback-dump=" + str(self.rollback_set / "database-before.dump"),
             "rollback-dump-sha256=" + recovery.sha256(self.rollback_set / "database-before.dump")],
            ["database-transaction-intent", "incoming", "restored", "500",
             f"northstar-restore-{self.restore_id}-incoming", "target-database=northstar",
             "worker-backend-pid=123"],
        ]
        self.flush()

    def flush(self) -> None:
        data = "".join("\t".join(row) + "\n" for row in self.records).encode("ascii")
        write(self.cutover / "journal.tsv", data)

    def evidence(self) -> recovery.Evidence:
        return recovery.Evidence(types.SimpleNamespace(
            upload_dir=self.upload, rollback_dir=self.rollback, backup_dir=self.backup,
            rollback_state_file=self.floor, cutover_dir=self.cutover,
        ))


class ReplayTests(unittest.TestCase):
    def test_encrypted_rollback_path_and_digest_are_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="northstar-recovery-test-") as directory:
            fixture = JournalFixture(Path(directory))
            original = fixture.rollback_set / "database-before.dump"
            encrypted = fixture.rollback_set / "database-before.dump.age"
            original.rename(encrypted)
            fixture.records[4][-2:] = [
                "rollback-dump=" + str(encrypted),
                "rollback-dump-sha256=" + recovery.sha256(encrypted),
            ]
            fixture.flush()
            self.assertTrue(fixture.evidence().encrypted_rollback)
            write(encrypted, b"changed ciphertext")
            with self.assertRaisesRegex(recovery.RecoveryError, "dump differs"):
                fixture.evidence()
            fixture.records[4][-2] = "rollback-dump=" + str(fixture.rollback_set / "other.age")
            write(fixture.rollback_set / "other.age", b"changed ciphertext")
            fixture.records[4][-1] = "rollback-dump-sha256=" + recovery.sha256(
                fixture.rollback_set / "other.age")
            fixture.flush()
            with self.assertRaisesRegex(recovery.RecoveryError, "dump differs"):
                fixture.evidence()

    def test_s3_import_intent_binds_attempts_before_database_cutover(self) -> None:
        with tempfile.TemporaryDirectory(prefix="northstar-recovery-test-") as directory:
            fixture = JournalFixture(Path(directory))
            fixture.records = [row for row in fixture.records
                               if row[0] not in {"object-manifests", "staged",
                                                 "database-transaction-intent"}]
            fixture.records[0][1] = "northstar-restore-s3-journal-v1"
            attempts = fixture.cutover / "s3-attempts.tsv"
            write(attempts, b"northstar-s3-restore-attempts-v1\n"
                  + fixture.new_id.encode() + b"\t"
                  + b"33333333-3333-4333-8333-333333333333\n")
            fixture.records.insert(1, ["s3-inventory", "source-namespace=" + "1" * 64,
                                       "source-generation=1", "target-namespace=" + "2" * 64,
                                       "inventory-sha256=" + "3" * 64])
            fixture.records.insert(2, ["s3-import-intent",
                                       "attempts-sha256=" + recovery.sha256(attempts)])
            fixture.flush()
            evidence = fixture.evidence()
            self.assertTrue(evidence.s3)
            self.assertFalse(evidence.s3_import_verified)
            self.assertEqual(evidence.s3_attempts, attempts)
            write(attempts, b"tampered\n")
            with self.assertRaisesRegex(recovery.RecoveryError, "attempt identities differ"):
                fixture.evidence()

    def test_forward_resumes_after_first_old_move(self) -> None:
        with tempfile.TemporaryDirectory(prefix="northstar-recovery-test-") as directory:
            fixture = JournalFixture(Path(directory))
            write(fixture.old_stage / fixture.old_id, fixture.old_content)
            write(fixture.new_stage / fixture.new_id, fixture.new_content)
            evidence = fixture.evidence()
            recovery.finish_forward(evidence)
            recovery.verify_namespace(evidence, evidence.new)
            self.assertEqual((fixture.previous / fixture.old_id).read_bytes(), fixture.old_content)
            self.assertNotIn("forward-decision", (fixture.cutover / "journal.tsv").read_text())

    def test_compensation_reverses_first_new_move(self) -> None:
        with tempfile.TemporaryDirectory(prefix="northstar-recovery-test-") as directory:
            fixture = JournalFixture(Path(directory))
            write(fixture.old_stage / fixture.old_id, fixture.old_content)
            write(fixture.upload / fixture.new_id, fixture.new_content)
            evidence = fixture.evidence()
            recovery.compensate_uploads(evidence)
            recovery.verify_namespace(evidence, evidence.old)

    def test_tampered_object_manifest_blocks_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="northstar-recovery-test-") as directory:
            fixture = JournalFixture(Path(directory))
            write(fixture.old_stage / fixture.old_id, fixture.old_content)
            write(fixture.new_stage / fixture.new_id, fixture.new_content)
            write(fixture.cutover / "new-objects.tsv", b"attacker\n")
            with self.assertRaisesRegex(recovery.RecoveryError, "manifest digest differs"):
                fixture.evidence()

    def test_unrelated_restore_floor_blocks_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="northstar-recovery-test-") as directory:
            fixture = JournalFixture(Path(directory))
            write(fixture.floor,
                  b"format=northstar-restore-state-v2\nlast_restore_id="
                  b"ffffffffffffffffffffffffffffffff\nlast_manifest_sha256="
                  + b"0" * 64 + b"\n")
            with self.assertRaisesRegex(recovery.RecoveryError, "floor changed"):
                fixture.evidence()

    def test_linked_restore_floor_blocks_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="northstar-recovery-test-") as directory:
            fixture = JournalFixture(Path(directory))
            fixture.floor.symlink_to(fixture.backup / "manifest.txt")
            with self.assertRaisesRegex(recovery.RecoveryError, "symlink"):
                fixture.evidence()

    def test_unknown_trailing_journal_record_blocks_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="northstar-recovery-test-") as directory:
            fixture = JournalFixture(Path(directory))
            with (fixture.cutover / "journal.tsv").open("ab") as stream:
                stream.write(b"database-transaction-intent\tincoming")
            with self.assertRaisesRegex(recovery.RecoveryError, "truncated"):
                fixture.evidence()

    def test_transaction_status_requires_the_exact_marker(self) -> None:
        class Session:
            def __init__(self, *, status: str, marker: str) -> None:
                self.status = status
                self.marker = marker

            def query(self, sql: str) -> str:
                if "pg_xact_status" in sql:
                    return self.status
                if "to_regclass" in sql:
                    return "t"
                if "northstar_restore_outcome_markers" in sql:
                    return self.marker
                raise AssertionError(sql)

        with tempfile.TemporaryDirectory(prefix="northstar-recovery-test-") as directory:
            fixture = JournalFixture(Path(directory))
            evidence = fixture.evidence()
            proof = f"{evidence.manifest_sha}:{evidence.database_oid}:500"
            self.assertEqual(recovery.decide(Session(status="committed", marker=proof),
                                             evidence), "forward")
            self.assertEqual(recovery.decide(Session(status="aborted", marker=""),
                                             evidence), "compensate")
            self.assertEqual(recovery.decide(Session(status="too-old", marker=proof),
                                             evidence), "forward")
            with self.assertRaisesRegex(recovery.RecoveryError, "lacks a conclusive"):
                recovery.decide(Session(status="too-old", marker=""), evidence)
            bad_proof = f"{'0' * 64}:{evidence.database_oid}:500"
            with self.assertRaisesRegex(recovery.RecoveryError, "marker differs"):
                recovery.decide(Session(status="committed", marker=bad_proof), evidence)


if __name__ == "__main__":
    unittest.main()
