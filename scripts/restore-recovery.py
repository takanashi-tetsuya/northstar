#!/usr/bin/env python3
"""Resume an interrupted, fenced restore from exact durable evidence."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid


SCRIPT_DIR = Path(__file__).resolve().parent
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
RESTORE_ID = re.compile(r"[0-9a-f]{32}")
SHA = re.compile(r"[0-9a-f]{64}")
DB_NAME = re.compile(r"[A-Za-z0-9_.-]{1,63}")
XID = re.compile(r"[1-9][0-9]{0,19}")
MAINTENANCE_LOCK = 735559096281326101
CONNECT_ROLES = (
    "northstar_migrator", "northstar_runtime", "northstar_storage",
    "northstar_commands", "northstar_backup",
)


class RecoveryError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryError(message)


def private(path: Path, *, directory: bool) -> Path:
    metadata = path.lstat()
    require(stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode),
            f"unsafe recovery path type: {path}")
    require(metadata.st_uid == os.getuid() and metadata.st_gid == os.getgid(),
            f"recovery path is not owned by this account: {path}")
    require(stat.S_IMODE(metadata.st_mode) == (0o700 if directory else 0o600),
            f"recovery path has unsafe permissions: {path}")
    if not directory:
        require(metadata.st_nlink == 1, f"recovery file has multiple links: {path}")
    return path.resolve(strict=True)


def regular_readable(path: Path) -> Path:
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and os.access(path, os.R_OK),
            f"required recovery input is not a readable regular file: {path}")
    return path.resolve(strict=True)


def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def fsync(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if path.is_dir():
        flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def append(journal: Path, cutover: Path, *fields: str) -> None:
    require(all(field.isascii() and field.isprintable() and "\t" not in field
                for field in fields), "unsafe recovery journal field")
    descriptor = os.open(journal, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    try:
        data = ("\t".join(fields) + "\n").encode("ascii")
        while data:
            written = os.write(descriptor, data)
            require(written > 0, "recovery journal write made no progress")
            data = data[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync(cutover)


def manifest(path: Path, expected_sha: str) -> dict[str, tuple[int, str]]:
    private(path, directory=False)
    require(sha256(path) == expected_sha, f"object manifest digest differs: {path}")
    objects: dict[str, tuple[int, str]] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split("\t")
        require(len(fields) == 3 and UUID.fullmatch(fields[0]) is not None
                and fields[1].isdigit() and SHA.fullmatch(fields[2]) is not None,
                f"malformed object manifest: {path}")
        require(fields[0] not in objects, f"duplicate object in manifest: {fields[0]}")
        objects[fields[0]] = (int(fields[1]), fields[2])
    return objects


def named_record(records: list[list[str]], label: str, fields: int) -> list[str]:
    found = [record for record in records if record[0] == label]
    require(len(found) == 1 and len(found[0]) == fields,
            f"recovery journal requires one complete {label} record")
    return found[0]


def parse_binding(fields: list[str], names: tuple[str, ...]) -> dict[str, str]:
    require(len(fields) == len(names) + 1, "recovery binding has unexpected fields")
    result = {}
    for field, name in zip(fields[1:], names):
        require(field.startswith(name + "=") and len(field) > len(name) + 1,
                f"recovery binding lacks {name}")
        result[name] = field[len(name) + 1:]
    return result


class Evidence:
    def __init__(self, args: argparse.Namespace) -> None:
        self.upload = private(args.upload_dir, directory=True)
        self.rollback = private(args.rollback_dir, directory=True)
        require(private(self.upload / ".northstar-upload-root", directory=False).read_bytes()
                == b"northstar-upload-root-v1\n", "upload root marker differs")
        require(private(self.rollback / ".northstar-rollback-root", directory=False).read_bytes()
                == b"northstar-restore-rollback-v1\n", "rollback root marker differs")
        self.backup = args.backup_dir.resolve(strict=True)
        require(args.backup_dir.is_dir() and not args.backup_dir.is_symlink(),
                "backup source is not a real directory")
        require(not args.rollback_state_file.is_symlink()
                and not args.rollback_state_file.parent.is_symlink(),
                "trusted restore floor or its parent is a symlink")
        self.floor = args.rollback_state_file.resolve(strict=False)
        private(self.floor.parent, directory=True)
        if self.floor.exists() or self.floor.is_symlink():
            private(self.floor, directory=False)
        self.cutover = private(args.cutover_dir, directory=True)
        require(self.cutover.parent == self.upload,
                "cutover is not directly inside the selected upload root")
        match = re.fullmatch(r"\.northstar-restore-cutover-([0-9a-f]{32})", self.cutover.name)
        require(match is not None, "cutover name does not contain a canonical restore ID")
        self.restore_id = match.group(1)
        self.journal = private(self.cutover / "journal.tsv", directory=False)
        raw = self.journal.read_bytes()
        require(raw.endswith(b"\n") and len(raw) <= 16 * 1024 * 1024,
                "recovery journal is truncated or unreasonably large")
        try:
            records = [line.split("\t") for line in raw.decode("ascii").splitlines()]
        except UnicodeError as error:
            raise RecoveryError("recovery journal is not ASCII") from error
        require(all(all(field and field.isprintable() for field in row) for row in records),
                "recovery journal contains an invalid field")
        require(records[0] in (
            ["format", "northstar-restore-journal-v1", self.restore_id],
            ["format", "northstar-restore-s3-journal-v1", self.restore_id]),
            "recovery journal format or restore ID differs")
        self.s3 = records[0][1] == "northstar-restore-s3-journal-v1"
        allowed = {
            "format", "object-manifests", "staged", "rollback-ready", "restore-binding",
            "state", "fence-intent", "fence-active", "fence-undone",
            "database-switch-intent", "database-switch-done", "database-transaction-intent",
            "database-transaction-outcome", "old-intent", "old-done", "new-intent", "new-done",
            "rollback-uploads-verified", "forward-decision", "committed", "compensated",
            "recovery-maintenance-open-intent", "recovery-maintenance-closed",
            "recovery-decision", "recovery-complete",
            "s3-inventory", "s3-import-intent", "s3-import-verified",
            "s3-new-objects-retained",
        }
        require(all(row[0] in allowed for row in records),
                "recovery journal contains an unknown transition")
        self.records = records
        if self.s3:
            require(not any(row[0] in {"object-manifests", "old-intent", "old-done",
                                         "new-intent", "new-done"} for row in records),
                    "S3 journal contains local object transitions")
            s3_binding = parse_binding(named_record(records, "s3-inventory", 5),
                                       ("source-namespace", "source-generation",
                                        "target-namespace", "inventory-sha256"))
            require(SHA.fullmatch(s3_binding["source-namespace"]) is not None
                    and SHA.fullmatch(s3_binding["target-namespace"]) is not None
                    and SHA.fullmatch(s3_binding["inventory-sha256"]) is not None
                    and s3_binding["source-generation"].isdigit()
                    and int(s3_binding["source-generation"]) > 0,
                    "S3 inventory binding is malformed")
            self.s3_binding = s3_binding
            intents = [row for row in records if row[0] == "s3-import-intent"]
            require(len(intents) <= 1, "duplicate S3 import intent")
            if intents:
                intent = parse_binding(intents[0], ("attempts-sha256",))
                require(SHA.fullmatch(intent["attempts-sha256"]) is not None,
                        "S3 import intent digest is malformed")
                self.s3_attempts = private(self.cutover / "s3-attempts.tsv", directory=False)
                require(sha256(self.s3_attempts) == intent["attempts-sha256"],
                        "S3 attempt identities differ from the durable journal")
            verified = [row for row in records if row[0] == "s3-import-verified"]
            require(len(verified) <= 1, "duplicate S3 import verification")
            require(not verified or intents,
                    "verified S3 import lacks its durable attempt intent")
            self.s3_import_verified = bool(verified)
            if verified:
                digests = parse_binding(verified[0],
                                        ("results-sha256", "target-sha256", "remap-sha256"))
                require(all(SHA.fullmatch(value) for value in digests.values()),
                        "S3 import digests are malformed")
                self.s3_target = private(self.cutover / "s3-target-inventory.tsv", directory=False)
                self.s3_results = private(self.cutover / "s3-results.tsv", directory=False)
                self.s3_remap = private(self.cutover / "s3-remap.sql", directory=False)
                require(sha256(self.s3_target) == digests["target-sha256"]
                        and sha256(self.s3_results) == digests["results-sha256"]
                        and sha256(self.s3_remap) == digests["remap-sha256"],
                        "S3 import evidence differs from the durable journal")
            require(not any(row[0] == "database-transaction-intent" and row[1] == "incoming"
                            for row in records) or self.s3_import_verified,
                    "incoming replacement lacks complete S3 import evidence")
        else:
            object_bindings = parse_binding(named_record(records, "object-manifests", 3),
                                            ("old-sha256", "new-sha256"))
            require(all(SHA.fullmatch(value) for value in object_bindings.values()),
                    "object manifest binding is invalid")
            self.old = manifest(self.cutover / "old-objects.tsv", object_bindings["old-sha256"])
            self.new = manifest(self.cutover / "new-objects.tsv", object_bindings["new-sha256"])
        binding = parse_binding(named_record(records, "restore-binding", 9),
                                ("target-database", "target-database-oid", "manifest-sha256",
                                 "rollback-state-file", "rollback-state-pre-sha256",
                                 "backup-directory", "rollback-dump",
                                 "rollback-dump-sha256"))
        require(DB_NAME.fullmatch(binding["target-database"]) is not None
                and binding["target-database"] not in {"postgres", "template0", "template1"},
                "unsafe journal target database")
        require(re.fullmatch(r"[1-9][0-9]{0,9}", binding["target-database-oid"]) is not None,
                "invalid target database OID")
        require(SHA.fullmatch(binding["manifest-sha256"]) is not None
                and SHA.fullmatch(binding["rollback-dump-sha256"]) is not None,
                "invalid restore manifest or rollback dump digest")
        require(binding["rollback-state-file"] == str(self.floor)
                and binding["backup-directory"] == str(self.backup),
                "recovery arguments differ from the signed restore's binding")
        self.database = binding["target-database"]
        self.database_oid = binding["target-database-oid"]
        self.manifest_sha = binding["manifest-sha256"]
        pre_floor = binding["rollback-state-pre-sha256"]
        require(pre_floor == "none" or SHA.fullmatch(pre_floor) is not None,
                "invalid pre-restore floor digest")
        current_floor = sha256(self.floor) if self.floor.exists() else "none"
        if current_floor != pre_floor:
            # A completed floor write is the only permitted external change.
            require(self.floor.exists(), "trusted floor disappeared during recovery")
            fields: dict[str, str] = {}
            for line in self.floor.read_text(encoding="utf-8").splitlines():
                key, separator, value = line.partition("=")
                require(separator == "=" and key and value and key not in fields,
                        "trusted restore floor is malformed")
                fields[key] = value
            require(fields.get("format") == "northstar-restore-state-v2"
                    and fields.get("last_restore_id") == self.restore_id
                    and fields.get("last_manifest_sha256") == self.manifest_sha,
                    "trusted restore floor changed after the journal binding")
        rollback_ready = named_record(records, "rollback-ready", 2)[1]
        self.rollback_set = private(Path(rollback_ready), directory=True)
        require(self.rollback_set.parent == self.rollback
                and self.rollback_set.name.endswith("-" + self.restore_id),
                "rollback set is outside the selected retention root")
        self.rollback_dump = private(Path(binding["rollback-dump"]), directory=False)
        require(self.rollback_dump in (self.rollback_set / "database-before.dump",
                                       self.rollback_set / "database-before.dump.age")
                and sha256(self.rollback_dump) == binding["rollback-dump-sha256"],
                "pre-restore database dump differs from the durable binding")
        self.encrypted_rollback = self.rollback_dump.suffix == ".age"
        if not self.s3:
            self.previous = private(self.rollback_set / "uploads", directory=True)
        require((self.backup / "manifest.txt").is_file()
                and sha256(self.backup / "manifest.txt") == self.manifest_sha,
                "signed backup manifest differs from the journal")
        for kind, label in (("incoming", "restored"), ("rollback", "rollback")):
            intents = [row for row in records if row[0] == "database-transaction-intent"
                       and len(row) >= 2 and row[1] == kind]
            require(len(intents) <= 1, f"duplicate {kind} transaction intent")
            if intents:
                row = intents[0]
                require(len(row) == 7 and row[2] == label and XID.fullmatch(row[3]) is not None
                        and row[4] == f"northstar-restore-{self.restore_id}-{kind}"
                        and row[5] == f"target-database={self.database}"
                        and re.fullmatch(r"worker-backend-pid=[1-9][0-9]*", row[6]) is not None,
                        f"malformed {kind} transaction intent")
            setattr(self, f"{kind}_xid", intents[0][3] if intents else None)
        decisions = [row for row in records if row[0] == "forward-decision"]
        require(len(decisions) <= 1 and (not decisions or decisions[0] ==
                ["forward-decision", self.restore_id, self.manifest_sha, self.incoming_xid]),
                "forward decision does not match the transaction binding")
        self.forward_decided = bool(decisions)


def object_matches(path: Path, expected: tuple[int, str]) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            f"recovery object is not a single regular file: {path}")
    return info.st_size == expected[0] and sha256(path) == expected[1]


def move_exact(source: Path, target: Path, expected: tuple[int, str]) -> None:
    require(object_matches(source, expected), f"exact recovery source differs: {source}")
    require(not target.exists() and not target.is_symlink(),
            f"recovery target already exists: {target}")
    os.rename(source, target)
    fsync(source.parent)
    fsync(target.parent)


def copy_exact(source: Path, target: Path, expected: tuple[int, str]) -> None:
    require(object_matches(source, expected), f"exact recovery copy source differs: {source}")
    require(not target.exists() and not target.is_symlink(),
            f"recovery copy target already exists: {target}")
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with source.open("rb") as reader, os.fdopen(descriptor, "wb", closefd=False) as writer:
            for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
    finally:
        os.close(descriptor)
    require(object_matches(target, expected), f"recovery copy verification failed: {target}")
    fsync(target.parent)


def verify_namespace(evidence: Evidence, expected: dict[str, tuple[int, str]]) -> None:
    actual = set()
    for path in evidence.upload.iterdir():
        if path.name in {".northstar-upload-root", evidence.cutover.name}:
            continue
        require(UUID.fullmatch(path.name) is not None,
                f"unexpected path in upload root: {path}")
        actual.add(path.name)
    require(actual == set(expected), "live upload object set differs from the recovery manifest")
    for name, identity in expected.items():
        require(object_matches(evidence.upload / name, identity),
                f"live upload object differs: {name}")


def finish_forward(evidence: Evidence) -> None:
    old_stage = private(evidence.cutover / "old", directory=True)
    new_stage = private(evidence.cutover / "new", directory=True)
    for name, identity in evidence.old.items():
        live, staged, retained = (evidence.upload / name, old_stage / name,
                                  evidence.previous / name)
        if object_matches(staged, identity) or object_matches(retained, identity):
            continue
        move_exact(live, staged, identity)
    for name, identity in evidence.new.items():
        live, staged = evidence.upload / name, new_stage / name
        if object_matches(live, identity):
            continue
        move_exact(staged, live, identity)
    verify_namespace(evidence, evidence.new)
    for name, identity in evidence.old.items():
        retained = evidence.previous / name
        if object_matches(retained, identity):
            continue
        copy_exact(old_stage / name, retained, identity)
    for name, identity in evidence.old.items():
        require(object_matches(evidence.previous / name, identity),
                f"retained original object differs: {name}")
def verify_restored_upload_rows(session: TargetSession, evidence: Evidence) -> None:
    rows = session.query(
        "SELECT id::text || E'\\t' || size::text || E'\\t' || "
        "COALESCE(encode(content_sha256,'hex'),'') FROM public.upload_slots "
        "WHERE uploaded AND expires_at > clock_timestamp() ORDER BY id")
    for row in rows.splitlines():
        fields = row.split("\t")
        require(len(fields) == 3 and UUID.fullmatch(fields[0]) is not None
                and fields[1].isdigit() and (not fields[2] or SHA.fullmatch(fields[2]) is not None),
                "restored upload metadata is malformed")
        identity = evidence.new.get(fields[0])
        require(identity is not None and identity[0] == int(fields[1]),
                f"restored upload row has no exact object: {fields[0]}")
        if fields[2]:
            require(identity[1] == fields[2],
                    f"restored upload digest differs: {fields[0]}")


def compensate_uploads(evidence: Evidence) -> None:
    old_stage = private(evidence.cutover / "old", directory=True)
    new_stage = private(evidence.cutover / "new", directory=True)
    for name, identity in evidence.new.items():
        live, staged = evidence.upload / name, new_stage / name
        if object_matches(staged, identity):
            continue
        if object_matches(live, identity):
            move_exact(live, staged, identity)
    for name, identity in evidence.old.items():
        live, staged, retained = (evidence.upload / name, old_stage / name,
                                  evidence.previous / name)
        if object_matches(live, identity):
            continue
        if object_matches(staged, identity):
            move_exact(staged, live, identity)
        else:
            copy_exact(retained, live, identity)
    verify_namespace(evidence, evidence.old)


def run_pg(args: argparse.Namespace, database: str, sql: str) -> str:
    command = ["python3", str(SCRIPT_DIR / "run-postgres.py"),
               "--database-url-file", str(args.database_url_file), "--",
               "psql", "--no-psqlrc", "--quiet", "--tuples-only", "--no-align",
               "--set", "ON_ERROR_STOP=1", f"--dbname={database}", "--command", sql]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    require(result.returncode == 0, f"PostgreSQL maintenance command failed: {result.stderr[-400:]}")
    return result.stdout.strip()


class TargetSession:
    def __init__(self, args: argparse.Namespace, database: str) -> None:
        command = ["python3", str(SCRIPT_DIR / "run-postgres.py"),
                   "--database-url-file", str(args.database_url_file), "--",
                   "psql", "--no-psqlrc", "--quiet", "--tuples-only", "--no-align",
                   "--set", "ON_ERROR_STOP=1", f"--dbname={database}"]
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, bufsize=0)
        self.counter = 0

    def query(self, sql: str) -> str:
        require(self.process.poll() is None, "target maintenance session has ended")
        self.counter += 1
        marker = f"__NORTHSTAR_RECOVERY_DONE_{os.getpid()}_{self.counter}__"
        assert self.process.stdin is not None and self.process.stdout is not None
        statement = sql.rstrip()
        if not statement.endswith(";"):
            statement += ";"
        self.process.stdin.write((statement + "\n\\echo " + marker + "\n").encode("ascii"))
        self.process.stdin.flush()
        deadline = time.monotonic() + 300
        rows = []
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.process.stdout], [], [], max(0, deadline - time.monotonic()))
            if not ready:
                break
            line = self.process.stdout.readline()
            require(bool(line), "target maintenance response ended before its marker")
            text = line.decode("ascii").rstrip("\n")
            if text == marker:
                return "\n".join(rows).strip()
            rows.append(text)
        raise RecoveryError("target maintenance response timed out")

    def close(self) -> None:
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=10)


def marker(session: TargetSession, evidence: Evidence, kind: str) -> tuple[str, str, str] | None:
    exists = session.query("SELECT to_regclass('public.northstar_restore_outcome_markers') IS NOT NULL")
    require(exists in {"t", "f"}, "marker table presence is ambiguous")
    if exists == "f":
        return None
    rows = session.query(
        "SELECT encode(manifest_sha256,'hex') || ':' || target_database_oid::text || ':' || "
        "transaction_xid::text FROM public.northstar_restore_outcome_markers "
        f"WHERE restore_id='{evidence.restore_id}' AND outcome='{kind}'")
    if not rows:
        return None
    require("\n" not in rows, "duplicate restore outcome markers")
    parts = rows.split(":")
    require(len(parts) == 3 and SHA.fullmatch(parts[0]) is not None
            and parts[1].isdigit() and XID.fullmatch(parts[2]) is not None,
            "malformed restore outcome marker")
    return parts[0], parts[1], parts[2]


def decide(session: TargetSession, evidence: Evidence) -> str:
    seen = {}
    for kind in ("incoming", "rollback"):
        xid = getattr(evidence, f"{kind}_xid")
        if xid is None:
            seen[kind] = (None, None)
            continue
        status = session.query(
            "SELECT COALESCE(pg_catalog.pg_xact_status("
            f"'{xid}'::pg_catalog.xid8),'too-old')")
        require(status in {"committed", "aborted", "in progress", "too-old"},
                f"unrecognized {kind} transaction status")
        proof = marker(session, evidence, kind)
        if proof is not None:
            require(proof == (evidence.manifest_sha, evidence.database_oid, xid),
                    f"{kind} marker differs from the exact restore binding")
            require(status in {"committed", "too-old"},
                    f"{kind} marker conflicts with transaction status")
        seen[kind] = (status, proof)
    incoming_status, incoming_marker = seen["incoming"]
    rollback_status, rollback_marker = seen["rollback"]
    require(not (incoming_marker and rollback_marker),
            "replacement and compensation markers coexist")
    if rollback_marker:
        return "compensate"
    if rollback_status in {"in progress", "too-old", "committed"}:
        raise RecoveryError("rollback transaction lacks a conclusive matching marker")
    if incoming_marker:
        return "forward"
    if incoming_status in {"in progress", "too-old", "committed"}:
        raise RecoveryError("incoming transaction lacks a conclusive matching marker")
    require(not evidence.forward_decided,
            "durable forward decision conflicts with an aborted incoming transaction")
    return "compensate"


def verify_backup(args: argparse.Namespace, evidence: Evidence) -> None:
    staging_root = private(args.plaintext_staging_dir, directory=True)
    with tempfile.TemporaryDirectory(prefix="northstar-restore-recovery.", dir=staging_root) as area:
        payload = Path(area) / "payload"
        payload.mkdir(mode=0o700)
        command = ["bash", str(SCRIPT_DIR / "verify-backup.sh"), str(evidence.backup),
                   "--require-signature", "--public-key-file", str(args.public_key_file),
                   "--rollback-state-file", str(evidence.floor),
                   "--materialize-dir", str(payload),
                   "--allow-rollback", "--allow-generation-change",
                   "--age-identity-file", str(args.age_identity_file)]
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=3600, check=False)
        require(result.returncode == 0,
                f"signed backup verification failed: {result.stderr[-400:]}")
        require(sha256(payload / "manifest.txt") == evidence.manifest_sha,
                "materialized backup manifest differs from the recovery binding")
        if evidence.s3:
            specification = importlib.util.spec_from_file_location(
                "northstar_backup_inventory", SCRIPT_DIR / "backup-inventory.py")
            require(specification is not None and specification.loader is not None,
                    "S3 inventory validator is unavailable")
            inventory_module = importlib.util.module_from_spec(specification)
            specification.loader.exec_module(inventory_module)
            values = {}
            for line in (payload / "manifest.txt").read_text(encoding="utf-8").splitlines():
                key, separator, value = line.partition("=")
                require(separator == "=" and key not in values, "S3 manifest is malformed")
                values[key] = value
            require(values.get("format") == "northstar-backup-v3"
                    and values.get("storage_namespace_sha256") ==
                    evidence.s3_binding["source-namespace"]
                    and values.get("storage_generation") ==
                    evidence.s3_binding["source-generation"]
                    and sha256(payload / "upload-inventory.tsv") ==
                    evidence.s3_binding["inventory-sha256"],
                    "signed S3 authority or inventory differs from journal")
            source = inventory_module.inventory(payload / "upload-inventory.tsv")
            if evidence.s3_import_verified:
                reconstructed = Path(area) / "reconstructed-target.tsv"
                inventory_module.restored_inventory(
                    payload / "upload-inventory.tsv", evidence.s3_results, reconstructed)
                require(reconstructed.read_bytes() == evidence.s3_target.read_bytes(),
                        "S3 target inventory differs from authenticated source and import results")
                target = inventory_module.inventory(evidence.s3_target)
                require(len(source) == len(target), "S3 restore target count is incomplete")
            return
        actual: dict[str, tuple[int, str]] = {}
        with tarfile.open(payload / "uploads.tar.gz", mode="r:gz") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                name = member.name.removeprefix("./")
                require(UUID.fullmatch(name) is not None and name not in actual,
                        "materialized upload archive has an invalid object name")
                digest = hashlib.sha256()
                reader = archive.extractfile(member)
                require(reader is not None, "materialized upload object is unreadable")
                with reader:
                    for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                        digest.update(chunk)
                actual[name] = member.size, digest.hexdigest()
        require(actual == evidence.new,
                "staged object manifest differs from the authenticated backup archive")


def verify_encrypted_rollback(identity: Path, evidence: Evidence) -> None:
    """Prove a supplied key can recover the bound dump before database access."""
    require(evidence.encrypted_rollback,
            "encrypted rollback verification requires an encrypted dump")
    decrypt = subprocess.Popen(
        ["age", "--decrypt", "--identity", str(identity), str(evidence.rollback_dump)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert decrypt.stdout is not None
    try:
        archive = subprocess.run(
            ["pg_restore", "--list"], stdin=decrypt.stdout,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=3600, check=False,
        )
        decrypt.stdout.close()
        _, decrypt_errors = decrypt.communicate(timeout=3600)
    except BaseException:
        decrypt.stdout.close()
        decrypt.kill()
        decrypt.communicate()
        raise
    require(decrypt.returncode == 0 and archive.returncode == 0,
            "rollback identity cannot decrypt a valid bound database dump: "
            + (decrypt_errors + archive.stderr).decode("utf-8", "replace")[-200:])


def verify_s3_forward(session: TargetSession, evidence: Evidence) -> None:
    require(evidence.s3_import_verified,
            "incoming S3 restore lacks an exact verified target inventory")
    helper = os.environ.get("NORTHSTAR_BACKUP_STORAGE_HELPER", "xmpp-server")
    result = subprocess.run(
        [helper, "storage", "backup-object", "verify", str(evidence.s3_target),
         evidence.s3_binding["target-namespace"]],
        capture_output=True, text=True, timeout=3600, check=False)
    require(result.returncode == 0,
            f"restored S3 exact versions failed readback: {result.stderr[-400:]}")
    lines = evidence.s3_target.read_text(encoding="utf-8").splitlines()[1:]
    rows = session.query(
        "SELECT id::text || E'\\t' || storage_object_key || E'\\t' || "
        "storage_object_version || E'\\t' || storage_size::text || E'\\t' || "
        "encode(storage_sha256,'hex') FROM public.upload_slots ORDER BY id")
    require(rows.splitlines() == lines, "recovered S3 database locators differ from exact versions")
    namespace = evidence.s3_binding["target-namespace"]
    generation = int(evidence.s3_binding["source-generation"]) + 1
    authority = session.query(
        "SELECT storage_backend || ':' || encode(namespace_sha256,'hex') || ':' || "
        "generation::text FROM public.upload_storage_authority WHERE singleton")
    require(authority == f"s3:{namespace}:{generation}",
            "recovered S3 authority differs from the verified destination")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cutover_dir", type=Path)
    parser.add_argument("--database-url-file", required=True, type=Path)
    parser.add_argument("--upload-dir", required=True, type=Path)
    parser.add_argument("--rollback-dir", required=True, type=Path)
    parser.add_argument("--rollback-state-file", required=True, type=Path)
    parser.add_argument("--backup-dir", required=True, type=Path)
    parser.add_argument("--public-key-file", required=True, type=Path)
    parser.add_argument("--age-identity-file", required=True, type=Path)
    parser.add_argument("--rollback-age-identity-file", type=Path)
    parser.add_argument("--plaintext-staging-dir", required=True, type=Path)
    parser.add_argument("--confirm-stopped", required=True)
    args = parser.parse_args()
    require(args.confirm_stopped == "NORTHSTAR-RECOVER",
            "recovery requires the explicit stopped-workload confirmation")
    regular_readable(args.database_url_file)
    regular_readable(args.public_key_file)
    regular_readable(args.age_identity_file)
    evidence = Evidence(args)
    if evidence.encrypted_rollback:
        require(args.rollback_age_identity_file is not None,
                "encrypted rollback requires a separate rollback age identity")
        rollback_identity = private(args.rollback_age_identity_file, directory=False)
        require(not any(root == rollback_identity or root in rollback_identity.parents
                        for root in (evidence.upload, evidence.rollback, evidence.backup)),
                "rollback age identity must be outside payload and retention roots")
        verify_encrypted_rollback(rollback_identity, evidence)
    else:
        require(args.rollback_age_identity_file is None,
                "rollback age identity was supplied for a plaintext dump")
    lock_path = evidence.floor.with_name(evidence.floor.name + ".lock")
    if lock_path.exists() or lock_path.is_symlink():
        private(lock_path, directory=False)
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        verify_backup(args, evidence)
        # The controller stays on postgres while the target's hard fence is
        # briefly relaxed for one migrator session. Workload CONNECT grants
        # are revoked before that relaxation, then the hard fence is restored.
        target = evidence.database
        quote = '"' + target + '"'
        catalog = run_pg(args, "postgres",
                         "SELECT current_database() || ':' || current_user || ':' || "
                         "oid::text || ':' || datallowconn::text || ':' || datconnlimit::text "
                         f"FROM pg_database WHERE datname='{target}'")
        parts = catalog.split(":")
        require(len(parts) == 5 and parts[:3] == ["postgres", "northstar_migrator",
                                                  evidence.database_oid],
                "maintenance connection or target database identity differs")
        require(parts[3] in {"true", "false"} and re.fullmatch(r"-?[0-9]+", parts[4]) is not None,
                "target database fence catalog is invalid")
        sessions = run_pg(args, "postgres",
                          f"SELECT count(*) FROM pg_stat_activity WHERE datname='{target}'")
        require(sessions == "0", "target database has an active session; stop every workload")
        for role in CONNECT_ROLES:
            if role != "northstar_migrator":
                run_pg(args, "postgres", f"REVOKE CONNECT ON DATABASE {quote} FROM {role}")
        run_pg(args, "postgres", f"REVOKE CONNECT ON DATABASE {quote} FROM PUBLIC")
        unauthorized = run_pg(args, "postgres",
                              "SELECT rolname FROM pg_roles WHERE rolcanlogin AND NOT rolsuper "
                              "AND rolname <> 'northstar_migrator' AND "
                              f"has_database_privilege(rolname, '{target}', 'CONNECT')")
        require(not unauthorized, "another login role can enter the maintenance target")
        session = None
        opened_for_maintenance = True
        published = False
        try:
            append(evidence.journal, evidence.cutover, "recovery-maintenance-open-intent",
                   evidence.restore_id)
            run_pg(args, "postgres", f"ALTER DATABASE {quote} WITH ALLOW_CONNECTIONS true")
            session = TargetSession(args, target)
            current = session.query("SELECT current_database() || ':' || current_user || ':' || "
                                    "(SELECT oid FROM pg_database WHERE datname=current_database())::text "
                                    "|| ':' || pg_backend_pid()::text")
            current_parts = current.split(":")
            require(len(current_parts) == 4 and current_parts[:3] ==
                    [target, "northstar_migrator", evidence.database_oid],
                    f"maintenance target session has a different identity: {current!r}")
            run_pg(args, "postgres", f"ALTER DATABASE {quote} WITH ALLOW_CONNECTIONS false")
            append(evidence.journal, evidence.cutover, "recovery-maintenance-closed",
                   evidence.restore_id)
            count = run_pg(args, "postgres",
                           f"SELECT count(*) FROM pg_stat_activity WHERE datname='{target}'")
            require(count == "1", "unexpected target session after hard-fence reinstatement")
            lock = session.query(f"SELECT pg_try_advisory_lock({MAINTENANCE_LOCK})")
            require(lock == "t", "another backup or restore holds the target maintenance lock")
            outcome = decide(session, evidence)
            append(evidence.journal, evidence.cutover, "recovery-decision", outcome,
                   evidence.restore_id, evidence.manifest_sha)
            if outcome == "forward":
                if evidence.s3:
                    verify_s3_forward(session, evidence)
                else:
                    finish_forward(evidence)
                    verify_restored_upload_rows(session, evidence)
                if not evidence.forward_decided:
                    append(evidence.journal, evidence.cutover, "forward-decision",
                           evidence.restore_id, evidence.manifest_sha, evidence.incoming_xid)
                commit = ["python3", str(SCRIPT_DIR / "backup-security.py"),
                          "commit-restore-state", str(evidence.backup / "manifest.txt"),
                          str(evidence.floor), "--restore-id", evidence.restore_id,
                          "--allow-generation-change"]
                result = subprocess.run(commit, capture_output=True, text=True, timeout=30,
                                        check=False)
                require(result.returncode == 0,
                        f"trusted restore floor could not be committed: {result.stderr[-400:]}")
            else:
                if evidence.s3:
                    # The original exact versions were never changed. Newly
                    # uploaded attempt keys stay journaled for operator-owned
                    # cleanup, rather than deleting an uncertain version.
                    append(evidence.journal, evidence.cutover, "s3-new-objects-retained")
                else:
                    compensate_uploads(evidence)
                append(evidence.journal, evidence.cutover, "compensated")
            # The exact target remains fenced while canonical CONNECT grants
            # and the original connection limit are restored from postgres.
            for role in CONNECT_ROLES:
                run_pg(args, "postgres", f"GRANT CONNECT ON DATABASE {quote} TO {role}")
            session.close()
            session = None
            require(run_pg(args, "postgres",
                           f"SELECT count(*) FROM pg_stat_activity WHERE datname='{target}'") == "0",
                    "target maintenance backend did not exit before publication")
            run_pg(args, "postgres", f"ALTER DATABASE {quote} WITH ALLOW_CONNECTIONS true")
            published = True
            append(evidence.journal, evidence.cutover, "recovery-complete", outcome)
            print(f"restore recovery complete: {outcome}; target={target}; restore_id={evidence.restore_id}")
        finally:
            # Any error after temporary opening closes the hard fence again.
            if opened_for_maintenance and not published:
                try:
                    run_pg(args, "postgres", f"ALTER DATABASE {quote} WITH ALLOW_CONNECTIONS false")
                finally:
                    if session is not None:
                        session.close()
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    try:
        main()
    except (RecoveryError, OSError, subprocess.TimeoutExpired, tarfile.TarError,
            UnicodeError, ValueError) as error:
        print(f"restore recovery refused: {error}", file=sys.stderr)
        raise SystemExit(1)
