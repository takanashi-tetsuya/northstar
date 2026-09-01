#!/usr/bin/env python3
"""Strict metadata and monotonic-state helpers for Northstar backups.

This program deliberately keeps cryptographic operations in the calling shell
scripts, where OpenSSL and age are invoked with file arguments.  It owns the
security-sensitive parsing, digest verification, and atomic sequence/state
updates so no manifest content is ever evaluated as shell code.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import uuid


HEX_256 = re.compile(r"[0-9a-f]{64}")
SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}")
RFC3339_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

V2_REQUIRED = {
    "format",
    "manifest_version",
    "backup_generation",
    "backup_sequence",
    "created_at",
    "northstar_version",
    "postgresql_version",
    "successful_migrations",
    "encryption",
    "signature",
    "signing_key_id",
    "database_archive",
    "database_archive_sha256",
    "database_plain_sha256",
    "database_contents",
    "database_contents_archive_sha256",
    "database_contents_plain_sha256",
    "upload_archive",
    "upload_archive_sha256",
    "upload_plain_sha256",
    "upload_consistency",
}

V1_REQUIRED = {
    "format",
    "created_at",
    "postgresql_version",
    "successful_migrations",
    "database_archive",
    "upload_archive",
    "upload_consistency",
}


class SecurityError(ValueError):
    pass


def fail(message: str) -> "None":
    raise SecurityError(message)


def parse_kv(path: Path, *, allowed: set[str], required: set[str]) -> dict[str, str]:
    require_regular(path, private=False)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        fail(f"cannot read metadata file: {exc}")
    if len(raw) > 64 * 1024:
        fail("metadata file is unreasonably large")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail("metadata file is not valid UTF-8")
    if "\x00" in text or "\r" in text:
        fail("metadata file contains forbidden control bytes")

    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or "=" not in line:
            fail("metadata contains a blank or malformed line")
        key, value = line.split("=", 1)
        if key not in allowed:
            fail(f"metadata contains unsupported field: {key}")
        if key in values:
            fail(f"metadata contains duplicate field: {key}")
        if not value or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            fail(f"metadata field has an invalid value: {key}")
        values[key] = value
    missing = sorted(required - values.keys())
    if missing:
        fail(f"metadata is missing fields: {', '.join(missing)}")
    return values


def require_regular(path: Path, *, private: bool) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        fail(f"required file is unavailable: {path.name}: {exc}")
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        fail(f"required path is not a regular non-symlink file: {path.name}")
    if info.st_nlink != 1:
        fail(f"security state must not have multiple hard links: {path.name}")
    if private and info.st_mode & 0o077:
        fail(f"private state permissions are too broad: {path.name}")
    return info


def validate_manifest(path: Path) -> dict[str, str]:
    # Read only the format line first, then reparse against an exact schema.
    require_regular(path, private=False)
    try:
        with path.open("r", encoding="utf-8", errors="strict") as handle:
            first = handle.readline().rstrip("\n")
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"cannot read manifest: {exc}")
    if first == "format=northstar-backup-v1":
        values = parse_kv(path, allowed=V1_REQUIRED, required=V1_REQUIRED)
        if values["database_archive"] != "database.dump":
            fail("legacy database archive name is not canonical")
        if values["upload_archive"] != "uploads.tar.gz":
            fail("legacy upload archive name is not canonical")
        if values["upload_consistency"] != "immutable-final-files":
            fail("unsupported upload consistency model")
        if not values["successful_migrations"].isdigit():
            fail("successful_migrations must be a non-negative integer")
        return values
    if first != "format=northstar-backup-v2":
        fail("unsupported backup format")

    values = parse_kv(path, allowed=V2_REQUIRED, required=V2_REQUIRED)
    if values["manifest_version"] != "2":
        fail("unsupported manifest version")
    try:
        parsed_generation = uuid.UUID(values["backup_generation"])
    except ValueError:
        fail("backup_generation is not a UUID")
    if str(parsed_generation) != values["backup_generation"]:
        fail("backup_generation is not a canonical lowercase UUID")
    if not values["backup_sequence"].isdigit() or int(values["backup_sequence"]) < 1:
        fail("backup_sequence must be a positive integer")
    if not RFC3339_UTC.fullmatch(values["created_at"]):
        fail("created_at must be an RFC3339 UTC timestamp")
    try:
        dt.datetime.strptime(values["created_at"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        fail("created_at is not a real UTC date")
    if not SAFE_VERSION.fullmatch(values["northstar_version"]):
        fail("northstar_version is not a safe version identifier")
    if not values["successful_migrations"].isdigit():
        fail("successful_migrations must be a non-negative integer")
    if values["upload_consistency"] != "immutable-final-files":
        fail("unsupported upload consistency model")
    if values["encryption"] not in {"none", "age"}:
        fail("unsupported payload encryption")
    if values["signature"] not in {"none", "openssl-ed25519"}:
        fail("unsupported manifest signature")
    if values["signature"] == "none":
        if values["signing_key_id"] != "none":
            fail("unsigned manifest must use signing_key_id=none")
    elif not re.fullmatch(r"sha256:[0-9a-f]{64}", values["signing_key_id"]):
        fail("signed manifest has an invalid signing key ID")

    suffix = ".age" if values["encryption"] == "age" else ""
    expected_names = {
        "database_archive": f"database.dump{suffix}",
        "database_contents": f"database.contents{suffix}",
        "upload_archive": f"uploads.tar.gz{suffix}",
    }
    for key, expected in expected_names.items():
        if values[key] != expected:
            fail(f"{key} is not the canonical name for this encryption mode")
    for key in (
        "database_archive_sha256",
        "database_plain_sha256",
        "database_contents_archive_sha256",
        "database_contents_plain_sha256",
        "upload_archive_sha256",
        "upload_plain_sha256",
    ):
        if not HEX_256.fullmatch(values[key]):
            fail(f"{key} is not a lowercase SHA-256 digest")
    return values


def digest(path: Path) -> str:
    require_regular(path, private=False)
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def parse_checksum_file(path: Path, expected: set[str]) -> dict[str, str]:
    require_regular(path, private=False)
    entries: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"cannot read SHA256SUMS: {exc}")
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64}) ([ *])([^/\\]+)", line)
        if not match:
            fail("SHA256SUMS contains a malformed or non-local path")
        name = match.group(3)
        if name in entries:
            fail(f"SHA256SUMS contains duplicate entry: {name}")
        entries[name] = match.group(1)
    if set(entries) != expected:
        fail("SHA256SUMS does not contain exactly the required backup files")
    return entries


def verify_artifacts(
    backup: Path,
    manifest_path: Path,
    signature_path: Path | None,
) -> None:
    manifest = validate_manifest(manifest_path)
    require_regular(backup / "READY", private=False)
    expected = {"manifest.txt"}
    if manifest["format"] == "northstar-backup-v1":
        expected |= {"database.dump", "database.contents", "uploads.tar.gz"}
    else:
        expected |= {
            manifest["database_archive"],
            manifest["database_contents"],
            manifest["upload_archive"],
        }
        if manifest["signature"] != "none":
            expected.add("manifest.sig")
    checksums = parse_checksum_file(backup / "SHA256SUMS", expected)
    for name, expected_digest in checksums.items():
        if name == "manifest.txt":
            artifact = manifest_path
        elif name == "manifest.sig":
            if signature_path is None:
                fail("signed backup did not provide a frozen signature")
            artifact = signature_path
        else:
            artifact = backup / name
        if digest(artifact) != expected_digest:
            fail(f"SHA-256 mismatch for {name}")
    if manifest["format"] == "northstar-backup-v2":
        pairs = (
            (manifest["database_archive"], manifest["database_archive_sha256"]),
            (manifest["database_contents"], manifest["database_contents_archive_sha256"]),
            (manifest["upload_archive"], manifest["upload_archive_sha256"]),
        )
        for name, expected_digest in pairs:
            if digest(backup / name) != expected_digest:
                fail(f"signed manifest digest mismatch for {name}")


def atomic_write(path: Path, contents: str) -> None:
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        fail("state parent must be a pre-created real directory")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def open_lock(path: Path) -> int:
    if not path.parent.is_dir() or path.parent.is_symlink():
        fail("lock parent must be a pre-created real directory")
    if path.exists() or path.is_symlink():
        require_regular(path, private=True)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    os.fchmod(fd, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def read_backup_state(path: Path) -> tuple[str, int] | None:
    if not path.exists() and not path.is_symlink():
        return None
    require_regular(path, private=True)
    values = parse_kv(
        path,
        allowed={"format", "generation", "sequence"},
        required={"format", "generation", "sequence"},
    )
    if values["format"] != "northstar-backup-state-v1":
        fail("unsupported backup sequence state format")
    try:
        generation = str(uuid.UUID(values["generation"]))
    except ValueError:
        fail("backup state generation is not a UUID")
    if generation != values["generation"]:
        fail("backup state generation is not canonical")
    if not values["sequence"].isdigit() or int(values["sequence"]) < 1:
        fail("backup state sequence is invalid")
    return generation, int(values["sequence"])


def reserve_sequence(state_path: Path) -> None:
    lock_fd = open_lock(Path(f"{state_path}.lock"))
    try:
        current = read_backup_state(state_path)
        if current is None:
            generation, sequence = str(uuid.uuid4()), 1
        else:
            generation, sequence = current[0], current[1] + 1
        atomic_write(
            state_path,
            "format=northstar-backup-state-v1\n"
            f"generation={generation}\n"
            f"sequence={sequence}\n",
        )
        print(generation, sequence)
    finally:
        os.close(lock_fd)


def read_restore_state(path: Path) -> dict[str, str] | None:
    if not path.exists() and not path.is_symlink():
        return None
    require_regular(path, private=True)
    values = parse_kv(
        path,
        allowed={"format", "generation", "sequence", "manifest_sha256", "restored_at"},
        required={"format", "generation", "sequence", "manifest_sha256", "restored_at"},
    )
    if values["format"] != "northstar-restore-state-v1":
        fail("unsupported restore state format")
    try:
        generation = str(uuid.UUID(values["generation"]))
    except ValueError:
        fail("restore state generation is not a UUID")
    if generation != values["generation"]:
        fail("restore state generation is not canonical")
    if not values["sequence"].isdigit() or int(values["sequence"]) < 1:
        fail("restore state sequence is invalid")
    if not HEX_256.fullmatch(values["manifest_sha256"]):
        fail("restore state manifest digest is invalid")
    if not RFC3339_UTC.fullmatch(values["restored_at"]):
        fail("restore state timestamp is invalid")
    return values


def check_rollback(
    manifest_path: Path,
    state_path: Path,
    *,
    allow_rollback: bool,
    allow_generation_change: bool,
) -> None:
    manifest = validate_manifest(manifest_path)
    if manifest["format"] != "northstar-backup-v2":
        fail("legacy backups do not carry monotonic rollback metadata")
    current = read_restore_state(state_path)
    if current is None:
        return
    generation = manifest["backup_generation"]
    sequence = int(manifest["backup_sequence"])
    if current["generation"] != generation:
        if not allow_generation_change:
            fail("backup generation differs from the trusted restore state")
        return
    if sequence <= int(current["sequence"]) and not allow_rollback:
        fail("backup sequence is not newer than the trusted restore state")


def commit_restore_state(
    manifest_path: Path,
    state_path: Path,
    *,
    allow_generation_change: bool,
) -> None:
    manifest = validate_manifest(manifest_path)
    if manifest["format"] != "northstar-backup-v2":
        fail("cannot commit rollback state for a legacy backup")
    current = read_restore_state(state_path)
    generation = manifest["backup_generation"]
    sequence = int(manifest["backup_sequence"])
    manifest_digest = digest(manifest_path)
    if current is not None and current["generation"] == generation:
        # A deliberate older restore must never lower the replay floor.
        if sequence <= int(current["sequence"]):
            sequence = int(current["sequence"])
            manifest_digest = current["manifest_sha256"]
    elif current is not None and not allow_generation_change:
        fail("refusing to commit an unapproved backup generation")
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    atomic_write(
        state_path,
        "format=northstar-restore-state-v1\n"
        f"generation={generation}\n"
        f"sequence={sequence}\n"
        f"manifest_sha256={manifest_digest}\n"
        f"restored_at={timestamp}\n",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    reserve = commands.add_parser("reserve-sequence")
    reserve.add_argument("state_file", type=Path)

    validate = commands.add_parser("validate-manifest")
    validate.add_argument("manifest", type=Path)

    field = commands.add_parser("field")
    field.add_argument("manifest", type=Path)
    field.add_argument("key")

    verify = commands.add_parser("verify-artifacts")
    verify.add_argument("backup_directory", type=Path)
    verify.add_argument("--manifest", type=Path)
    verify.add_argument("--signature", type=Path)

    rollback = commands.add_parser("check-rollback")
    rollback.add_argument("manifest", type=Path)
    rollback.add_argument("state_file", type=Path)
    rollback.add_argument("--allow-rollback", action="store_true")
    rollback.add_argument("--allow-generation-change", action="store_true")

    commit = commands.add_parser("commit-restore-state")
    commit.add_argument("manifest", type=Path)
    commit.add_argument("state_file", type=Path)
    commit.add_argument("--allow-generation-change", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "reserve-sequence":
        reserve_sequence(args.state_file)
    elif args.command == "validate-manifest":
        validate_manifest(args.manifest)
    elif args.command == "field":
        manifest = validate_manifest(args.manifest)
        if args.key not in manifest:
            fail(f"manifest field is unavailable: {args.key}")
        print(manifest[args.key])
    elif args.command == "verify-artifacts":
        backup = args.backup_directory.resolve(strict=True)
        if not backup.is_dir():
            fail("backup directory is not a directory")
        manifest_path = args.manifest or (backup / "manifest.txt")
        verify_artifacts(backup, manifest_path, args.signature)
    elif args.command == "check-rollback":
        check_rollback(
            args.manifest,
            args.state_file,
            allow_rollback=args.allow_rollback,
            allow_generation_change=args.allow_generation_change,
        )
    elif args.command == "commit-restore-state":
        commit_restore_state(
            args.manifest,
            args.state_file,
            allow_generation_change=args.allow_generation_change,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SecurityError, OSError) as exc:
        print(f"backup security check failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
