#!/usr/bin/env python3
"""Install one staged lab.test TLSA change on the isolated DNS guest after soak."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile


def load_stager():
    path = Path(__file__).with_name("local-vm-lab-dane-zone.py")
    spec = importlib.util.spec_from_file_location("lab_dane_zone", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the adjacent DANE zone staging helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


zone = load_stager()
ZONE_PATH = Path("/var/lib/bind/lab.test.zone")
LOCK_PATH = Path("/run/lock/northstar-lab-dane-zone.lock")


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid)


def read_regular(path: Path, maximum: int = 65536) -> tuple[bytes, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError(f"expected a regular file of at most {maximum} bytes: {path}")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if (len(data) > maximum or identity(before) != identity(after)
            or identity(after) != identity(path.lstat())):
        raise ValueError(f"file changed while reading: {path}")
    return data, after


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def exclusive_lock(path: Path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("zone update lock must be an owned private regular file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if identity(info) != identity(path.lstat()):
            raise RuntimeError("zone update lock changed while acquiring it")
        yield
    finally:
        os.close(fd)
    # Never unlink: a waiter must not retain a lock on an obsolete inode.


def same_snapshot(path: Path, data: bytes, info: os.stat_result) -> None:
    current, current_info = read_regular(path)
    if current != data or identity(info) != identity(current_info):
        raise RuntimeError("current zone changed during validation; stage again")


def replace_zone(path: Path, data: bytes, metadata: os.stat_result) -> None:
    fd, name = tempfile.mkstemp(prefix=".northstar-dane-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def owner_records(text: str, owner: str) -> list[str]:
    return [zone.tlsa_record(line, owner) for line in text.splitlines()
            if line.split() and line.split()[0].lower() == owner]


def run_command(arguments: list[str], input_bytes: bytes | None = None):
    return subprocess.run(arguments, input=input_bytes, capture_output=True, timeout=30)


def install(target: Path, lock: Path, staged: bytes, base_sha256: str,
            base_serial: int, staged_sha256: str, owner: str, evidence: Path,
            command=run_command) -> dict:
    if any(re.fullmatch(r"[0-9a-f]{64}", digest) is None
           for digest in (base_sha256, staged_sha256)):
        raise ValueError("expected lowercase SHA-256 pins")
    if len(staged) > 65536 or zone.sha256(staged) != staged_sha256:
        raise ValueError("staged zone SHA-256 differs from its pin or exceeds the size limit")
    with exclusive_lock(lock):
        baseline, metadata = read_regular(target)
        if zone.sha256(baseline) != base_sha256:
            raise ValueError("current zone SHA-256 differs from the staged baseline; stage again")
        candidate, old, new = zone.stage_zone(
            baseline.decode("ascii"), owner, owner_records(staged.decode("ascii"), owner),
        )
        if old != base_serial:
            raise ValueError("current zone SOA serial differs from the staged baseline; stage again")
        if candidate.encode("ascii") != staged:
            raise ValueError("staged zone changes more than the chosen TLSA RRset and SOA serial")
        # Restore the old RRset with a NEW serial; publishing the old serial can
        # leave named or its clients observing the rejected candidate.
        restored, _, restored_serial = zone.stage_zone(
            candidate, owner, owner_records(baseline.decode("ascii"), owner),
        )
        restored_bytes = restored.encode("ascii")
        evidence.mkdir(mode=0o700, parents=False, exist_ok=False)
        write_private(evidence / "original.zone", baseline)
        write_private(evidence / "staged.zone", staged)
        write_private(evidence / "rollback.zone", restored_bytes)
        report = {"base_sha256": base_sha256, "staged_sha256": staged_sha256,
                  "old_soa_serial": old, "new_soa_serial": new, "tlsa_owner": owner,
                  "rollback_soa_serial": restored_serial,
                  "rollback_sha256": zone.sha256(restored_bytes),
                  "zone_uid": metadata.st_uid, "zone_gid": metadata.st_gid,
                  "zone_mode": oct(stat.S_IMODE(metadata.st_mode)),
                  "scope": "unsigned zone installation and reload; DNSSEC and delivery unverified"}
        write_private(evidence / "prepared.json", (json.dumps(report, sort_keys=True) + "\n").encode())
        sync_directory(evidence)
        sync_directory(evidence.parent)

        def event(status: str, **details) -> None:
            data = {"status": status, "time_utc": datetime.now(timezone.utc).isoformat(), **details}
            fd = os.open(evidence / "events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND
                         | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "ab") as stream:
                stream.write((json.dumps(data, sort_keys=True) + "\n").encode())
                stream.flush()
                os.fsync(stream.fileno())
            sync_directory(evidence)

        def recovery_event(status: str, **details) -> None:
            # A full evidence disk must not suppress compensation. The original
            # operation still fails even when restoring service succeeds.
            try:
                event(status, **details)
            except OSError as error:
                print(f"could not persist recovery event {status}: {error}", file=sys.stderr)

        def checked(label: str, args: list[str], data: bytes | None = None,
                    recovery: bool = False) -> None:
            record = recovery_event if recovery else event
            record(f"{label}_started", argv=args)
            try:
                result = command(args, data)
            except subprocess.TimeoutExpired as error:
                write_private(evidence / f"{label}.stdout", error.stdout or b"")
                write_private(evidence / f"{label}.stderr", error.stderr or b"")
                raise
            try:
                write_private(evidence / f"{label}.stdout", result.stdout)
                write_private(evidence / f"{label}.stderr", result.stderr)
            except OSError as error:
                if not recovery:
                    raise
                print(f"could not persist {label} output: {error}", file=sys.stderr)
            record(f"{label}_finished", returncode=result.returncode)
            if result.returncode:
                raise RuntimeError(f"{label} exited {result.returncode}; see retained evidence")

        attempted = False
        installed_metadata = None
        try:
            checked("candidate_check", ["named-checkzone", "lab.test", "-"], staged)
            checked("rollback_check", ["named-checkzone", "lab.test", "-"], restored_bytes)
            same_snapshot(target, baseline, metadata)
            event("install_started")
            attempted = True
            replace_zone(target, staged, metadata)
            current, installed_metadata = read_regular(target)
            if current != staged:
                raise RuntimeError("installed zone differs from the pinned candidate")
            event("installed")
            checked("reload", ["rndc", "reload", "lab.test"])
            same_snapshot(target, staged, installed_metadata)
            event("completed")
            return {**report, "status": "installed", "evidence_directory": str(evidence)}
        except BaseException as error:
            recovery_event("failed", error=str(error))
            if attempted:
                try:
                    current, current_metadata = read_regular(target)
                    if current == baseline and identity(current_metadata) == identity(metadata):
                        recovery_event("original_retained")
                    else:
                        if current != staged:
                            raise RuntimeError("zone changed outside installer; refusing to overwrite it")
                        if installed_metadata is not None:
                            same_snapshot(target, staged, installed_metadata)
                        recovery_event("rollback_started")
                        replace_zone(target, restored_bytes, metadata)
                        rollback_data, rollback_metadata = read_regular(target)
                        if rollback_data != restored_bytes:
                            raise RuntimeError("rollback zone differs from the prepared recovery file")
                        checked("rollback_reload", ["rndc", "reload", "lab.test"], recovery=True)
                        same_snapshot(target, restored_bytes, rollback_metadata)
                        recovery_event("rolled_back", soa_serial=restored_serial)
                except BaseException as rollback_error:
                    recovery_event("recovery_required", error=str(rollback_error))
                    raise RuntimeError(f"installation failed; recovery required: {evidence}") from error
            raise


def require_guest() -> None:
    if os.geteuid() != 0 or socket.gethostname() != "northstar-lab-dns-ca":
        raise RuntimeError("run under sudo only on northstar-lab-dns-ca, after sealing the soak")
    for family in ("-4", "-6"):
        result = run_command(["ip", "-j", family, "route", "show", "default"])
        if result.returncode or json.loads(result.stdout):
            raise RuntimeError("DNS guest must have no IPv4 or IPv6 default route")


def interrupted(signum, _frame) -> None:
    raise InterruptedError(f"interrupted by signal {signum}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged-zone", type=Path, required=True)
    parser.add_argument("--expected-base-sha256", required=True)
    parser.add_argument("--expected-base-serial", type=int, required=True)
    parser.add_argument("--expected-staged-sha256", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    args = parser.parse_args()
    require_guest()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    staged, _ = read_regular(args.staged_zone)
    result = install(ZONE_PATH, LOCK_PATH, staged, args.expected_base_sha256,
                     args.expected_base_serial, args.expected_staged_sha256,
                     args.owner.lower(), args.evidence_directory)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"local DANE zone installation failed: {error}", file=sys.stderr)
        sys.exit(2)
