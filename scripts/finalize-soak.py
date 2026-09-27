#!/usr/bin/env python3
"""Seal a successful 24-hour local VM soak for the active-load controller."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from typing import Callable


ROOT = Path(__file__).resolve().parent


def load_script(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unit_status(unit: str) -> bytes:
    result = subprocess.run(
        ["systemctl", "--user", "show", unit, "-p", "ActiveState",
         "-p", "Result", "-p", "ExecMainStatus", "-p", "ExecMainCode"],
        check=True, capture_output=True, timeout=15,
    )
    return result.stdout


def copy_private(source: Path, destination: Path, verifier, maximum: int) -> None:
    expected = verifier.private_regular(source, maximum)
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(source_fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
                expected.st_dev, expected.st_ino, expected.st_size):
            raise RuntimeError(f"source changed during verification: {source}")
        destination_fd = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
        )
        try:
            with os.fdopen(source_fd, "rb") as input_file, os.fdopen(destination_fd, "wb") as output_file:
                source_fd = -1
                shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
                output_file.flush()
                os.fsync(output_file.fileno())
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
    finally:
        if source_fd >= 0:
            os.close(source_fd)
    verifier.private_regular(source, maximum)
    if verifier.digest_file(source) != verifier.digest_file(destination):
        raise RuntimeError(f"source changed while copying: {source}")


def write_private(path: Path, contents: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(contents)
        output.flush()
        os.fsync(output.fileno())


def finalize(source: Path, room_dir: Path, output: Path, candidate_sha: str,
             read_status: Callable[[], bytes]) -> dict[str, object]:
    verifier = load_script(ROOT / "verify-soak.py", "northstar_verify_soak")
    active = load_script(ROOT / "local-vm-lab-active-load.py", "northstar_active_load")
    verifier.private_directory(source.parent)
    verifier.private_directory(room_dir)
    verifier.private_directory(output.parent)
    if output.name in ("", ".", "..") or output.is_symlink():
        raise ValueError("invalid sealed evidence directory")
    archive = output.parent / f"{output.name}.tar.gz"
    if output.exists() or archive.exists() or archive.is_symlink():
        raise FileExistsError("sealed evidence directory or archive already exists")
    start_status = read_status()
    report, room_files = verifier.verify(source, room_dir, candidate_sha, start_status)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}-stage-", dir=output.parent))
    stage = temporary / output.name
    stage_archive = temporary / f"{output.name}.tar.gz"
    moved = False
    try:
        stage.mkdir(mode=0o700)
        copied_log = stage / "soak-24h-release.jsonl"
        copy_private(source, copied_log, verifier, verifier.MAX_LOG_BYTES)
        copied_rooms = stage / "soak-24h-release-room-mam-evidence"
        copied_rooms.mkdir(mode=0o700)
        for room in room_files:
            copy_private(room, copied_rooms / room.name, verifier, verifier.MAX_ROOM_BYTES)
        copied_verifier = stage / "verify-soak.py"
        write_private(copied_verifier, (ROOT / "verify-soak.py").read_bytes())
        end_status = read_status()
        if end_status != start_status:
            raise RuntimeError("soak systemd unit status changed while sealing")
        write_private(stage / "unit-final-status.txt", end_status)
        copied_report, _ = verifier.verify(
            copied_log, copied_rooms, candidate_sha, end_status,
        )
        if copied_report != report:
            raise RuntimeError("copied soak evidence differs from source verification")
        write_private(stage / "soak-verification.json",
                      (json.dumps(copied_report, sort_keys=True, indent=2) + "\n").encode())
        files = sorted(path for path in stage.rglob("*") if path.is_file())
        manifest = "".join(
            f"{verifier.digest_file(path)}  ./{path.relative_to(stage)}\n"
            for path in files
        )
        write_private(stage / "SHA256SUMS.txt", manifest.encode())
        with tarfile.open(stage_archive, "w:gz") as bundle:
            bundle.add(stage, arcname=output.name, recursive=True)
        stage_archive.chmod(0o600)
        pinned = verifier.digest_file(stage_archive)
        parsed = active.parse_soak(copied_log, candidate_sha)
        active.check_sealed_soak(copied_log, pinned, candidate_sha, parsed)
        if output.exists() or archive.exists():
            raise FileExistsError("sealed evidence path was created concurrently")
        stage.rename(output)
        try:
            stage_archive.rename(archive)
        except BaseException:
            output.rename(stage)
            raise
        moved = True
        parsed = active.parse_soak(output / "soak-24h-release.jsonl", candidate_sha)
        active.check_sealed_soak(
            output / "soak-24h-release.jsonl", pinned, candidate_sha, parsed,
        )
        return {"sealed_directory": str(output), "archive": str(archive),
                "archive_sha256": pinned, "verification": copied_report}
    finally:
        if not moved:
            shutil.rmtree(temporary, ignore_errors=True)
        else:
            temporary.rmdir()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path,
                        help="completed, private original soak JSONL")
    parser.add_argument("--room-evidence-dir", type=Path,
                        help="defaults to SOURCE stem plus -room-mam-evidence")
    parser.add_argument("--unit", required=True, help="completed systemd user unit")
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args()
    if (not args.unit.startswith("northstar-lab-soak-")
            or not args.unit.endswith(".service")
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-."
                   for character in args.unit)):
        parser.error("--unit must name a northstar-lab-soak-*.service user unit")
    source = args.source.absolute()
    room_dir = args.room_evidence_dir or source.with_name(source.stem + "-room-mam-evidence")
    result = finalize(source, room_dir.absolute(), args.output_directory.absolute(),
                      args.candidate_sha256, lambda: unit_status(args.unit))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
