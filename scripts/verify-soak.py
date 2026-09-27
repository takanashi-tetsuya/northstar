#!/usr/bin/env python3
"""Verify a completed local VM soak and its saved room MAM evidence offline."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat


MIN_OBSERVATIONS = 1430
MAX_OBSERVATIONS = 5000
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_ROOM_BYTES = 1024 * 1024
ROOM_NAME = re.compile(r"[0-9]{6}-northstar-lab-muc-mam-[0-9a-f]{32}\.jsonl\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def private_regular(path: Path, maximum: int) -> os.stat_result:
    if path.is_symlink():
        raise ValueError(f"symlink is not evidence: {path}")
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_size > maximum):
        raise ValueError(f"evidence is not a bounded private file: {path}")
    return info


def private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"symlink is not an evidence directory: {path}")
    info = path.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077):
        raise ValueError(f"evidence directory is not private: {path}")


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def timestamp(value: object) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError("soak record has no timestamp")
    parsed = dt.datetime.fromisoformat(value)
    if parsed.utcoffset() is None:
        raise ValueError("soak timestamp has no timezone")
    return parsed.astimezone(dt.timezone.utc)


def read_records(path: Path) -> list[dict[str, object]]:
    private_regular(path, MAX_LOG_BYTES)
    records: list[dict[str, object]] = []
    with path.open("rb") as source:
        for line in source:
            if not line.endswith(b"\n") or len(line) > 64 * 1024:
                raise ValueError("soak has an incomplete or oversized line")
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("soak line is not an object")
            records.append(record)
            if len(records) > MAX_OBSERVATIONS + 2:
                raise ValueError("soak has too many observations")
    if len(records) < MIN_OBSERVATIONS + 2:
        raise ValueError("soak has too few observations")
    return records


def verify_unit_status(contents: bytes) -> None:
    if len(contents) > 16 * 1024:
        raise ValueError("systemd status is oversized")
    lines = contents.decode("utf-8").splitlines()
    if not all(value in lines for value in
               ("ActiveState=inactive", "Result=success", "ExecMainStatus=0")):
        raise ValueError("soak systemd unit did not finish successfully")


def verify(soak: Path, room_dir: Path, candidate_sha: str,
           unit_status: bytes) -> tuple[dict[str, object], list[Path]]:
    if not SHA256.fullmatch(candidate_sha):
        raise ValueError("candidate SHA-256 is invalid")
    verify_unit_status(unit_status)
    private_directory(room_dir)
    records = read_records(soak)
    first, last = records[0], records[-1]
    if (first.get("event") != "candidate_start_verification"
            or last.get("event") != "candidate_end_verification"):
        raise ValueError("soak lacks successful candidate start/end verification")
    if any(row.get("expected_binary_sha256") != candidate_sha for row in records):
        raise ValueError("soak record has a different candidate digest")
    identity = first.get("identity")
    if (not isinstance(identity, dict)
            or set(identity) != {"ns-a", "ns-b"}
            or any(not isinstance(identity[node], list) or len(identity[node]) != 2
                   or type(identity[node][0]) is not int or identity[node][0] <= 0
                   or not isinstance(identity[node][1], str)
                   or not re.fullmatch(r"[0-9]+:[0-9]+", identity[node][1])
                   for node in ("ns-a", "ns-b"))):
        raise ValueError("start candidate identity is missing or invalid")
    for node in ("ns-a", "ns-b"):
        end_identity = last.get(node)
        if (not isinstance(end_identity, dict)
                or type(end_identity.get("pid")) is not int
                or end_identity["pid"] <= 0
                or not isinstance(end_identity.get("binary_inode"), str)
                or not re.fullmatch(r"[0-9]+:[0-9]+", end_identity["binary_inode"])):
            raise ValueError(f"end candidate identity is missing for {node}")

    started, ended = timestamp(first.get("time_utc")), timestamp(last.get("time_utc"))
    if (ended - started).total_seconds() < 24 * 3600:
        raise ValueError("soak did not run for 24 hours")
    if ended > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=1):
        raise ValueError("soak ends in the future")
    checks = records[1:-1]
    if len(checks) > MAX_OBSERVATIONS:
        raise ValueError("soak has too many minute checks")
    room_files: list[Path] = []
    previous = started
    counts = {"cross_node": 0, "federation_prosody": 0,
              "federation_ejabberd": 0, "room_mam": 0, "upload": 0}
    for minute, row in enumerate(checks):
        if row.get("iteration") != minute or row.get("status") != "passed":
            raise ValueError(f"failed or missing soak minute {minute}")
        observed = timestamp(row.get("time_utc"))
        if not previous <= observed < ended:
            raise ValueError(f"minute {minute} has an out-of-order timestamp")
        if (observed - previous).total_seconds() > 120:
            raise ValueError(f"minute {minute} leaves a gap over two minutes")
        if abs((observed - started).total_seconds() - minute * 60) > 120:
            raise ValueError(f"minute {minute} drifted over two minutes from the schedule")
        previous = observed
        for node in ("ns-a", "ns-b"):
            if (type(row.get(f"pid_{node}")) is not int
                    or row[f"pid_{node}"] <= 0
                    or type(row.get(f"rss_kib_{node}")) is not int
                    or row[f"rss_kib_{node}"] <= 0
                    or not isinstance(row.get(f"binary_inode_{node}"), str)):
                raise ValueError(f"minute {minute} lacks a node resource sample")
            change = row.get(f"candidate_change_{node}")
            if change is not None and (not isinstance(change, dict)
                                       or change.get("sha256") != candidate_sha):
                raise ValueError(f"minute {minute} has unverified candidate replacement")
        if type(row.get("postgres_wal_bytes")) is not int or row["postgres_wal_bytes"] < 0:
            raise ValueError(f"minute {minute} lacks the PostgreSQL WAL sample")
        if not isinstance(row.get("cross_node"), str) or not row["cross_node"].strip():
            raise ValueError(f"minute {minute} lacks cross-node delivery")
        counts["cross_node"] += 1
        if minute % 5 == 0:
            for peer in ("prosody", "ejabberd"):
                name = f"federation_{peer}"
                if not isinstance(row.get(name), str) or not row[name].strip():
                    raise ValueError(f"minute {minute} lacks {name}")
                counts[name] += 1
        if minute % 60 == 0:
            report = row.get("room_mam")
            if (not isinstance(report, dict) or report.get("probe") != "room-mam-adjacent-pages"
                    or report.get("status") != "passed"):
                raise ValueError(f"minute {minute} lacks a passed room MAM probe")
            expected_path = report.get("evidence_jsonl")
            saved_path = report.get("host_evidence_jsonl")
            expected_sha = report.get("evidence_sha256")
            expected_bytes = report.get("evidence_bytes")
            if (not isinstance(expected_path, str)
                    or not re.fullmatch(r"/tmp/northstar-lab-muc-mam-[0-9a-f]{32}\.jsonl", expected_path)
                    or not isinstance(saved_path, str)
                    or not isinstance(expected_sha, str)
                    or not SHA256.fullmatch(expected_sha)
                    or type(expected_bytes) is not int
                    or not 0 < expected_bytes <= MAX_ROOM_BYTES):
                raise ValueError(f"minute {minute} has invalid room MAM evidence metadata")
            filename = f"{minute:06d}-{Path(expected_path).name}"
            if Path(saved_path).name != filename or not ROOM_NAME.fullmatch(filename):
                raise ValueError(f"minute {minute} points to the wrong room MAM evidence")
            source = room_dir / filename
            info = private_regular(source, MAX_ROOM_BYTES)
            if info.st_size != expected_bytes or digest_file(source) != expected_sha:
                raise ValueError(f"minute {minute} room MAM evidence differs from probe")
            with source.open("rb") as raw:
                lines = raw.readlines()
            if not lines or any(not line.endswith(b"\n") or not isinstance(json.loads(line), dict)
                                for line in lines):
                raise ValueError(f"minute {minute} raw room MAM evidence is malformed")
            room_files.append(source)
            counts["room_mam"] += 1
        if minute > 0 and minute % 90 == 0:
            if not isinstance(row.get("upload"), str) or not row["upload"].strip():
                raise ValueError(f"minute {minute} lacks upload probe")
            counts["upload"] += 1
    if (ended - previous).total_seconds() > 120:
        raise ValueError("last soak observation is too far from end verification")
    if len(room_files) < 24:
        raise ValueError("soak has fewer than 24 hourly room MAM evidence files")
    actual_names = {entry.name for entry in room_dir.iterdir()}
    if actual_names != {entry.name for entry in room_files}:
        raise ValueError("room MAM evidence directory contains missing or extra files")
    report: dict[str, object] = {
        "result": "complete", "candidate_sha256": candidate_sha,
        "start_utc": first["time_utc"], "end_utc": last["time_utc"],
        "observations": len(checks), "room_mam_evidence_files": len(room_files),
        "probe_counts": counts, "soak_sha256": digest_file(soak),
    }
    return report, room_files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--soak", required=True, type=Path)
    parser.add_argument("--room-evidence-dir", required=True, type=Path)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--unit-status", required=True, type=Path)
    args = parser.parse_args()
    private_regular(args.unit_status, 16 * 1024)
    report, _ = verify(args.soak, args.room_evidence_dir,
                       args.candidate_sha256, args.unit_status.read_bytes())
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
