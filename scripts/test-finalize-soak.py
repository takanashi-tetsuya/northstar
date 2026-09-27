#!/usr/bin/env python3
"""Offline fixture checks for the local soak sealer and verifier."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent


def load_script(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


finalizer = load_script(ROOT / "finalize-soak.py", "finalize_soak_under_test")
verifier = load_script(ROOT / "verify-soak.py", "verify_soak_under_test")
active = load_script(ROOT / "local-vm-lab-active-load.py", "active_load_under_test")
SHA = "a" * 64
SUCCESS = b"ActiveState=inactive\nResult=success\nExecMainStatus=0\n"
START = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


def fixture(root: Path) -> tuple[Path, Path, Path]:
    source_dir = root / "source"
    source_dir.mkdir(mode=0o700)
    source = source_dir / "soak-fixture.jsonl"
    rooms = source_dir / "soak-fixture-room-mam-evidence"
    rooms.mkdir(mode=0o700)
    rows: list[dict[str, object]] = [{
        "event": "candidate_start_verification", "time_utc": START.isoformat(),
        "expected_binary_sha256": SHA,
        "identity": {"ns-a": [100, "1:2"], "ns-b": [200, "1:3"]},
    }]
    for minute in range(1440):
        record: dict[str, object] = {
            "time_utc": (START + dt.timedelta(minutes=minute)).isoformat(),
            "iteration": minute, "status": "passed", "expected_binary_sha256": SHA,
            "cross_node": "passed", "pid_ns-a": 100, "pid_ns-b": 200,
            "rss_kib_ns-a": 100, "rss_kib_ns-b": 100,
            "binary_inode_ns-a": "1:2", "binary_inode_ns-b": "1:3",
            "postgres_wal_bytes": minute,
        }
        if minute % 5 == 0:
            record["federation_prosody"] = "passed"
            record["federation_ejabberd"] = "passed"
        if minute % 60 == 0:
            guest = f"/tmp/northstar-lab-muc-mam-{minute:032x}.jsonl"
            saved = rooms / f"{minute:06d}-{Path(guest).name}"
            payload = b'{"phase":"room_join","direction":"sent","xml":"<presence/>"}\n'
            saved.write_bytes(payload)
            saved.chmod(0o600)
            record["room_mam"] = {
                "probe": "room-mam-adjacent-pages", "status": "passed",
                "evidence_jsonl": guest, "host_evidence_jsonl": str(saved),
                "evidence_sha256": hashlib.sha256(payload).hexdigest(),
                "evidence_bytes": len(payload),
            }
        if minute > 0 and minute % 90 == 0:
            record["upload"] = "passed"
        rows.append(record)
    rows.append({
        "event": "candidate_end_verification",
        "time_utc": (START + dt.timedelta(days=1, seconds=1)).isoformat(),
        "expected_binary_sha256": SHA,
        "ns-a": {"pid": 100, "binary_inode": "1:2"},
        "ns-b": {"pid": 200, "binary_inode": "1:3"},
    })
    source.write_text("".join(json.dumps(row) + "\n" for row in rows))
    source.chmod(0o600)
    return source, rooms, root / "sealed"


class FinalizeSoakTests(unittest.TestCase):
    def test_complete_soak_seals_and_active_load_accepts_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source, rooms, output = fixture(Path(directory))
            before = verifier.digest_file(source)
            result = finalizer.finalize(source, rooms, output, SHA, lambda: SUCCESS)
            self.assertEqual(verifier.digest_file(source), before)
            self.assertEqual(result["verification"]["observations"], 1440)
            self.assertEqual(result["verification"]["room_mam_evidence_files"], 24)
            sealed = output / "soak-24h-release.jsonl"
            parsed = active.parse_soak(sealed, SHA)
            self.assertEqual(active.check_sealed_soak(
                sealed, result["archive_sha256"], SHA, parsed,
            )["verified_files"], 28)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual(sealed.stat().st_mode & 0o777, 0o600)
            self.assertEqual(Path(result["archive"]).stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                finalizer.finalize(source, rooms, output, SHA, lambda: SUCCESS)

    def test_failed_unit_and_missing_minute_cannot_be_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source, rooms, output = fixture(Path(directory))
            with self.assertRaisesRegex(ValueError, "systemd"):
                finalizer.finalize(source, rooms, output, SHA,
                                   lambda: b"ActiveState=active\nResult=success\nExecMainStatus=0\n")
            self.assertFalse(output.exists())
            rows = [json.loads(line) for line in source.read_text().splitlines()]
            rows.pop(30)
            source.write_text("".join(json.dumps(row) + "\n" for row in rows))
            with self.assertRaisesRegex(ValueError, "missing soak minute"):
                finalizer.finalize(source, rooms, output, SHA, lambda: SUCCESS)
            self.assertFalse(output.exists())

    def test_room_evidence_tampering_cannot_be_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source, rooms, output = fixture(Path(directory))
            next(rooms.iterdir()).write_text("tampered\n")
            with self.assertRaisesRegex(ValueError, "room MAM evidence differs"):
                finalizer.finalize(source, rooms, output, SHA, lambda: SUCCESS)
            self.assertFalse(output.exists())

    def test_short_duration_and_changed_unit_cannot_be_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source, rooms, output = fixture(Path(directory))
            rows = [json.loads(line) for line in source.read_text().splitlines()]
            rows[-1]["time_utc"] = (
                START + dt.timedelta(hours=23, minutes=59)
            ).isoformat()
            source.write_text("".join(json.dumps(row) + "\n" for row in rows))
            with self.assertRaisesRegex(ValueError, "24 hours"):
                finalizer.finalize(source, rooms, output, SHA, lambda: SUCCESS)
            rows[-1]["time_utc"] = (
                START + dt.timedelta(days=1, seconds=1)
            ).isoformat()
            source.write_text("".join(json.dumps(row) + "\n" for row in rows))
            statuses = iter((SUCCESS, b"ActiveState=active\nResult=success\nExecMainStatus=0\n"))
            with self.assertRaisesRegex(RuntimeError, "status changed"):
                finalizer.finalize(source, rooms, output, SHA, lambda: next(statuses))
            self.assertFalse(output.exists())
            self.assertFalse(output.with_name(output.name + ".tar.gz").exists())


if __name__ == "__main__":
    unittest.main()
