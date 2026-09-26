#!/usr/bin/env python3
"""Run a bounded, low-rate mixed smoke soak on the isolated VM lab."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
from typing import Callable


MAX_ROOM_EVIDENCE_BYTES = 1024 * 1024
ROOM_EVIDENCE_PATH = re.compile(r"/tmp/northstar-lab-muc-mam-[0-9a-f]{32}\.jsonl\Z")


def parse_probe_json(output: str, expected_probe: str) -> dict[str, object]:
    if len(output.encode()) > 16 * 1024:
        raise RuntimeError(f"{expected_probe} output exceeded 16 KiB")
    result = json.loads(output)
    if not isinstance(result, dict) or result.get("status") != "passed" or result.get("probe") != expected_probe:
        raise RuntimeError(f"{expected_probe} returned an unexpected result")
    return result


def due(iteration: int, interval_minutes: int) -> bool:
    return iteration >= 0 and interval_minutes > 0 and iteration % interval_minutes == 0


def parse_service_sample(output: str) -> tuple[int, int, str]:
    fields = output.split()
    if (len(fields) != 4 or not fields[0].isdigit() or not fields[1].isdigit()
            or int(fields[0]) <= 0 or int(fields[1]) <= 0
            or not re.fullmatch(r"[0-9]+:[0-9]+", fields[2])
            or fields[2] != fields[3]):
        raise RuntimeError("running service identity, inode or RSS is invalid")
    return int(fields[0]), int(fields[1]), fields[2]


def save_room_evidence(
    report: dict[str, object], output: Path, iteration: int,
    fetch: Callable[[str], bytes],
) -> Path:
    guest_path = report.get("evidence_jsonl")
    expected_sha = report.get("evidence_sha256")
    expected_bytes = report.get("evidence_bytes")
    if not isinstance(guest_path, str) or not ROOM_EVIDENCE_PATH.fullmatch(guest_path):
        raise RuntimeError("room MAM evidence path is outside the lab whitelist")
    if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise RuntimeError("room MAM evidence digest is invalid")
    if type(expected_bytes) is not int or not 0 < expected_bytes <= MAX_ROOM_EVIDENCE_BYTES:
        raise RuntimeError("room MAM evidence size is invalid")
    contents = fetch(guest_path)
    if len(contents) != expected_bytes or hashlib.sha256(contents).hexdigest() != expected_sha:
        raise RuntimeError("room MAM evidence size or SHA-256 differs from the guest report")

    directory = output.parent / f"{output.stem}-room-mam-evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(directory_fd)
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise RuntimeError("host room MAM evidence directory is not private")
        name = f"{iteration:06d}-{Path(guest_path).name}"
        file_fd = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=directory_fd,
        )
        try:
            with os.fdopen(file_fd, "wb") as evidence_file:
                evidence_file.write(contents)
                evidence_file.flush()
                os.fsync(evidence_file.fileno())
            os.fsync(directory_fd)
        except Exception:
            os.unlink(name, dir_fd=directory_fd)
            raise
    finally:
        os.close(directory_fd)
    return (directory / name).resolve()


def self_test() -> None:
    assert [i for i in range(121) if due(i, 60)] == [0, 60, 120]
    assert not due(-1, 60) and not due(1, 60)
    assert parse_service_sample("123 4567 8:99 8:99") == (123, 4567, "8:99")
    for invalid in ("0 4567 8:99 8:99", "123 0 8:99 8:99",
                    "123 4567 8:99 8:100", "123 4567 8:99 8:99 extra"):
        try:
            parse_service_sample(invalid)
        except RuntimeError:
            pass
        else:
            raise AssertionError("invalid running service identity was accepted")
    result = parse_probe_json('{"probe":"room-mam-adjacent-pages","status":"passed"}', "room-mam-adjacent-pages")
    assert result["status"] == "passed"
    for invalid in ('{"probe":"wrong","status":"passed"}', '{"probe":"room-mam-adjacent-pages","status":"failed"}'):
        try:
            parse_probe_json(invalid, "room-mam-adjacent-pages")
        except RuntimeError:
            pass
        else:
            raise AssertionError("invalid MUC/MAM result was accepted")
    contents = b'{"phase":"room_join","direction":"sent","xml":"<presence/>"}\n'
    guest_path = "/tmp/northstar-lab-muc-mam-" + "a" * 32 + ".jsonl"
    report = {
        "evidence_jsonl": guest_path,
        "evidence_sha256": hashlib.sha256(contents).hexdigest(),
        "evidence_bytes": len(contents),
    }
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "soak.jsonl"
        saved = save_room_evidence(report, output, 60, lambda path: contents)
        assert saved.read_bytes() == contents
        assert saved.stat().st_mode & 0o777 == 0o600
        assert saved.parent.stat().st_mode & 0o777 == 0o700
        for bad_report, payload in (
            ({**report, "evidence_jsonl": "/etc/passwd"}, contents),
            ({**report, "evidence_bytes": len(contents) + 1}, contents),
            (report, contents + b"tampered"),
        ):
            try:
                save_room_evidence(bad_report, output, 61, lambda path: payload)
            except RuntimeError:
                pass
            else:
                raise AssertionError("invalid room MAM evidence was accepted")
    print("local-vm-lab-soak self-test passed")


def guest_ip(name: str) -> str:
    leases = subprocess.run(
        ["virsh", "net-dhcp-leases", "northstar-lab"],
        check=True, capture_output=True, text=True,
    ).stdout
    match = re.search(
        rf"\b(192\.168\.197\.\d+)/\d+\s+{re.escape('northstar-lab-' + name)}\b",
        leases,
    )
    if not match:
        raise RuntimeError(f"no private address for {name}")
    return match.group(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hours", type=float, default=24.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--muc-mam-every-minutes", type=int, default=60)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.output is None or args.expected_binary_sha256 is None:
        parser.error("--output and --expected-binary-sha256 are required")
    if not 1 <= args.hours <= 72:
        parser.error("--hours must be 1..72")
    if not 30 <= args.muc_mam_every_minutes <= 360:
        parser.error("--muc-mam-every-minutes must be 30..360")
    if not re.fullmatch(r"[a-f0-9]{64}", args.expected_binary_sha256):
        parser.error("invalid binary SHA-256")
    # A terminated run must not look like a completed 24-hour qualification.
    def interrupted(signum: int, _frame: object) -> None:
        raise InterruptedError(f"received signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    key = Path(os.environ.get("NORTHSTAR_LAB_SSH_KEY", "/tmp/northstar-lab-keys/id_ed25519"))
    if not key.is_file():
        parser.error("lab SSH key is missing")
    ssh = [
        "ssh", "-i", str(key), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
        "-o", f"UserKnownHostsFile={key.parent / 'known_hosts'}",
    ]
    guests = {name: f"lab@{guest_ip(name)}" for name in ("ns-a", "ns-b", "infra")}

    def run(name: str, command: str, timeout: int = 45) -> str:
        result = subprocess.run(
            ssh + [guests[name], command], capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode:
            raise RuntimeError(
                f"{name} probe exited {result.returncode}: "
                f"{(result.stdout + result.stderr)[-1200:]}"
            )
        return result.stdout.strip()

    def fetch_room_evidence(path: str) -> bytes:
        result = subprocess.run(
            ssh + [guests["ns-a"], f"head -c {MAX_ROOM_EVIDENCE_BYTES + 1} -- {path}"],
            capture_output=True, timeout=20,
        )
        if result.returncode:
            raise RuntimeError(
                f"could not copy room MAM evidence from ns-a: {result.stderr[-300:]!r}"
            )
        if len(result.stdout) > MAX_ROOM_EVIDENCE_BYTES:
            raise RuntimeError("room MAM evidence exceeded 1 MiB")
        return result.stdout

    def service_sample(name: str) -> tuple[int, int, str]:
        observed = run(name,
            "set -e; "
            "pid=$(systemctl show northstar-lab.service -p MainPID --value); "
            "test \"$pid\" -gt 0 || exit 1; "
            "rss=$(ps -o rss= -p \"$pid\" | tr -d '[:space:]'); "
            "test -n \"$rss\" || exit 1; "
            "running=$(sudo -n stat -Lc '%d:%i' \"/proc/$pid/exe\"); "
            "on_disk=$(stat -Lc '%d:%i' /home/lab/northstar/rust-xmpp-server); "
            "printf '%s %s %s %s\\n' \"$pid\" \"$rss\" \"$running\" \"$on_disk\"",
        )
        return parse_service_sample(observed)

    def check_service_hash(name: str, pid: int) -> None:
        observed = run(name,
            "sudo -n sha256sum /home/lab/northstar/rust-xmpp-server "
            f"/proc/{pid}/exe",
            timeout=90,
        ).splitlines()
        hashes = [line.split()[0] for line in observed]
        if len(hashes) != 2 or any(
            value != args.expected_binary_sha256 for value in hashes
        ):
            raise RuntimeError(f"candidate binary or running executable differs on {name}")

    candidate_identity: dict[str, tuple[int, str]] = {}
    for name in ("ns-a", "ns-b"):
        pid, _, inode = service_sample(name)
        check_service_hash(name, pid)
        candidate_identity[name] = (pid, inode)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    deadline = start + args.hours * 3600
    iteration = 0
    log_fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(log_fd, "w", encoding="utf-8", buffering=1) as log:
        log.write(json.dumps({
            "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "event": "candidate_start_verification",
            "expected_binary_sha256": args.expected_binary_sha256,
            "identity": candidate_identity,
        }, sort_keys=True) + "\n")
        log.flush()
        os.fsync(log.fileno())
        while time.monotonic() < deadline:
            now = dt.datetime.now(dt.timezone.utc).isoformat()
            record: dict[str, object] = {
                "time_utc": now,
                "iteration": iteration,
                "expected_binary_sha256": args.expected_binary_sha256,
            }
            try:
                record["cross_node"] = run(
                    "ns-a", "cd /home/lab/northstar && python3 local-vm-lab-cluster-delivery.py"
                )
                if iteration % 5 == 0:
                    for peer in ("prosody", "ejabberd"):
                        record[f"federation_{peer}"] = run(
                            "ns-a",
                            f"cd /home/lab/northstar && python3 local-vm-lab-federation.py {peer}",
                        )
                if due(iteration, args.muc_mam_every_minutes):
                    probe_start = time.monotonic_ns()
                    probe_output = run(
                        "ns-a",
                        "cd /home/lab/northstar && python3 local-vm-lab-muc-mam.py",
                        timeout=120,
                    )
                    report = parse_probe_json(
                        probe_output, "room-mam-adjacent-pages",
                    )
                    record["room_mam"] = report
                    report["host_evidence_jsonl"] = str(save_room_evidence(
                        report, args.output, iteration, fetch_room_evidence,
                    ))
                    record["room_mam_elapsed_ms"] = (
                        time.monotonic_ns() - probe_start
                    ) // 1_000_000
                # A fresh slot immediately after a smoke run can hit the
                # account's upload admission window. Space these writes out.
                if iteration > 0 and iteration % 90 == 0:
                    record["upload"] = run(
                        "ns-a", "cd /home/lab/northstar && python3 local-vm-lab-upload.py"
                    )
                for name in ("ns-a", "ns-b"):
                    pid, rss_kib, inode = service_sample(name)
                    if candidate_identity[name] != (pid, inode):
                        check_service_hash(name, pid)
                        record[f"candidate_change_{name}"] = {
                            "previous_pid_inode": candidate_identity[name],
                            "current_pid_inode": (pid, inode),
                            "sha256": args.expected_binary_sha256,
                        }
                        candidate_identity[name] = (pid, inode)
                    record[f"pid_{name}"] = pid
                    record[f"rss_kib_{name}"] = rss_kib
                    record[f"binary_inode_{name}"] = inode
                record["postgres_wal_bytes"] = int(run("infra",
                    "sudo -u postgres psql -d xmpp --no-psqlrc -Atqc "
                    "'SELECT wal_bytes FROM pg_stat_wal'"))
                record["status"] = "passed"
            except BaseException as error:
                record["status"] = "failed"
                record["error"] = str(error)
                record["error_type"] = type(error).__name__
                log.write(json.dumps(record, sort_keys=True) + "\n")
                log.flush()
                os.fsync(log.fileno())
                raise
            log.write(json.dumps(record, sort_keys=True) + "\n")
            if iteration % 10 == 0:
                log.flush()
                os.fsync(log.fileno())
            iteration += 1
            next_tick = start + iteration * 60
            try:
                time.sleep(max(0, min(next_tick, deadline) - time.monotonic()))
            except BaseException as error:
                log.write(json.dumps({
                    "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "event": "soak_interrupted",
                    "error_type": type(error).__name__,
                    "error": str(error),
                }, sort_keys=True) + "\n")
                log.flush()
                os.fsync(log.fileno())
                raise

        end_record: dict[str, object] = {
            "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "event": "candidate_end_verification",
            "expected_binary_sha256": args.expected_binary_sha256,
        }
        try:
            for name in ("ns-a", "ns-b"):
                pid, _, inode = service_sample(name)
                check_service_hash(name, pid)
                end_record[name] = {"pid": pid, "binary_inode": inode}
        except BaseException as error:
            end_record["event"] = "candidate_end_verification_failed"
            end_record["error_type"] = type(error).__name__
            end_record["error"] = str(error)
            log.write(json.dumps(end_record, sort_keys=True) + "\n")
            log.flush()
            os.fsync(log.fileno())
            raise
        log.write(json.dumps(end_record, sort_keys=True) + "\n")
        log.flush()
        os.fsync(log.fileno())


if __name__ == "__main__":
    main()
