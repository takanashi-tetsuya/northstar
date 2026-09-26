#!/usr/bin/env python3
"""Run a bounded active mixed workload after a completed isolated-VM soak.

This is a short, low-concurrency characterization of the frozen lab candidate,
not a saturation test or a production SLA. It never provisions or restarts a VM.
"""

from __future__ import annotations

import argparse
from concurrent.futures import Future, ThreadPoolExecutor
import datetime as dt
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import tarfile
import tempfile
import time
from typing import Any
from xml.etree import ElementTree as ET


ROOT = Path(__file__).resolve().parent
MAX_WORKERS = 3
MAX_DURATION_MINUTES = 30
MIN_HOST_AVAILABLE_KIB = 2 * 1024 * 1024
MIN_GUEST_AVAILABLE_KIB = 512 * 1024
MAX_NODE_RSS_KIB = 1536 * 1024
MAX_VM_MEMORY_KIB = 14 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 128 * 1024 * 1024
MAX_SEALED_REPORT_BYTES = 1024 * 1024
MAX_SEALED_LOG_BYTES = 32 * 1024 * 1024
GUEST_HELPERS = (
    "integration-wsl.py",
    "local-vm-lab-federation.py", "local-vm-lab-mam.py",
    "local-vm-lab-muc-mam.py", "local-vm-lab-upload.py",
)
LANES = {
    "presence": ("local-vm-lab-active-presence.py", 10, 0),
    "muc_mam": ("local-vm-lab-muc-mam.py", 90, 0),
    "personal_mam": ("local-vm-lab-mam.py", 90, 30),
    "s2s_prosody": ("local-vm-lab-federation.py prosody", 30, 0),
    "s2s_ejabberd": ("local-vm-lab-federation.py ejabberd", 30, 15),
}
METRICS = (
    "xmpp_active_sessions", "xmpp_database_up",
    "xmpp_database_pool_connections", "xmpp_database_pool_max_connections",
    "xmpp_cluster_muc_outbox_queued", "xmpp_cluster_muc_outbox_oldest_age_seconds",
    "xmpp_pubsub_event_outbox_pending_rows",
    "xmpp_sm_recovery_queue_jobs", "xmpp_sm_recovery_queue_oldest_age_seconds",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise ValueError("cannot summarize empty latency samples")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * fraction + 0.999999) - 1))
    return ordered[index]


def latency_summary(values: list[float]) -> dict[str, Any]:
    if not values:
        raise ValueError("cannot summarize empty latency samples")
    return {
        "samples": len(values), "min_ms": min(values), "max_ms": max(values),
        "p50_ms": percentile(values, 0.50) if len(values) >= 2 else None,
        "p95_ms": percentile(values, 0.95) if len(values) >= 20 else None,
        "p99_ms": percentile(values, 0.99) if len(values) >= 100 else None,
        "insufficient_for": (["p50"] if len(values) < 2 else [])
        + (["p95"] if len(values) < 20 else [])
        + (["p99"] if len(values) < 100 else []),
    }


def presence_ack_ms(report: Any, outer_duration_ms: float) -> float:
    """Accept only the helper's measured self-presence acknowledgement."""
    if (not isinstance(report, dict) or report.get("status") != "passed"
            or report.get("probe") != "self-presence"
            or not isinstance(report.get("resource"), str)
            or not re.fullmatch(r"active-[0-9a-f]{12}", report["resource"])):
        raise RuntimeError("presence probe did not report a valid self-presence result")
    value = report.get("ack_ms")
    if (type(value) not in (int, float) or not math.isfinite(value)
            or value < 0 or value > outer_duration_ms):
        raise RuntimeError("presence acknowledgement latency is invalid")
    return float(value)


def parse_soak(path: Path, expected_sha: str) -> dict[str, Any]:
    records = []
    with path.open(encoding="utf-8") as source:
        for line in source:
            if len(line) > 64 * 1024:
                raise RuntimeError("soak evidence has an oversized record")
            records.append(json.loads(line))
            if len(records) > 5000:
                raise RuntimeError("soak evidence has too many records")
    if len(records) < 1432 or any(not isinstance(row, dict) for row in records):
        raise RuntimeError("soak evidence is incomplete")
    start, end = records[0], records[-1]
    if (start.get("event") != "candidate_start_verification"
            or end.get("event") != "candidate_end_verification"):
        raise RuntimeError("soak lacks successful start/end candidate attestations")
    if any(row.get("expected_binary_sha256") != expected_sha for row in records):
        raise RuntimeError("soak and active load candidate digests differ")
    checks = records[1:-1]
    if (len(checks) < 1430 or any(row.get("status") != "passed" for row in checks)
            or [row.get("iteration") for row in checks] != list(range(len(checks)))):
        raise RuntimeError("soak has a failed or missing minute")
    started = dt.datetime.fromisoformat(start["time_utc"])
    finished = dt.datetime.fromisoformat(end["time_utc"])
    if (started.tzinfo is None or finished.tzinfo is None
            or (finished - started).total_seconds() < 24 * 3600 - 60):
        raise RuntimeError("soak ran for less than 24 hours")
    if finished > dt.datetime.now(dt.timezone.utc):
        raise RuntimeError("soak evidence ends in the future")
    # A soak observation is timestamped before its probes run. The following
    # observation (or the end attestation) is the first recorded time known to
    # be after an upload finished, so use that upper bound for the cooldown.
    last_upload = max(
        (dt.datetime.fromisoformat(records[index + 2]["time_utc"])
         for index, row in enumerate(checks) if "upload" in row),
        default=None,
    )
    return {
        "started_utc": started.isoformat(), "finished_utc": finished.isoformat(),
        "minute_checks": len(checks), "last_upload_utc": last_upload.isoformat() if last_upload else None,
        "sha256": sha256_file(path),
    }


def check_sealed_soak(path: Path, pinned_sha: str, expected_sha: str,
                      parsed: dict[str, Any]) -> dict[str, Any]:
    """Bind the verifier report, raw evidence and JSONL to a pinned archive."""
    if path.name != "soak-24h-release.jsonl":
        raise RuntimeError("soak JSONL must use the finalized release-soak path")
    if path.is_symlink():
        raise RuntimeError("soak JSONL must not be a symlink")
    directory = path.parent.resolve(strict=True)
    if path.resolve(strict=True).parent != directory:
        raise RuntimeError("soak JSONL escaped its evidence directory")
    if directory.stat().st_mode & 0o777 != 0o700 or directory.stat().st_uid != os.getuid():
        raise RuntimeError("soak evidence directory is not private to this operator")
    archive = directory.parent / f"{directory.name}.tar.gz"
    if (archive.is_symlink() or not archive.is_file()
            or archive.stat().st_size > MAX_ARCHIVE_BYTES):
        raise RuntimeError("sealed soak archive is missing or oversized")
    if sha256_file(archive) != pinned_sha:
        raise RuntimeError("sealed soak archive differs from the pinned SHA-256")
    root_name = directory.name + "/"
    sealed: dict[str, bytes] = {}
    requested = {
        "SHA256SUMS.txt", "soak-verification.json", "unit-final-status.txt",
        "soak-24h-release.jsonl",
    }
    archive_file_digests: dict[str, str] = {}
    count = 0
    total_size = 0
    seen_members: set[str] = set()
    with tarfile.open(archive, "r|gz") as bundle:
        for item in bundle:
            count += 1
            total_size += item.size
            if (count > MAX_ARCHIVE_MEMBERS or total_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES
                    or item.size > MAX_ARCHIVE_MEMBER_BYTES):
                raise RuntimeError("sealed soak archive exceeds bounded member limits")
            name = item.name
            if name in seen_members:
                raise RuntimeError("sealed soak archive has a duplicate member")
            seen_members.add(name)
            parts = Path(name).parts
            if name == directory.name and item.isdir():
                continue
            if (name.startswith("/") or ".." in parts or not name.startswith(root_name)
                    or item.issym() or item.islnk() or not (item.isfile() or item.isdir())):
                raise RuntimeError("sealed soak archive has an unsafe member")
            relative = name[len(root_name):]
            if item.isfile():
                extracted = bundle.extractfile(item)
                if extracted is None:
                    raise RuntimeError(f"sealed soak member {relative} cannot be read")
                digest = hashlib.sha256()
                pieces = []
                captured = 0
                for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
                    digest.update(chunk)
                    if relative in requested:
                        pieces.append(chunk)
                        captured += len(chunk)
                        maximum = (MAX_SEALED_LOG_BYTES if relative == "soak-24h-release.jsonl"
                                   else MAX_SEALED_REPORT_BYTES)
                        if captured > maximum:
                            raise RuntimeError(f"sealed soak member {relative} is oversized")
                archive_file_digests[relative] = digest.hexdigest()
                if relative in requested:
                    sealed[relative] = b"".join(pieces)
    if set(sealed) != requested:
        raise RuntimeError("sealed soak archive lacks the verifier or final evidence")
    if hashlib.sha256(sealed["soak-24h-release.jsonl"]).hexdigest() != parsed["sha256"]:
        raise RuntimeError("soak JSONL differs from the sealed archive")
    manifest_path = directory / "SHA256SUMS.txt"
    if (manifest_path.is_symlink() or manifest_path.stat().st_uid != os.getuid()
            or manifest_path.stat().st_mode & 0o777 != 0o600):
        raise RuntimeError("soak checksum manifest is no longer private")
    if manifest_path.read_bytes() != sealed["SHA256SUMS.txt"]:
        raise RuntimeError("local soak checksum manifest differs from the sealed archive")
    entries: set[str] = set()
    for line in sealed["SHA256SUMS.txt"].decode().splitlines():
        digest, separator, filename = line.partition("  ")
        if not separator or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError("sealed soak checksum manifest has an invalid row")
        if not filename.startswith("./"):
            raise RuntimeError("sealed soak checksum path is not relative")
        relative = filename[2:]
        if (not relative or relative in entries or ".." in Path(relative).parts
                or Path(relative).is_absolute() or relative == "SHA256SUMS.txt"):
            raise RuntimeError("sealed soak checksum path is unsafe or duplicated")
        entries.add(relative)
        target = directory / relative
        if not target.is_file() or target.is_symlink() or target.resolve().is_relative_to(directory) is False:
            raise RuntimeError("sealed soak checksum target is unsafe or missing")
        if target.stat().st_uid != os.getuid() or target.stat().st_mode & 0o077:
            raise RuntimeError("sealed soak file is no longer private")
        if sha256_file(target) != digest:
            raise RuntimeError(f"sealed soak checksum changed: {relative}")
    if not {"soak-24h-release.jsonl", "soak-verification.json", "unit-final-status.txt",
            "verify-soak.py"}.issubset(entries):
        raise RuntimeError("sealed soak manifest omits required verification files")
    if set(archive_file_digests) != entries | {"SHA256SUMS.txt"}:
        raise RuntimeError("sealed archive and checksum manifest contain different file sets")
    for line in sealed["SHA256SUMS.txt"].decode().splitlines():
        digest, _, filename = line.partition("  ")
        if archive_file_digests[filename[2:]] != digest:
            raise RuntimeError(f"archived soak file differs from its manifest: {filename}")
    report = json.loads(sealed["soak-verification.json"])
    if (report.get("result") != "complete" or report.get("candidate_sha256") != expected_sha
            or report.get("start_utc") != parsed["started_utc"]
            or report.get("end_utc") != parsed["finished_utc"]
            or report.get("observations") != parsed["minute_checks"]
            or report.get("room_mam_evidence_files", 0) < 24):
        raise RuntimeError("sealed verifier did not attest this complete 24-hour candidate")
    unit = sealed["unit-final-status.txt"].decode()
    if not all(value in unit.splitlines() for value in
               ("ActiveState=inactive", "Result=success", "ExecMainStatus=0")):
        raise RuntimeError("sealed soak systemd unit did not exit successfully")
    return {"archive_sha256": pinned_sha, "archive": str(archive),
            "verified_files": len(entries), "verifier": report}


def parse_node_sample(output: str) -> dict[str, Any]:
    value = json.loads(output)
    required = ("pid", "rss_kib", "fds", "mem_available_kib", "cpu_ticks",
                "clock_ticks_per_second", "exe_inode", "disk_inode")
    if (not isinstance(value, dict) or any(key not in value for key in required)
            or any(type(value[key]) is not int or value[key] <= 0 for key in required[:4])
            or any(type(value[key]) is not int or value[key] < 0 for key in required[4:6])
            or value["clock_ticks_per_second"] == 0
            or not re.fullmatch(r"[0-9]+:[0-9]+", value["exe_inode"])
            or value["exe_inode"] != value["disk_inode"]):
        raise RuntimeError("node resource sample or running binary identity is invalid")
    metrics = value.get("metrics")
    if not isinstance(metrics, dict) or not all(name in metrics for name in
            ("xmpp_active_sessions", "xmpp_database_up", "xmpp_database_pool_connections")):
        raise RuntimeError("required runtime metrics are missing")
    if any(type(item) not in (int, float) or not math.isfinite(item) or item < 0
           for item in metrics.values()):
        raise RuntimeError("runtime metrics are invalid")
    return value


NODE_SAMPLE = r'''import json, os, pathlib, urllib.request
pid = int(os.popen('systemctl show northstar-lab.service -p MainPID --value').read().strip())
if pid <= 0: raise RuntimeError('Northstar service is not active')
root = pathlib.Path('/proc') / str(pid)
status = (root / 'status').read_text()
rss = int(next(x.split()[1] for x in status.splitlines() if x.startswith('VmRSS:')))
stat = (root / 'stat').read_text().rpartition(') ')[2].split()
cpu_ticks = int(stat[11]) + int(stat[12])
available = int(next(x.split()[1] for x in pathlib.Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))
token = pathlib.Path('/home/lab/northstar/secrets/metrics_bearer_token').read_text().strip()
request = urllib.request.Request('http://127.0.0.1:9091/metrics',
                                 headers={'Authorization': 'Bearer ' + token})
raw = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
    request, timeout=5).read(2 * 1024 * 1024).decode()
needed = %s
metrics = {}
for line in raw.splitlines():
    parts = line.split()
    if len(parts) == 2 and parts[0] in needed:
        metrics[parts[0]] = float(parts[1])
print(json.dumps({'pid':pid,'rss_kib':rss,'fds':len(list((root / 'fd').iterdir())),
                  'mem_available_kib':available, 'cpu_ticks':cpu_ticks,
                  'clock_ticks_per_second':os.sysconf('SC_CLK_TCK'),
                  'exe_inode':f'{os.stat(root / "exe").st_dev}:{os.stat(root / "exe").st_ino}',
                  'disk_inode':f'{os.stat("/home/lab/northstar/rust-xmpp-server").st_dev}:{os.stat("/home/lab/northstar/rust-xmpp-server").st_ino}',
                  'metrics':metrics},sort_keys=True))
''' % (repr(METRICS),)


def private_write(path: Path, content: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(content)
        target.flush()
        os.fsync(target.fileno())


def write_digest_sidecar(output: Path, summary: Path) -> None:
    private_write(output.with_suffix(".sha256"),
                  f"{hashlib.sha256(output.read_bytes()).hexdigest()}  {output.name}\n"
                  f"{hashlib.sha256(summary.read_bytes()).hexdigest()}  {summary.name}\n".encode())


def record_preflight_failure(output: Path, error: BaseException,
                             phase: str = "preflight") -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    summary_path = output.with_suffix(".summary.json")
    failed = {"status": "failed", "phase": phase, "time_utc": utc_now(),
              "error_type": type(error).__name__, "error": str(error)[:1000]}
    private_write(output, (json.dumps({"event": f"{phase}_failed", **failed}) + "\n").encode())
    private_write(summary_path, (json.dumps(failed, sort_keys=True, indent=2) + "\n").encode())
    write_digest_sidecar(output, summary_path)


class Lab:
    def __init__(self, key: Path):
        self.ssh = [
            "ssh", "-i", str(key), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={key.parent / 'known_hosts'}",
        ]
        self.hosts = {}
        leases = subprocess.run(
            ["virsh", "net-dhcp-leases", "northstar-lab"], check=True,
            capture_output=True, text=True,
        ).stdout
        for name in ("ns-a", "ns-b", "infra"):
            match = re.search(
                rf"\b(192\.168\.197\.\d+)/\d+\s+northstar-lab-{re.escape(name)}\b",
                leases,
            )
            if not match:
                raise RuntimeError(f"missing isolated lab DHCP lease for {name}")
            self.hosts[name] = f"lab@{match.group(1)}"

    def run(self, name: str, command: str, *, timeout: int = 30,
            input_bytes: bytes | None = None) -> str:
        result = subprocess.run(
            self.ssh + [self.hosts[name], command], input=input_bytes,
            capture_output=True, timeout=timeout,
        )
        if result.returncode:
            detail = (result.stdout + result.stderr)[-1000:].decode(errors="replace")
            raise RuntimeError(f"{name} command failed ({result.returncode}): {detail}")
        if len(result.stdout) > 2 * 1024 * 1024:
            raise RuntimeError(f"{name} command output exceeded 2 MiB")
        return result.stdout.decode().strip()

    def sample(self) -> dict[str, Any]:
        record = {"time_utc": utc_now(), "monotonic_ns": time.monotonic_ns()}
        for name in ("ns-a", "ns-b"):
            node = parse_node_sample(self.run(
                name, "python3 -", timeout=20, input_bytes=NODE_SAMPLE.encode(),
            ))
            if node["rss_kib"] > MAX_NODE_RSS_KIB:
                raise RuntimeError(f"{name} exceeded the 1.5 GiB RSS guard")
            if node["mem_available_kib"] < MIN_GUEST_AVAILABLE_KIB:
                raise RuntimeError(f"{name} has under 512 MiB available memory")
            if node["metrics"]["xmpp_database_up"] != 1:
                raise RuntimeError(f"{name} reports database unavailable")
            if (node["metrics"].get("xmpp_database_pool_max_connections", 0) > 0
                    and node["metrics"]["xmpp_database_pool_connections"] >
                    node["metrics"]["xmpp_database_pool_max_connections"]):
                raise RuntimeError(f"{name} exceeded its database pool limit")
            record[name] = node
        infra = self.run("infra",
            "sudo -u postgres psql -d xmpp --no-psqlrc -AtF, -c "
            "'SELECT (SELECT wal_bytes FROM pg_stat_wal), "
            "(SELECT COALESCE(SUM(reads),0) FROM pg_stat_io), "
            "(SELECT COALESCE(SUM(writes),0) FROM pg_stat_io)'",
        )
        values = infra.split(",")
        if len(values) != 3 or not all(value.isdigit() for value in values):
            raise RuntimeError("PostgreSQL WAL/IO counters are invalid")
        record["postgres"] = dict(zip(
            ("wal_bytes", "reads", "writes"), (int(value) for value in values),
        ))
        infra_available = self.run("infra", "awk '/^MemAvailable:/ {print $2}' /proc/meminfo")
        if not infra_available.isdigit() or int(infra_available) < MIN_GUEST_AVAILABLE_KIB:
            raise RuntimeError("infra has under 512 MiB available memory")
        record["infra_mem_available_kib"] = int(infra_available)
        host_available = int(next(
            line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
            if line.startswith("MemAvailable:")
        ))
        if host_available < MIN_HOST_AVAILABLE_KIB:
            raise RuntimeError("host has under 2 GiB available memory")
        record["host_mem_available_kib"] = host_available
        return record

    def check_helpers(self) -> dict[str, str]:
        digests = {}
        for name in GUEST_HELPERS:
            path = ROOT / name
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            observed = self.run("ns-a", f"sha256sum /home/lab/northstar/{name}").split()[0]
            if expected != observed:
                raise RuntimeError(f"ns-a guest helper differs from frozen host source: {name}")
            digests[name] = expected
        return digests

    def ensure_presence_helper(self) -> str:
        """Stage only the new helper, after all read-only candidate checks."""
        name = "local-vm-lab-active-presence.py"
        source = (ROOT / name).read_bytes()
        expected = hashlib.sha256(source).hexdigest()
        destination = f"/home/lab/northstar/{name}"
        observed = self.run("ns-a", f"if test -f {destination}; then sha256sum {destination}; fi")
        if observed:
            if observed.split()[0] != expected:
                raise RuntimeError("existing active presence helper differs from host source")
            return expected
        self.run("ns-a",
            "set -eu; umask 077; "
            "tmp=$(mktemp /home/lab/northstar/.active-presence.XXXXXXXX); "
            "trap 'rm -f \"$tmp\"' EXIT; "
            "cat > \"$tmp\"; chmod 600 \"$tmp\"; "
            f"mv -T \"$tmp\" {destination}",
            input_bytes=source,
        )
        actual = self.run("ns-a", f"sha256sum {destination}").split()[0]
        if actual != expected:
            raise RuntimeError("staged active presence helper has a digest mismatch")
        return expected

    def fetch_room_evidence(self, path: str) -> bytes:
        if not re.fullmatch(r"/tmp/northstar-lab-muc-mam-[0-9a-f]{32}\.jsonl", path):
            raise RuntimeError("room evidence path is outside the lab whitelist")
        result = subprocess.run(
            self.ssh + [self.hosts["ns-a"], f"head -c 1048577 -- {path}"],
            capture_output=True, timeout=20,
        )
        if result.returncode or len(result.stdout) > 1024 * 1024:
            raise RuntimeError("room evidence fetch failed or exceeded 1 MiB")
        return result.stdout

    def check_binary(self, expected: str, identities: dict[str, tuple[int, str]]) -> None:
        for name in ("ns-a", "ns-b"):
            pid, inode = identities[name]
            observed = self.run(name,
                "sudo -n sha256sum /home/lab/northstar/rust-xmpp-server "
                f"/proc/{pid}/exe", timeout=100,
            ).splitlines()
            hashes = [line.split()[0] for line in observed]
            if len(hashes) != 2 or any(value != expected for value in hashes):
                raise RuntimeError(f"{name} running binary differs from the completed soak")
            sample = parse_node_sample(self.run(
                name, "python3 -", timeout=20, input_bytes=NODE_SAMPLE.encode(),
            ))
            if sample["pid"] != pid or sample["exe_inode"] != inode:
                raise RuntimeError(f"{name} restarted during the active window")

    def probe(self, lane: str) -> dict[str, Any]:
        command = ("local-vm-lab-upload.py" if lane == "upload" else LANES[lane][0])
        started = time.monotonic_ns()
        output = self.run(
            "ns-a", "cd /home/lab/northstar && timeout -s TERM -k 5 130s "
            f"python3 {command}", timeout=140,
        )
        result: dict[str, Any] = {
            "lane": lane, "duration_ms": (time.monotonic_ns() - started) / 1_000_000,
            "output": output[-2000:],
        }
        if lane in ("presence", "muc_mam", "personal_mam"):
            parsed = json.loads(output.splitlines()[-1])
            if parsed.get("status") != "passed":
                raise RuntimeError(f"{lane} probe did not report success")
            if lane == "presence":
                presence_ack_ms(parsed, result["duration_ms"])
            result["probe"] = parsed
        return result


def check_isolation_and_budget() -> None:
    subprocess.run(["bash", str(ROOT / "local-vm-lab-preflight.sh")], check=True,
                   stdout=subprocess.DEVNULL, timeout=120)
    # The lab soak normally runs as a user transient unit. A system-scope
    # check alone would miss it, especially when this process has a PID view
    # restricted by a sandbox. Failure to query either scope fails closed.
    for scope in ("system", "user"):
        command = ["systemctl"] + (["--user"] if scope == "user" else []) + [
            "list-units", "--all", "--plain", "--no-legend", "northstar-lab-soak*",
        ]
        output = subprocess.run(command, check=True, capture_output=True, text=True).stdout
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 4 or fields[2] != "inactive":
                raise RuntimeError(f"{scope}-scope VM soak unit is not inactive: {line[:200]}")
    processes = subprocess.run(
        ["ps", "-eo", "pid=,args="], check=True, capture_output=True, text=True,
    ).stdout
    if any("local-vm-lab-soak.py" in line and int(line.split(None, 1)[0]) != os.getpid()
           for line in processes.splitlines()):
        raise RuntimeError("a VM soak process is still running")
    available = int(next(
        line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
        if line.startswith("MemAvailable:")
    ))
    if available < MIN_HOST_AVAILABLE_KIB:
        raise RuntimeError("host has under 2 GiB available memory")
    memory_kib = 0
    for name in ("ns-a", "ns-b", "prosody", "ejabberd", "infra", "dns-ca"):
        xml = subprocess.run(
            ["virsh", "dumpxml", f"northstar-lab-{name}"], check=True,
            capture_output=True, text=True,
        ).stdout
        element = ET.fromstring(xml).find("memory")
        if element is None or element.text is None or element.get("unit") != "KiB":
            raise RuntimeError(f"{name} memory allocation is not in KiB")
        memory_kib += int(element.text)
    if memory_kib > MAX_VM_MEMORY_KIB:
        raise RuntimeError("six-guest allocation exceeds the 14 GiB lab budget")


def write_event(log: Any, record: dict[str, Any]) -> None:
    log.write(json.dumps(record, sort_keys=True) + "\n")
    log.flush()
    os.fsync(log.fileno())


def self_test() -> None:
    assert latency_summary([float(i) for i in range(1, 101)])["p99_ms"] == 99
    assert latency_summary([1.0])["p95_ms"] is None
    assert latency_summary([1.0])["p99_ms"] is None
    assert latency_summary([1.0])["insufficient_for"] == ["p50", "p95", "p99"]
    assert latency_summary([float(i) for i in range(1, 21)])["p95_ms"] == 19
    report = {"status": "passed", "probe": "self-presence",
              "resource": "active-0123456789ab", "ack_ms": 12.5}
    assert presence_ack_ms(report, 100.0) == 12.5
    for invalid in ({**report, "probe": "other"}, {**report, "ack_ms": float("nan")},
                    {**report, "ack_ms": 101.0}, {**report, "resource": "other"}):
        try:
            presence_ack_ms(invalid, 100.0)
        except RuntimeError:
            pass
        else:
            raise AssertionError("invalid presence acknowledgement was accepted")
    sample = {
        "pid": 42, "rss_kib": 100, "fds": 10, "mem_available_kib": 1000,
        "cpu_ticks": 10, "clock_ticks_per_second": 100,
        "exe_inode": "1:2", "disk_inode": "1:2",
        "metrics": {"xmpp_active_sessions": 0, "xmpp_database_up": 1,
                    "xmpp_database_pool_connections": 2},
    }
    assert parse_node_sample(json.dumps(sample))["pid"] == 42
    try:
        parse_node_sample(json.dumps({**sample, "disk_inode": "1:3"}))
    except RuntimeError:
        pass
    else:
        raise AssertionError("candidate inode mismatch was accepted")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "soak.jsonl"
        started = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
        sha = "a" * 64
        rows = [{"event": "candidate_start_verification", "time_utc": started.isoformat(),
                 "expected_binary_sha256": sha}]
        rows.extend({"iteration": minute, "status": "passed",
                     "time_utc": (started + dt.timedelta(minutes=minute)).isoformat(),
                     "expected_binary_sha256": sha} for minute in range(1440))
        rows.append({"event": "candidate_end_verification",
                     "time_utc": (started + dt.timedelta(hours=24)).isoformat(),
                     "expected_binary_sha256": sha})
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        assert parse_soak(path, sha)["minute_checks"] == 1440
        rows[1351]["upload"] = "verified upload"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        assert parse_soak(path, sha)["last_upload_utc"] == (
            started + dt.timedelta(minutes=1351)
        ).isoformat()
        rows[600]["status"] = "failed"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        try:
            parse_soak(path, sha)
        except RuntimeError:
            pass
        else:
            raise AssertionError("failed soak was accepted")
        rows[600]["status"] = "passed"
        sealed_dir = Path(directory) / "sealed-soak"
        sealed_dir.mkdir()
        sealed_dir.chmod(0o700)
        sealed_log = sealed_dir / "soak-24h-release.jsonl"
        sealed_log.write_text("".join(json.dumps(row) + "\n" for row in rows))
        (sealed_dir / "verify-soak.py").write_text("# fixture verifier\n")
        (sealed_dir / "unit-final-status.txt").write_text(
            "ActiveState=inactive\nResult=success\nExecMainStatus=0\n"
        )
        report = {"result": "complete", "candidate_sha256": sha,
                  "start_utc": started.isoformat(),
                  "end_utc": (started + dt.timedelta(hours=24)).isoformat(),
                  "observations": 1440, "room_mam_evidence_files": 24}
        (sealed_dir / "soak-verification.json").write_text(json.dumps(report))
        room_dir = sealed_dir / "soak-24h-release-room-mam-evidence"
        room_dir.mkdir()
        for index in range(24):
            (room_dir / f"{index:06d}-room.jsonl").write_text("{}\n")
        files = sorted(item for item in sealed_dir.rglob("*") if item.is_file())
        (sealed_dir / "SHA256SUMS.txt").write_text("".join(
            f"{sha256_file(item)}  ./{item.relative_to(sealed_dir)}\n" for item in files
        ))
        for item in sealed_dir.rglob("*"):
            item.chmod(0o700 if item.is_dir() else 0o600)
        archive = Path(directory) / "sealed-soak.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(sealed_dir, arcname=sealed_dir.name)
        parsed = parse_soak(sealed_log, sha)
        assert check_sealed_soak(sealed_log, sha256_file(archive), sha, parsed)["verified_files"] == 28
        (room_dir / "000000-room.jsonl").write_text("tampered\n")
        try:
            check_sealed_soak(sealed_log, sha256_file(archive), sha, parsed)
        except RuntimeError:
            pass
        else:
            raise AssertionError("tampered raw evidence was accepted")
        output = Path(directory) / "preflight.jsonl"
        record_preflight_failure(output, RuntimeError("fixture unavailable"))
        assert json.loads(output.read_text())["event"] == "preflight_failed"
        assert json.loads(output.with_suffix(".summary.json").read_text())["phase"] == "preflight"
        assert output.with_suffix(".sha256").is_file()
    print("local-vm-lab-active-load self-test passed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--soak-evidence", type=Path)
    parser.add_argument("--sealed-archive-sha256")
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--duration-minutes", type=int, default=15)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if (args.soak_evidence is None or args.output is None
            or args.expected_binary_sha256 is None or args.sealed_archive_sha256 is None):
        parser.error("--soak-evidence, --sealed-archive-sha256, --output and --expected-binary-sha256 are required")
    if not 5 <= args.duration_minutes <= MAX_DURATION_MINUTES:
        parser.error("--duration-minutes must be 5..30")
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_binary_sha256):
        parser.error("invalid binary SHA-256")
    if not re.fullmatch(r"[0-9a-f]{64}", args.sealed_archive_sha256):
        parser.error("invalid sealed archive SHA-256")
    if args.output.resolve().is_relative_to(args.soak_evidence.parent.resolve()):
        parser.error("write active-load evidence outside the sealed soak directory")
    if (args.output.exists() or args.output.with_suffix(".summary.json").exists()
            or args.output.with_suffix(".sha256").exists()):
        parser.error("output already exists")
    try:
        soak = parse_soak(args.soak_evidence, args.expected_binary_sha256)
        sealed = check_sealed_soak(
            args.soak_evidence, args.sealed_archive_sha256,
            args.expected_binary_sha256, soak,
        )
        last_upload = soak["last_upload_utc"]
        if last_upload is not None:
            elapsed = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(last_upload)
            if elapsed.total_seconds() < 90 * 60:
                raise RuntimeError("wait until 90 minutes after the soak's last upload")
        check_isolation_and_budget()
        key = Path(os.environ.get("NORTHSTAR_LAB_SSH_KEY", "/tmp/northstar-lab-keys/id_ed25519"))
        if not key.is_file():
            raise RuntimeError("lab SSH key is missing")
        lab = Lab(key)
        helpers = lab.check_helpers()
        baseline = lab.sample()
        identities = {name: (baseline[name]["pid"], baseline[name]["exe_inode"])
                      for name in ("ns-a", "ns-b")}
        lab.check_binary(args.expected_binary_sha256, identities)
    except BaseException as error:
        record_preflight_failure(args.output, error)
        raise

    # No guest writes occur above this line. Install the new, checksum-pinned
    # probe only after the completed soak and frozen candidate are attested.
    try:
        helpers["local-vm-lab-active-presence.py"] = lab.ensure_presence_helper()
    except BaseException as error:
        record_preflight_failure(args.output, error, phase="staging")
        raise

    args.output.parent.mkdir(parents=True, exist_ok=True)
    summary_path = args.output.with_suffix(".summary.json")
    controller_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    latencies: dict[str, list[float]] = {name: [] for name in (*LANES, "upload")}
    presence_acks: list[float] = []
    failures: list[str] = []
    samples = [baseline]
    started = time.monotonic()
    deadline = started + args.duration_minutes * 60
    next_due = {name: started + lane[2] for name, lane in LANES.items()}
    next_due["upload"] = started + args.duration_minutes * 30
    intervals = {name: lane[1] for name, lane in LANES.items()}
    intervals["upload"] = float("inf")
    next_sample = started + 5
    submitted = {name: 0 for name in latencies}
    with os.fdopen(fd, "w", encoding="utf-8", buffering=1) as log:
        write_event(log, {
            "event": "start", "time_utc": utc_now(), "candidate_sha256": args.expected_binary_sha256,
            "soak": soak, "sealed_soak": sealed, "helpers": helpers,
            "controller_sha256": controller_sha256,
            "duration_minutes": args.duration_minutes,
            "max_workers": MAX_WORKERS, "baseline": baseline,
            "coverage_excluded": ["OMEMO real-client exchange", "XEP-0357 Push peer"],
        })
        in_flight: dict[str, Future[dict[str, Any]]] = {}
        def interrupted(signum: int, _frame: object) -> None:
            raise InterruptedError(f"received signal {signum}")
        old_term = signal.signal(signal.SIGTERM, interrupted)
        try:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                while time.monotonic() < deadline or in_flight:
                    now = time.monotonic()
                    for name, future in list(in_flight.items()):
                        if not future.done():
                            continue
                        del in_flight[name]
                        try:
                            result = future.result()
                        except Exception as error:
                            failures.append(f"{name}: {error}")
                            write_event(log, {"event": "probe_failed", "time_utc": utc_now(),
                                              "lane": name, "error": str(error)[:1000]})
                        else:
                            if name == "muc_mam":
                                spec = importlib.util.spec_from_file_location(
                                    "northstar_lab_soak", ROOT / "local-vm-lab-soak.py"
                                )
                                if spec is None or spec.loader is None:
                                    raise RuntimeError("room evidence verifier is unavailable")
                                soak_util = importlib.util.module_from_spec(spec)
                                spec.loader.exec_module(soak_util)
                                result["probe"]["host_evidence_jsonl"] = str(
                                    soak_util.save_room_evidence(
                                        result["probe"], args.output, submitted[name],
                                        lab.fetch_room_evidence,
                                    )
                                )
                            latencies[name].append(result["duration_ms"])
                            if name == "presence":
                                presence_acks.append(presence_ack_ms(
                                    result["probe"], result["duration_ms"]
                                ))
                            write_event(log, {"event": "probe_passed", "time_utc": utc_now(), **result})
                        if name != "upload":
                            next_due[name] = max(next_due[name] + intervals[name],
                                                 time.monotonic() + intervals[name])
                        else:
                            next_due[name] = float("inf")
                    if failures:
                        break
                    if now >= next_sample:
                        sample = lab.sample()
                        for name in ("ns-a", "ns-b"):
                            if (sample[name]["pid"], sample[name]["exe_inode"]) != identities[name]:
                                raise RuntimeError(f"{name} restarted during the active window")
                        samples.append(sample)
                        write_event(log, {"event": "resource_sample", **sample})
                        next_sample = time.monotonic() + 5
                    if now < deadline:
                        for name in sorted(next_due, key=lambda item: item != "upload"):
                            if (name not in in_flight and len(in_flight) < MAX_WORKERS
                                    and now >= next_due[name]):
                                in_flight[name] = executor.submit(lab.probe, name)
                                submitted[name] += 1
                    time.sleep(0.5)
        except BaseException as error:
            failures.append(str(error))
            write_event(log, {"event": "run_failed", "time_utc": utc_now(),
                              "error": str(error)[:1000]})
        finally:
            signal.signal(signal.SIGTERM, old_term)
        try:
            lab.check_binary(args.expected_binary_sha256, identities)
        except Exception as error:
            failures.append(str(error))
        if any(submitted[name] == 0 for name in latencies):
            failures.append("one or more required workload lanes did not execute")
        for name in latencies:
            if submitted[name] != len(latencies[name]):
                failures.append(f"{name} did not complete all submitted probes")
        elapsed_seconds = max(0.001, (samples[-1]["monotonic_ns"] - baseline["monotonic_ns"]) / 1e9)
        postgres_delta = {key: samples[-1]["postgres"][key] - baseline["postgres"][key]
                          for key in ("wal_bytes", "reads", "writes")}
        if any(value < 0 for value in postgres_delta.values()):
            failures.append("PostgreSQL WAL/IO statistics reset during the active window")
        peak_cpu_percent = {}
        for name in ("ns-a", "ns-b"):
            cpu_rates = []
            for previous, current in zip(samples, samples[1:]):
                seconds = (current["monotonic_ns"] - previous["monotonic_ns"]) / 1e9
                ticks = current[name]["cpu_ticks"] - previous[name]["cpu_ticks"]
                if seconds > 0 and ticks >= 0:
                    cpu_rates.append(ticks / current[name]["clock_ticks_per_second"] / seconds * 100)
            peak_cpu_percent[name] = max(cpu_rates, default=None)
        metric_peaks = {
            name: {metric: max(
                sample[name]["metrics"][metric] for sample in samples
                if metric in sample[name]["metrics"]
            ) for metric in METRICS if any(metric in sample[name]["metrics"] for sample in samples)}
            for name in ("ns-a", "ns-b")
        }
        summary = {
            "status": "passed" if not failures else "failed",
            "time_utc": utc_now(), "candidate_sha256": args.expected_binary_sha256,
            "controller_sha256": controller_sha256,
            "soak_evidence_sha256": soak["sha256"], "duration_minutes": args.duration_minutes,
            "sealed_soak_archive_sha256": sealed["archive_sha256"],
            "submitted": submitted, "latency_ms": {name: latency_summary(values) for name, values
                                               in latencies.items() if values},
            "presence_ack_latency_ms": latency_summary(presence_acks) if presence_acks else None,
            "resource_samples": len(samples), "sampled_elapsed_seconds": elapsed_seconds,
            "peak_rss_kib": {name: max(item[name]["rss_kib"] for item in samples)
                             for name in ("ns-a", "ns-b")},
            "peak_fds": {name: max(item[name]["fds"] for item in samples)
                         for name in ("ns-a", "ns-b")},
            "minimum_available_kib": {name: min(item[name]["mem_available_kib"] for item in samples)
                                      for name in ("ns-a", "ns-b")},
            "minimum_infra_available_kib": min(item["infra_mem_available_kib"] for item in samples),
            "minimum_host_available_kib": min(item["host_mem_available_kib"] for item in samples),
            "peak_cpu_percent_one_core_equals_100": peak_cpu_percent,
            "sampled_metric_peaks": metric_peaks,
            "wal_bytes_delta": postgres_delta["wal_bytes"],
            "wal_bytes_per_second": postgres_delta["wal_bytes"] / elapsed_seconds,
            "postgres_reads_delta": postgres_delta["reads"],
            "postgres_writes_delta": postgres_delta["writes"],
            "postgres_reads_per_second": postgres_delta["reads"] / elapsed_seconds,
            "postgres_writes_per_second": postgres_delta["writes"] / elapsed_seconds,
            "coverage_excluded": ["OMEMO real-client exchange", "XEP-0357 Push peer"],
            "failures": failures,
        }
        write_event(log, {"event": "summary", **summary})
    private_write(summary_path, (json.dumps(summary, sort_keys=True, indent=2) + "\n").encode())
    write_digest_sidecar(args.output, summary_path)
    print(json.dumps(summary, sort_keys=True))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
