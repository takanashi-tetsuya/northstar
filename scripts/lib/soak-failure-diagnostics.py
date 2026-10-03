#!/usr/bin/env python3
"""Bounded, failure-only diagnostics for the owned loopback mixed-soak fixture.

Each JSONL stage is flushed independently. The caller runs this observer in its
own process group under a total deadline, so blocked diagnostics never hold up
fixture cleanup. No process command lines, environments, SQL text, or user
payloads are read. Missing Linux counters are evidence gaps, not zero values.
"""
from __future__ import annotations

import argparse
import datetime as dt
import http.client
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

MAX_FILE_BYTES = 16 * 1024
MAX_THREADS = 128
MAX_HTTP_BYTES = 256 * 1024
CAPTURE_SECONDS = 8.0


def stamp():
    return {"at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "monotonic_seconds": time.monotonic()}


def bounded_read(path, limit=MAX_FILE_BYTES):
    with Path(path).open("rb") as source:
        value = source.read(limit + 1)
    if len(value) > limit:
        raise ValueError("diagnostic_file_exceeded_byte_limit")
    return value.decode("utf-8", errors="replace")


def attempt(operation):
    try:
        return {"status": "ok", "value": operation()}
    except Exception as error:
        # Error types describe missing/denied counters without reflecting a
        # potentially sensitive filename, URL, command, or backend error text.
        return {"status": "unavailable", "error_type": type(error).__name__}


def process_snapshot(pid, proc=Path("/proc"), cgroup_root=Path("/sys/fs/cgroup")):
    base = proc / str(pid)
    identity = bounded_read(base / "stat")
    fields = identity.rsplit(")", 1)[1].split()
    result = {"pid": pid, "start_ticks": fields[19], "state": fields[0],
              "cpu_user_ticks": int(fields[11]), "cpu_system_ticks": int(fields[12]),
              "major_faults": int(fields[9]), "minor_faults": int(fields[7])}
    allowed_status = {"State", "VmPeak", "VmSize", "VmRSS", "VmSwap", "Threads",
                      "SigPnd", "ShdPnd", "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"}
    result["status"] = attempt(lambda: {key: value.strip()
        for key, value in (line.split(":", 1) for line in bounded_read(base / "status").splitlines() if ":" in line)
        if key in allowed_status})
    result["schedstat"] = attempt(lambda: bounded_read(base / "schedstat"))
    result["io"] = attempt(lambda: bounded_read(base / "io"))
    tids = sorted((int(p.name) for p in (base / "task").iterdir() if p.name.isdecimal()))
    result["thread_count"] = len(tids)
    result["threads_truncated"] = len(tids) > MAX_THREADS
    result["threads"] = [{"tid": tid, **{name: attempt(lambda path=base / "task" / str(tid) / name: bounded_read(path))
        for name in ("stat", "schedstat", "wchan")}} for tid in tids[:MAX_THREADS]]
    result["host_pressure"] = {name: attempt(lambda name=name: bounded_read(proc / "pressure" / name))
                               for name in ("cpu", "memory", "io")}
    result["cgroup"] = attempt(lambda: cgroup_snapshot(base, cgroup_root))
    return result


def cgroup_snapshot(process_path, cgroup_root):
    record = next(line[3:] for line in bounded_read(process_path / "cgroup").splitlines()
                  if line.startswith("0::"))
    relative = Path(record.lstrip("/"))
    if ".." in relative.parts or not record.startswith("/"):
        raise ValueError("invalid_cgroup_path")
    base = cgroup_root / relative
    return {name: attempt(lambda name=name: bounded_read(base / name)) for name in (
        "cpu.stat", "cpu.max", "cpu.weight", "cpu.pressure", "memory.current",
        "memory.max", "memory.events", "memory.pressure", "io.pressure")}


def http_snapshot(address, path, seconds=1.5):
    host, port = address.rsplit(":", 1)
    if host != "127.0.0.1" or not 1 <= int(port) <= 65535 or path not in ("/metrics", "/readyz"):
        raise ValueError("diagnostics_require_fixture_loopback_endpoint")
    deadline = time.monotonic() + seconds

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("http_diagnostic_deadline")
        return value

    # Bound the complete exchange, including dribbled status/header bytes.
    # HTTPConnection's individual socket timeout alone is not a total deadline.
    maximum_wire_bytes = MAX_HTTP_BYTES + 16 * 1024
    with socket.create_connection((host, int(port)), timeout=remaining()) as stream:
        stream.settimeout(remaining())
        stream.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                       "Connection: close\r\n\r\n").encode("ascii"))
        wire = bytearray()
        while len(wire) <= maximum_wire_bytes:
            stream.settimeout(remaining())
            part = stream.recv(min(8192, maximum_wire_bytes + 1 - len(wire)))
            if not part:
                break
            wire.extend(part)
        if len(wire) > maximum_wire_bytes:
            raise ValueError("http_diagnostic_exceeded_byte_limit")
    headers, separator, _ = wire.partition(b"\r\n\r\n")
    if not separator or len(headers) > 16 * 1024:
        raise ValueError("http_diagnostic_invalid_or_oversized_headers")

    class BufferedSocket:
        def makefile(self, *_args):
            return io.BytesIO(wire)

    response = http.client.HTTPResponse(BufferedSocket())
    try:
        response.begin()
        body = response.read(MAX_HTTP_BYTES + 1)
        if len(body) > MAX_HTTP_BYTES:
            raise ValueError("http_diagnostic_exceeded_byte_limit")
        return {"status_code": response.status, "body": body.decode("utf-8", errors="replace")}
    finally:
        response.close()


# Restrict the observer to its synthetic fixture database. SQL contents, role
# names, client addresses, and rows/payloads are intentionally excluded.
ACTIVITY_SQL = """
SELECT json_build_object('activity', COALESCE((SELECT json_agg(s) FROM (
 SELECT pid,state,wait_event_type,wait_event,pg_blocking_pids(pid) AS blocking_pids,
 EXTRACT(EPOCH FROM clock_timestamp()-query_start) AS query_age_seconds,
 EXTRACT(EPOCH FROM clock_timestamp()-xact_start) AS transaction_age_seconds
 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()
 ORDER BY pid LIMIT 128) s),'[]'::json), 'locks', COALESCE((SELECT json_agg(l) FROM (
 SELECT locktype,mode,granted,pid,relation FROM pg_locks
 WHERE pid IN (SELECT pid FROM pg_stat_activity WHERE datname=current_database())
 ORDER BY granted,pid LIMIT 256) l),'[]'::json));
"""


# Table counts may wait behind DDL/table locks. Keep them separate so a count
# timeout cannot erase catalog evidence of that very lock contention.
COUNTS_SQL = """
SELECT json_build_object('muc_messages',(SELECT count(*) FROM short_soak.muc_messages),
 'direct_messages',(SELECT count(*) FROM short_soak.message_archive));
"""


def database_snapshot(port, counts=False):
    if not 1 <= port <= 65535:
        raise ValueError("invalid_fixture_database_port")
    env = {**os.environ, "PGHOST": "127.0.0.1", "PGPORT": str(port),
           "PGUSER": "short_soak", "PGDATABASE": "short_soak", "PGCONNECT_TIMEOUT": "2",
           "PGOPTIONS": "-c default_transaction_read_only=on -c statement_timeout=1500 -c lock_timeout=1000"}
    completed = subprocess.run(["psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-c", COUNTS_SQL if counts else ACTIVITY_SQL],
                               env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=2.5, check=True)
    if len(completed.stdout) > MAX_HTTP_BYTES:
        raise ValueError("database_diagnostic_exceeded_byte_limit")
    return json.loads(completed.stdout)


def write_stage(name, operation, stream=sys.stdout):
    event = {**stamp(), "stage": name, **attempt(operation)}
    stream.write(json.dumps(event, allow_nan=False) + "\n")
    stream.flush()
    return event


def capture_failure(pid, metrics_address, http_address, db_port, destination, env,
                    seconds=CAPTURE_SECONDS, worker=None):
    """Best effort: always return serializable status, retain partial JSONL.

    Called only after recording the authoritative workload failure and before
    closing peers or signalling the owned server. Never retries the workload.
    """
    started = stamp()
    process = None
    timed_out = False
    try:
        command = [sys.executable, str(worker or Path(__file__).resolve()),
                   "--pid", str(pid), "--database-port", str(db_port)]
        if metrics_address:
            command += ["--metrics", metrics_address]
        if http_address:
            command += ["--http", http_address]
        with Path(destination).open("x", encoding="utf-8") as output:
            os.chmod(destination, 0o600)
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.DEVNULL,
                                       env=env, start_new_session=True)
            try:
                process.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
            finally:
                # Also reap any observer-owned child (such as psql) if the
                # observer itself exited unexpectedly before collecting it.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=1)
        return {"status": "deadline" if timed_out else ("complete" if process.returncode == 0 else "failed"),
                "started": started, "finished": stamp(), "exit_code": process.returncode,
                "artifact": str(destination)}
    except Exception as error:
        return {"status": "unavailable", "started": started, "finished": stamp(),
                "error_type": type(error).__name__, "artifact": str(destination)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--database-port", type=int, required=True)
    parser.add_argument("--metrics")
    parser.add_argument("--http")
    args = parser.parse_args()
    if args.pid <= 0:
        parser.error("PID must name the owned fixture process")
    write_stage("process_before", lambda: process_snapshot(args.pid))
    if args.metrics:
        write_stage("metrics", lambda: http_snapshot(args.metrics, "/metrics"))
    if args.http:
        write_stage("readiness", lambda: http_snapshot(args.http, "/readyz"))
    write_stage("postgres_activity", lambda: database_snapshot(args.database_port))
    write_stage("process_after", lambda: process_snapshot(args.pid))
    write_stage("postgres_counts", lambda: database_snapshot(args.database_port, counts=True))


if __name__ == "__main__":
    main()
