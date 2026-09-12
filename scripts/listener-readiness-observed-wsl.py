#!/usr/bin/env python3
"""Run the unchanged regular listener matrix with one bounded PG observer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import stat
import subprocess
import sys
import secrets
import tempfile
import time

from github_ci_supervisor import (
    enable_linux_child_subreaper,
    publish_failure_marker,
    terminate_adopted_descendants,
    terminate_owned_direct_child,
)

OBSERVER_MAX_SECONDS = 9000  # Existing regular CI job ceiling, never a worker budget.
READY_SECONDS = 15.0  # Bounded connect + identity attestation + first sample.
POST_WAIT_SECONDS = 20.0  # Fixed 15s post-window plus one bounded query and finalization.
OBSERVER_STOP_SECONDS = 4
DRIVER_CANCEL_SECONDS = 45
RESULT_LIMIT = 16 * 1024
TOTAL_EVIDENCE_LIMIT = 8 * 1024 * 1024
STOP_SIGNAL: int | None = None


def stop_requested(signum: int, _frame) -> None:
    global STOP_SIGNAL
    STOP_SIGNAL = signum


def read_private_json(path: Path, limit: int = RESULT_LIMIT) -> dict:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > limit):
            raise ValueError("invalid diagnostic record")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("oversized diagnostic record")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("invalid diagnostic object")
    return value


def write_result(path: Path, result: dict) -> None:
    data = (json.dumps(result, separators=(",", ":"), allow_nan=False) + "\n").encode()
    if len(data) > RESULT_LIMIT:
        raise ValueError("oversized wrapper result")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def observer_environment(environment: dict[str, str]) -> dict[str, str]:
    # Only the driver owns the disposable fixture. This connection cannot
    # choose another account/database or inherit service/query configuration.
    result = {key: value for key, value in environment.items() if not key.startswith("PG")}
    host = environment.get("NORTHSTAR_LISTENER_STRESS_DATABASE_HOST", "127.0.0.1")
    port = environment.get("NORTHSTAR_LISTENER_STRESS_DATABASE_PORT", "5432")
    if (host != "127.0.0.1" or not re.fullmatch("[1-9][0-9]{0,4}", port)
            or int(port) > 65535
            or "NORTHSTAR_LISTENER_STRESS_DATABASE_USER" in environment
            or "NORTHSTAR_LISTENER_STRESS_DATABASE_PASSWORD" in environment):
        raise ValueError("invalid fixture endpoint")
    result.update(PGHOST=host, PGPORT=port, PGDATABASE="postgres", PGUSER="xmpp_test",
                  PGPASSWORD="xmpp-test-password")
    result.pop("NORTHSTAR_LISTENER_STRESS_FAILURE_MARKER", None)
    return result


def publish_case_map(round_number: int, pairs: int, data: bytes, environment: dict[str, str]) -> None:
    # One small batch per round; original database names and the run salt
    # never reach the retained mapping or the job console.
    if not 1 <= round_number <= 20 or not 1 <= pairs <= 50 or len(data) > 16384:
        raise ValueError("invalid case-map bounds")
    salt_path = Path(environment["NORTHSTAR_LISTENER_STRESS_OBSERVER_SALT_FILE"])
    map_path = Path(environment["NORTHSTAR_LISTENER_STRESS_OBSERVER_MAP_FILE"])
    if (not salt_path.is_absolute() or not map_path.is_absolute()
            or salt_path.name != "database-hash-salt" or map_path.name != "database-map.json"
            or salt_path.parent != map_path.parent or salt_path.parent.is_symlink()):
        raise ValueError("invalid case-map location")
    parent = salt_path.parent.stat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise ValueError("invalid case-map parent")
    descriptor = os.open(salt_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size != 32):
            raise ValueError("invalid case-map salt")
        salt = stream.read(33).decode("ascii")
    if not re.fullmatch("[0-9a-f]{32}", salt):
        raise ValueError("invalid case-map salt")
    rows, identities, databases = [], set(), set()
    for line in data.decode("ascii").splitlines():
        values = line.split("\t")
        if len(values) != 3 or not re.fullmatch("[1-9][0-9]?", values[0]):
            raise ValueError("invalid case-map row")
        pair, node, database = int(values[0]), values[1], values[2]
        if not 1 <= pair <= pairs or node not in {"A", "B"} or not re.fullmatch("[a-z][a-z0-9_]{0,62}", database):
            raise ValueError("invalid case-map identity")
        if (pair, node) in identities or database in databases:
            raise ValueError("duplicate case-map identity")
        identities.add((pair, node))
        databases.add(database)
        rows.append(dict(round=round_number, pair=pair, node=node,
                         database_hash=hashlib.md5((salt + ":" + database).encode("ascii")).hexdigest()))
    if len(rows) != pairs * 2:
        raise ValueError("incomplete case-map batch")
    rows.sort(key=lambda row: (row["pair"], row["node"]))
    descriptor, temporary = tempfile.mkstemp(prefix=".case-map.", dir=map_path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            json.dump(dict(schema_version=1, round=round_number, pairs=pairs, cases=rows),
                      stream, separators=(",", ":"))
            stream.write("\n")
        if Path(temporary).stat().st_size > RESULT_LIMIT:
            raise ValueError("oversized case map")
        os.replace(temporary, map_path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def case_map_valid(value: dict, expected_pairs: int = 50) -> bool:
    if (set(value) != {"schema_version", "round", "pairs", "cases"}
            or value["schema_version"] != 1 or value["pairs"] != expected_pairs
            or type(expected_pairs) is not int or not 1 <= expected_pairs <= 50
            or type(value["round"]) is not int or not 1 <= value["round"] <= 20
            or not isinstance(value["cases"], list) or len(value["cases"]) != expected_pairs * 2):
        return False
    identities = set()
    for row in value["cases"]:
        if (not isinstance(row, dict) or set(row) != {"round", "pair", "node", "database_hash"}
                or row["round"] != value["round"] or type(row["pair"]) is not int
                or not 1 <= row["pair"] <= expected_pairs or not isinstance(row["node"], str)
                or row["node"] not in {"A", "B"}
                or not isinstance(row["database_hash"], str)
                or not re.fullmatch("[0-9a-f]{32}", row["database_hash"])):
            return False
        identities.add((row["pair"], row["node"]))
    return len(identities) == expected_pairs * 2


def finish_observer(process: subprocess.Popen, *, allow_post: bool,
                    post_wait: float = POST_WAIT_SECONDS, stop_wait: int = OBSERVER_STOP_SECONDS) -> bool:
    if allow_post and STOP_SIGNAL is None:
        try:
            process.wait(timeout=post_wait)
        except subprocess.TimeoutExpired:
            pass
    if process.poll() is None:
        return terminate_owned_direct_child(
            process, reason="observer_finalization", kill_after_seconds=stop_wait,
        )
    return True


def run_observed(driver_command: list[str], observer_command: list[str], *,
                 control_dir: Path, output_dir: Path, environment: dict[str, str],
                 ready_wait: float = READY_SECONDS, post_wait: float = POST_WAIT_SECONDS,
                 stop_wait: int = OBSERVER_STOP_SECONDS,
                 driver_cancel_wait: int = DRIVER_CANCEL_SECONDS, expected_pairs: int = 50) -> int:
    """Keep process ownership and both outcomes explicit; command injection is test-only."""
    marker = control_dir / "first-failure.json"
    driver_environment = dict(environment)
    driver_environment["NORTHSTAR_LISTENER_STRESS_FAILURE_MARKER"] = str(marker)
    driver_environment["NORTHSTAR_LISTENER_STRESS_OBSERVER_CONNECTIONS"] = "1"
    observer = driver = None
    driver_status = None
    observer_ready = False
    observer_ok = False
    cleanup_ok = True
    fatal = None
    adopted_detected = False
    marker_ok = True
    if not enable_linux_child_subreaper():
        fatal = "subreaper_unavailable"
    else:
        try:
            observer = subprocess.Popen(
                observer_command, env=observer_environment(environment),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + ready_wait
            while time.monotonic() < deadline and observer.poll() is None and STOP_SIGNAL is None:
                try:
                    ready = read_private_json(output_dir / "observer-ready.json", 4096)
                    observer_ready = (type(ready.get("observer_pid")) is int
                                      and ready["observer_pid"] == observer.pid
                                      and type(ready.get("sample_count")) is int
                                      and ready["sample_count"] >= 1)
                    if observer_ready:
                        break
                except FileNotFoundError:
                    pass
                except (OSError, ValueError):
                    fatal = "observer_readiness_invalid"
                    break
                time.sleep(0.05)
            if not observer_ready:
                fatal = fatal or "observer_unavailable"
            if STOP_SIGNAL is None:
                # Observer failure remains visible, but never substitutes a
                # reduced workload or a retry for the required matrix.
                driver = subprocess.Popen(driver_command, env=driver_environment, start_new_session=True)
                observer_exit_reported = False
                while driver.poll() is None and STOP_SIGNAL is None:
                    if observer.poll() is not None and not observer_exit_reported:
                        print(f"listener_observer_early_exit={observer.returncode}", flush=True)
                        observer_exit_reported = True
                    time.sleep(0.1)
                if STOP_SIGNAL is not None and driver.poll() is None:
                    marker_ok = publish_failure_marker("parent_cancel", marker) and marker_ok
                    cleanup_ok = terminate_owned_direct_child(
                        driver, reason="observed_matrix_cancel", kill_after_seconds=driver_cancel_wait,
                    ) and cleanup_ok
                driver_status = driver.poll()
                if driver_status is None:
                    fatal = "driver_cleanup_incomplete"
                if driver_status != 0:
                    marker_ok = publish_failure_marker("command_exit", marker) and marker_ok
            else:
                driver_status = -STOP_SIGNAL
        except (OSError, ValueError):
            fatal = fatal or "observer_or_driver_startup_failed"
            marker_ok = publish_failure_marker("startup", marker) and marker_ok
        finally:
            # Popen owns these exact direct-child PIDs until reap. The inherited
            # subreaper then handles only this wrapper's orphaned descendants.
            if driver is not None and driver.poll() is None:
                cleanup_ok = terminate_owned_direct_child(
                    driver, reason="observed_matrix_finalization",
                    kill_after_seconds=driver_cancel_wait,
                ) and cleanup_ok
                driver_status = driver.poll()
                if driver_status is None:
                    fatal = "driver_cleanup_incomplete"
            if observer is not None:
                cleanup_ok = finish_observer(
                    observer, allow_post=marker.exists(), post_wait=post_wait, stop_wait=stop_wait,
                ) and cleanup_ok
                if observer.poll() is None:
                    cleanup_ok = False
                try:
                    result = read_private_json(output_dir / "observer-result.json")
                    observer_ok = (observer_ready and observer.returncode == 0
                                   and result.get("observer_ok") is True
                                   and result.get("truncated") is False
                                   and type(result.get("observations_bytes")) is int
                                   and 0 <= result["observations_bytes"] <= TOTAL_EVIDENCE_LIMIT)
                    if marker.exists():
                        observer_ok = observer_ok and result.get("post_window_complete") is True
                except (OSError, ValueError):
                    fatal = fatal or "observer_result_unavailable"
            complete, adopted_detected = terminate_adopted_descendants(
                supervisor_pid=os.getpid(),
                excluded_direct_child_pids={process.pid for process in (driver, observer)
                                            if process is not None and process.poll() is None},
                reason="observed_matrix_finalization", kill_after_seconds=stop_wait,
            )
            cleanup_ok = complete and cleanup_ok

    map_ok = False
    try:
        case_map = read_private_json(control_dir / "database-map.json")
        map_ok = case_map_valid(case_map, expected_pairs)
    except (OSError, ValueError):
        pass
    evidence_ok = False
    if observer is not None and observer.poll() is not None:
        try:
            # Only these fixed files are uploaded. The 64 KiB log reservation
            # covers every bounded summary/map/marker plus the wrapper record.
            total = 0
            expected = (
                (output_dir / "observations.jsonl", TOTAL_EVIDENCE_LIMIT - 64 * 1024),
                (output_dir / "observer-ready.json", 4096),
                (output_dir / "observer-result.json", RESULT_LIMIT),
                (control_dir / "database-map.json", RESULT_LIMIT),
            )
            if marker.exists():
                expected += ((marker, 1024),)
            for path, cap in expected:
                info = path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > cap):
                    raise ValueError("invalid retained evidence")
                total += info.st_size
            evidence_ok = total + RESULT_LIMIT <= TOTAL_EVIDENCE_LIMIT
        except (OSError, ValueError):
            pass
    # Only an explicitly successful workload may skip the business-failure
    # transcript upload. Unknown/startup outcomes keep that upload mandatory.
    if environment.get("GITHUB_OUTPUT"):
        try:
            with open(environment["GITHUB_OUTPUT"], "a", encoding="ascii") as stream:
                stream.write("driver_succeeded=" + ("true" if driver_status == 0 else "false") + "\n")
        except OSError:
            fatal = fatal or "github_output_write_failed"
    diagnostic_ok = evidence_ok and map_ok and observer_ok and cleanup_ok and marker_ok and fatal is None and not adopted_detected
    # A genuine driver failure always wins; diagnostics cannot turn it green,
    # nor replace its original failure with an observer's unrelated exit code.
    exit_status = (128 - driver_status if driver_status is not None and driver_status < 0
                   else driver_status) or (0 if diagnostic_ok else 2)
    record = dict(schema_version=1, driver_exit_status=driver_status,
                  exit_status=exit_status, observer_ready=observer_ready,
                  observer_ok=observer_ok, diagnostic_ok=diagnostic_ok,
                  marker_ok=marker_ok, cleanup_ok=cleanup_ok, case_map_ok=map_ok,
                  evidence_bounds_ok=evidence_ok,
                  adopted_descendants_detected=adopted_detected, error_code=fatal)
    try:
        write_result(control_dir / "wrapper-result.json", record)
    except (OSError, ValueError):
        if not driver_status:
            exit_status = 2
        try:
            print("listener_observer_error=wrapper_result_write_failed", file=sys.stderr)
        except OSError:
            pass
    try:
        print("listener_observer_result=" + json.dumps(record, separators=(",", ":")), flush=True)
    except OSError:
        pass
    return exit_status


def main() -> int:
    if len(sys.argv) == 5 and sys.argv[1] == "--publish-round-map" and sys.argv[3] == "--map-pairs":
        try:
            publish_case_map(int(sys.argv[2]), int(sys.argv[4]), sys.stdin.buffer.read(16385), dict(os.environ))
            return 0
        except (OSError, ValueError, KeyError, UnicodeError):
            print("listener_observer_error=case_map_unavailable", file=sys.stderr)
            return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["regular"], required=True)
    parser.add_argument("--fixture", choices=["federation", "mix-federation"], required=True)
    parser.add_argument("--rounds", choices=[20], type=int, required=True)
    parser.add_argument("--pairs", choices=[50], type=int, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, stop_requested)
    project = Path(__file__).resolve().parents[1]
    root = Path(os.environ.get("NORTHSTAR_CI_DIAGNOSTICS_DIR",
                str(Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "northstar-ci-diagnostics")))
    try:
        root.mkdir(parents=True, exist_ok=True)
        control = Path(tempfile.mkdtemp(prefix="listener-control-observer.", dir=root.resolve()))
        output = control / "observer"
        salt_path = control / "database-hash-salt"
        descriptor = os.open(salt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(secrets.token_hex(16))
        environment = dict(os.environ)
        environment["NORTHSTAR_LISTENER_STRESS_OBSERVER_SALT_FILE"] = str(salt_path)
        environment["NORTHSTAR_LISTENER_STRESS_OBSERVER_MAP_FILE"] = str(control / "database-map.json")
        driver_command = ["bash", str(project / "scripts/listener-readiness-stress-wsl.sh"),
                          "--mode", args.mode, "--fixture", args.fixture,
                          "--rounds", str(args.rounds), "--pairs", str(args.pairs)]
        observer_command = [sys.executable, str(project / "scripts/lib/listener-control-observer.py"),
                            "--output-dir", str(output), "--failure-marker", str(control / "first-failure.json"),
                            "--max-seconds", str(OBSERVER_MAX_SECONDS), "--parent-pid", str(os.getpid()),
                            "--database-hash-salt-file", str(salt_path)]
        return run_observed(driver_command, observer_command, control_dir=control,
                            output_dir=output, environment=environment)
    except OSError:
        print("listener_observer_error=private_directory_unavailable", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
