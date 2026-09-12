#!/usr/bin/env python3
"""Prepare all fixtures, bound cold-start batches, then release all live pairs.

Only the listener-stress parent issues nonce-bound per-pair startup permission.
The original server deadlines, worker count and protocol assertions are retained.
"""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import re
import stat
import sys
import time


PHASES = ("prepared", "live", "transport")
POLL_SECONDS = 0.025


def positive(value: str) -> int:
    if re.fullmatch(r"[1-9][0-9]{0,9}", value) is None:
        raise ValueError("phase identity must be a positive integer")
    return int(value)


def startup_pair_concurrency(cpus: int, pairs: int) -> int:
    if type(cpus) is not int or cpus < 1 or type(pairs) is not int or not 1 <= pairs <= 10000:
        raise ValueError("startup capacity requires positive CPU and pair counts")
    # Leave CPU room for PostgreSQL and already-live nodes. Each admitted pair
    # still starts A then B, so this also bounds concurrent cold server starts.
    return min(pairs, max(1, cpus // 2), 4)


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        process_stat = Path(f"/proc/{pid}/stat")
        if process_stat.exists() and process_stat.read_text().rsplit(")", 1)[1].split()[0] == "Z":
            return False
        return True
    except ProcessLookupError:
        return False


def process_start_time(pid: int) -> int:
    if type(pid) is not int or pid <= 0 or not process_alive(pid):
        raise ValueError("server child exited before phase release")
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        started = int(fields[19])
        if fields[0] == "Z" or started <= 0:
            raise ValueError("server child exited before phase release")
        return started
    except (OSError, IndexError) as error:
        raise ValueError("server child identity could not be verified") from error


def belongs_to_worker(pid: int, leader: int) -> bool:
    """Check the actual publisher's ancestry, including nested supervisors."""
    for _ in range(64):
        if pid == leader:
            return True
        if pid <= 1:
            return False
        try:
            pid = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            return False
    return False


def read_record(file: Path) -> dict:
    try:
        descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError("phase record must be a private regular file") from error
        raise
    with os.fdopen(descriptor) as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 4096):
            raise ValueError("phase record must be a private regular file")
        contents = stream.read(4097)
        if len(contents) > 4096:
            raise ValueError("phase record exceeded its size limit")
    record = json.loads(contents)
    if not isinstance(record, dict):
        raise ValueError("phase record must be an object")
    return record


def publish(file: Path, record: dict) -> None:
    if file.exists() or file.is_symlink():
        raise ValueError("phase record must only be published once")
    temporary = file.with_name(f".{file.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(record, stream, sort_keys=True)
        os.replace(temporary, file)
    finally:
        temporary.unlink(missing_ok=True)


def configuration(directory: Path, nonce: str, round_number: int) -> dict:
    metadata = directory.lstat()
    if (directory.resolve() != directory or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ValueError("phase directory must be private and must not traverse symlinks")
    config = read_record(directory / "round.json")
    if config != {
        "version": 2, "nonce": nonce, "round": round_number,
        "pairs": config.get("pairs"), "parent_pid": config.get("parent_pid"),
        "startup_concurrency": config.get("startup_concurrency"),
    } or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise ValueError("phase round identity does not match")
    if (type(config["pairs"]) is not int or not 1 <= config["pairs"] <= 10000
            or type(config["parent_pid"]) is not int or config["parent_pid"] <= 0
            or type(config["startup_concurrency"]) is not int
            or not 1 <= config["startup_concurrency"] <= config["pairs"]):
        raise ValueError("phase round dimensions are invalid")
    if not process_alive(config["parent_pid"]):
        raise ValueError("phase parent exited before release")
    return config


def initialize(directory: Path, nonce: str, round_number: int, pairs: int, parent_pid: int,
               startup_concurrency: int | None = None) -> None:
    directory.mkdir(mode=0o700)
    publish(directory / "round.json", {
        "version": 2, "nonce": nonce, "round": round_number,
        "pairs": pairs, "parent_pid": parent_pid,
        "startup_concurrency": pairs if startup_concurrency is None else startup_concurrency,
    })
    configuration(directory, nonce, round_number)


def ready_record(config: dict, phase: str, pair: int, pid: int,
                 child_pids: tuple[int, ...] = ()) -> dict:
    record = {**config, "phase": phase, "pair": pair, "pid": pid}
    if phase == "live":
        if len(child_pids) != 2 or len(set(child_pids)) != 2:
            raise ValueError("live phase requires both distinct server children")
        record["children"] = [{"pid": child, "start_time": process_start_time(child)} for child in child_pids]
    elif child_pids:
        raise ValueError("only the live phase accepts server children")
    return record


def startup_permission(config: dict, pair: int) -> dict:
    return {**config, "phase": "prepared", "pair": pair, "released": True}


def require_startup_permission(directory: Path, config: dict, pair: int) -> None:
    try:
        record = read_record(directory / f"prepared-start-{pair}.json")
    except FileNotFoundError as error:
        raise ValueError("pair has not received startup permission") from error
    if record != startup_permission(config, pair):
        raise ValueError("pair startup permission identity does not match")


def require_previous_release(directory: Path, config: dict, phase: str) -> None:
    previous = {"live": "prepared", "transport": "live"}.get(phase)
    if previous is None:
        return
    try:
        record = read_record(directory / f"{previous}-release.json")
    except FileNotFoundError as error:
        raise ValueError("previous fixture phase has not been released") from error
    if record != {**config, "phase": previous, "released": True}:
        raise ValueError("previous phase release identity does not match")


def verify_children(record: dict, leader: int | None = None) -> None:
    children = record.get("children")
    if not isinstance(children, list) or len(children) != 2:
        raise ValueError("live phase requires both distinct server children")
    pids = []
    for child in children:
        if (not isinstance(child, dict) or set(child) != {"pid", "start_time"}
                or type(child["pid"]) is not int or child["pid"] <= 0
                or type(child["start_time"]) is not int or child["start_time"] <= 0):
            raise ValueError("server child identity is invalid")
        if process_start_time(child["pid"]) != child["start_time"]:
            raise ValueError("server child identity changed before phase release")
        if leader is not None and not belongs_to_worker(child["pid"], leader):
            raise ValueError("server child does not belong to its assigned worker")
        pids.append(child["pid"])
    if len(set(pids)) != 2:
        raise ValueError("live phase requires both distinct server children")


def all_prepared(directory: Path, config: dict, phase: str, leaders: list[int] | None = None,
                 pair_numbers: range | None = None) -> bool:
    complete = True
    for pair in range(1, config["pairs"] + 1) if pair_numbers is None else pair_numbers:
        file = directory / f"{phase}-{pair}.json"
        try:
            record = read_record(file)
        except FileNotFoundError:
            complete = False
            continue
        pid = record.get("pid")
        if phase == "live":
            require_startup_permission(directory, config, pair)
            verify_children(record, None if leaders is None else leaders[pair - 1])
            expected = {**config, "phase": phase, "pair": pair, "pid": pid, "children": record["children"]}
        else:
            expected = ready_record(config, phase, pair, pid)
        if type(pid) is not int or pid <= 0 or record != expected:
            raise ValueError("phase readiness identity does not match")
        if not process_alive(pid):
            raise ValueError("fixture exited before phase release")
        if leaders is not None and not belongs_to_worker(pid, leaders[pair - 1]):
            raise ValueError("phase publisher does not belong to its assigned worker")
    return complete


def worker(directory: Path, nonce: str, round_number: int, phase: str, pair: int, timeout: int,
           child_pids: tuple[int, ...] = ()) -> None:
    config = configuration(directory, nonce, round_number)
    if phase not in PHASES or not 1 <= pair <= config["pairs"]:
        raise ValueError("worker phase or pair is outside this round")
    require_previous_release(directory, config, phase)
    if phase == "live":
        require_startup_permission(directory, config, pair)
    record = ready_record(config, phase, pair, os.getpid(), child_pids)
    publish(directory / f"{phase}-{pair}.json", record)
    release_record = {**config, "phase": phase, "released": True}
    release_file = directory / f"{phase}-release.json"
    if phase == "prepared":
        release_record = startup_permission(config, pair)
        release_file = directory / f"prepared-start-{pair}.json"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not process_alive(config["parent_pid"]):
            raise ValueError("phase parent exited before release")
        if phase == "live":
            verify_children(record)
        try:
            if read_record(release_file) != release_record:
                raise ValueError("parent phase release identity does not match")
            if time.monotonic() >= deadline:
                break
            return
        except FileNotFoundError:
            time.sleep(POLL_SECONDS)
    raise TimeoutError("fixture phase was not released within its worker budget")


def require_active_round(config: dict, leaders: list[int], deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TimeoutError("not every fixture reached the parent phase barrier")
    if not process_alive(config["parent_pid"]):
        raise ValueError("phase parent exited before release")
    if not all(process_alive(pid) for pid in leaders):
        raise ValueError("worker leader exited before phase release")


def release(directory: Path, nonce: str, round_number: int, phase: str, timeout: int, leaders: list[int]) -> None:
    config = configuration(directory, nonce, round_number)
    if phase not in PHASES or len(leaders) != config["pairs"] or len(set(leaders)) != len(leaders):
        raise ValueError("phase release requires every distinct worker leader")
    require_previous_release(directory, config, phase)
    deadline = time.monotonic() + timeout
    while True:
        require_active_round(config, leaders, deadline)
        if all_prepared(directory, config, phase, leaders):
            require_active_round(config, leaders, deadline)
            publish(directory / f"{phase}-release.json", {**config, "phase": phase, "released": True})
            break
        time.sleep(POLL_SECONDS)
    if phase == "prepared":
        capacity = config["startup_concurrency"]
        for first in range(1, config["pairs"] + 1, capacity):
            if first > 1:
                while True:
                    require_active_round(config, leaders, deadline)
                    # Recheck every earlier live pair, not just the newest one.
                    if all_prepared(directory, config, "live", leaders, range(1, first)):
                        break
                    time.sleep(POLL_SECONDS)
            last = min(config["pairs"], first + capacity - 1)
            for pair in range(first, last + 1):
                require_active_round(config, leaders, deadline)
                if (directory / f"live-{pair}.json").exists():
                    raise ValueError("pair published live before startup permission")
                publish(directory / f"prepared-start-{pair}.json", startup_permission(config, pair))
            print(f"listener stress startup round={round_number} first_pair={first} last_pair={last} capacity={capacity} admitted", flush=True)
    print(f"listener stress phase={phase} round={round_number} pairs={config['pairs']} released", flush=True)


def wait_for_fixture_phase(phase: str, child_pids: tuple[int, ...] = ()) -> None:
    """Join a phase from the live Python fixture, without an extra publisher."""
    if phase not in PHASES:
        raise ValueError("unknown fixture phase")
    names = ("DIR", "NONCE", "ROUND", "PAIR")
    values = [os.environ.get("NORTHSTAR_LISTENER_STRESS_PHASE_" + name, "") for name in names]
    if not any(values):
        return
    if not all(values):
        raise ValueError("listener stress phase configuration must be set together")
    directory, nonce, raw_round, raw_pair = values
    timeout = positive(os.environ.get("NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS", "900"))
    if timeout > 7200:
        raise ValueError("fixture phase timeout exceeds the worker budget limit")
    # This wait remains inside the original github-ci-run supervisor's total
    # budget. It never holds an authentication slot or starts its I/O clock.
    worker(Path(directory), nonce, positive(raw_round), phase, positive(raw_pair), timeout, child_pids)


def main(argv: list[str]) -> None:
    if len(argv) == 3 and argv[0] == "--startup-pair-concurrency":
        print(startup_pair_concurrency(positive(argv[1]), positive(argv[2])))
        return
    action, raw_directory, nonce, raw_round, *arguments = argv
    directory = Path(raw_directory)
    round_number = positive(raw_round)
    if action == "init" and len(arguments) in (2, 3):
        initialize(directory, nonce, round_number, positive(arguments[0]), positive(arguments[1]),
                   None if len(arguments) == 2 else positive(arguments[2]))
    elif action == "worker" and len(arguments) in (3, 5):
        worker(directory, nonce, round_number, arguments[0], positive(arguments[1]), positive(arguments[2]),
               tuple(map(positive, arguments[3:])))
    elif action == "release" and len(arguments) >= 3:
        release(directory, nonce, round_number, arguments[0], positive(arguments[1]), list(map(positive, arguments[2:])))
    else:
        raise ValueError("invalid listener stress phase arguments")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TimeoutError) as error:
        print(f"listener stress phase rejected: {error}", file=sys.stderr)
        sys.exit(2)
