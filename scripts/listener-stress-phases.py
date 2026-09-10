#!/usr/bin/env python3
"""Keep fixture key generation and credential setup outside concurrent startup.

Only the listener-stress parent creates/releases a private per-round barrier.
No server deadline, worker count, or protocol assertion is changed here.
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


PHASES = ("prepared", "live")
POLL_SECONDS = 0.025


def positive(value: str) -> int:
    if re.fullmatch(r"[1-9][0-9]{0,9}", value) is None:
        raise ValueError("phase identity must be a positive integer")
    return int(value)


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        process_stat = Path(f"/proc/{pid}/stat")
        if process_stat.exists() and process_stat.read_text().rsplit(")", 1)[1].split()[0] == "Z":
            return False
        return True
    except ProcessLookupError:
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
        "version": 1, "nonce": nonce, "round": round_number,
        "pairs": config.get("pairs"), "parent_pid": config.get("parent_pid"),
    } or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise ValueError("phase round identity does not match")
    if (type(config["pairs"]) is not int or not 1 <= config["pairs"] <= 10000
            or type(config["parent_pid"]) is not int or config["parent_pid"] <= 0):
        raise ValueError("phase round dimensions are invalid")
    if not process_alive(config["parent_pid"]):
        raise ValueError("phase parent exited before release")
    return config


def initialize(directory: Path, nonce: str, round_number: int, pairs: int, parent_pid: int) -> None:
    directory.mkdir(mode=0o700)
    publish(directory / "round.json", {
        "version": 1, "nonce": nonce, "round": round_number,
        "pairs": pairs, "parent_pid": parent_pid,
    })
    configuration(directory, nonce, round_number)


def ready_record(config: dict, phase: str, pair: int, pid: int) -> dict:
    return {**config, "phase": phase, "pair": pair, "pid": pid}


def all_prepared(directory: Path, config: dict, phase: str) -> bool:
    complete = True
    for pair in range(1, config["pairs"] + 1):
        file = directory / f"{phase}-{pair}.json"
        try:
            record = read_record(file)
        except FileNotFoundError:
            complete = False
            continue
        pid = record.get("pid")
        if type(pid) is not int or pid <= 0 or record != ready_record(config, phase, pair, pid):
            raise ValueError("phase readiness identity does not match")
        if not process_alive(pid):
            raise ValueError("fixture exited before phase release")
    return complete


def worker(directory: Path, nonce: str, round_number: int, phase: str, pair: int, timeout: int) -> None:
    config = configuration(directory, nonce, round_number)
    if phase not in PHASES or not 1 <= pair <= config["pairs"]:
        raise ValueError("worker phase or pair is outside this round")
    publish(directory / f"{phase}-{pair}.json", ready_record(config, phase, pair, os.getpid()))
    release = {**config, "phase": phase, "released": True}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not process_alive(config["parent_pid"]):
            raise ValueError("phase parent exited before release")
        try:
            if read_record(directory / f"{phase}-release.json") != release:
                raise ValueError("parent phase release identity does not match")
            return
        except FileNotFoundError:
            time.sleep(POLL_SECONDS)
    raise TimeoutError("fixture phase was not released within its worker budget")


def release(directory: Path, nonce: str, round_number: int, phase: str, timeout: int, leaders: list[int]) -> None:
    config = configuration(directory, nonce, round_number)
    if phase not in PHASES or len(leaders) != config["pairs"] or len(set(leaders)) != len(leaders):
        raise ValueError("phase release requires every distinct worker leader")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not all(process_alive(pid) for pid in leaders):
            raise ValueError("worker leader exited before phase release")
        if all_prepared(directory, config, phase):
            publish(directory / f"{phase}-release.json", {**config, "phase": phase, "released": True})
            print(f"listener stress phase={phase} round={round_number} pairs={config['pairs']} released")
            return
        time.sleep(POLL_SECONDS)
    raise TimeoutError("not every fixture reached the parent phase barrier")


def main(argv: list[str]) -> None:
    action, raw_directory, nonce, raw_round, *arguments = argv
    directory = Path(raw_directory)
    round_number = positive(raw_round)
    if action == "init" and len(arguments) == 2:
        initialize(directory, nonce, round_number, positive(arguments[0]), positive(arguments[1]))
    elif action == "worker" and len(arguments) == 3:
        worker(directory, nonce, round_number, arguments[0], positive(arguments[1]), positive(arguments[2]))
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
