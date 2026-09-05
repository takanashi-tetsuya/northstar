#!/usr/bin/env python3
"""Run one CI command in a private process group with an observable deadline.

``timeout`` only signals its direct child.  That is insufficient for shell
fixtures that use command substitution: the shell can be terminated while the
child it is waiting for remains alive.  This supervisor creates a separate
session for the whole fixture, forwards its combined output, and terminates
the complete process group on expiry.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import BinaryIO


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-seconds", type=int, required=True)
    parser.add_argument("--kill-after-seconds", type=int, required=True)
    parser.add_argument("--log-file", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.timeout_seconds < 1 or args.kill_after_seconds < 0:
        parser.error("timeout values must be non-negative, with a positive deadline")
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    return args


def copy_output(source: BinaryIO, destination: BinaryIO) -> None:
    console = sys.stdout.buffer
    while chunk := source.read(64 * 1024):
        destination.write(chunk)
        destination.flush()
        console.write(chunk)
        console.flush()


def signal_group(pid: int, signum: signal.Signals) -> None:
    try:
        os.killpg(pid, signum)
    except ProcessLookupError:
        pass


def main() -> int:
    args = parse_args()
    if os.name != "posix":
        raise RuntimeError("github_ci_supervisor requires POSIX process groups")

    with args.log_file.open("wb") as log_file:
        process = subprocess.Popen(
            args.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        assert process.stdout is not None
        output_thread = threading.Thread(
            target=copy_output,
            args=(process.stdout, log_file),
            name="northstar-ci-output-copy",
            daemon=True,
        )
        output_thread.start()
        expired = False
        interrupted_by: list[signal.Signals] = []

        def request_shutdown(signum: int, _frame: object) -> None:
            # A nested supervisor owns a different process group from its
            # parent. Forward parent cancellation before this process exits,
            # otherwise an inner fixture can outlive its CI step.
            interrupted_by.append(signal.Signals(signum))
            signal_group(process.pid, signal.SIGTERM)

        previous_handlers = {
            signum: signal.signal(signum, request_shutdown)
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        }
        try:
            deadline = time.monotonic() + args.timeout_seconds
            while process.poll() is None and not interrupted_by and time.monotonic() < deadline:
                time.sleep(0.1)
            expired = process.poll() is None and not interrupted_by
            if process.poll() is None:
                if expired:
                    print(
                        "phase=command_deadline_reached "
                        f"pid={process.pid} timeout_seconds={args.timeout_seconds} "
                        "action=terminate_process_group",
                        file=sys.stderr,
                        flush=True,
                    )
                    signal_group(process.pid, signal.SIGTERM)
                else:
                    print(
                        "phase=command_cancelled_by_parent "
                        f"pid={process.pid} signal={interrupted_by[-1].name} "
                        "action=terminate_process_group",
                        file=sys.stderr,
                        flush=True,
                    )
                grace_deadline = time.monotonic() + args.kill_after_seconds
                while process.poll() is None and time.monotonic() < grace_deadline:
                    time.sleep(0.1)
                if process.poll() is None:
                    print(
                        "phase=command_grace_elapsed "
                        f"pid={process.pid} kill_after_seconds={args.kill_after_seconds} "
                        "action=kill_process_group",
                        file=sys.stderr,
                        flush=True,
                    )
                    signal_group(process.pid, signal.SIGKILL)
                    process.wait()
        finally:
            for signum, previous_handler in previous_handlers.items():
                signal.signal(signum, previous_handler)
            process.stdout.close()
            output_thread.join(timeout=5)

    if expired:
        return 124
    if interrupted_by:
        return 128 + int(interrupted_by[-1])
    return process.returncode if process.returncode is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
