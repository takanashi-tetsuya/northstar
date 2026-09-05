#!/usr/bin/env python3
"""Run one CI command in a private process group with an observable deadline.

``timeout`` only signals its direct child. That is insufficient for shell
fixtures that use command substitution or background workers: the shell can
exit while a child it started remains in the fixture's process group and keeps
its stdout pipe open. This supervisor creates a separate session for the
whole fixture, forwards combined output promptly, and treats process-group
quiescence -- not direct-child exit -- as command completion.
"""

from __future__ import annotations

import argparse
import os
import select
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import BinaryIO


POLL_INTERVAL_SECONDS = 0.05
OUTPUT_DRAIN_SECONDS = 5.0
OUTPUT_STOP_SECONDS = 1.0
KILL_REAP_SECONDS = 2.0


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


def copy_output(
    source: BinaryIO,
    destination: BinaryIO,
    stop_requested: threading.Event,
) -> None:
    """Copy output as soon as a pipe has bytes, rather than waiting for 64 KiB.

    ``BufferedReader.read(65536)`` is allowed to wait for the entire requested
    buffer. CI diagnostics are often one short line followed by a hung test,
    so use ``select`` plus ``os.read`` to publish low-volume output promptly.
    """

    source_fd = source.fileno()
    console = sys.stdout.buffer
    while not stop_requested.is_set():
        try:
            readable, _, _ = select.select([source_fd], [], [], POLL_INTERVAL_SECONDS)
        except (OSError, ValueError):
            return
        if not readable:
            continue
        try:
            chunk = os.read(source_fd, 64 * 1024)
        except OSError:
            return
        if not chunk:
            return
        if stop_requested.is_set():
            return
        destination.write(chunk)
        destination.flush()
        try:
            console.write(chunk)
            console.flush()
        except BrokenPipeError:
            # A caller may deliberately close its output stream while
            # cancelling a job. Preserve the private diagnostic log.
            pass


def live_group_members(pgid: int) -> list[int] | None:
    """Return non-zombie Linux members of *pgid*, or ``None`` without procfs.

    ``killpg(pgid, 0)`` also succeeds while a group contains only zombies. A
    zombie cannot hold an XMPP listener, DB connection, or CI output pipe, so
    it must not make a completed fixture look alive. GitHub's Linux runners
    expose procfs; the signal-based fallback below retains POSIX portability.
    """

    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return None

    members: list[int] = []
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return None
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            stat = (entry / "stat").read_bytes()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            # Do not mistake an unreadable member for an empty group.
            return None
        closing_paren = stat.rfind(b")")
        if closing_paren < 0:
            continue
        fields = stat[closing_paren + 2 :].split()
        # Fields after ``comm`` begin with state, ppid, then pgrp.
        if len(fields) < 3:
            continue
        try:
            state = fields[0]
            member_pgid = int(fields[2])
        except ValueError:
            continue
        if member_pgid == pgid and state not in {b"Z", b"X"}:
            members.append(int(entry.name))
    return members


def group_has_live_members(pgid: int) -> bool:
    members = live_group_members(pgid)
    if members is not None:
        return bool(members)
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def signal_group(pgid: int, signum: signal.Signals) -> None:
    # Do not signal a vanished group by a potentially recycled numeric ID.
    # This remains scoped to the fixture's private PGID; no name-based or
    # system-wide process termination is used.
    if not group_has_live_members(pgid):
        return
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        pass


def wait_for_group_exit(pgid: int, deadline: float) -> bool:
    """Wait only until a fixed deadline for all non-zombie group members."""

    while group_has_live_members(pgid):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(POLL_INTERVAL_SECONDS, remaining))
    return True


def terminate_group(
    pgid: int,
    *,
    reason: str,
    kill_after_seconds: int,
) -> bool:
    """Terminate a fixture group and wait for the *group*, not its leader."""

    if not group_has_live_members(pgid):
        return True

    print(
        "phase=command_group_termination_started "
        f"pid={pgid} reason={reason} action=terminate_process_group",
        file=sys.stderr,
        flush=True,
    )
    signal_group(pgid, signal.SIGTERM)
    if wait_for_group_exit(pgid, time.monotonic() + kill_after_seconds):
        return True

    print(
        "phase=command_grace_elapsed "
        f"pid={pgid} reason={reason} kill_after_seconds={kill_after_seconds} "
        "action=kill_process_group",
        file=sys.stderr,
        flush=True,
    )
    signal_group(pgid, signal.SIGKILL)
    if wait_for_group_exit(pgid, time.monotonic() + KILL_REAP_SECONDS):
        return True

    print(
        "phase=command_group_survived_kill "
        f"pid={pgid} reason={reason} action=stop_waiting",
        file=sys.stderr,
        flush=True,
    )
    return False


def reap_direct_child(process: subprocess.Popen[bytes]) -> bool:
    """Reap the direct child without turning a stuck process into an unbounded wait."""

    if process.poll() is not None:
        return True
    try:
        process.wait(timeout=KILL_REAP_SECONDS)
    except subprocess.TimeoutExpired:
        print(
            "phase=command_direct_child_survived_cleanup "
            f"pid={process.pid} action=stop_waiting",
            file=sys.stderr,
            flush=True,
        )
        return False
    return True


def finalize_output(
    source: BinaryIO,
    output_thread: threading.Thread,
    stop_requested: threading.Event,
) -> bool:
    """Drain normal output, then force a bounded shutdown for held pipe FDs."""

    output_thread.join(timeout=OUTPUT_DRAIN_SECONDS)
    if output_thread.is_alive():
        print(
            "phase=command_output_drain_elapsed "
            f"drain_seconds={OUTPUT_DRAIN_SECONDS:g} action=close_output_pipe",
            file=sys.stderr,
            flush=True,
        )
        stop_requested.set()
        try:
            source.close()
        except OSError:
            pass
        output_thread.join(timeout=OUTPUT_STOP_SECONDS)
    if output_thread.is_alive():
        # The thread is daemonized, but this state is observable and bounded.
        # It can only occur when an escaped descendant retains the pipe despite
        # closure; never wait indefinitely or touch unrelated processes.
        print(
            "phase=command_output_copy_survived_close "
            f"stop_seconds={OUTPUT_STOP_SECONDS:g} action=abandon_daemon_copy",
            file=sys.stderr,
            flush=True,
        )
        return False
    return True


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
        output_stop_requested = threading.Event()
        output_thread = threading.Thread(
            target=copy_output,
            args=(process.stdout, log_file, output_stop_requested),
            name="northstar-ci-output-copy",
            daemon=True,
        )
        output_thread.start()

        interrupted_by: list[signal.Signals] = []

        def request_shutdown(signum: int, _frame: object) -> None:
            # A nested supervisor owns a different process group from its
            # parent. Forward parent cancellation immediately, then let the
            # main loop perform the same TERM -> KILL group cleanup sequence.
            interrupted_by.append(signal.Signals(signum))
            signal_group(process.pid, signal.SIGTERM)

        previous_handlers = {
            signum: signal.signal(signum, request_shutdown)
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        }
        expired = False
        cleanup_completed = True
        output_completed = True
        residual_group_detected = False
        try:
            deadline = time.monotonic() + args.timeout_seconds
            termination_reason: str | None = None

            while True:
                direct_returncode = process.poll()
                # The direct process itself is a member of its private group;
                # retaining that fact makes a partially hidden procfs fail
                # closed rather than prematurely reporting completion.
                group_alive = (
                    direct_returncode is None or group_has_live_members(process.pid)
                )
                if interrupted_by:
                    termination_reason = f"parent_signal_{interrupted_by[-1].name.lower()}"
                    print(
                        "phase=command_cancelled_by_parent "
                        f"pid={process.pid} signal={interrupted_by[-1].name} "
                        "action=terminate_process_group",
                        file=sys.stderr,
                        flush=True,
                    )
                    break
                if not group_alive:
                    break
                if direct_returncode is not None:
                    # A successful shell exit is not successful fixture
                    # completion if children remain in its private group.
                    termination_reason = "direct_child_exited_with_residual_group"
                    residual_group_detected = True
                    print(
                        "phase=command_parent_exited_with_residual_group "
                        f"pid={process.pid} exit_status={direct_returncode} "
                        "action=terminate_process_group",
                        file=sys.stderr,
                        flush=True,
                    )
                    break
                if time.monotonic() >= deadline:
                    expired = True
                    termination_reason = "deadline"
                    print(
                        "phase=command_deadline_reached "
                        f"pid={process.pid} timeout_seconds={args.timeout_seconds} "
                        "action=terminate_process_group",
                        file=sys.stderr,
                        flush=True,
                    )
                    break
                time.sleep(POLL_INTERVAL_SECONDS)

            if termination_reason is not None:
                cleanup_completed = terminate_group(
                    process.pid,
                    reason=termination_reason,
                    kill_after_seconds=args.kill_after_seconds,
                )
            cleanup_completed = reap_direct_child(process) and cleanup_completed
        finally:
            for signum, previous_handler in previous_handlers.items():
                signal.signal(signum, previous_handler)
            output_completed = finalize_output(
                process.stdout,
                output_thread,
                output_stop_requested,
            )
            try:
                process.stdout.close()
            except OSError:
                pass

    if expired:
        return 124
    if interrupted_by:
        return 128 + int(interrupted_by[-1])
    if not cleanup_completed or not output_completed:
        return 1
    if residual_group_detected and process.returncode == 0:
        # Cleanup prevented a runner leak, but a fixture that backgrounded
        # work outside its direct command lifecycle has still violated its CI
        # contract. Preserve timeout and parent-cancellation status above.
        print(
            "phase=command_residual_group_cleaned outcome=failed_fixture_lifecycle",
            file=sys.stderr,
            flush=True,
        )
        return 1
    return process.returncode if process.returncode is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
