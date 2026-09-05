#!/usr/bin/env python3
"""Run one CI command in a private process group with optional deadline control.

``timeout`` only signals its direct child. That is insufficient for shell
fixtures that use command substitution or background workers: the shell can
exit while a child it started remains in the fixture's process group and keeps
its stdout pipe open. This supervisor creates a separate session for the
whole fixture, forwards combined output promptly, and treats process-group
quiescence -- not direct-child exit -- as command completion.
"""

from __future__ import annotations

import argparse
import ctypes
import dataclasses
import os
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import BinaryIO


POLL_INTERVAL_SECONDS = 0.05
OUTPUT_DRAIN_SECONDS = 5.0
OUTPUT_STOP_SECONDS = 1.0
KILL_REAP_SECONDS = 2.0
CONSOLE_FORWARD_SECONDS = 1.0
CONSOLE_STOP_SECONDS = 1.0
DEFAULT_MAX_LOG_BYTES = 16 * 1024 * 1024
MIN_MAX_LOG_BYTES = 1024
MAX_MAX_LOG_BYTES = 64 * 1024 * 1024
PR_SET_CHILD_SUBREAPER = 36


@dataclasses.dataclass(frozen=True)
class LinuxProcessIdentity:
    """A PID paired with its kernel start tick, safe against PID reuse."""

    pid: int
    start_time: int


@dataclasses.dataclass(frozen=True)
class LinuxProcess:
    """The process fields needed for private-group and subreaper ownership."""

    identity: LinuxProcessIdentity
    ppid: int
    pgid: int
    state: bytes


@dataclasses.dataclass
class ConsoleForwarder:
    """A separately-owned stdout writer fed through bounded private pipes."""

    process: subprocess.Popen[bytes]
    input_write_fd: int
    acknowledgement_read_fd: int
    input_closed: bool = False


class OutputCopyState:
    """Share output limits and terminal copier failures with the main thread."""

    def __init__(self, max_log_bytes: int) -> None:
        self._lock = threading.Lock()
        self._failure: str | None = None
        self._max_log_bytes = max_log_bytes
        self._log_bytes = 0

    def record_failure(self, reason: str) -> None:
        with self._lock:
            if self._failure is None:
                self._failure = reason

    def failure(self) -> str | None:
        with self._lock:
            return self._failure

    def reserve_log_bytes(self, requested: int) -> int:
        """Reserve up to *requested* bytes of the private transcript budget.

        The copier is the only caller today, but keeping the accounting under
        the same lock as the terminal state prevents a future secondary output
        path from bypassing the bound.
        """

        with self._lock:
            remaining = self._max_log_bytes - self._log_bytes
            allowed = min(max(remaining, 0), requested)
            self._log_bytes += allowed
            return allowed

    def log_bytes(self) -> int:
        with self._lock:
            return self._log_bytes

    def max_log_bytes(self) -> int:
        return self._max_log_bytes


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-seconds", type=int)
    parser.add_argument("--kill-after-seconds", type=int, required=True)
    parser.add_argument("--max-log-bytes", type=int, default=DEFAULT_MAX_LOG_BYTES)
    parser.add_argument("--log-file", type=Path, required=True)
    parser.add_argument(
        "--outcome-file",
        type=Path,
        help="private wrapper control-plane record; written atomically before exit",
    )
    parser.add_argument(
        "--require-linux-subreaper",
        action="store_true",
        help="fail closed unless Linux PR_SET_CHILD_SUBREAPER is available",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.timeout_seconds is not None and args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be positive when it is set")
    if args.kill_after_seconds < 0:
        parser.error("--kill-after-seconds must be non-negative")
    if not MIN_MAX_LOG_BYTES <= args.max_log_bytes <= MAX_MAX_LOG_BYTES:
        parser.error(
            "--max-log-bytes must be between "
            f"{MIN_MAX_LOG_BYTES} and {MAX_MAX_LOG_BYTES}"
        )
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    return args


def read_console_forwarder_frame(input_fd: int) -> bytes | None:
    """Read one length-prefixed frame from the supervisor's private pipe."""

    header = bytearray()
    while len(header) < 4:
        try:
            chunk = os.read(input_fd, 4 - len(header))
        except InterruptedError:
            continue
        if not chunk:
            if header:
                raise ValueError("truncated console forwarder frame header")
            return None
        header.extend(chunk)
    payload_length = int.from_bytes(header, "big")
    if payload_length < 1 or payload_length > 64 * 1024:
        raise ValueError("invalid console forwarder frame length")
    payload = bytearray()
    while len(payload) < payload_length:
        try:
            chunk = os.read(input_fd, payload_length - len(payload))
        except InterruptedError:
            continue
        if not chunk:
            raise ValueError("truncated console forwarder frame payload")
        payload.extend(chunk)
    return bytes(payload)


def console_forwarder_main(argv: list[str]) -> int:
    """Write framed diagnostic output to inherited stdout and acknowledge it.

    This intentionally runs in a separate child: a blocked runner stdout pipe
    may block this helper, but it can never block the supervisor's control loop
    or require an unbounded in-memory forwarding queue.
    """

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--console-forwarder", action="store_true")
    parser.add_argument("--input-fd", type=int, required=True)
    parser.add_argument("--acknowledgement-fd", type=int, required=True)
    args = parser.parse_args(argv)
    if not args.console_forwarder or args.input_fd < 0 or args.acknowledgement_fd < 0:
        return 2
    try:
        while True:
            payload = read_console_forwarder_frame(args.input_fd)
            if payload is None:
                return 0
            remaining = memoryview(payload)
            while remaining:
                try:
                    written = os.write(sys.stdout.fileno(), remaining)
                except InterruptedError:
                    continue
                if written <= 0:
                    return 1
                remaining = remaining[written:]
            try:
                os.write(args.acknowledgement_fd, b"\x01")
            except InterruptedError:
                os.write(args.acknowledgement_fd, b"\x01")
    except (BrokenPipeError, OSError, ValueError):
        return 1


def spawn_console_forwarder() -> ConsoleForwarder:
    """Create bounded private pipes and an independently terminable writer."""

    input_read_fd, input_write_fd = os.pipe()
    acknowledgement_read_fd, acknowledgement_write_fd = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    spawned = False
    try:
        # These are newly-created private descriptors; unlike changing the
        # inherited stdout flags, making this writer nonblocking cannot alter
        # the parent shell or GitHub runner's shared file description.
        os.set_blocking(input_write_fd, False)
        os.set_blocking(acknowledgement_read_fd, False)
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--console-forwarder",
                "--input-fd",
                str(input_read_fd),
                "--acknowledgement-fd",
                str(acknowledgement_write_fd),
            ],
            stdin=subprocess.DEVNULL,
            pass_fds=(input_read_fd, acknowledgement_write_fd),
            close_fds=True,
        )
        os.close(input_read_fd)
        input_read_fd = -1
        os.close(acknowledgement_write_fd)
        acknowledgement_write_fd = -1
        forwarder = ConsoleForwarder(
            process=process,
            input_write_fd=input_write_fd,
            acknowledgement_read_fd=acknowledgement_read_fd,
        )
        spawned = True
        return forwarder
    except Exception:
        if process is not None and process.poll() is None:
            # This helper is a direct Popen child, so this is the same exact
            # ownership boundary used during normal finalization.  Do not let
            # a cleanup error mask the original pipe/spawn failure.
            try:
                process.kill()
                process.wait(timeout=KILL_REAP_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                pass
        raise
    finally:
        for descriptor in (
            input_read_fd,
            acknowledgement_write_fd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if not spawned:
            for descriptor in (input_write_fd, acknowledgement_read_fd):
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def close_console_forwarder_input(forwarder: ConsoleForwarder) -> None:
    if forwarder.input_closed:
        return
    forwarder.input_closed = True
    try:
        os.close(forwarder.input_write_fd)
    except OSError:
        pass


def finalize_console_forwarder(forwarder: ConsoleForwarder) -> bool:
    """Close, reap, and if necessary terminate the known helper process."""

    close_console_forwarder_input(forwarder)
    try:
        status = forwarder.process.wait(timeout=CONSOLE_STOP_SECONDS)
    except subprocess.TimeoutExpired:
        print(
            "phase=command_console_forwarder_drain_elapsed "
            f"pid={forwarder.process.pid} drain_seconds={CONSOLE_STOP_SECONDS:g} "
            "action=terminate_popen_helper",
            file=sys.stderr,
            flush=True,
        )
        try:
            forwarder.process.terminate()
            status = forwarder.process.wait(timeout=CONSOLE_STOP_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            print(
                "phase=command_console_forwarder_grace_elapsed "
                f"pid={forwarder.process.pid} stop_seconds={CONSOLE_STOP_SECONDS:g} "
                "action=kill_popen_helper",
                file=sys.stderr,
                flush=True,
            )
            try:
                forwarder.process.kill()
                forwarder.process.wait(timeout=KILL_REAP_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                print(
                    "phase=command_console_forwarder_survived_kill "
                    f"pid={forwarder.process.pid} action=stop_waiting",
                    file=sys.stderr,
                    flush=True,
                )
        return False
    except (OSError, ChildProcessError):
        # An ownership/reap anomaly must not skip the later subreaper scan or
        # be mistaken for a clean writer shutdown.
        print(
            "phase=command_console_forwarder_reap_failed "
            f"pid={forwarder.process.pid} outcome=failed_fixture_lifecycle",
            file=sys.stderr,
            flush=True,
        )
        return False
    finally:
        try:
            os.close(forwarder.acknowledgement_read_fd)
        except OSError:
            pass
    return status == 0


def forward_console_frame(
    forwarder: ConsoleForwarder,
    payload: bytes,
    stop_requested: threading.Event,
    state: OutputCopyState,
) -> bool:
    """Send exactly one bounded frame and wait for stdout completion evidence."""

    frame = len(payload).to_bytes(4, "big") + payload
    pending = memoryview(frame)
    deadline = time.monotonic() + CONSOLE_FORWARD_SECONDS
    while pending:
        if stop_requested.is_set():
            return False
        if forwarder.process.poll() is not None:
            state.record_failure("console_forwarder_exit")
            return False
        try:
            written = os.write(forwarder.input_write_fd, pending)
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                state.record_failure("console_pipe_backpressure")
                return False
            try:
                select.select(
                    [],
                    [forwarder.input_write_fd],
                    [],
                    min(POLL_INTERVAL_SECONDS, remaining),
                )
            except (OSError, ValueError):
                state.record_failure("console_pipe_select")
                return False
            continue
        except (BrokenPipeError, OSError):
            state.record_failure("console_forwarder_pipe")
            return False
        if written <= 0:
            state.record_failure("console_forwarder_pipe")
            return False
        pending = pending[written:]

    while True:
        if stop_requested.is_set():
            return False
        if forwarder.process.poll() is not None:
            state.record_failure("console_forwarder_exit")
            return False
        try:
            acknowledgement = os.read(forwarder.acknowledgement_read_fd, 1)
        except BlockingIOError:
            acknowledgement = None
        except OSError:
            state.record_failure("console_ack_read")
            return False
        if acknowledgement:
            return True
        if acknowledgement == b"":
            state.record_failure("console_forwarder_ack_eof")
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            state.record_failure("console_delivery_stalled")
            return False
        try:
            readable, _, _ = select.select(
                [forwarder.acknowledgement_read_fd],
                [],
                [],
                min(POLL_INTERVAL_SECONDS, remaining),
            )
        except (OSError, ValueError):
            state.record_failure("console_ack_select")
            return False
        if not readable:
            continue


def copy_output(
    source: BinaryIO,
    destination: BinaryIO,
    stop_requested: threading.Event,
    state: OutputCopyState,
    console_forwarder: ConsoleForwarder,
) -> None:
    """Copy output as soon as a pipe has bytes, rather than waiting for 64 KiB.

    ``BufferedReader.read(65536)`` is allowed to wait for the entire requested
    buffer. CI diagnostics are often one short line followed by a hung test,
    so use ``select`` plus ``os.read`` to publish low-volume output promptly.
    """

    try:
        source_fd = source.fileno()
        while not stop_requested.is_set():
            try:
                readable, _, _ = select.select([source_fd], [], [], POLL_INTERVAL_SECONDS)
            except (OSError, ValueError):
                if not stop_requested.is_set():
                    state.record_failure("source_select")
                return
            if not readable:
                continue
            try:
                chunk = os.read(source_fd, 64 * 1024)
            except OSError:
                if not stop_requested.is_set():
                    state.record_failure("source_read")
                return
            if not chunk or stop_requested.is_set():
                return
            allowed = state.reserve_log_bytes(len(chunk))
            if allowed:
                bounded_chunk = chunk[:allowed]
            else:
                bounded_chunk = b""
            try:
                if bounded_chunk:
                    destination.write(bounded_chunk)
                    destination.flush()
            except (OSError, ValueError):
                # Do not silently succeed if the only durable diagnostic copy
                # could not be written (for example because the runner disk is
                # full). The main loop will terminate the private group.
                state.record_failure("log_write")
                return
            if allowed < len(chunk):
                # The primary command's transcript is intentionally bounded.
                # The main loop observes this state, emits a deterministic
                # phase record, and terminates only the owned process group.
                # Do not forward the over-budget suffix either: runner output
                # is part of the same diagnostic attack surface.
                state.record_failure("log_limit")
                return
            if not bounded_chunk:
                # ``len(chunk)`` is positive above, so this is reachable only
                # when a future caller changes the reservation semantics.
                state.record_failure("log_limit")
                return
            # The private transcript is durable before anything is offered to
            # the runner console. A separately-owned helper forwards one
            # bounded frame at a time and acknowledges completion; a stopped
            # downstream consumer therefore becomes a timed, observable
            # lifecycle failure instead of blocking this daemon thread.
            if not forward_console_frame(
                console_forwarder,
                bounded_chunk,
                stop_requested,
                state,
            ):
                return
    except Exception:
        # A copier crash must be observable by the main supervisor instead of
        # being mistaken for a cleanly completed output thread.
        state.record_failure("unexpected_copy_exception")


def linux_process_table() -> dict[int, LinuxProcess] | None:
    """Snapshot readable Linux process identities, or ``None`` when unknown.

    The kernel start tick prevents a stale PID from being treated as the
    fixture descendant that once had the same numeric PID. An unreadable
    process table is deliberately represented as unknown, never empty.
    """

    if sys.platform != "linux":
        return None
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return None

    processes: dict[int, LinuxProcess] = {}
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
            # Do not mistake an unreadable fixture descendant for absence.
            return None
        closing_paren = stat.rfind(b")")
        if closing_paren < 0:
            continue
        fields = stat[closing_paren + 2 :].split()
        # Fields after ``comm`` begin with state, ppid, pgrp. Start time is
        # field 22 in proc(5), or index 19 in this suffix.
        if len(fields) < 20:
            continue
        try:
            pid = int(entry.name)
            processes[pid] = LinuxProcess(
                identity=LinuxProcessIdentity(pid=pid, start_time=int(fields[19])),
                ppid=int(fields[1]),
                pgid=int(fields[2]),
                state=fields[0],
            )
        except ValueError:
            continue
    return processes


def live_group_members(pgid: int) -> list[LinuxProcessIdentity] | None:
    """Return non-zombie Linux identities in *pgid*, or ``None`` without procfs.

    ``killpg(pgid, 0)`` also succeeds while a group contains only zombies. A
    zombie cannot hold an XMPP listener, DB connection, or CI output pipe, so
    it must not make a completed fixture look alive. GitHub's Linux runners
    expose procfs; the signal-based fallback below retains POSIX portability.
    """

    processes = linux_process_table()
    if processes is None:
        return None
    return [
        process.identity
        for process in processes.values()
        if process.pgid == pgid and process.state not in {b"Z", b"X"}
    ]


def enable_linux_child_subreaper() -> bool:
    """Adopt descendants which deliberately leave the fixture process group.

    A private process group alone cannot contain a child that calls ``setsid``.
    On Linux, becoming a child subreaper *before* ``Popen`` makes orphaned
    grandchildren children of this supervisor instead of PID 1, so their
    exact PID/start-time identity can be terminated during finalization.
    """

    if sys.platform != "linux":
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.restype = ctypes.c_int
        if prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER failed")
    except (AttributeError, OSError):
        return False
    return True


def live_subreaper_descendants(
    *,
    supervisor_pid: int,
    excluded_direct_child_pids: set[int],
) -> list[LinuxProcessIdentity] | None:
    """Return live descendants adopted by this supervisor after root reaping.

    This is intentionally called only after ``Popen`` has reaped the direct
    child. At that point every deliberately detached descendant has been
    reparented to the Linux child subreaper, while this process owns no other
    children. Starting from those direct, adopted children avoids relying on a
    transient root PID: a very short command can validly exit before a procfs
    snapshot observes it.
    """

    processes = linux_process_table()
    if processes is None:
        return None

    children: dict[int, list[LinuxProcess]] = {}
    for process in processes.values():
        children.setdefault(process.ppid, []).append(process)

    # Once Popen has reaped the root, a Linux subreaper becomes the parent of
    # every orphaned descendant. This supervisor creates no unrelated child
    # after that point, so direct children are exact adopted fixture roots.
    roots = [
        process.identity.pid
        for process in children.get(supervisor_pid, [])
        if process.identity.pid not in excluded_direct_child_pids
    ]

    seen: set[int] = set()
    pending = roots
    while pending:
        parent = pending.pop()
        if parent in seen:
            continue
        seen.add(parent)
        pending.extend(child.identity.pid for child in children.get(parent, []))

    return [
        processes[pid].identity
        for pid in seen
        if pid in processes and processes[pid].state not in {b"Z", b"X"}
    ]


def signal_exact_linux_identities(
    identities: list[LinuxProcessIdentity], signum: signal.Signals
) -> None:
    """Signal only descendants whose PID/start-time identity still matches."""

    processes = linux_process_table()
    if processes is None:
        return
    for identity in identities:
        if processes.get(identity.pid, None) is None:
            continue
        if processes[identity.pid].identity != identity:
            continue
        try:
            os.kill(identity.pid, signum)
        except ProcessLookupError:
            continue


def reap_adopted_children(
    *,
    supervisor_pid: int,
    excluded_direct_child_pids: set[int],
) -> None:
    """Reap adopted fixture children without stealing a helper Popen status.

    Calling ``waitpid(-1)`` would also reap the separately-owned console
    forwarder. Instead, after Popen has reaped the fixture root, select only
    current direct children of this Linux subreaper and exclude the helper's
    still-Popen-owned PID. Repeating after each reap handles a chain of zombie
    descendants reparenting to the supervisor.
    """

    while True:
        processes = linux_process_table()
        if processes is None:
            return
        candidates = [
            process.identity.pid
            for process in processes.values()
            if process.ppid == supervisor_pid
            and process.identity.pid not in excluded_direct_child_pids
        ]
        reaped_any = False
        for pid in candidates:
            try:
                reaped_pid, _status = os.waitpid(pid, os.WNOHANG)
            except (ChildProcessError, ProcessLookupError):
                continue
            reaped_any = reaped_any or reaped_pid != 0
        if not reaped_any:
            return


def terminate_adopted_descendants(
    *,
    supervisor_pid: int,
    excluded_direct_child_pids: set[int],
    reason: str,
    kill_after_seconds: int,
) -> tuple[bool, bool]:
    """Boundedly terminate detached descendants adopted by the subreaper.

    Returns ``(complete, detected)``. The caller converts a detected detached
    worker into a failed fixture lifecycle even if the original shell exited
    zero. No process-name matching or global signal is used.
    """

    reap_adopted_children(
        supervisor_pid=supervisor_pid,
        excluded_direct_child_pids=excluded_direct_child_pids,
    )
    descendants = live_subreaper_descendants(
        supervisor_pid=supervisor_pid,
        excluded_direct_child_pids=excluded_direct_child_pids,
    )
    if descendants is None:
        print(
            "phase=command_detached_descendant_visibility_unavailable "
            "outcome=failed_fixture_lifecycle",
            file=sys.stderr,
            flush=True,
        )
        return False, False
    if not descendants:
        return True, False

    print(
        "phase=command_detached_descendants_detected "
        f"count={len(descendants)} reason={reason} action=terminate_exact_descendants",
        file=sys.stderr,
        flush=True,
    )
    term_signaled: set[LinuxProcessIdentity] = set()
    deadline = time.monotonic() + kill_after_seconds
    while True:
        for identity in descendants:
            if identity not in term_signaled:
                signal_exact_linux_identities([identity], signal.SIGTERM)
                term_signaled.add(identity)
        reap_adopted_children(
            supervisor_pid=supervisor_pid,
            excluded_direct_child_pids=excluded_direct_child_pids,
        )
        descendants = live_subreaper_descendants(
            supervisor_pid=supervisor_pid,
            excluded_direct_child_pids=excluded_direct_child_pids,
        )
        if descendants is None:
            return False, True
        if not descendants:
            return True, True
        if time.monotonic() >= deadline:
            break
        time.sleep(POLL_INTERVAL_SECONDS)

    print(
        "phase=command_detached_descendant_grace_elapsed "
        f"reason={reason} kill_after_seconds={kill_after_seconds} "
        "action=kill_exact_descendants",
        file=sys.stderr,
        flush=True,
    )
    signal_exact_linux_identities(descendants, signal.SIGKILL)
    deadline = time.monotonic() + KILL_REAP_SECONDS
    while True:
        # A TERM-ignoring descendant can fork between the first SIGKILL and
        # the next procfs snapshot. Signal the freshly enumerated exact
        # identities on every bounded pass instead of leaving that child for
        # PID 1 or declaring cleanup successful.
        signal_exact_linux_identities(descendants, signal.SIGKILL)
        reap_adopted_children(
            supervisor_pid=supervisor_pid,
            excluded_direct_child_pids=excluded_direct_child_pids,
        )
        descendants = live_subreaper_descendants(
            supervisor_pid=supervisor_pid,
            excluded_direct_child_pids=excluded_direct_child_pids,
        )
        if descendants is None:
            return False, True
        if not descendants:
            return True, True
        if time.monotonic() >= deadline:
            break
        time.sleep(POLL_INTERVAL_SECONDS)
    print(
        "phase=command_detached_descendants_survived_kill "
        f"reason={reason} action=stop_waiting",
        file=sys.stderr,
        flush=True,
    )
    return False, True


def write_outcome(outcome_file: Path | None, termination: str) -> bool:
    """Atomically publish trusted supervisor outcome provenance to its wrapper."""

    if outcome_file is None:
        return True
    temporary_path: Path | None = None
    try:
        outcome_file.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{outcome_file.name}.",
            suffix=".tmp",
            dir=outcome_file.parent,
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            handle.write(f"version=1\ntermination={termination}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, outcome_file)
        return True
    except OSError:
        print(
            "phase=command_outcome_write_failed outcome=failed_fixture_lifecycle",
            file=sys.stderr,
            flush=True,
        )
        return False
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def group_has_live_members(
    pgid: int,
    *,
    require_linux_identity: bool,
) -> bool | None:
    """Return group liveness, or ``None`` when strict identity proof is absent.

    The non-strict POSIX mode retains the historical ``killpg(..., 0)``
    compatibility fallback. GitHub's strict Linux mode must never turn an
    unreadable process table into a blind signal against a recycled PGID, so it
    returns ``None`` instead and lets the caller fail closed.
    """

    members = live_group_members(pgid)
    if members is not None:
        return bool(members)
    if require_linux_identity:
        return None
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def signal_group(
    pgid: int,
    signum: signal.Signals,
    *,
    require_linux_identity: bool,
) -> bool:
    """Signal the private group, returning false if strict identity is absent.

    Strict Linux mode refreshes and signals exact PID/start-time identities on
    each pass. This handles descendants which fork during shutdown without
    treating the numeric PGID as a durable identity. The non-strict fallback is
    retained only for callers that explicitly did not request Linux identity
    containment.
    """

    members = live_group_members(pgid)
    if members is not None:
        if not members:
            return True
        if require_linux_identity:
            signal_exact_linux_identities(members, signum)
            return True
        try:
            os.killpg(pgid, signum)
        except ProcessLookupError:
            pass
        return True
    if require_linux_identity:
        return False
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        pass
    return True


def wait_for_group_exit(
    pgid: int,
    deadline: float,
    *,
    require_linux_identity: bool,
) -> bool | None:
    """Wait for non-zombie group members, preserving strict visibility state."""

    while True:
        group_live = group_has_live_members(
            pgid,
            require_linux_identity=require_linux_identity,
        )
        if group_live is None:
            return None
        if not group_live:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(POLL_INTERVAL_SECONDS, remaining))


def terminate_owned_direct_child(
    process: subprocess.Popen[bytes],
    *,
    reason: str,
    kill_after_seconds: int,
) -> bool:
    """Boundedly terminate only the still-Popen-owned direct child.

    This is the strict-mode fallback when procfs visibility disappears. Until
    ``Popen`` reaps its child, Linux cannot recycle that PID, so signalling this
    exact direct child is safe. Deliberately do *not* guess at a process group
    or any descendant in this branch; inability to prove those identities is a
    lifecycle failure reported by the caller.
    """

    if process.poll() is not None:
        return True
    print(
        "phase=command_direct_child_termination_started "
        f"pid={process.pid} reason={reason} action=terminate_popen_child_only",
        file=sys.stderr,
        flush=True,
    )
    try:
        process.send_signal(signal.SIGTERM)
    except ProcessLookupError:
        return process.poll() is not None
    deadline = time.monotonic() + kill_after_seconds
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL_SECONDS)
    if process.poll() is not None:
        return True
    print(
        "phase=command_direct_child_grace_elapsed "
        f"pid={process.pid} reason={reason} kill_after_seconds={kill_after_seconds} "
        "action=kill_popen_child_only",
        file=sys.stderr,
        flush=True,
    )
    try:
        process.kill()
    except ProcessLookupError:
        return process.poll() is not None
    return reap_direct_child(process)


def terminate_group(
    pgid: int,
    *,
    reason: str,
    kill_after_seconds: int,
    require_linux_identity: bool,
    direct_child: subprocess.Popen[bytes],
) -> bool:
    """Terminate a fixture group and wait for the *group*, not its leader."""

    group_live = group_has_live_members(
        pgid,
        require_linux_identity=require_linux_identity,
    )
    if group_live is None:
        print(
            "phase=command_group_identity_visibility_unavailable "
            f"pid={pgid} reason={reason} "
            "action=terminate_popen_child_only_fail_fixture_lifecycle",
            file=sys.stderr,
            flush=True,
        )
        terminate_owned_direct_child(
            direct_child,
            reason=reason,
            kill_after_seconds=kill_after_seconds,
        )
        return False
    if not group_live:
        return True

    print(
        "phase=command_group_termination_started "
        f"pid={pgid} reason={reason} action=terminate_process_group",
        file=sys.stderr,
        flush=True,
    )
    if not signal_group(
        pgid,
        signal.SIGTERM,
        require_linux_identity=require_linux_identity,
    ):
        terminate_owned_direct_child(
            direct_child,
            reason=reason,
            kill_after_seconds=kill_after_seconds,
        )
        return False
    group_exited = wait_for_group_exit(
        pgid,
        time.monotonic() + kill_after_seconds,
        require_linux_identity=require_linux_identity,
    )
    if group_exited is None:
        print(
            "phase=command_group_identity_visibility_unavailable "
            f"pid={pgid} reason={reason} "
            "action=terminate_popen_child_only_fail_fixture_lifecycle",
            file=sys.stderr,
            flush=True,
        )
        terminate_owned_direct_child(
            direct_child,
            reason=reason,
            kill_after_seconds=kill_after_seconds,
        )
        return False
    if group_exited:
        return True

    print(
        "phase=command_grace_elapsed "
        f"pid={pgid} reason={reason} kill_after_seconds={kill_after_seconds} "
        "action=kill_process_group",
        file=sys.stderr,
        flush=True,
    )
    if not signal_group(
        pgid,
        signal.SIGKILL,
        require_linux_identity=require_linux_identity,
    ):
        terminate_owned_direct_child(
            direct_child,
            reason=reason,
            kill_after_seconds=kill_after_seconds,
        )
        return False
    group_exited = wait_for_group_exit(
        pgid,
        time.monotonic() + KILL_REAP_SECONDS,
        require_linux_identity=require_linux_identity,
    )
    if group_exited is None:
        print(
            "phase=command_group_identity_visibility_unavailable "
            f"pid={pgid} reason={reason} "
            "action=terminate_popen_child_only_fail_fixture_lifecycle",
            file=sys.stderr,
            flush=True,
        )
        terminate_owned_direct_child(
            direct_child,
            reason=reason,
            kill_after_seconds=kill_after_seconds,
        )
        return False
    if group_exited:
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
    state: OutputCopyState,
) -> bool:
    """Drain normal output, then force a bounded shutdown for held pipe FDs."""

    forced_pipe_close = False
    output_thread.join(timeout=OUTPUT_DRAIN_SECONDS)
    if output_thread.is_alive():
        forced_pipe_close = True
        print(
            "phase=command_output_drain_elapsed "
            f"drain_seconds={OUTPUT_DRAIN_SECONDS:g} action=close_output_pipe",
            file=sys.stderr,
            flush=True,
        )
        print(
            "phase=command_output_pipe_held "
            "outcome=failed_fixture_lifecycle",
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
    failure = state.failure()
    if failure is not None:
        print(
            "phase=command_output_copy_failed "
            f"reason={failure} action=fail_supervisor",
            file=sys.stderr,
            flush=True,
        )
        return False
    if forced_pipe_close:
        # A pipe retained after the command group became quiescent belongs to
        # a descendant that escaped the fixture lifecycle. Closing our reader
        # bounds finalization, but must not turn that lifecycle breach into a
        # successful CI command.
        return False
    return True


def main() -> int:
    args = parse_args()

    def finish_without_child(status: int, termination: str) -> int:
        return status if write_outcome(args.outcome_file, termination) else 1

    if os.name != "posix":
        raise RuntimeError("github_ci_supervisor requires POSIX process groups")

    subreaper_enabled = enable_linux_child_subreaper()
    if args.require_linux_subreaper and not subreaper_enabled:
        print(
            "phase=command_descendant_containment_unavailable "
            "outcome=failed_fixture_lifecycle",
            file=sys.stderr,
            flush=True,
        )
        return finish_without_child(1, "subreaper_unavailable")
    supervisor_pid = os.getpid()

    # Install cancellation handlers before spawning the command. A signal that
    # arrives after fork/exec but before the assignment to ``process`` records
    # a pending cancellation; the main loop then reaps the freshly created
    # private group instead of allowing the default handler to orphan it.
    interrupted_by: list[signal.Signals] = []
    process: subprocess.Popen[bytes] | None = None

    def request_shutdown(signum: int, _frame: object) -> None:
        # A nested supervisor owns a different process group from its parent.
        # Only record cancellation here. Python runs signal handlers on the
        # main thread at bytecode boundaries; keeping this handler free of
        # procfs scans and process signalling lets the normal lifecycle loop
        # perform one ordered TERM -> KILL cleanup after Popen is assigned.
        interrupted_by.append(signal.Signals(signum))

    expired = False
    cleanup_completed = True
    output_completed = True
    residual_group_detected = False
    detached_descendants_detected = False
    cleanup_attempted = False
    direct_child_reaped = False
    termination_reason: str | None = None
    detached_descendants_finalized = False

    def finalize_detached_descendants() -> None:
        """Reap/contain Linux descendants after Popen's direct child is known dead."""

        nonlocal cleanup_completed
        nonlocal detached_descendants_detected
        nonlocal detached_descendants_finalized
        if detached_descendants_finalized or not subreaper_enabled:
            return
        detached_descendants_finalized = True
        if not direct_child_reaped:
            # A strict Linux supervisor must never claim that it contained an
            # escaped descendant before Popen has established the direct-child
            # reap boundary.
            cleanup_completed = False
            return
        excluded_direct_child_pids = (
            {console_forwarder.process.pid}
            if console_forwarder is not None
            else set()
        )
        descendants_complete, detected = terminate_adopted_descendants(
            supervisor_pid=supervisor_pid,
            excluded_direct_child_pids=excluded_direct_child_pids,
            reason=termination_reason or "direct_child_completed",
            kill_after_seconds=args.kill_after_seconds,
        )
        cleanup_completed = descendants_complete and cleanup_completed
        detached_descendants_detected = detected

    with args.log_file.open("wb") as log_file:
        previous_handlers: dict[signal.Signals, signal.Handlers] = {}
        output_stop_requested: threading.Event | None = None
        output_thread: threading.Thread | None = None
        output_state: OutputCopyState | None = None
        console_forwarder: ConsoleForwarder | None = None
        try:
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                previous_handlers[signum] = signal.signal(signum, request_shutdown)
            if interrupted_by:
                print(
                    "phase=command_cancelled_before_spawn "
                    f"signal={interrupted_by[-1].name} action=skip_command",
                    file=sys.stderr,
                    flush=True,
                )
                return finish_without_child(
                    128 + int(interrupted_by[-1]), "parent_signal"
                )
            try:
                console_forwarder = spawn_console_forwarder()
            except OSError:
                print(
                    "phase=command_console_forwarder_spawn_failed "
                    "outcome=failed_fixture_lifecycle",
                    file=sys.stderr,
                    flush=True,
                )
                return finish_without_child(1, "console_forwarder_spawn_failed")
            try:
                process = subprocess.Popen(
                    args.command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except FileNotFoundError:
                print(
                    "phase=command_exec_failed reason=not_found",
                    file=sys.stderr,
                    flush=True,
                )
                return finish_without_child(127, "exec_not_found")
            except PermissionError:
                print(
                    "phase=command_exec_failed reason=not_executable",
                    file=sys.stderr,
                    flush=True,
                )
                return finish_without_child(126, "exec_not_executable")
            except OSError:
                # Preserve the shell-facing "found but not executable" class
                # for other exec failures (for example an invalid executable
                # format) now that no-deadline commands also use Popen.
                print(
                    "phase=command_exec_failed reason=spawn_failed",
                    file=sys.stderr,
                    flush=True,
                )
                return finish_without_child(126, "exec_failed")
            assert process.stdout is not None
            output_stop_requested = threading.Event()
            output_state = OutputCopyState(args.max_log_bytes)
            output_thread = threading.Thread(
                target=copy_output,
                args=(
                    process.stdout,
                    log_file,
                    output_stop_requested,
                    output_state,
                    console_forwarder,
                ),
                name="northstar-ci-output-copy",
                daemon=True,
            )
            output_thread.start()

            deadline = (
                time.monotonic() + args.timeout_seconds
                if args.timeout_seconds is not None
                else None
            )
            while True:
                direct_returncode = process.poll()
                # The direct process itself is a member of its private group;
                # retaining that fact makes a partially hidden procfs fail
                # closed rather than prematurely reporting completion.
                group_alive = (
                    True
                    if direct_returncode is None
                    else group_has_live_members(
                        process.pid,
                        require_linux_identity=args.require_linux_subreaper,
                    )
                )
                if termination_reason is not None:
                    break
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
                if console_forwarder.process.poll() is not None:
                    termination_reason = "console_forwarder_exit"
                    print(
                        "phase=command_console_forwarder_exit_detected "
                        f"pid={console_forwarder.process.pid} "
                        "action=terminate_process_group",
                        file=sys.stderr,
                        flush=True,
                    )
                    break
                copy_failure = output_state.failure()
                if copy_failure is not None:
                    termination_reason = f"output_copy_{copy_failure}"
                    if copy_failure == "log_limit":
                        print(
                            "phase=command_output_log_limit_reached "
                            f"pid={process.pid} max_log_bytes={output_state.max_log_bytes()} "
                            f"logged_bytes={output_state.log_bytes()} "
                            "action=terminate_process_group",
                            file=sys.stderr,
                            flush=True,
                        )
                    print(
                        "phase=command_output_copy_failure_detected "
                        f"pid={process.pid} reason={copy_failure} "
                        "action=terminate_process_group",
                        file=sys.stderr,
                        flush=True,
                    )
                    break
                if group_alive is None:
                    termination_reason = "group_identity_visibility_unavailable"
                    print(
                        "phase=command_group_identity_visibility_unavailable "
                        f"pid={process.pid} reason=direct_child_completed "
                        "action=fail_fixture_lifecycle",
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
                if deadline is not None and time.monotonic() >= deadline:
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
                cleanup_attempted = True
                cleanup_completed = terminate_group(
                    process.pid,
                    reason=termination_reason,
                    kill_after_seconds=args.kill_after_seconds,
                    require_linux_identity=args.require_linux_subreaper,
                    direct_child=process,
                )
            reaped = reap_direct_child(process)
            cleanup_completed = reaped and cleanup_completed
            direct_child_reaped = reaped
        finally:
            try:
                # This also covers an exception after Popen but before the
                # regular lifecycle loop could decide on a termination reason.
                if process is not None and not cleanup_attempted:
                    direct_returncode = process.poll()
                    group_alive = (
                        True
                        if direct_returncode is None
                        else group_has_live_members(
                            process.pid,
                            require_linux_identity=args.require_linux_subreaper,
                        )
                    )
                    if group_alive is None:
                        cleanup_attempted = True
                        cleanup_completed = terminate_group(
                            process.pid,
                            reason="supervisor_finalization",
                            kill_after_seconds=args.kill_after_seconds,
                            require_linux_identity=args.require_linux_subreaper,
                            direct_child=process,
                        ) and cleanup_completed
                    elif group_alive:
                        cleanup_attempted = True
                        cleanup_completed = terminate_group(
                            process.pid,
                            reason="supervisor_finalization",
                            kill_after_seconds=args.kill_after_seconds,
                            require_linux_identity=args.require_linux_subreaper,
                            direct_child=process,
                        ) and cleanup_completed
                    if not direct_child_reaped:
                        reaped = reap_direct_child(process)
                        cleanup_completed = reaped and cleanup_completed
                        direct_child_reaped = reaped
                if process is not None and process.stdout is not None:
                    try:
                        if (
                            output_thread is not None
                            and output_stop_requested is not None
                            and output_state is not None
                        ):
                            output_completed = finalize_output(
                                process.stdout,
                                output_thread,
                                output_stop_requested,
                                output_state,
                            )
                    except Exception:
                        # Finalization continues below: this supervisor must
                        # never leak its separately-owned writer just because
                        # the copier lifecycle itself raised unexpectedly.
                        output_completed = False
                        print(
                            "phase=command_output_finalization_failed "
                            "outcome=failed_fixture_lifecycle",
                            file=sys.stderr,
                            flush=True,
                        )
                    finally:
                        try:
                            process.stdout.close()
                        except (OSError, ValueError):
                            pass
                if console_forwarder is not None:
                    try:
                        output_completed = (
                            finalize_console_forwarder(console_forwarder)
                            and output_completed
                        )
                    except Exception:
                        output_completed = False
                        print(
                            "phase=command_console_forwarder_finalization_failed "
                            "outcome=failed_fixture_lifecycle",
                            file=sys.stderr,
                            flush=True,
                        )
                # The writer helper is a direct child of this supervisor.  It
                # must be reaped (or recorded as a bounded lifecycle failure)
                # before scanning subreaper children, otherwise a normal
                # helper could be misclassified as an escaped fixture worker.
                # ``finalize_output`` runs first so a healthy helper receives
                # EOF only after the private transcript has finished draining.
                if process is not None:
                    try:
                        finalize_detached_descendants()
                    except Exception:
                        cleanup_completed = False
                        print(
                            "phase=command_detached_descendant_finalization_failed "
                            "outcome=failed_fixture_lifecycle",
                            file=sys.stderr,
                            flush=True,
                        )
            finally:
                for signum, previous_handler in previous_handlers.items():
                    signal.signal(signum, previous_handler)

    final_status: int
    final_termination: str
    # A deadline is only a trustworthy timeout result once the supervisor has
    # actually completed its own containment and diagnostic finalization.  If
    # a private group or its output copier survived TERM/KILL, reporting 124
    # would hide a lifecycle breach behind an ordinary test timeout.  Preserve
    # cancellation semantics below, but make an uncontained deadline a
    # supervisor failure with explicit provenance for the wrapper/CI summary.
    if not cleanup_completed or not output_completed:
        final_status = 1
        final_termination = termination_reason or "cleanup_failed"
    elif expired:
        final_status = 124
        final_termination = "deadline"
    elif interrupted_by:
        final_status = 128 + int(interrupted_by[-1])
        final_termination = "parent_signal"
    elif residual_group_detected and process.returncode == 0:
        # Cleanup prevented a runner leak, but a fixture that backgrounded
        # work outside its direct command lifecycle has still violated its CI
        # contract. Preserve timeout and parent-cancellation status above.
        print(
            "phase=command_residual_group_cleaned outcome=failed_fixture_lifecycle",
            file=sys.stderr,
            flush=True,
        )
        final_status = 1
        final_termination = "residual_group"
    elif detached_descendants_detected and process.returncode == 0:
        print(
            "phase=command_detached_descendants_cleaned "
            "outcome=failed_fixture_lifecycle",
            file=sys.stderr,
            flush=True,
        )
        final_status = 1
        final_termination = "detached_descendants"
    else:
        returncode = process.returncode if process.returncode is not None else 1
        # Popen represents signal termination as a negative number. Shells
        # conventionally expose it as 128 + signal, not a wrapped negative
        # SystemExit status such as 241 for SIGTERM.
        final_status = 128 + (-returncode) if returncode < 0 else returncode
        final_termination = termination_reason or "normal"

    return final_status if write_outcome(args.outcome_file, final_termination) else 1


if __name__ == "__main__":
    if sys.argv[1:2] == ["--console-forwarder"]:
        raise SystemExit(console_forwarder_main(sys.argv[1:]))
    raise SystemExit(main())
