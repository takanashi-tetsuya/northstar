#!/usr/bin/env python3
"""A child-owned, readiness-bound TCP relay for two-node fixture bootstrap.

The relay exists only because each Northstar child must bind its own ephemeral
S2S listener, while each process also needs a stable peer endpoint in its
startup-only federation DNS overrides.  It owns 127.0.0.1:0, publishes the
same nonce/PID readiness format as Northstar, and waits for the child-written
target file before forwarding any accepted connection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time
import tempfile
from pathlib import Path


STOP = threading.Event()
MAX_BUFFERED_BYTES = 1024 * 1024
STARTUP_DIAGNOSTIC_LIMIT = 4096


def signal_child_group(process: subprocess.Popen[str], signal_number: int) -> None:
    """Signal the isolated self-test group even after its direct child exits."""

    if os.name == "posix":
        try:
            os.killpg(process.pid, signal_number)
        except ProcessLookupError:
            pass
        return
    if process.poll() is None:
        process.send_signal(signal_number)


def terminate_and_collect(process: subprocess.Popen[str], grace_seconds: float = 2.0) -> str:
    """Reap a failed self-test group without blocking on an inherited pipe.

    A direct ``stderr.read()`` waits for EOF, which a parent that exits before
    a descendant (or a child that ignores TERM) need not produce.  All helper
    children start in an isolated process group, so TERM and then KILL cover
    that complete group even when ``process.poll()`` says the direct child has
    exited.  Both drain attempts are deadline-bound; only a small diagnostic
    tail is returned.
    """

    signal_child_group(process, signal.SIGTERM)
    try:
        _stdout, stderr = process.communicate(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        signal_child_group(process, signal.SIGKILL)
        try:
            _stdout, stderr = process.communicate(timeout=grace_seconds)
        except subprocess.TimeoutExpired as error:
            # This should be unreachable after a group KILL.  Do not fall
            # back to an unbounded pipe read if the host process facility is
            # broken; surface a bounded diagnostic instead.
            diagnostic = error.stderr or ""
            if isinstance(diagnostic, bytes):
                diagnostic = diagnostic.decode("utf-8", errors="replace")
            return f"relay diagnostic collection timed out: {diagnostic[-STARTUP_DIAGNOSTIC_LIMIT:]}"
    return (stderr or "")[-STARTUP_DIAGNOSTIC_LIMIT:]


def parse_target(path: Path) -> tuple[str, int]:
    raw = path.read_text(encoding="ascii").strip()
    host, separator, port = raw.rpartition(":")
    if not separator or not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("target file does not contain HOST:PORT")
    return host, int(port)


def wait_for_target(path: Path, deadline: float) -> tuple[str, int]:
    last_error = "target file is absent"
    while not STOP.is_set() and time.monotonic() < deadline:
        try:
            return parse_target(path)
        except (OSError, ValueError) as error:
            last_error = str(error)
            time.sleep(0.025)
    raise TimeoutError(f"relay target did not become available: {last_error}")


def publish_readiness(path: Path, nonce: str, purpose: str, port: int) -> None:
    if path.exists():
        raise RuntimeError(f"refusing to overwrite readiness record: {path}")
    if not path.parent.is_dir():
        raise RuntimeError(f"readiness parent directory does not exist: {path.parent}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(
                {
                    "version": 1,
                    "instance_nonce": nonce,
                    "pid": os.getpid(),
                    "listeners": {purpose: f"127.0.0.1:{port}"},
                },
                output,
                separators=(",", ":"),
            )
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        # ``replace`` would overwrite a readiness proof created after the
        # preflight check.  Publish with link(2) instead: it is an atomic
        # create-only operation in this directory, so a stale or competing
        # record fails closed rather than being silently replaced.
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise RuntimeError(f"refusing to overwrite readiness record: {path}") from error
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def relay_connection(client: socket.socket, target_file: Path) -> None:
    with client:
        client.settimeout(0.5)
        try:
            host, port = wait_for_target(target_file, time.monotonic() + 15)
            upstream = socket.create_connection((host, port), timeout=10)
        except (OSError, TimeoutError) as error:
            print(f"relay connection setup failed: {error}", file=sys.stderr, flush=True)
            return
        with upstream:
            client.setblocking(False)
            upstream.setblocking(False)
            selector = selectors.DefaultSelector()
            peers = {client: upstream, upstream: client}
            buffered = {client: bytearray(), upstream: bytearray()}
            read_closed: set[socket.socket] = set()
            write_closed: set[socket.socket] = set()

            def refresh_interest(connection: socket.socket) -> None:
                """Apply TCP backpressure instead of dropping a partial write.

                A source is not read while its peer has a full userspace
                buffer.  The kernel receive window then provides the bounded
                backpressure to the fixture client or server.  This keeps the
                test relay faithful to a stream transport even when a peer is
                deliberately slow.
                """

                events = 0
                peer = peers[connection]
                if (
                    connection not in read_closed
                    and len(buffered[peer]) < MAX_BUFFERED_BYTES
                ):
                    events |= selectors.EVENT_READ
                if buffered[connection] and connection not in write_closed:
                    events |= selectors.EVENT_WRITE
                if not events:
                    try:
                        selector.unregister(connection)
                    except KeyError:
                        pass
                    return
                try:
                    selector.modify(connection, events)
                except KeyError:
                    selector.register(connection, events)
                except OSError:
                    raise

            def close_completed_write(source: socket.socket) -> None:
                """Forward EOF only after all preceding bytes reach its peer."""

                destination = peers[source]
                if (
                    source in read_closed
                    and not buffered[destination]
                    and destination not in write_closed
                ):
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    write_closed.add(destination)

            selector.register(client, selectors.EVENT_READ)
            selector.register(upstream, selectors.EVENT_READ)
            try:
                while not STOP.is_set():
                    events = selector.select(0.25)
                    if not events:
                        continue
                    for key, mask in events:
                        source = key.fileobj
                        destination = peers[source]
                        if mask & selectors.EVENT_READ:
                            try:
                                payload = source.recv(65536)
                            except BlockingIOError:
                                payload = None
                            if payload is None:
                                continue
                            if payload:
                                buffered[destination].extend(payload)
                            else:
                                read_closed.add(source)

                        if mask & selectors.EVENT_WRITE and buffered[source]:
                            try:
                                written = source.send(buffered[source])
                            except BlockingIOError:
                                written = 0
                            if written:
                                del buffered[source][:written]

                        close_completed_write(client)
                        close_completed_write(upstream)
                        refresh_interest(client)
                        refresh_interest(upstream)
                    if not selector.get_map():
                        return
            except OSError:
                return
            finally:
                selector.close()


def self_test() -> None:
    """Exercise startup, target rollover, and slow-peer stream forwarding."""
    with tempfile.TemporaryDirectory(prefix="northstar-listener-relay-test-") as raw_directory:
        directory = Path(raw_directory)
        readiness_file = directory / "ready.json"
        target_file = directory / "target.txt"
        occupied_readiness_file = directory / "occupied-ready.json"
        occupied_payload = b'{"existing":"readiness-proof"}\n'
        occupied_readiness_file.write_bytes(occupied_payload)
        try:
            publish_readiness(
                occupied_readiness_file,
                "0123456789abcdef",
                "relay-self-test",
                40123,
            )
        except RuntimeError:
            pass
        else:
            raise RuntimeError("relay readiness publication overwrote an existing record")
        if occupied_readiness_file.read_bytes() != occupied_payload:
            raise RuntimeError("relay readiness publication changed an existing record")
        first_upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        first_upstream.bind(("127.0.0.1", 0))
        first_upstream.listen(1)
        second_upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        second_upstream.bind(("127.0.0.1", 0))
        second_upstream.listen(1)
        target_file.write_text(
            f"127.0.0.1:{first_upstream.getsockname()[1]}\n", encoding="ascii"
        )
        received: list[bytes] = []

        def receive_exact(connection: socket.socket, expected: int) -> bytes:
            chunks: list[bytes] = []
            remaining = expected
            while remaining:
                chunk = connection.recv(remaining)
                if not chunk:
                    raise RuntimeError("relay peer closed before the expected payload arrived")
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)

        def serve_first_upstream() -> None:
            client, _address = first_upstream.accept()
            with client:
                received.append(receive_exact(client, len(b"ping-first")))
                client.sendall(b"pong-first")

        large_payload = os.urandom(2 * 1024 * 1024)

        def serve_second_upstream() -> None:
            client, _address = second_upstream.accept()
            with client:
                received.append(receive_exact(client, len(large_payload)))
                client.sendall(hashlib.sha256(received[-1]).digest())

        first_thread = threading.Thread(target=serve_first_upstream, daemon=True)
        second_thread = threading.Thread(target=serve_second_upstream, daemon=True)
        first_thread.start()
        second_thread.start()

        # Keep the startup-failure path honest: the direct child exits first,
        # while its descendant ignores TERM and retains inherited diagnostic
        # pipes.  A ready file removes scheduling luck from this regression:
        # the descendant has installed its handler and inherited the pipe
        # before we wait for its direct parent to exit.
        stubborn_child_ready = directory / "stubborn-child.ready"
        stubborn_child_program = (
            "import os, pathlib, signal, sys, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii'); "
            "sys.stderr.write('relay-startup-stubborn-descendant\\n'); "
            "sys.stderr.flush(); time.sleep(60)"
        )
        stubborn_parent_program = (
            "import subprocess, sys; "
            f"subprocess.Popen([sys.executable, '-c', {stubborn_child_program!r}, sys.argv[1]]); "
            "sys.stderr.write('relay-startup-parent-exited\\n'); "
            "sys.stderr.flush()"
        )
        stubborn = subprocess.Popen(
            [
                sys.executable,
                "-c",
                stubborn_parent_program,
                str(stubborn_child_ready),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        startup_deadline = time.monotonic() + 2
        while not stubborn_child_ready.exists() and time.monotonic() < startup_deadline:
            time.sleep(0.01)
        if not stubborn_child_ready.exists():
            raise RuntimeError("relay startup descendant did not become ready")
        try:
            stubborn_child_pid = int(
                stubborn_child_ready.read_text(encoding="ascii").strip()
            )
        except ValueError as error:
            raise RuntimeError("relay startup descendant published an invalid PID") from error
        if os.name == "posix" and os.getpgid(stubborn_child_pid) != stubborn.pid:
            raise RuntimeError("relay startup descendant escaped its private process group")
        while stubborn.poll() is None and time.monotonic() < startup_deadline:
            time.sleep(0.01)
        if stubborn.poll() != 0:
            raise RuntimeError("relay startup parent did not exit after launching its descendant")
        stubborn_diagnostics = terminate_and_collect(stubborn, grace_seconds=0.25)
        if "relay-startup-stubborn-descendant" not in stubborn_diagnostics:
            raise RuntimeError("relay startup diagnostic cleanup was not bounded")

        command = [
            sys.executable,
            __file__,
            "--readiness-file",
            str(readiness_file),
            "--nonce",
            "0123456789abcdef",
            "--purpose",
            "relay-self-test",
            "--target-file",
            str(target_file),
        ]
        relay = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 5
            while not readiness_file.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if not readiness_file.exists():
                raise RuntimeError(
                    "relay did not publish readiness: "
                    f"{terminate_and_collect(relay)}"
                )
            record = json.loads(readiness_file.read_text(encoding="utf-8"))
            if record.get("pid") != relay.pid:
                raise RuntimeError("relay readiness PID did not match child")
            address = record.get("listeners", {}).get("relay-self-test", "")
            host, separator, raw_port = address.rpartition(":")
            if host != "127.0.0.1" or not separator or not raw_port.isdigit():
                raise RuntimeError("relay readiness address was invalid")
            with socket.create_connection((host, int(raw_port)), timeout=3) as client:
                client.sendall(b"ping-first")
                if receive_exact(client, len(b"pong-first")) != b"pong-first":
                    raise RuntimeError("relay did not preserve the first bidirectional stream")
            first_thread.join(3)
            if received != [b"ping-first"]:
                raise RuntimeError(f"relay first target did not receive expected bytes: {received!r}")

            # A restarted child replaces the dynamic target.  New S2S
            # connections must use that new target, without moving the relay
            # endpoint already embedded in the peer's startup DNS overrides.
            target_file.write_text(
                f"127.0.0.1:{second_upstream.getsockname()[1]}\n", encoding="ascii"
            )
            with socket.create_connection((host, int(raw_port)), timeout=3) as client:
                client.sendall(large_payload)
                if (
                    receive_exact(client, hashlib.sha256().digest_size)
                    != hashlib.sha256(large_payload).digest()
                ):
                    raise RuntimeError("relay lost or reordered bytes while its target was under backpressure")
            second_thread.join(10)
            if received != [b"ping-first", large_payload]:
                raise RuntimeError("relay target rollover did not preserve the complete second stream")
        finally:
            terminate_and_collect(relay)
            first_upstream.close()
            second_upstream.close()


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        print("test listener relay self-test PASS")
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument("--readiness-file", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--purpose", required=True)
    parser.add_argument("--target-file", required=True)
    arguments = parser.parse_args()
    if not 16 <= len(arguments.nonce) <= 128 or any(char not in "0123456789abcdef" for char in arguments.nonce):
        raise ValueError("relay readiness nonce must be lowercase hexadecimal")
    if not arguments.purpose.replace("-", "").isalnum() or not arguments.purpose.islower():
        raise ValueError("relay purpose must be canonical lowercase alphanumeric/hyphen")

    def stop(_signal: int, _frame: object) -> None:
        STOP.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    listener.settimeout(0.25)
    port = listener.getsockname()[1]
    publish_readiness(Path(arguments.readiness_file), arguments.nonce, arguments.purpose, port)
    print(f"relay-ready purpose={arguments.purpose} listener=127.0.0.1:{port}", flush=True)
    try:
        while not STOP.is_set():
            try:
                client, _address = listener.accept()
            except TimeoutError:
                continue
            thread = threading.Thread(
                target=relay_connection,
                args=(client, Path(arguments.target_file)),
                daemon=True,
            )
            thread.start()
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"test listener relay failed: {error}", file=sys.stderr)
        raise SystemExit(1)
