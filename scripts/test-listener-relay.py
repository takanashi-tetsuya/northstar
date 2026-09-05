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
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


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
            selector.register(client, selectors.EVENT_READ, upstream)
            selector.register(upstream, selectors.EVENT_READ, client)
            try:
                while not STOP.is_set():
                    events = selector.select(0.25)
                    if not events:
                        continue
                    for key, _ in events:
                        source = key.fileobj
                        destination = key.data
                        try:
                            payload = source.recv(65536)
                        except BlockingIOError:
                            continue
                        if not payload:
                            return
                        destination.sendall(payload)
            except OSError:
                return
            finally:
                selector.close()


def self_test() -> None:
    """Exercise a child relay with a real target socket and readiness record."""
    with tempfile.TemporaryDirectory(prefix="northstar-listener-relay-test-") as raw_directory:
        directory = Path(raw_directory)
        readiness_file = directory / "ready.json"
        target_file = directory / "target.txt"
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        target_file.write_text(
            f"127.0.0.1:{upstream.getsockname()[1]}\n", encoding="ascii"
        )
        received: list[bytes] = []

        def serve_upstream() -> None:
            client, _address = upstream.accept()
            with client:
                received.append(client.recv(64))
                client.sendall(b"pong")

        server_thread = threading.Thread(target=serve_upstream, daemon=True)
        server_thread.start()
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
        relay = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not readiness_file.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if not readiness_file.exists():
                raise RuntimeError(f"relay did not publish readiness: {relay.stderr.read()}")
            record = json.loads(readiness_file.read_text(encoding="utf-8"))
            if record.get("pid") != relay.pid:
                raise RuntimeError("relay readiness PID did not match child")
            address = record.get("listeners", {}).get("relay-self-test", "")
            host, separator, raw_port = address.rpartition(":")
            if host != "127.0.0.1" or not separator or not raw_port.isdigit():
                raise RuntimeError("relay readiness address was invalid")
            with socket.create_connection((host, int(raw_port)), timeout=3) as client:
                client.sendall(b"ping")
                if client.recv(4) != b"pong":
                    raise RuntimeError("relay did not preserve bidirectional bytes")
            server_thread.join(3)
            if received != [b"ping"]:
                raise RuntimeError(f"relay target did not receive expected bytes: {received!r}")
        finally:
            relay.terminate()
            try:
                relay.wait(timeout=5)
            except subprocess.TimeoutExpired:
                relay.kill()
                relay.wait(timeout=5)
            upstream.close()


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
