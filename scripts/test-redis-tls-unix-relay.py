#!/usr/bin/env python3
"""A child-owned TLS/mTLS TCP frontend for a private Redis Unix socket.

The cluster fixture deliberately keeps Redis itself off TCP.  This helper is
the narrow transport boundary used when the fixture must still exercise a
``rediss://`` client, certificate validation, and required client
authentication.  It binds ``127.0.0.1:0`` itself, publishes a nonce- and
PID-bound readiness record, and forwards complete byte streams to the exact
private Unix-domain socket supplied by its parent.

It is test infrastructure, not a production Redis proxy.  Its lifetime is
strictly owned by the fixture which started it.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


STOP = threading.Event()


def publish_readiness(path: Path, nonce: str, purpose: str, port: int) -> None:
    """Atomically publish the same contract used by Northstar test listeners."""

    if not path.parent.is_dir():
        raise RuntimeError(f"readiness parent directory does not exist: {path.parent}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
        # `link` is create-only: unlike `replace`, it cannot overwrite a
        # record planted between any parent-side cleanup and this child's
        # publication.  The fixture's verifier consequently sees either this
        # exact PID/nonce record or a hard failure, never a substituted file.
        os.link(temporary, path)
        os.unlink(temporary)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def copy_stream(source: socket.socket, destination: socket.socket) -> None:
    """Forward one half of a stream and preserve ordered EOF propagation."""

    try:
        while not STOP.is_set():
            payload = source.recv(65536)
            if not payload:
                break
            destination.sendall(payload)
    except (ssl.SSLError, OSError):
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def serve_connection(raw_client: socket.socket, context: ssl.SSLContext, unix_socket: str) -> None:
    """Authenticate a TLS peer before opening its disposable Unix-socket path."""

    with raw_client:
        try:
            with context.wrap_socket(raw_client, server_side=True) as client:
                upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    upstream.connect(unix_socket)
                    with upstream:
                        client_to_upstream = threading.Thread(
                            target=copy_stream,
                            args=(client, upstream),
                            daemon=True,
                        )
                        upstream_to_client = threading.Thread(
                            target=copy_stream,
                            args=(upstream, client),
                            daemon=True,
                        )
                        client_to_upstream.start()
                        upstream_to_client.start()
                        client_to_upstream.join()
                        upstream_to_client.join()
                finally:
                    upstream.close()
        except (ssl.SSLError, OSError):
            # Missing or untrusted client certificates are expected negative
            # test cases.  The owning fixture asserts them at the protocol
            # boundary without treating an individual rejected connection as
            # a relay crash.
            return


def make_context(certificate: str, private_key: str, ca_certificate: str, client_auth: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key)
    context.load_verify_locations(cafile=ca_certificate)
    context.verify_mode = (
        ssl.CERT_REQUIRED if client_auth == "required" else ssl.CERT_OPTIONAL
    )
    return context


def validate_arguments(arguments: argparse.Namespace) -> None:
    if not 16 <= len(arguments.nonce) <= 128 or any(
        character not in "0123456789abcdef" for character in arguments.nonce
    ):
        raise ValueError("relay readiness nonce must be 16-128 lowercase hexadecimal characters")
    if not arguments.purpose.replace("-", "").isalnum() or not arguments.purpose.islower():
        raise ValueError("relay purpose must be canonical lowercase alphanumeric/hyphen")
    if not Path(arguments.unix_socket).is_socket():
        raise ValueError("Redis relay target is not an existing Unix-domain socket")
    for label, value in (
        ("certificate", arguments.certificate),
        ("private key", arguments.private_key),
        ("CA certificate", arguments.ca_certificate),
    ):
        if not Path(value).is_file():
            raise ValueError(f"Redis relay {label} is not a regular file")


def run(arguments: argparse.Namespace) -> int:
    validate_arguments(arguments)
    context = make_context(
        arguments.certificate,
        arguments.private_key,
        arguments.ca_certificate,
        arguments.client_auth,
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    listener.settimeout(0.25)
    port = listener.getsockname()[1]
    publish_readiness(Path(arguments.readiness_file), arguments.nonce, arguments.purpose, port)
    print(
        f"redis-tls-unix-relay-ready purpose={arguments.purpose} listener=127.0.0.1:{port}",
        flush=True,
    )
    try:
        while not STOP.is_set():
            try:
                client, _address = listener.accept()
            except TimeoutError:
                continue
            thread = threading.Thread(
                target=serve_connection,
                args=(client, context, arguments.unix_socket),
                daemon=True,
            )
            thread.start()
    finally:
        listener.close()
    return 0


def openssl(*arguments: str) -> None:
    subprocess.run(
        ["openssl", *arguments],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def self_test() -> None:
    """Cover readiness, mTLS admission, byte forwarding, and scoped shutdown."""

    with tempfile.TemporaryDirectory(prefix="northstar-redis-tls-relay-test-") as raw_directory:
        directory = Path(raw_directory)
        unix_socket = directory / "redis.sock"
        ca_key = directory / "ca.key"
        ca_certificate = directory / "ca.crt"
        server_key = directory / "server.key"
        server_csr = directory / "server.csr"
        server_certificate = directory / "server.crt"
        client_key = directory / "client.key"
        client_csr = directory / "client.csr"
        client_certificate = directory / "client.crt"
        readiness_file = directory / "ready.json"
        stop_echo = threading.Event()
        echo_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        echo_listener.bind(str(unix_socket))
        echo_listener.listen(8)
        echo_listener.settimeout(0.1)

        def echo_server() -> None:
            while not stop_echo.is_set():
                try:
                    connection, _ = echo_listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    while True:
                        payload = connection.recv(65536)
                        if not payload:
                            break
                        connection.sendall(payload)

        echo_thread = threading.Thread(target=echo_server, daemon=True)
        echo_thread.start()
        openssl(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=Northstar Relay Test CA",
            "-keyout", str(ca_key), "-out", str(ca_certificate),
        )
        openssl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
            "-keyout", str(server_key), "-out", str(server_csr),
        )
        openssl(
            "x509", "-req", "-days", "1", "-in", str(server_csr),
            "-CA", str(ca_certificate), "-CAkey", str(ca_key), "-CAcreateserial",
            "-copy_extensions", "copy", "-out", str(server_certificate),
        )
        openssl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=relay-client",
            "-keyout", str(client_key), "-out", str(client_csr),
        )
        openssl(
            "x509", "-req", "-days", "1", "-in", str(client_csr),
            "-CA", str(ca_certificate), "-CAkey", str(ca_key), "-CAcreateserial",
            "-out", str(client_certificate),
        )
        command = [
            sys.executable,
            __file__,
            "--readiness-file", str(readiness_file),
            "--nonce", "0123456789abcdef",
            "--purpose", "redis-relay-self-test",
            "--unix-socket", str(unix_socket),
            "--certificate", str(server_certificate),
            "--private-key", str(server_key),
            "--ca-certificate", str(ca_certificate),
            "--client-auth", "required",
        ]
        relay = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not readiness_file.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if not readiness_file.exists():
                if relay.poll() is None:
                    relay.terminate()
                    try:
                        _stdout, stderr = relay.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        relay.kill()
                        _stdout, stderr = relay.communicate(timeout=5)
                else:
                    _stdout, stderr = relay.communicate(timeout=1)
                raise RuntimeError(
                    "relay did not publish readiness within its bounded startup window: "
                    f"{stderr[-4096:]}"
                )
            record = json.loads(readiness_file.read_text(encoding="utf-8"))
            if record.get("pid") != relay.pid:
                raise RuntimeError("relay readiness PID did not match child")
            address = record.get("listeners", {}).get("redis-relay-self-test", "")
            host, separator, raw_port = address.rpartition(":")
            if host != "127.0.0.1" or not separator or not raw_port.isdigit():
                raise RuntimeError("relay readiness address was invalid")
            port = int(raw_port)
            trusted = ssl.create_default_context(cafile=str(ca_certificate))
            trusted.load_cert_chain(str(client_certificate), str(client_key))
            with socket.create_connection((host, port), timeout=3) as raw_client:
                with trusted.wrap_socket(raw_client, server_hostname="localhost") as client:
                    payload = os.urandom(131_072)
                    client.sendall(payload)
                    received = bytearray()
                    while len(received) < len(payload):
                        part = client.recv(len(payload) - len(received))
                        if not part:
                            raise RuntimeError("relay closed before the echoed payload arrived")
                        received.extend(part)
                    if bytes(received) != payload:
                        raise RuntimeError("relay changed or reordered a TLS stream")
            untrusted = ssl.create_default_context(cafile=str(ca_certificate))
            try:
                with socket.create_connection((host, port), timeout=3) as raw_client:
                    with untrusted.wrap_socket(raw_client, server_hostname="localhost") as client:
                        client.sendall(b"must-be-rejected")
                        client.recv(1)
            except (ssl.SSLError, OSError):
                pass
            else:
                raise RuntimeError("required mTLS relay accepted a client without a certificate")

            collision = directory / "collision.ready.json"
            collision.write_text("sentinel\n", encoding="utf-8")
            try:
                publish_readiness(collision, "0123456789abcdef", "redis-relay-collision", port)
            except FileExistsError:
                pass
            else:
                raise RuntimeError("create-only readiness publication overwrote an existing record")
            if collision.read_text(encoding="utf-8") != "sentinel\n":
                raise RuntimeError("create-only readiness publication changed an existing record")
        finally:
            if relay.poll() is None:
                relay.terminate()
                try:
                    relay.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    relay.kill()
                    relay.wait(timeout=5)
            stop_echo.set()
            echo_listener.close()
            echo_thread.join(1)


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        self_test()
        print("test Redis TLS Unix relay self-test PASS")
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument("--readiness-file", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--purpose", required=True)
    parser.add_argument("--unix-socket", required=True)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--ca-certificate", required=True)
    parser.add_argument("--client-auth", choices=("required", "optional"), required=True)
    arguments = parser.parse_args(argv)

    def stop(_signal: int, _frame: object) -> None:
        STOP.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    return run(arguments)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"test Redis TLS Unix relay failed: {error}", file=sys.stderr)
        raise SystemExit(1)
