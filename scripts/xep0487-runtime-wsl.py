#!/usr/bin/env python3
"""Local HTTPS XEP-0487 discovery and two-domain federation probe."""

from __future__ import annotations

import http.server
import importlib.util
import json
import os
import pathlib
import socket
import ssl
import sys
import time


ROOT = pathlib.Path(__file__).resolve().parent
PASSWORD = "xep0487-password-123"
ALICE = "xep0487_alice"
BOB = "xep0487_bob"


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} must be set")
    return value


def _activated_https_socket(port: int) -> socket.socket:
    """Adopt the one listener passed by the root-only test activator.

    This is deliberately a test-fixture-only protocol.  Northstar itself never
    accepts an inherited descriptor in normal operation.  The activating parent
    remains responsible for the privileged bind until this child publishes its
    nonce-bound takeover acknowledgement.
    """

    raw_fd = _required_environment("XEP0487_INHERITED_HTTPS_FD")
    try:
        fd = int(raw_fd)
    except ValueError as error:
        raise RuntimeError("XEP0487_INHERITED_HTTPS_FD must be an integer") from error
    if fd < 0:
        raise RuntimeError("XEP0487_INHERITED_HTTPS_FD must be non-negative")
    if os.geteuid() == 0:
        raise RuntimeError("the XEP-0487 HTTPS handler must not run as root")

    listener = socket.socket(fileno=fd)
    if listener.family != socket.AF_INET or listener.type != socket.SOCK_STREAM:
        listener.close()
        raise RuntimeError("inherited XEP-0487 listener is not an IPv4 TCP socket")
    address = listener.getsockname()
    if address[0] != "127.0.0.1" or address[1] != port:
        listener.close()
        raise RuntimeError("inherited XEP-0487 listener is not bound to the expected loopback address")
    return listener


def _write_takeover_ack(port: int) -> None:
    """Atomically publish child ownership after TLS has adopted the listener."""

    ack_path = pathlib.Path(_required_environment("XEP0487_TAKEOVER_ACK"))
    nonce = _required_environment("XEP0487_TAKEOVER_NONCE")
    if not ack_path.is_absolute() or len(nonce) < 16:
        raise RuntimeError("invalid XEP-0487 takeover acknowledgement configuration")
    if ack_path.exists():
        raise RuntimeError("XEP-0487 takeover acknowledgement already exists")

    payload = json.dumps(
        {
            "version": 1,
            "nonce": nonce,
            "pid": os.getpid(),
            "euid": os.geteuid(),
            "listener": f"127.0.0.1:{port}",
        },
        separators=(",", ":"),
    ).encode("utf-8")
    temporary = ack_path.with_name(f".{ack_path.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        # The parent created an empty acknowledgement path contract and
        # validates the nonce/PID before dropping its descriptor.  A rename
        # makes partial JSON impossible for the waiting parent to observe.
        os.replace(temporary, ack_path)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def serve_https(*, activated: bool = False) -> None:
    port = int(os.environ.get("XEP0487_HTTPS_PORT", "443"))
    s2s_port = int(os.environ["XEP0487_S2S_PORT"])
    certificate = os.environ["XEP0487_HTTPS_CERT"]
    key = os.environ["XEP0487_HTTPS_KEY"]
    mode_file = pathlib.Path(os.environ["XEP0487_MODE_FILE"])
    correct_pin = os.environ["XEP0487_PUBLIC_KEY_PIN"]

    def document(mode: str) -> bytes:
        xmpp: dict[str, object] = {"ttl": 1 if mode == "stale-valid" else 60}
        if mode == "wrong-pin":
            xmpp["public-key-pins-sha-256"] = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
        elif mode != "missing-pin":
            xmpp["public-key-pins-sha-256"] = [correct_pin]
        return json.dumps(
            {
                "xmpp": xmpp,
                "links": [
                    {
                        "rel": "urn:xmpp:alt-connections:s2s-tls",
                        "port": s2s_port,
                        "priority": 0,
                        "weight": 1,
                        "sni": "remote.localhost",
                        "ips": ["127.0.0.1"],
                    }
                ],
            },
            separators=(",", ":"),
        ).encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
            mode = mode_file.read_text(encoding="ascii").strip()
            host = self.headers.get("Host", "")
            print(
                f"{self.command} {self.path} host={host} mode={mode} uid={os.geteuid()}",
                flush=True,
            )
            if self.path != "/.well-known/host-meta.json":
                self.send_error(404)
                return
            if mode == "timeout":
                time.sleep(14)
            if mode == "redirect" and host.startswith("remote.localhost"):
                self.send_response(302)
                self.send_header(
                    "Location",
                    "https://redirect.remote.localhost/.well-known/host-meta.json",
                )
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            if mode == "downgrade":
                self.send_response(302)
                self.send_header(
                    "Location",
                    "http://redirect.remote.localhost/.well-known/host-meta.json",
                )
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            body = b"x" * (300 * 1024) if mode == "oversize" else document(mode)
            self.send_response(200)
            self.send_header("Content-Type", "application/jrd+json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

        def log_message(self, _: str, *args: object) -> None:
            return

        def finish(self) -> None:
            # Northstar deliberately reads the complete authenticated HTTPS
            # response and requires a clean TLS close.  The stdlib server
            # normally closes its SSLSocket at TCP level without emitting
            # close_notify, so unwrap explicitly completes the TLS shutdown.
            try:
                super().finish()
            finally:
                try:
                    self.connection.unwrap()
                except (OSError, ssl.SSLError):
                    pass

    if activated:
        listener = _activated_https_socket(port)
        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", port), Handler, bind_and_activate=False
        )
        unused_socket = server.socket
        server.socket = listener
        unused_socket.close()
        server.server_address = listener.getsockname()
        server.server_name, server.server_port = server.server_address
    else:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    context.set_alpn_protocols(["http/1.1"])
    server.socket = context.wrap_socket(server.socket, server_side=True)
    if activated:
        _write_takeover_ack(port)
    server.serve_forever()


def load_fixture(name: str, domain: str, http_port: str):
    saved = {key: os.environ.get(key) for key in ("XMPP_TEST_DOMAIN", "XMPP_TEST_HTTP_PORT")}
    os.environ["XMPP_TEST_DOMAIN"] = domain
    os.environ["XMPP_TEST_HTTP_PORT"] = http_port
    spec = importlib.util.spec_from_file_location(name, ROOT / "integration-wsl.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    return module


def check(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def register(fixture, username: str) -> str:
    status, result = fixture.register_account(username, PASSWORD)
    check(status == 201, f"registration failed for {username}: {status} {result}")
    status, result = fixture.api(
        "POST", "/api/v1/login", {"username": username, "password": PASSWORD}
    )
    check(status == 200, f"login failed for {username}: {status} {result}")
    return result["token"]


def login(fixture, username: str) -> str:
    status, result = fixture.api(
        "POST", "/api/v1/login", {"username": username, "password": PASSWORD}
    )
    check(status == 200, f"login failed for {username}: {status} {result}")
    return result["token"]


def fixtures():
    fixture_a = load_fixture(
        "northstar_xep0487_a", "localhost", os.environ["XEP0487_HTTP_A"]
    )
    fixture_b = load_fixture(
        "northstar_xep0487_b", "remote.localhost", os.environ["XEP0487_HTTP_B"]
    )
    fixture_a.wait_ready()
    fixture_b.wait_ready()
    return fixture_a, fixture_b


def clients(fixture_a, fixture_b):
    alice = fixture_a.XmppWebSocket(ALICE, PASSWORD, "xep0487-a")
    bob = fixture_b.XmppWebSocket(BOB, PASSWORD, "xep0487-b")
    return alice, bob


def run_probe() -> None:
    fixture_a, fixture_b = fixtures()
    alice_token = register(fixture_a, ALICE)
    bob_token = register(fixture_b, BOB)
    alice, bob = clients(fixture_a, fixture_b)
    alice.send_with_pow(
        "<message xmlns='jabber:client' to='xep0487_bob@remote.localhost/xep0487-b' "
        "type='chat' id='xep0487-forward'><body>XEP-0487 HTTPS forward</body></message>",
        alice_token,
    )
    forward, _ = bob.receive_until("xep0487-forward", timeout=30)
    check(
        "XEP-0487 HTTPS forward" in forward
        and "from='xep0487_alice@localhost/xep0487-a'" in forward,
        f"forward XEP-0487 federation delivery failed: {forward}",
    )
    bob.send_with_pow(
        "<message xmlns='jabber:client' to='xep0487_alice@localhost/xep0487-a' "
        "type='chat' id='xep0487-reverse'><body>XEP-0487 reverse</body></message>",
        bob_token,
    )
    reverse, _ = alice.receive_until("xep0487-reverse", timeout=30)
    check(
        "XEP-0487 reverse" in reverse
        and "from='xep0487_bob@remote.localhost/xep0487-b'" in reverse,
        f"reverse federation delivery failed: {reverse}",
    )
    alice.close()
    bob.close()
    time.sleep(0.2)
    print("XEP-0487 local HTTPS discovery and bidirectional federation PASS")


def delivery_probe(marker: str, expect_delivery: bool, timeout: float = 5) -> None:
    fixture_a, fixture_b = fixtures()
    alice_token = login(fixture_a, ALICE)
    alice, bob = clients(fixture_a, fixture_b)
    alice.send_with_pow(
        "<message xmlns='jabber:client' to='xep0487_bob@remote.localhost/xep0487-b' "
        f"type='chat' id='{marker}'><body>{marker}</body></message>",
        alice_token,
    )
    if expect_delivery:
        delivered, _ = bob.receive_until(marker, timeout=timeout)
        check(f"<body>{marker}</body>" in delivered, f"delivery probe failed: {delivered}")
    else:
        try:
            unexpected, _ = bob.receive_until(marker, timeout=timeout)
        except (TimeoutError, socket.timeout):
            pass
        else:
            raise AssertionError(f"rejected XEP-0487 policy delivered a stanza: {unexpected}")
    alice.close()
    bob.close()
    print(f"XEP-0487 probe {marker}: {'delivery' if expect_delivery else 'rejected'} PASS")


def stale_cache_probe() -> None:
    fixture_a, fixture_b = fixtures()
    alice_token = login(fixture_a, ALICE)
    alice, bob = clients(fixture_a, fixture_b)
    mode_file = pathlib.Path(os.environ["XEP0487_MODE_FILE"])
    mode_file.write_text("stale-valid\n", encoding="ascii")
    alice.send_with_pow(
        "<message xmlns='jabber:client' to='xep0487_bob@remote.localhost/xep0487-b' "
        "type='chat' id='stale-seed'><body>stale-seed</body></message>",
        alice_token,
    )
    bob.receive_until("stale-seed", timeout=30)
    time.sleep(1.3)
    mode_file.write_text("timeout\n", encoding="ascii")
    alice.send_with_pow(
        "<message xmlns='jabber:client' to='xep0487_bob@remote.localhost/xep0487-b' "
        "type='chat' id='stale-recovery'><body>stale-recovery</body></message>",
        alice_token,
    )
    recovered, _ = bob.receive_until("stale-recovery", timeout=30)
    check("<body>stale-recovery</body>" in recovered, f"stale cache recovery failed: {recovered}")
    alice.close()
    bob.close()
    print("XEP-0487 expired metadata fallback after HTTPS timeout PASS")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "serve":
        serve_https()
    elif len(sys.argv) == 2 and sys.argv[1] == "serve-activated":
        serve_https(activated=True)
    elif len(sys.argv) == 2 and sys.argv[1] == "bootstrap":
        run_probe()
    elif len(sys.argv) == 4 and sys.argv[1] == "deliver":
        delivery_probe(sys.argv[2], True, float(sys.argv[3]))
    elif len(sys.argv) == 4 and sys.argv[1] == "reject":
        delivery_probe(sys.argv[2], False, float(sys.argv[3]))
    elif len(sys.argv) == 2 and sys.argv[1] == "stale":
        stale_cache_probe()
    else:
        raise SystemExit("usage: xep0487-runtime-wsl.py serve|serve-activated|bootstrap|deliver MARKER TIMEOUT|reject MARKER TIMEOUT|stale")
