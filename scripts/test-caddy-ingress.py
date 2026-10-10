#!/usr/bin/env python3
"""Exercise the shipped Caddy policy on private loopback listeners only.

Uses a supplied Caddy binary (CI extracts it from the Compose-pinned image).
The backend is a small fixture returning early application body rejections;
REST deadline/admission behavior is separately tested against real Axum sockets.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from lib.http_response_diagnostics import summarize_http_response


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        if self.path.startswith("/api/reject/"):
            # Admission can reject from headers alone. A proxy may coalesce
            # the first tiny body fragment, so waiting for it here would test
            # the fixture's blocking read instead of an early response.
            status = int(self.path.rsplit("/", 1)[1])
            content = json.dumps({"error": {"code": f"fixture_{status}"}}).encode()
        else:
            content = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.path == "/http-bind":
                # A completed BOSH body may legitimately hold its response
                # longer than both the default and BOSH body-read deadlines.
                time.sleep(31)
            status = 200
        self.send_response(status)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Connection", "close")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(content)
        self.close_connection = True

    do_PUT = do_POST

    def do_GET(self):
        assert self.path == "/xmpp-websocket"
        accept = base64.b64encode(hashlib.sha1((self.headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        frame = self.rfile.read(10)
        assert frame[:2] == b"\x89\x84" and len(frame) == 10, frame
        payload = bytes(frame[6 + i] ^ frame[2 + i] for i in range(4))
        self.wfile.write(b"\x8a\x04" + payload)
        self.close_connection = True

    def log_message(self, *_args):
        pass


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def read_to_close(stream, *, rejection_status=None):
    chunks = []
    try:
        while chunk := stream.recv(65536):
            chunks.append(chunk)
    except OSError:
        if rejection_status is not None:
            preview = b""
            for chunk in chunks:
                preview += chunk[:512 - len(preview)]
                if len(preview) == 512:
                    break
            try:
                print(
                    f"synthetic early-body-rejection: case=POST /api/reject/{rejection_status} "
                    f"expected_status={rejection_status} declared_body_bytes=128 sent_body_bytes=1 "
                    f"transport=tls response_diagnostic={json.dumps(summarize_http_response(chunks), separators=(',', ':'))} "
                    f"partial_reply_prefix_512={preview!r}",
                    file=sys.stderr, flush=True,
                )
            except Exception:
                pass  # A diagnostic write must not replace the receive error.
        raise
    return b"".join(chunks)


def tls_socket(port, certificate, timeout=3):
    # This one-use certificate belongs only to the loopback fixture.
    context = ssl.create_default_context(cafile=str(certificate))
    return context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=timeout), server_hostname="localhost")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--caddy", required=True)
    parser.add_argument("--backend-port", type=int)
    parser.add_argument("--admin-port", type=int)
    args = parser.parse_args()
    caddy = str(Path(args.caddy).resolve())
    if args.backend_port is not None:
        assert 0 < args.backend_port < 65536 and args.admin_port and 0 < args.admin_port < 65536
    template = (Path(__file__).resolve().parents[1] / "deploy/Caddyfile").read_text()
    assert template.count("{$XMPP_DOMAIN}") == template.count("xmpp:8080") == 1
    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="northstar-caddy-ingress-") as directory:
            directory = Path(directory)
            port = free_port()
            certificate, key = directory / "tls.crt", directory / "tls.key"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", str(key), "-out", str(certificate)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            config = template.replace("{$XMPP_DOMAIN}", f"https://127.0.0.1:{port}").replace("xmpp:8080", f"127.0.0.1:{args.backend_port or backend.server_port}")
            config = config.replace("{\n", "{\n    admin off\n    auto_https disable_redirects\n", 1)
            config = config.replace(f"https://127.0.0.1:{port} {{", f"https://127.0.0.1:{port} {{\n    bind 127.0.0.1\n    tls {certificate} {key}")
            path = directory / "Caddyfile"
            path.write_text(config)
            env = dict(os.environ, XDG_CONFIG_HOME=str(directory / "config"), XDG_DATA_HOME=str(directory / "data"))
            adapted = subprocess.check_output([caddy, "adapt", "--config", str(path), "--adapter", "caddyfile"], env=env)
            servers = json.loads(adapted)["apps"]["http"]["servers"]
            assert len(servers) == 1
            settings = next(iter(servers.values()))
            assert settings["listen"] == [f"127.0.0.1:{port}"]
            assert settings["read_header_timeout"] == 10_000_000_000
            assert settings["read_timeout"] == 20_000_000_000
            assert settings["idle_timeout"] == 60_000_000_000
            assert settings["max_header_bytes"] == 64_000
            def body_handlers(value):
                if isinstance(value, dict):
                    if value.get("handler") == "request_body":
                        yield value
                    for child in value.values():
                        yield from body_handlers(child)
                elif isinstance(value, list):
                    for child in value:
                        yield from body_handlers(child)
            policies = list(body_handlers(settings))
            assert sorted(p["read_timeout"] for p in policies) == [20_000_000_000, 30_000_000_000, 900_000_000_000]
            assert [p.get("max_size") for p in policies if p.get("max_size")] == [262144]
            subprocess.run([caddy, "validate", "--config", str(path), "--adapter", "caddyfile"], env=env, check=True)
            with (directory / "caddy.log").open("w+") as log:
                process = subprocess.Popen([caddy, "run", "--config", str(path), "--adapter", "caddyfile"], env=env, stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                                break
                        except OSError:
                            if process.poll() is not None or time.monotonic() >= deadline:
                                raise RuntimeError("Caddy fixture did not start")
                            time.sleep(0.05)
                    for status in (408, 413, 429):
                        if args.backend_port is not None:
                            break
                        with tls_socket(port, certificate) as stream:
                            stream.sendall(f"POST /api/reject/{status} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 128\r\n\r\n{{".encode())
                            reply = read_to_close(stream, rejection_status=status)
                            assert reply.startswith(f"HTTP/1.1 {status} ".encode()), reply
                            assert f"fixture_{status}".encode() in reply, reply
                    def fragmented_request(method, route, content):
                        with tls_socket(port, certificate, timeout=36) as stream:
                            stream.sendall(f"{method} {route} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {len(content)}\r\nConnection: close\r\n\r\n".encode() + content[:1])
                            # A legitimate upload may take longer than the
                            # default 20s ingress budget; prove its exemption.
                            time.sleep(21 if method == "PUT" else 0.05)
                            stream.sendall(content[1:])
                            reply = read_to_close(stream)
                            assert reply.startswith(b"HTTP/1.1 200 "), reply[:200]
                            assert reply.split(b"\r\n\r\n", 1)[1] == content
                    def websocket():
                        with tls_socket(port, certificate) as stream:
                            stream.sendall(b"GET /xmpp-websocket HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
                            reply = b""
                            while not reply.endswith(b"\r\n\r\n"):
                                byte = stream.recv(1)
                                assert byte, reply
                                reply += byte
                            assert reply.startswith(b"HTTP/1.1 101 "), reply
                            time.sleep(21)
                            mask = b"abcd"
                            stream.sendall(b"\x89\x84" + mask + bytes(a ^ b for a, b in zip(b"ping", mask)))
                            assert read_to_close(stream) == b"\x8a\x04ping"
                    if args.backend_port is None:
                        subprocess.run(["node", str(Path(__file__).with_name("test-caddy-http2.mjs")), str(port), str(certificate)], check=True, timeout=10)
                        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                            futures = [executor.submit(fragmented_request, *case) for case in (("POST", "/api/normal", b'{"ok":true}'), ("POST", "/http-bind", b"<body/>"), ("PUT", "/api/v1/upload/test", b"x" * 300000))]
                            futures.append(executor.submit(websocket))
                            for future in futures:
                                future.result()
                    # Incomplete headers must close at the actual shipped 10s
                    # deadline, even before application admission can run.
                    with tls_socket(port, certificate, timeout=14) as stream:
                        started = time.monotonic()
                        stream.sendall(b"POST /api/normal HTTP/1.1\r\nHost:")
                        reply = read_to_close(stream)
                        elapsed = time.monotonic() - started
                        assert elapsed < 13, elapsed
                        assert not reply or reply.startswith(b"HTTP/1.1 400 "), reply
                    if args.backend_port is not None:
                        subprocess.run([sys.executable, str(Path(__file__).with_name("rest-body-wire.py")), "--port", str(port), "--admin-port", str(args.admin_port), "--tls", "--ca-cert", str(certificate)], check=True)
                    print(json.dumps({"status": "passed", "early_body_rejections": [408, 413, 429] if args.backend_port is None else [408, 429], "fragmented_routes": 3 if args.backend_port is None else 1, "long_poll_and_websocket": "passed" if args.backend_port is None else "separate fixture", "header_timeout_seconds": round(elapsed, 2), "fixture": "loopback TLS/HTTP1; real application" if args.backend_port else "loopback TLS/HTTP1; fixture upstream"}))
                except BaseException:
                    log.seek(0)
                    print(log.read())
                    raise
                finally:
                    process.terminate()
                    process.wait(timeout=10)
                    process = None
    finally:
        if process is not None:
            process.kill()
            process.wait(timeout=10)
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
