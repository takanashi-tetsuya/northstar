#!/usr/bin/env python3
"""Bounded unauthenticated slow-body regression against the owned lab server."""
import argparse
import json
import socket
import ssl
import time

TLS_PORT = None
TLS_CONTEXT = None


def open_socket(port, timeout):
    stream = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    if port == TLS_PORT:
        return TLS_CONTEXT.wrap_socket(stream, server_hostname="localhost")
    return stream


def connect(port, method, path, body=b"{", length=128):
    stream = open_socket(port, 23)
    stream.sendall(f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n\r\n".encode() + body)
    return stream


def read_closed(stream, expected):
    with stream:
        data = bytearray()
        while part := stream.recv(65536):
            data.extend(part)
    assert data.startswith(f"HTTP/1.1 {expected} ".encode()), data[:300]
    assert b"x-request-id:" in data.lower(), data[:300]
    return bytes(data)


def ordinary_json(port):
    # Valid fragmented JSON, rejected by the Credentials schema rather than
    # by the body guard. No account, authentication attempt or DB write.
    with open_socket(port, 3) as stream:
        stream.sendall(b"POST /api/v1/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{")
        time.sleep(0.03)
        stream.sendall(b"}")
        read_closed(stream, 400)


def main():
    global TLS_PORT, TLS_CONTEXT
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--admin-port", type=int, required=True)
    parser.add_argument("--tls", action="store_true", help="use the private fixture TLS certificate on the public port")
    parser.add_argument("--ca-cert", help="trusted certificate for the private TLS fixture")
    args = parser.parse_args()
    assert 0 < args.port < 65536 and 0 < args.admin_port < 65536
    TLS_PORT = args.port if args.tls else None
    if args.tls:
        assert args.ca_cert, "TLS fixture requires its explicit trust root"
        TLS_CONTEXT = ssl.create_default_context(cafile=args.ca_cert)
    ordinary_json(args.port)
    routes = [("POST", "/api/v1/login")] * 4 + [("POST", "/api/v1/passkeys/login/start")] * 2 + [("DELETE", "/api/v1/session")] * 2
    pending = []
    started = time.monotonic()
    try:
        for method, path in routes:
            pending.append(connect(args.port, method, path))
        # Let the fixture TCP relay deliver all eight complete header blocks.
        time.sleep(0.3)
        for port in [args.port, args.admin_port]:
            denied = connect(port, "POST", "/api/v1/login")
            denied.settimeout(3)
            reply = read_closed(denied, 429)
            assert b"retry-after: 1" in reply.lower(), reply
        for stream in pending:
            reply = read_closed(stream, 408)
            assert b'"code":"request_timeout"' in reply, reply
            assert b"connection: close" in reply.lower(), reply
        elapsed = time.monotonic() - started
        assert 14 <= elapsed < 23, elapsed
    finally:
        for stream in pending:
            stream.close()
    ordinary_json(args.port)
    # Cancellation also releases the production permit without waiting for
    # its 15s expiry; the subsequent fragmented request has a 3s socket bound.
    cancelled = [connect(args.port, "POST", "/api/v1/login") for _ in range(8)]
    time.sleep(0.1)
    for stream in cancelled:
        stream.close()
    time.sleep(0.3)
    ordinary_json(args.port)
    print(json.dumps({"status": "passed", "incomplete_bodies": 8, "elapsed_seconds": round(elapsed, 2), "shared_public_admin_limit": "passed", "fragmented_json_and_reclaimed_capacity": "passed", "scope": "real application; private loopback fixture only"}))


if __name__ == "__main__":
    main()
