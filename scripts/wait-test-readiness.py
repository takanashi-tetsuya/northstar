#!/usr/bin/env python3
"""Verify and print a nonce-bound Northstar test readiness record.

Usage: wait-test-readiness.py <record> <nonce> <pid> [timeout-seconds]

The child owns its listeners and writes the record only after binding them.
This program rejects stale, forged, partial, or mismatched records instead of
turning a port number into an unsafe bind-close-launch lease.
"""

import json
import math
import os
import re
import socket
import stat
import sys
import tempfile
import time
from urllib.parse import urlsplit


NONCE = re.compile(r"^[0-9a-f]{16,128}$")
PURPOSE = re.compile(r"^[a-z0-9-]{1,64}$")


def fail(message):
    raise ValueError(message)


def verify(record, nonce, pid):
    if record.get("version") != 1:
        fail("unsupported readiness record version")
    if record.get("instance_nonce") != nonce:
        fail("readiness nonce did not match the parent-issued nonce")
    if record.get("pid") != pid:
        fail("readiness PID did not match the spawned child PID")
    listeners = record.get("listeners")
    if not isinstance(listeners, dict) or not listeners:
        fail("readiness record has no listeners")
    normalized = {}
    for purpose, address in listeners.items():
        if not isinstance(purpose, str) or not PURPOSE.fullmatch(purpose):
            fail("readiness listener purpose is not canonical")
        if not isinstance(address, str) or ":" not in address:
            fail("readiness listener address is invalid")
        host, port = address.rsplit(":", 1)
        if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
            fail("readiness listener address has an invalid port")
        normalized[purpose] = address
    return normalized


def require_live_child(pid):
    try:
        os.kill(pid, 0)
        # kill(0) alone also accepts a child that exited but is not yet reaped.
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as source:
                if source.read().rsplit(")", 1)[1].split()[0] == "Z":
                    fail("child exited before completing readiness")
        except FileNotFoundError:
            pass
    except ProcessLookupError:
        fail("child exited before completing readiness")
    except PermissionError:
        fail("cannot verify ownership of the readiness child PID")


def startup_deadline(raw):
    deadline = float(raw)
    if not math.isfinite(deadline) or deadline > time.monotonic() + 15:
        fail("startup deadline must fit the original 15 second window")
    return deadline


def read_record(path):
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, encoding="utf-8") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            fail("readiness record must be a regular file")
        if metadata.st_size > 8192:
            fail("readiness record exceeded its 8192 byte bound")
        contents = source.read(8193)
        if len(contents.encode("utf-8")) > 8192:
            fail("readiness record exceeded its 8192 byte bound")
    record = json.loads(contents)
    if not isinstance(record, dict):
        fail("readiness record must be a JSON object")
    return record


def wait_for_record(path, nonce, pid, timeout, deadline=None):
    if not NONCE.fullmatch(nonce):
        fail("expected readiness nonce is not canonical")
    if pid <= 0:
        fail("expected child PID must be positive")
    deadline = min(time.monotonic() + timeout, deadline) if deadline is not None else time.monotonic() + timeout
    latest = None
    while time.monotonic() < deadline:
        require_live_child(pid)
        try:
            listeners = verify(read_record(path), nonce, pid)
        except FileNotFoundError:
            pass
        except (OSError, ValueError, json.JSONDecodeError) as error:
            latest = str(error)
        else:
            require_live_child(pid)
            if time.monotonic() >= deadline:
                fail("nonce-bound readiness record arrived after the startup deadline")
            return listeners
        time.sleep(0.025)
    fail("timed out waiting for nonce-bound readiness: " + (latest or "record was never published"))


def readiness_address(url):
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or parsed.username is not None or parsed.password is not None
            or parsed.path != "/readyz" or parsed.query or parsed.fragment
            or parsed.port is None or not 1 <= parsed.port <= 65535):
        fail("HTTP readiness must use a fixture-owned loopback /readyz endpoint")
    return parsed.hostname, parsed.port


def probe_http_readiness(url, deadline):
    """Read a bounded close-delimited reply under one absolute I/O deadline."""
    address = readiness_address(url)

    def remaining():
        budget = deadline - time.monotonic()
        if budget <= 0:
            raise TimeoutError("startup HTTP readiness deadline expired")
        return budget

    with socket.create_connection(address, timeout=remaining()) as stream:
        stream.settimeout(remaining())
        stream.sendall((f"GET /readyz HTTP/1.1\r\nHost: 127.0.0.1:{address[1]}\r\n"
                       "Connection: close\r\n\r\n").encode("ascii"))
        reply = bytearray()
        while True:
            stream.settimeout(remaining())
            block = stream.recv(min(4096, 8193 - len(reply)))
            if not block:
                break
            reply.extend(block)
            if len(reply) > 8192:
                fail("HTTP readiness response exceeded its 8192 byte bound")
        headers, separator, body = bytes(reply).partition(b"\r\n\r\n")
        if not separator or len(headers) > 4096 or len(body) > 4096:
            fail("HTTP readiness response is malformed or exceeded its header/body bound")
        status_line = headers.split(b"\r\n", 1)[0].split(b" ", 2)
        if (len(status_line) < 2 or status_line[0] not in (b"HTTP/1.0", b"HTTP/1.1")
                or re.fullmatch(rb"[1-5][0-9]{2}", status_line[1]) is None):
            fail("HTTP readiness status line is malformed")
        return int(status_line[1]), body.decode("utf-8", errors="replace")


def wait_for_http_readiness(path, nonce, pid, deadline, urls):
    if not NONCE.fullmatch(nonce) or pid <= 0:
        fail("HTTP readiness requires a canonical nonce and positive child PID")
    if not urls:
        fail("HTTP readiness requires at least one endpoint")
    for url in urls:
        readiness_address(url)
    latest = "no successful HTTP health observation"
    logged_latest = None
    diagnostic_count = 0
    while time.monotonic() < deadline:
        require_live_child(pid)
        listeners = verify(read_record(path), nonce, pid)
        require_live_child(pid)
        if time.monotonic() >= deadline:
            break
        backend = "http://" + listeners.get("http", "") + "/readyz"
        if urls[0] != backend:
            fail("HTTP readiness backend does not match the nonce-bound listener")
        healthy = True
        for url in urls:
            require_live_child(pid)
            try:
                status, body = probe_http_readiness(url, deadline)
                if status == 200 and body.strip() == "ready":
                    continue
                rendered = json.dumps(body)
                if len(rendered) > 4096:
                    rendered = rendered[:4096] + "..."
                latest = f"url={url} status={status} response={rendered}"
            except OSError as error:
                latest = f"url={url} transport={type(error).__name__}"
            if latest != logged_latest:
                if diagnostic_count < 8:
                    print("startup HTTP readiness pending: " + latest, file=sys.stderr)
                elif diagnostic_count == 8:
                    print("startup HTTP readiness: further changing reasons omitted until final failure", file=sys.stderr)
                diagnostic_count += 1
                logged_latest = latest
            healthy = False
            break
        if healthy:
            require_live_child(pid)
            if time.monotonic() < deadline:
                return
        time.sleep(max(0, min(0.05, deadline - time.monotonic())))
    fail("startup HTTP readiness exceeded the shared 15 second deadline: " + latest)


def self_test():
    nonce = "0123456789abcdef"
    pid = os.getpid()
    with tempfile.TemporaryDirectory(prefix="northstar-readiness-test-") as directory:
        path = os.path.join(directory, "ready.json")
        with open(path, "w", encoding="utf-8") as output:
            json.dump(
                {
                    "version": 1,
                    "instance_nonce": nonce,
                    "pid": pid,
                    "listeners": {"http": "127.0.0.1:40123"},
                },
                output,
            )
        assert wait_for_record(path, nonce, pid, 0.1) == {"http": "127.0.0.1:40123"}
        try:
            wait_for_record(path, nonce, pid + 1, 0.01)
        except ValueError:
            return
        raise AssertionError("mismatched PID was accepted")


def main(argv):
    if argv == ["--self-test"]:
        self_test()
        return 0
    if argv == ["--startup-deadline"]:
        print(time.monotonic() + 15)
        return 0
    if argv[:1] == ["--http-ready"]:
        try:
            if len(argv) < 6:
                fail("HTTP readiness requires identity, deadline and endpoints")
            _, path, nonce, raw_pid, raw_deadline, *urls = argv
            wait_for_http_readiness(path, nonce, int(raw_pid), startup_deadline(raw_deadline), urls)
            return 0
        except (ValueError, OSError) as error:
            print(f"readiness verification failed: {error}", file=sys.stderr)
            return 1
    deadline = None
    if len(argv) >= 2 and argv[-2] == "--deadline":
        try:
            deadline = startup_deadline(argv[-1])
        except ValueError as error:
            print(f"readiness verification failed: {error}", file=sys.stderr)
            return 1
        argv = argv[:-2]
    if len(argv) not in (3, 4):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    path, nonce, raw_pid, *raw_timeout = argv
    try:
        pid = int(raw_pid)
        timeout = float(raw_timeout[0]) if raw_timeout else 15.0
        if timeout <= 0 or timeout > 120:
            fail("readiness timeout must be greater than zero and at most 120 seconds")
        for purpose, address in sorted(wait_for_record(path, nonce, pid, timeout, deadline).items()):
            print(f"{purpose}={address}")
        return 0
    except (ValueError, OSError) as error:
        print(f"readiness verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
