#!/usr/bin/env python3
"""Verify and print a nonce-bound Northstar test readiness record.

Usage: wait-test-readiness.py <record> <nonce> <pid> [timeout-seconds]

The child owns its listeners and writes the record only after binding them.
This program rejects stale, forged, partial, or mismatched records instead of
turning a port number into an unsafe bind-close-launch lease.
"""

import json
import os
import re
import sys
import tempfile
import time


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


def wait_for_record(path, nonce, pid, timeout):
    if not NONCE.fullmatch(nonce):
        fail("expected readiness nonce is not canonical")
    if pid <= 0:
        fail("expected child PID must be positive")
    deadline = time.monotonic() + timeout
    latest = None
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            fail("child exited before publishing readiness")
        except PermissionError:
            fail("cannot verify ownership of the readiness child PID")
        try:
            with open(path, "r", encoding="utf-8") as source:
                return verify(json.load(source), nonce, pid)
        except FileNotFoundError:
            pass
        except (OSError, ValueError, json.JSONDecodeError) as error:
            latest = str(error)
        time.sleep(0.025)
    fail("timed out waiting for nonce-bound readiness: " + (latest or "record was never published"))


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
    if len(argv) not in (3, 4):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    path, nonce, raw_pid, *raw_timeout = argv
    try:
        pid = int(raw_pid)
        timeout = float(raw_timeout[0]) if raw_timeout else 15.0
        if timeout <= 0 or timeout > 120:
            fail("readiness timeout must be greater than zero and at most 120 seconds")
        for purpose, address in sorted(wait_for_record(path, nonce, pid, timeout).items()):
            print(f"{purpose}={address}")
        return 0
    except (ValueError, OSError) as error:
        print(f"readiness verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
