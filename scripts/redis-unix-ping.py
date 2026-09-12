#!/usr/bin/env python3
"""Prove a private Redis Unix socket is live using the Redis wire protocol.

The cluster fixtures deliberately use a private Unix socket rather than a TCP
listener.  Their readiness proof must therefore exercise that exact socket,
not merely trust a Redis log message or an optional redis-cli installation.
"""

from __future__ import annotations

import argparse
import os
import socket
import stat
import sys


PING = b"*1\r\n$4\r\nPING\r\n"
PONG = b"+PONG\r\n"


def describe_socket(path: str, socket_stat: os.stat_result) -> str:
    return (
        f"socket={path!r} device={socket_stat.st_dev} inode={socket_stat.st_ino} "
        f"uid={socket_stat.st_uid} gid={socket_stat.st_gid} "
        f"mode={stat.S_IMODE(socket_stat.st_mode):04o}"
    )


def fail(reason: str, detail: str) -> int:
    print(f"redis_unix_ping status=failed reason={reason} {detail}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, dest="socket_path")
    parser.add_argument("--timeout-seconds", type=float, default=0.25)
    args = parser.parse_args()

    if args.timeout_seconds <= 0 or args.timeout_seconds > 5:
        return fail("invalid_timeout", f"timeout_seconds={args.timeout_seconds!r}")

    try:
        before = os.lstat(args.socket_path)
    except OSError as error:
        return fail("socket_stat", f"socket={args.socket_path!r} error={error}")
    if not stat.S_ISSOCK(before.st_mode):
        return fail("not_unix_socket", describe_socket(args.socket_path, before))
    if before.st_uid != os.geteuid():
        return fail("unexpected_socket_owner", describe_socket(args.socket_path, before))
    if stat.S_IMODE(before.st_mode) != 0o700:
        return fail("unexpected_socket_mode", describe_socket(args.socket_path, before))

    response = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(args.timeout_seconds)
            client.connect(args.socket_path)
            client.sendall(PING)
            while len(response) < 256 and not response.endswith(b"\r\n"):
                chunk = client.recv(256 - len(response))
                if not chunk:
                    break
                response.extend(chunk)
    except OSError as error:
        return fail(
            "connect_or_ping",
            f"{describe_socket(args.socket_path, before)} error={error}",
        )

    try:
        after = os.lstat(args.socket_path)
    except OSError as error:
        return fail("socket_restat", f"socket={args.socket_path!r} error={error}")
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        return fail(
            "socket_replaced_during_probe",
            f"before=({before.st_dev},{before.st_ino}) "
            f"after=({after.st_dev},{after.st_ino})",
        )
    if response != PONG:
        return fail(
            "unexpected_response",
            f"{describe_socket(args.socket_path, after)} response={bytes(response)!r}",
        )

    print(
        "redis_unix_ping status=ok "
        f"{describe_socket(args.socket_path, after)} response=PONG"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
