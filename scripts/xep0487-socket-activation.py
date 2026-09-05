#!/usr/bin/env python3
"""Root-only socket activation supervisor for the XEP-0487 CI fixture.

The fixture needs a local HTTPS endpoint on TCP/443 to exercise the protocol's
default-port behaviour.  Binding that port is the sole privileged operation:
this supervisor retains the descriptor until a non-root child has adopted it
and issued a one-time, nonce-bound acknowledgement.  It is intentionally not
a Northstar runtime feature and must never be used for production activation.
"""

from __future__ import annotations

import json
import os
import pathlib
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import NoReturn


PORT = 443
ADDRESS = "127.0.0.1"
ACK_TIMEOUT_SECONDS = 15.0


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        fail(f"{name} must be set")
    return value


def runtime_identity() -> tuple[int, int]:
    try:
        uid = int(required("XEP0487_RUNTIME_UID"))
        gid = int(required("XEP0487_RUNTIME_GID"))
    except ValueError as error:
        raise RuntimeError("XEP0487 runtime identity must use numeric uid/gid") from error
    if uid <= 0 or gid <= 0:
        fail("XEP0487 runtime identity must be non-root")
    return uid, gid


def acknowledgement_path() -> pathlib.Path:
    path = pathlib.Path(required("XEP0487_TAKEOVER_ACK"))
    if not path.is_absolute() or path.exists():
        fail("XEP0487 takeover acknowledgement must be a new absolute path")
    if not path.parent.is_dir():
        fail("XEP0487 takeover acknowledgement parent does not exist")
    return path


def validate_acknowledgement(path: pathlib.Path, nonce: str, child_pid: int, uid: int) -> None:
    try:
        metadata = path.lstat()
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("invalid XEP-0487 takeover acknowledgement") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid:
        fail("XEP-0487 takeover acknowledgement has unsafe ownership or permissions")
    # The production path is Linux-only.  Windows does not project POSIX mode
    # bits faithfully, so keep the portable self-test useful without claiming
    # that the Windows development path supports inherited socket activation.
    if os.name == "posix" and metadata.st_mode & 0o077 != 0:
        fail("XEP-0487 takeover acknowledgement has unsafe ownership or permissions")
    expected = {
        "version": 1,
        "nonce": nonce,
        "pid": child_pid,
        "euid": uid,
        "listener": f"{ADDRESS}:{PORT}",
    }
    if data != expected:
        fail("XEP-0487 takeover acknowledgement did not bind the child to this listener")


def stop_child(child: subprocess.Popen[object]) -> None:
    if child.poll() is not None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        child.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    child.wait(timeout=5)


def self_test() -> int:
    """Exercise the ACK contract without binding a privileged port."""

    nonce = "1" * 32
    child_pid = 4242
    with tempfile.TemporaryDirectory(prefix="northstar-xep0487-activation-") as directory:
        path = pathlib.Path(directory) / "takeover.json"
        path.write_text("", encoding="utf-8")
        uid = path.stat().st_uid
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "nonce": nonce,
                    "pid": child_pid,
                    "euid": uid,
                    "listener": f"{ADDRESS}:{PORT}",
                }
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        validate_acknowledgement(path, nonce, child_pid, uid)
        path.write_text("{}", encoding="utf-8")
        try:
            validate_acknowledgement(path, nonce, child_pid, uid)
        except RuntimeError:
            print("XEP-0487 socket activation ACK self-test PASS")
            return 0
    fail("XEP-0487 socket activation accepted a malformed acknowledgement")


def main() -> int:
    if os.geteuid() != 0:
        fail("XEP-0487 socket activation must run as root solely to bind 127.0.0.1:443")
    uid, gid = runtime_identity()
    ack = acknowledgement_path()
    nonce = required("XEP0487_TAKEOVER_NONCE")
    if len(nonce) < 16:
        fail("XEP0487 takeover nonce is too short")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Do not use SO_REUSEADDR/PORT: this fixture proves exclusive descriptor
    # ownership, not a best-effort restart behaviour.
    listener.bind((ADDRESS, PORT))
    listener.listen(socket.SOMAXCONN)
    listener.set_inheritable(True)

    server = pathlib.Path(__file__).with_name("xep0487-runtime-wsl.py")
    environment = os.environ.copy()
    environment["XEP0487_INHERITED_HTTPS_FD"] = str(listener.fileno())
    command = [
        "setpriv",
        f"--reuid={uid}",
        f"--regid={gid}",
        "--init-groups",
        sys.executable,
        str(server),
        "serve-activated",
    ]
    child = subprocess.Popen(
        command,
        env=environment,
        pass_fds=(listener.fileno(),),
        start_new_session=True,
    )
    def stop_on_signal(signum: int, _frame: object) -> None:
        raise RuntimeError(f"received signal {signum} while supervising XEP-0487 handler")

    signal.signal(signal.SIGINT, stop_on_signal)
    signal.signal(signal.SIGTERM, stop_on_signal)
    try:
        deadline = time.monotonic() + ACK_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if child.poll() is not None:
                fail("XEP-0487 handler exited before listener takeover acknowledgement")
            if ack.exists():
                validate_acknowledgement(ack, nonce, child.pid, uid)
                listener.close()
                print(
                    f"takeover-ack pid={child.pid} uid={uid} listener={ADDRESS}:{PORT}",
                    flush=True,
                )
                return child.wait()
            time.sleep(0.02)
        fail("timed out waiting for XEP-0487 listener takeover acknowledgement")
    finally:
        if child.poll() is None:
            stop_child(child)
        if listener.fileno() >= 0:
            listener.close()


if __name__ == "__main__":
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            raise SystemExit(self_test())
        if len(sys.argv) != 1:
            raise SystemExit("usage: xep0487-socket-activation.py [--self-test]")
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"XEP-0487 socket activation failed: {error}", file=sys.stderr)
        raise SystemExit(2)
