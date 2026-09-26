#!/usr/bin/env python3
"""Check S2S delivery just beyond the isolated lab's 300-second idle limit.

Copy this script alongside integration-wsl.py and local-vm-lab-federation.py
on ns-a. Run it only with a frozen candidate after CI, not during another soak.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import sys
import time


DOMAIN = "ns-a.lab.test"
BINARY = Path("/home/lab/northstar/rust-xmpp-server")
PASSWORD = Path("/home/lab/northstar/secrets/prosody-test-password")
HEARTBEAT_NS = 60_000_000_000
MIN_BOUNDARY_NS = 300_000_000_000
MAX_BOUNDARY_NS = 301_000_000_000


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load lab helper {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def has_chat_marker(raw: str, marker: str) -> bool:
    """Reject an error bounce carrying the same ID as a delivered message."""
    for opening in re.findall(r"<message\b[^>]*>", raw):
        attributes = dict(
            (key, value)
            for key, _, value in re.findall(r"\b([\w:-]+)\s*=\s*(['\"])(.*?)\2", opening)
        )
        if attributes.get("id") == marker and attributes.get("type") == "chat":
            return True
    return False


def utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


@contextmanager
def evidence_file(output: Path):
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", buffering=1) as log:
            yield log
    finally:
        output.chmod(0o400)
        sidecar = output.with_name(output.name + ".sha256")
        descriptor = os.open(sidecar, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as checksum:
            checksum.write(f"{digest(output)}  {output.name}\n")
            checksum.flush()
            os.fsync(checksum.fileno())
        sidecar.chmod(0o400)


def wait_for_boundary(target_ns: int, alice, peer: socket.socket, emit) -> None:
    next_heartbeat = time.monotonic_ns() + HEARTBEAT_NS
    while True:
        now = time.monotonic_ns()
        if now >= target_ns:
            return
        if now >= next_heartbeat and next_heartbeat < target_ns:
            # These keep C2S sockets alive without sending an S2S stanza.
            alice.send("idle-boundary", opcode=9)
            peer.sendall(b" ")
            emit("client_keepalive")
            next_heartbeat += HEARTBEAT_NS
            continue
        time.sleep(min(1.0, max(0.0, (min(target_ns, next_heartbeat) - now) / 1e9)))


def run(args: argparse.Namespace) -> None:
    lab_root = Path(__file__).resolve().parent
    helper_path = lab_root / "local-vm-lab-federation.py"
    fixture_path = lab_root / "integration-wsl.py"
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.with_name(output.name + ".sha256").exists():
        raise FileExistsError("checksum sidecar already exists")
    with evidence_file(output) as log:
        def emit(event: str, **fields) -> None:
            record = {
                "event": event,
                "utc": utc_stamp(),
                "monotonic_ns": time.monotonic_ns(),
                **fields,
            }
            log.write(json.dumps(record, sort_keys=True) + "\n")
            log.flush()
            os.fsync(log.fileno())

        peer = None
        alice = None
        try:
            observed_binary = digest(BINARY)
            emit(
                "start",
                peer=args.peer,
                rounds=args.rounds,
                gap_seconds=args.gap_seconds,
                expected_binary_sha256=args.expected_binary_sha256,
                observed_binary_sha256=observed_binary,
                probe_sha256=digest(Path(__file__)),
                federation_helper_sha256=digest(helper_path),
                integration_helper_sha256=digest(fixture_path),
            )
            if observed_binary != args.expected_binary_sha256:
                raise RuntimeError("running Northstar binary differs from frozen candidate")

            federation = load("northstar_lab_federation", helper_path)
            fixture = load("northstar_lab_integration", fixture_path)
            fixture.HTTP_HOST = "127.0.0.1"
            fixture.HTTP_PORT = 8080
            fixture.DOMAIN = DOMAIN
            domain = f"{args.peer}.lab.test"
            user = "bob" if args.peer == "prosody" else "carol"
            password = PASSWORD.read_text().strip()
            peer = federation.connect_peer(domain, user, password)
            alice = federation.connect_northstar_client(fixture, password)
            emit("clients_ready", alice_resource=alice.resource, peer_user=f"{user}@{domain}")

            def outbound(round_number: int) -> None:
                marker = f"idle-out-{time.time_ns()}"
                sent_at = time.monotonic_ns()
                alice.send(
                    f"<message xmlns='jabber:client' to='{user}@{domain}' type='chat' "
                    f"id='{marker}'><body>{marker}</body></message>"
                )
                emit("sent", round=round_number, direction="northstar_to_peer", marker=marker,
                     send_monotonic_ns=sent_at)
                raw = federation.receive_until(peer, marker, timeout=30)
                emit("received", round=round_number, direction="northstar_to_peer",
                     marker=marker, raw=raw, latency_ms=(time.monotonic_ns() - sent_at) / 1e6)
                if not has_chat_marker(raw, marker):
                    raise AssertionError("peer did not receive a chat stanza for outbound marker")

            def inbound(round_number: int, previous_sent: int | None = None) -> int:
                marker = f"idle-in-{time.time_ns()}"
                sent_at = time.monotonic_ns()
                peer.sendall(
                    f"<message to='alice@{DOMAIN}' type='chat' "
                    f"id='{marker}'><body>{marker}</body></message>".encode()
                )
                gap_ns = None if previous_sent is None else sent_at - previous_sent
                emit("sent", round=round_number, direction="peer_to_northstar", marker=marker,
                     send_monotonic_ns=sent_at, since_previous_inbound_ns=gap_ns)
                try:
                    raw, frames = alice.receive_until(marker, timeout=30)
                except (TimeoutError, EOFError) as error:
                    peer_reply = federation.peer_reply_after_timeout(peer, marker)
                    emit("inbound_failure", round=round_number, marker=marker,
                         client_error=str(error), peer_reply=peer_reply)
                    raise
                emit("received", round=round_number, direction="peer_to_northstar",
                     marker=marker, raw=raw, frames=frames,
                     latency_ms=(time.monotonic_ns() - sent_at) / 1e6)
                if not has_chat_marker(raw, marker):
                    raise AssertionError(
                        "Northstar did not deliver a chat stanza for inbound marker"
                    )
                return sent_at

            outbound(0)
            previous_sent = inbound(0)
            gap_ns = round(args.gap_seconds * 1e9)
            for round_number in range(1, args.rounds + 1):
                target = previous_sent + gap_ns
                wait_for_boundary(target, alice, peer, emit)
                current_sent = inbound(round_number, previous_sent)
                actual_gap = current_sent - previous_sent
                if not MIN_BOUNDARY_NS <= actual_gap <= MAX_BOUNDARY_NS:
                    raise RuntimeError(
                        f"boundary timing missed: {actual_gap / 1e9:.6f}s; "
                        "result is inconclusive"
                    )
                outbound(round_number)
                previous_sent = current_sent
            emit("result", status="passed", verified_boundaries=args.rounds)
        except Exception as error:
            emit("result", status="failed", error_type=type(error).__name__, error=str(error))
            raise
        finally:
            if alice is not None:
                alice.close()
            if peer is not None:
                peer.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("peer", choices=("prosody", "ejabberd"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--rounds", type=int, default=3)
    # The failed soak crossed the 300-second limit by about 1 ms. Aim 50 ms
    # beyond it so scheduling jitter still samples the one-second grace.
    parser.add_argument("--gap-seconds", type=float, default=300.05)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{64}", args.expected_binary_sha256):
        parser.error("invalid binary SHA-256")
    if not 1 <= args.rounds <= 6:
        parser.error("--rounds must be 1..6")
    if not 300.001 <= args.gap_seconds <= 300.5:
        parser.error("--gap-seconds must be 300.001..300.5")
    run(args)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"S2S idle-boundary check failed: {error}", file=sys.stderr)
        raise
