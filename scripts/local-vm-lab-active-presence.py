#!/usr/bin/env python3
"""Measure one self-presence route acknowledgement in the isolated VM lab."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import time
import uuid


DOMAIN = "ns-a.lab.test"


def measure(client: object, resource: str) -> float:
    started = time.monotonic_ns()
    client.send("<presence xmlns='jabber:client'><priority>10</priority></presence>")
    reply, _ = client.receive_until("<priority>10</priority>", timeout=20)
    expected = f"from='alice@{DOMAIN}/{resource}'"
    if expected not in reply:
        raise RuntimeError("self-presence did not acknowledge the exact resource")
    return (time.monotonic_ns() - started) / 1_000_000


def self_test() -> None:
    class FakeClient:
        def send(self, stanza: str) -> None:
            assert "<priority>10</priority>" in stanza

        def receive_until(self, marker: str, timeout: int) -> tuple[str, list[str]]:
            assert marker == "<priority>10</priority>" and timeout == 20
            return (
                "<presence from='alice@ns-a.lab.test/active-test'>"
                "<priority>10</priority></presence>", []
            )

    assert measure(FakeClient(), "active-test") >= 0
    try:
        measure(FakeClient(), "different-resource")
    except RuntimeError:
        pass
    else:
        raise AssertionError("wrong resource was accepted")
    print("local-vm-lab-active-presence self-test passed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    spec = importlib.util.spec_from_file_location(
        "northstar_integration", "/home/lab/northstar/integration-wsl.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("lab integration helper is unavailable")
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    lab.HTTP_HOST = "127.0.0.1"
    lab.HTTP_PORT = 8080
    lab.DOMAIN = DOMAIN
    password = Path("/home/lab/northstar/secrets/prosody-test-password").read_text().strip()
    resource = f"active-{uuid.uuid4().hex[:12]}"
    client = lab.XmppWebSocket("alice", password, resource, initial_presence=False)
    try:
        elapsed_ms = measure(client, resource)
        print(json.dumps({
            "probe": "self-presence", "status": "passed", "resource": resource,
            "ack_ms": elapsed_ms,
        }, sort_keys=True))
    finally:
        client.close()


if __name__ == "__main__":
    main()
