#!/usr/bin/env python3
"""Check bidirectional direct delivery between the two isolated core guests."""

from __future__ import annotations

import importlib.util
import pathlib
import time


def main() -> None:
    path = pathlib.Path(__file__).with_name("local-vm-lab-federation.py")
    spec = importlib.util.spec_from_file_location("northstar_lab_federation", path)
    assert spec and spec.loader
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    password = pathlib.Path(
        "/home/lab/northstar/secrets/prosody-test-password"
    ).read_text().strip()
    domain = "ns-a.lab.test"
    a = lab.connect_peer(domain, "alice", password, host="ns-a.lab.test", resource="lab-a")
    try:
        b = lab.connect_peer(domain, "alice", password, host="ns-b.lab.test", resource="lab-b")
        try:
            for source, target, resource in ((a, b, "lab-b"), (b, a, "lab-a")):
                marker = f"lab-cross-node-{time.time_ns()}"
                source.sendall(
                    f"<message to='alice@{domain}/{resource}' type='chat' "
                    f"id='{marker}'><body>{marker}</body></message>".encode()
                )
                assert marker in lab.receive_until(target, marker, timeout=20)
                print(f"cross-node direct delivery to {resource}: {marker}")
        finally:
            b.close()
    finally:
        a.close()


if __name__ == "__main__":
    main()
