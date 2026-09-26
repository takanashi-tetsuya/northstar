#!/usr/bin/env python3
"""Run a bounded, low-rate mixed smoke soak on the isolated VM lab."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import time


def guest_ip(name: str) -> str:
    leases = subprocess.run(
        ["virsh", "net-dhcp-leases", "northstar-lab"],
        check=True, capture_output=True, text=True,
    ).stdout
    match = re.search(
        rf"\b(192\.168\.197\.\d+)/\d+\s+{re.escape('northstar-lab-' + name)}\b",
        leases,
    )
    if not match:
        raise RuntimeError(f"no private address for {name}")
    return match.group(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hours", type=float, default=24.0)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    args = parser.parse_args()
    if not 1 <= args.hours <= 72:
        parser.error("--hours must be 1..72")
    if not re.fullmatch(r"[a-f0-9]{64}", args.expected_binary_sha256):
        parser.error("invalid binary SHA-256")
    key = Path(os.environ.get("NORTHSTAR_LAB_SSH_KEY", "/tmp/northstar-lab-keys/id_ed25519"))
    if not key.is_file():
        parser.error("lab SSH key is missing")
    ssh = [
        "ssh", "-i", str(key), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
        "-o", f"UserKnownHostsFile={key.parent / 'known_hosts'}",
    ]
    guests = {name: f"lab@{guest_ip(name)}" for name in ("ns-a", "ns-b", "infra")}

    def run(name: str, command: str, timeout: int = 45) -> str:
        result = subprocess.run(
            ssh + [guests[name], command], capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode:
            raise RuntimeError(
                f"{name} probe exited {result.returncode}: "
                f"{(result.stdout + result.stderr)[-1200:]}"
            )
        return result.stdout.strip()

    for name in ("ns-a", "ns-b"):
        observed = run(name, "sha256sum /home/lab/northstar/rust-xmpp-server").split()[0]
        if observed != args.expected_binary_sha256:
            raise RuntimeError(f"candidate binary differs on {name}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    deadline = start + args.hours * 3600
    iteration = 0
    with args.output.open("a", encoding="utf-8", buffering=1) as log:
        while time.monotonic() < deadline:
            now = dt.datetime.now(dt.timezone.utc).isoformat()
            record: dict[str, object] = {"time_utc": now, "iteration": iteration}
            try:
                record["cross_node"] = run(
                    "ns-a", "cd /home/lab/northstar && python3 local-vm-lab-cluster-delivery.py"
                )
                if iteration % 5 == 0:
                    for peer in ("prosody", "ejabberd"):
                        record[f"federation_{peer}"] = run(
                            "ns-a",
                            f"cd /home/lab/northstar && python3 local-vm-lab-federation.py {peer}",
                        )
                # A fresh slot immediately after a smoke run can hit the
                # account's upload admission window. Space these writes out.
                if iteration > 0 and iteration % 90 == 0:
                    record["upload"] = run(
                        "ns-a", "cd /home/lab/northstar && python3 local-vm-lab-upload.py"
                    )
                for name in ("ns-a", "ns-b"):
                    record[f"rss_kib_{name}"] = int(run(name,
                        "pid=$(systemctl show northstar-lab.service -p MainPID --value); "
                        "test \"$pid\" -gt 0 && ps -o rss= -p \"$pid\""))
                record["postgres_wal_bytes"] = int(run("infra",
                    "sudo -u postgres psql -d xmpp --no-psqlrc -Atqc "
                    "'SELECT wal_bytes FROM pg_stat_wal'"))
                record["status"] = "passed"
            except Exception as error:
                record["status"] = "failed"
                record["error"] = str(error)
                log.write(json.dumps(record, sort_keys=True) + "\n")
                log.flush()
                os.fsync(log.fileno())
                raise
            log.write(json.dumps(record, sort_keys=True) + "\n")
            if iteration % 10 == 0:
                log.flush()
                os.fsync(log.fileno())
            iteration += 1
            next_tick = start + iteration * 60
            time.sleep(max(0, min(next_tick, deadline) - time.monotonic()))


if __name__ == "__main__":
    main()
