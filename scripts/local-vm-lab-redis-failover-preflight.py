#!/usr/bin/env python3
"""Read-only, pre-fault Redis/Sentinel preflight for the isolated six-VM lab.

This checks the initial infra-primary topology only. It does not trigger or
qualify a promotion, and cannot establish Northstar's unattended recovery.
"""

import json
import ipaddress
import os
from pathlib import Path
import subprocess
import sys


GUESTS = ("infra", "ejabberd", "dns-ca")
PRIVATE_NETWORK = ipaddress.ip_network("192.168.197.0/24")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def run(args: list[str], *, stdin: bytes | None = None) -> str:
    result = subprocess.run(args, input=stdin, capture_output=True,
                            timeout=40, check=False)
    require(result.returncode == 0, f"command failed: {args[0]}")
    return result.stdout.decode().strip()


def leases() -> dict[str, str]:
    output = run(["virsh", "net-dhcp-leases", "northstar-lab"])
    addresses: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split()
        for guest in GUESTS:
            if f"northstar-lab-{guest}" not in fields:
                continue
            address = next((field.split("/", 1)[0] for field in fields
                            if field.startswith("192.168.197.") and "/" in field), None)
            try:
                valid = address is not None and ipaddress.ip_address(address) in PRIVATE_NETWORK
            except ValueError:
                valid = False
            require(valid, f"unsafe DHCP address for {guest}")
            require(guest not in addresses, f"duplicate DHCP lease for {guest}")
            addresses[guest] = address
    require(set(addresses) == set(GUESTS), "missing isolated Redis/Sentinel guest")
    return addresses


def collect(guest: str, address: str, key: Path, script: bytes) -> dict:
    ssh = ["ssh", "-T", "-i", str(key), "-o", "BatchMode=yes",
           "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=yes",
           "-o", f"UserKnownHostsFile={key.parent / 'known_hosts'}",
           f"lab@{address}", "sudo", "python3", "-", guest]
    output = run(ssh, stdin=script)
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid preflight response from {guest}") from error


def verify(snapshots: dict[str, dict]) -> dict[str, str]:
    require(set(snapshots) == set(GUESTS), "missing preflight guest")
    for guest in GUESTS:
        snapshot = snapshots[guest]
        require(snapshot.get("guest") == guest, f"preflight guest mismatch: {guest}")
        sentinel = snapshot.get("sentinel")
        require(isinstance(sentinel, dict) and sentinel.get("guest") == guest and
                sentinel.get("role") == "sentinel" and
                sentinel.get("master") == "infra.lab.test" and
                str(sentinel.get("quorum", "")).startswith("OK "),
                f"Sentinel quorum/master disagreement: {guest}")
    primary = snapshots["infra"].get("data")
    replica = snapshots["ejabberd"].get("data")
    require(isinstance(primary, dict) and primary.get("role") == "master" and
            primary.get("replication", {}).get("role") == "master",
            "infra is not the Redis primary")
    require(isinstance(replica, dict) and replica.get("role") == "slave" and
            replica.get("replication", {}).get("role") == "slave" and
            replica.get("replication", {}).get("master_link_status") == "up" and
            replica.get("replication", {}).get("master_host") == "infra.lab.test",
            "ejabberd is not following the expected primary")
    require(snapshots["dns-ca"].get("data") is None,
            "dns-ca unexpectedly hosts a data node")
    return {"primary": "infra.lab.test:6379", "replica": "ejabberd.lab.test:6379",
            "sentinel_voters": "3/3", "phase": "pre-fault-only"}


def main() -> None:
    require(len(sys.argv) == 1,
            "usage: local-vm-lab-redis-failover-preflight.py")
    project_dir = Path(__file__).resolve().parent
    key = Path(os.environ.get("NORTHSTAR_LAB_SSH_KEY",
                              "/tmp/northstar-lab-keys/id_ed25519"))
    require(key.is_file() and not key.is_symlink(), "lab SSH key is missing")
    guest_script = (project_dir / "local-vm-lab-redis-failover-guest.py").read_bytes()
    run(["bash", str(project_dir / "local-vm-lab-preflight.sh")])
    addresses = leases()
    snapshots = {guest: collect(guest, addresses[guest], key, guest_script)
                 for guest in GUESTS}
    print(json.dumps(verify(snapshots), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"Redis failover preflight failed: {error}", file=sys.stderr)
        sys.exit(1)
