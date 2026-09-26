#!/usr/bin/env python3
"""Guest half of the isolated ns-b -> Redis fault drill.

The host harness sends this file over SSH. It never modifies the host firewall.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys


LAB_NET = ipaddress.ip_network("192.168.197.0/24")


def command(*args: str, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=10)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr[-500:]}")
    return result


def identity(node_ip: str, infra_ip: str) -> str:
    addresses = json.loads(command("ip", "-j", "-4", "address", "show").stdout)
    matches = [item["ifname"] for item in addresses for addr in item.get("addr_info", [])
               if addr.get("local") == node_ip]
    if len(matches) != 1 or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", matches[0]):
        raise RuntimeError("ns-b lab address has no unique interface")
    if json.loads(command("ip", "-j", "-4", "route", "show", "default").stdout):
        raise RuntimeError("guest has an IPv4 default route")
    if json.loads(command("ip", "-j", "-6", "route", "show", "default").stdout):
        raise RuntimeError("guest has an IPv6 default route")
    route = json.loads(command("ip", "-j", "-4", "route", "get", infra_ip).stdout)
    if len(route) != 1 or route[0].get("dev") != matches[0] or route[0].get("prefsrc", route[0].get("src")) != node_ip:
        raise RuntimeError("Redis route does not use the ns-b lab interface")
    return matches[0]


def names(run_id: str) -> tuple[str, str]:
    if not re.fullmatch(r"[0-9a-f]{12}", run_id):
        raise ValueError("invalid run ID")
    return f"nslab_r_{run_id}", f"nslab-r-{run_id}"


def table_exists(table: str) -> bool:
    result = command("nft", "list", "table", "inet", table, check=False)
    if result.returncode == 0:
        return True
    if "No such file or directory" in result.stderr:
        return False
    raise RuntimeError(f"could not determine whether fault table exists: {result.stderr[-500:]}")


def run(action: str, run_id: str, infra_ip: str, node_ip: str, deadline: int) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("guest helper must run under sudo")
    if ipaddress.ip_address(infra_ip) not in LAB_NET or ipaddress.ip_address(node_ip) not in LAB_NET:
        raise RuntimeError("fault target is outside the isolated lab subnet")
    if infra_ip == node_ip:
        raise RuntimeError("Redis and ns-b addresses must differ")
    if not 60 <= deadline <= 90:
        raise RuntimeError("duration must be 60..90 seconds")
    nft = shutil.which("nft")
    if not nft:
        raise RuntimeError("nft is required on ns-b")
    systemd_run = shutil.which("systemd-run")
    if action in ("preflight", "add") and not systemd_run:
        raise RuntimeError("systemd-run is required for the guest safety timer")
    table, unit = names(run_id)
    # Cleanup must remain possible even if the guest route changes mid-drill.
    interface = identity(node_ip, infra_ip) if action in ("preflight", "add") else None
    if action == "preflight":
        if table_exists(table):
            raise RuntimeError("fault table already exists")
        print(json.dumps({"status": "ready", "interface": interface, "node_ip": node_ip,
                          "infra_ip": infra_ip, "table": table}, sort_keys=True))
    elif action == "add":
        if table_exists(table):
            raise RuntimeError("fault table already exists")
        # The timer survives host SSH loss and deletes only this run's table.
        command(systemd_run, "--quiet", f"--unit={unit}", f"--on-active={deadline + 30}s",
                nft, "delete", "table", "inet", table)
        rules = (f"add table inet {table}\n"
                 f"add chain inet {table} output {{ type filter hook output priority -10; policy accept; }}\n"
                 f"add rule inet {table} output oifname \"{interface}\" ip daddr {infra_ip} tcp dport 6379 drop\n")
        try:
            command(nft, "-f", "-", input_text=rules)
        except Exception:
            if table_exists(table):
                command(nft, "delete", "table", "inet", table, check=False)
            command("systemctl", "stop", f"{unit}.timer", check=False)
            raise
        if not table_exists(table):
            raise RuntimeError("fault table disappeared after installation")
        print(json.dumps({"status": "installed", "table": table, "interface": interface,
                          "auto_remove_after_seconds": deadline + 30}, sort_keys=True))
    elif action == "status":
        result = command(nft, "-a", "list", "table", "inet", table, check=False)
        print(json.dumps({"status": "present" if result.returncode == 0 else "absent",
                          "table": table, "ruleset": result.stdout}, sort_keys=True))
    elif action == "remove":
        if table_exists(table):
            command(nft, "delete", "table", "inet", table)
        if table_exists(table):
            raise RuntimeError("fault table remains after cleanup")
        command("systemctl", "stop", f"{unit}.timer", check=False)
        print(json.dumps({"status": "removed", "table": table}, sort_keys=True))
    else:
        raise RuntimeError("invalid action")


def self_test() -> None:
    assert names("012345abcdef") == ("nslab_r_012345abcdef", "nslab-r-012345abcdef")
    for invalid in ("../../etc", "A" * 12, "0" * 13):
        try:
            names(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted an unsafe run ID")
    print("redis fault guest self-test passed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "add", "status", "remove"), nargs="?")
    parser.add_argument("run_id", nargs="?")
    parser.add_argument("infra_ip", nargs="?")
    parser.add_argument("node_ip", nargs="?")
    parser.add_argument("duration", nargs="?", type=int)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if None in (args.action, args.run_id, args.infra_ip, args.node_ip, args.duration):
        parser.error("action, run ID, infra IP, node IP and duration are required")
    run(args.action, args.run_id, args.infra_ip, args.node_ip, args.duration)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"redis fault guest: {error}", file=sys.stderr)
        sys.exit(1)
