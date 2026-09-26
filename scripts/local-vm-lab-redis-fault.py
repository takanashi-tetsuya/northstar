#!/usr/bin/env python3
"""Bounded ns-b -> Redis partition drill for the six-guest isolated lab.

Run --self-test first. Live execution requires --execute and a frozen binary
SHA-256, for example:

    python3 scripts/local-vm-lab-redis-fault.py --execute \
        --expected-binary-sha256 <64-character-hex-digest>

The script changes only a uniquely named nft table inside ns-b. The guest
also schedules an exact-table cleanup in case the host process disappears.
Private raw command outputs, journal logs, and SHA256SUMS go under /tmp.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable
import xml.etree.ElementTree as ET


HERE = Path(__file__).resolve().parent
GUEST_HELPER = HERE / "local-vm-lab-redis-fault-guest.py"
GUESTS = ("ns-a", "ns-b", "prosody", "ejabberd", "infra", "dns-ca")
LAB_NETWORK = ipaddress.ip_network("192.168.197.0/24")
MAX_OUTPUT = 16 * 1024 * 1024


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def private_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


class Evidence:
    def __init__(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        self.path = Path(tempfile.mkdtemp(prefix="northstar-redis-fault-", dir=root))
        self.path.chmod(0o700)
        self.sequence = 0
        self.events = (self.path / "events.jsonl").open("x", encoding="utf-8")
        os.chmod(self.path / "events.jsonl", 0o600)

    def event(self, kind: str, **fields: object) -> None:
        row = {"utc": utc_now(), "monotonic_ns": time.monotonic_ns(), "kind": kind, **fields}
        self.events.write(json.dumps(row, sort_keys=True) + "\n")
        self.events.flush()
        os.fsync(self.events.fileno())

    def record(self, label: str, argv: list[str], result: subprocess.CompletedProcess[bytes]) -> None:
        self.sequence += 1
        name = f"{self.sequence:03d}-{label}"
        if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
            raise RuntimeError(f"{label} output exceeded the 16 MiB evidence bound")
        private_file(self.path / f"{name}.stdout", result.stdout)
        private_file(self.path / f"{name}.stderr", result.stderr)
        self.event("command", label=label, argv=argv, exit_code=result.returncode,
                   stdout_file=f"{name}.stdout", stderr_file=f"{name}.stderr")

    def finish(self) -> None:
        self.events.close()
        manifest = []
        for path in sorted(self.path.iterdir()):
            if path.is_file() and path.name != "SHA256SUMS":
                manifest.append(f"{digest(path.read_bytes())}  {path.name}\n")
        private_file(self.path / "SHA256SUMS", "".join(manifest).encode())
        directory_fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


class Runner:
    def __init__(self, evidence: Evidence) -> None:
        self.evidence = evidence

    def call_result(self, label: str, argv: list[str], *, stdin: bytes | None = None,
                    timeout: int = 20, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        try:
            result = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            partial = subprocess.CompletedProcess(
                argv, 124, error.stdout or b"", error.stderr or b"",
            )
            self.evidence.record(label, argv, partial)
            self.evidence.event("timeout", label=label, seconds=timeout)
            raise RuntimeError(f"{label} exceeded {timeout}s") from error
        self.evidence.record(label, argv, result)
        if check and result.returncode:
            raise RuntimeError(f"{label} exited {result.returncode}; see evidence")
        return result

    def call(self, label: str, argv: list[str], *, stdin: bytes | None = None,
             timeout: int = 20, check: bool = True) -> str:
        return self.call_result(label, argv, stdin=stdin, timeout=timeout,
                                check=check).stdout.decode(errors="replace")


def parse_network(xml: str) -> None:
    root = ET.fromstring(xml)
    if root.tag != "network" or root.findtext("name") != "northstar-lab" or root.find("forward") is not None:
        raise RuntimeError("libvirt network is not the isolated northstar-lab network")
    bridge = root.find("bridge")
    if bridge is None or bridge.get("name") != "virbr-nstar":
        raise RuntimeError("unexpected lab bridge")
    if not any(item.get("address") == "192.168.197.1" for item in root.findall("ip")):
        raise RuntimeError("unexpected lab IPv4 subnet")


def parse_interface_listing(output: str) -> str:
    rows = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 5 and re.fullmatch(r"[0-9a-fA-F:]{17}", parts[4]):
            rows.append(parts)
    if len(rows) != 1 or rows[0][1:3] != ["network", "northstar-lab"]:
        raise RuntimeError("guest has an extra or non-lab virtual interface")
    return rows[0][4].lower()


def lease_address(output: str, guest: str) -> str:
    vm = "northstar-lab-" + guest
    found = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[5] == vm:
            try:
                address = ipaddress.ip_interface(parts[4]).ip
            except ValueError:
                continue
            if address in LAB_NETWORK:
                found.append(str(address))
    if len(set(found)) != 1:
        raise RuntimeError(f"{guest} lacks one unambiguous lab DHCP lease")
    return found[0]


def check_soak_units(output: str) -> None:
    for line in output.splitlines():
        fields = line.lstrip("● ").split()
        if fields and fields[0].startswith("northstar-lab-soak"):
            if len(fields) < 3 or fields[2] in ("active", "activating", "deactivating"):
                raise RuntimeError(f"another lab soak is running: {fields[0]}")


def check_soak_processes() -> None:
    for proc in Path("/proc").iterdir():
        if not proc.name.isdecimal() or int(proc.name) == os.getpid():
            continue
        try:
            args = (proc / "cmdline").read_bytes().split(b"\0")
        except (OSError, PermissionError):
            continue
        # The lab probe may be a direct Python process or an SSH remote command.
        if any(name in arg for arg in args for name in
               (b"local-vm-lab-soak.py", b"local-vm-lab-s2s-idle-boundary.py")):
            raise RuntimeError(f"another VM experiment is running (pid {proc.name})")


class Lab:
    def __init__(self, runner: Runner, key: Path, expected_sha: str, duration: int,
                 run_id: str, process_check: Callable[[], None] = check_soak_processes) -> None:
        self.runner = runner
        self.key = key
        self.expected_sha = expected_sha
        self.duration = duration
        self.run_id = run_id
        self.process_check = process_check
        self.ips: dict[str, str] = {}
        self.ssh_opts = ["-i", str(key), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                         "-o", "StrictHostKeyChecking=yes", "-o",
                         f"UserKnownHostsFile={key.parent / 'known_hosts'}"]

    def ssh(self, guest: str, label: str, command: str, *, stdin: bytes | None = None,
            timeout: int = 20) -> str:
        return self.runner.call(label, ["ssh", *self.ssh_opts, f"lab@{self.ips[guest]}", command],
                                stdin=stdin, timeout=timeout)

    def helper(self, action: str) -> dict[str, object]:
        remote = shlex.join(["sudo", "python3", "-", action, self.run_id,
                              self.ips["infra"], self.ips["ns-b"], str(self.duration)])
        output = self.ssh("ns-b", f"fault-{action}", remote,
                          stdin=GUEST_HELPER.read_bytes(), timeout=20)
        report = json.loads(output)
        if not isinstance(report, dict):
            raise RuntimeError("guest helper did not return a report")
        return report

    def preflight(self) -> None:
        r = self.runner
        parse_network(r.call("network-xml", ["virsh", "net-dumpxml", "northstar-lab"]))
        leases = r.call("dhcp-leases", ["virsh", "net-dhcp-leases", "northstar-lab"])
        for guest in GUESTS:
            vm = f"northstar-lab-{guest}"
            if r.call(f"{guest}-state", ["virsh", "domstate", vm]).strip() != "running":
                raise RuntimeError(f"{guest} is not running")
            parse_interface_listing(r.call(f"{guest}-interfaces", ["virsh", "domiflist", vm]))
            self.ips[guest] = lease_address(leases, guest)
        check_soak_units(r.call("soak-units", ["systemctl", "list-units", "--all", "--type=service",
                                                "--no-legend", "--plain", "northstar-lab-soak*"]))
        self.process_check()
        for guest in GUESTS:
            # Existing preflight checks both IPv4 and IPv6 default routes.
            self.ssh(guest, f"{guest}-routes", "test -z \"$(ip -4 route show default)\" && test -z \"$(ip -6 route show default)\"")
        if self.helper("preflight").get("status") != "ready":
            raise RuntimeError("ns-b fault preflight failed")
        for guest in ("ns-a", "ns-b"):
            if self.ssh(guest, f"{guest}-binary", "sha256sum /home/lab/northstar/rust-xmpp-server").split()[0] != self.expected_sha:
                raise RuntimeError(f"frozen binary differs on {guest}")
            if self.ssh(guest, f"{guest}-service", "systemctl is-active northstar-lab.service").strip() != "active":
                raise RuntimeError(f"{guest} service is not active")
            running = self.ssh(guest, f"{guest}-running-binary",
                               "pid=$(systemctl show northstar-lab.service -p MainPID --value); "
                               "test \"$pid\" -gt 0 && sudo sha256sum \"/proc/$pid/exe\"")
            if running.split()[0] != self.expected_sha:
                raise RuntimeError(f"running process differs from frozen binary on {guest}")

    def probe(self, phase: str) -> None:
        self.ssh("ns-a", f"{phase}-cross-node",
                 "cd /home/lab/northstar && python3 local-vm-lab-cluster-delivery.py", timeout=55)
        self.ssh("ns-a", f"{phase}-federation",
                 "cd /home/lab/northstar && python3 local-vm-lab-federation.py prosody", timeout=55)

    def readyz(self, phase: str, attempt: int, removed_ns: int | None = None,
               timeout: int = 8) -> str:
        result = self.runner.call_result(
            f"{phase}-readyz-{attempt:02d}",
            ["ssh", *self.ssh_opts, f"lab@{self.ips['ns-b']}",
             "curl -sS -i --max-time 2 http://127.0.0.1:8080/readyz"],
            timeout=timeout, check=False,
        )
        response = result.stdout.decode(errors="replace")
        status_line = response.splitlines()[0] if response else ""
        match = re.fullmatch(r"HTTP/[0-9.]+ ([0-9]{3})(?: .*)?", status_line)
        status = match.group(1) if match else "000"
        fields: dict[str, object] = {"phase": phase, "attempt": attempt,
                                     "http_status": status, "exit_code": result.returncode}
        if removed_ns is not None:
            fields["since_cleanup_ms"] = (time.monotonic_ns() - removed_ns) // 1_000_000
        self.runner.evidence.event("readiness_observation", **fields)
        return status if result.returncode == 0 else "000"

    def recovery(self, removed_ns: int, readyz_available: bool) -> None:
        deadline_ns = removed_ns + 55_000_000_000
        if readyz_available:
            for attempt in range(1, 100):
                remaining_ns = deadline_ns - time.monotonic_ns()
                if remaining_ns <= 0:
                    raise RuntimeError("ns-b /readyz did not return HTTP 200 within 55s of fault removal")
                timeout = min(8, max(1, (remaining_ns + 999_999_999) // 1_000_000_000))
                status = self.readyz("recovery", attempt, removed_ns, timeout=timeout)
                if status == "200":
                    elapsed_ms = (time.monotonic_ns() - removed_ns) // 1_000_000
                    self.runner.evidence.event("readiness_restored", since_cleanup_ms=elapsed_ms)
                    break
                if status in ("000", "404"):
                    raise RuntimeError(f"ns-b /readyz disappeared after baseline HTTP 200: {status}")
                remaining_ns = deadline_ns - time.monotonic_ns()
                if remaining_ns > 0:
                    time.sleep(min(2, remaining_ns / 1_000_000_000))
            self.probe("recovery")
        else:
            for c2s_attempt in range(1, 100):
                remaining_ns = deadline_ns - time.monotonic_ns()
                if remaining_ns <= 0:
                    raise RuntimeError("cross-node C2S did not recover within 55s of fault removal")
                timeout = max(1, (remaining_ns + 999_999_999) // 1_000_000_000)
                result = self.runner.call_result(
                    f"recovery-cross-node-attempt-{c2s_attempt:02d}",
                    ["ssh", *self.ssh_opts, f"lab@{self.ips['ns-a']}",
                     "cd /home/lab/northstar && python3 local-vm-lab-cluster-delivery.py"],
                    timeout=min(55, timeout), check=False,
                )
                elapsed_ms = (time.monotonic_ns() - removed_ns) // 1_000_000
                self.runner.evidence.event("c2s_recovery_observation", attempt=c2s_attempt,
                                           exit_code=result.returncode,
                                           since_cleanup_ms=elapsed_ms)
                if result.returncode == 0:
                    self.runner.evidence.event("readiness_restored", since_cleanup_ms=elapsed_ms,
                                               proof="cross-node C2S fallback")
                    break
                remaining_ns = deadline_ns - time.monotonic_ns()
                if remaining_ns > 0:
                    time.sleep(min(5, remaining_ns / 1_000_000_000))
            self.ssh("ns-a", "recovery-federation",
                     "cd /home/lab/northstar && python3 local-vm-lab-federation.py prosody",
                     timeout=55)
        delivery_ms = (time.monotonic_ns() - removed_ns) // 1_000_000
        self.runner.evidence.event("delivery_restored", since_cleanup_ms=delivery_ms,
                                   proof="cross-node and Prosody federation")
        self.link("ns-a", "connected", "recovery")
        self.link("ns-b", "connected", "recovery")
        self.runner.evidence.event("recovery_completed", since_cleanup_ms=delivery_ms)

    def link(self, guest: str, expected: str, phase: str) -> None:
        code = ("import socket,sys\n"
                f"s=socket.socket(); s.settimeout(3); target=({self.ips['infra']!r},6379)\n"
                "try:\n s.connect(target); result='connected'\n"
                "except OSError as e:\n result='blocked:'+type(e).__name__\n"
                "finally:\n s.close()\n"
                "print(result)\n")
        observed = self.ssh(guest, f"{phase}-{guest}-redis-link", "python3 -",
                            stdin=code.encode(), timeout=8).strip()
        if expected == "connected" and observed != expected:
            raise RuntimeError(f"{guest} Redis link did not recover: {observed}")
        if expected == "blocked" and not observed.startswith("blocked:"):
            raise RuntimeError(f"{guest} Redis link remained reachable")

    def fault_phase(self, readyz_available: bool) -> None:
        start = time.monotonic()
        self.runner.evidence.event("fault_started", run_id=self.run_id, duration_seconds=self.duration)
        self.link("ns-b", "blocked", "fault")
        self.link("ns-a", "connected", "fault")
        for guest in ("ns-a", "ns-b"):
            if self.ssh(guest, f"fault-{guest}-service",
                        "systemctl is-active northstar-lab.service").strip() != "active":
                raise RuntimeError(f"{guest} stopped during ns-b partition")
        if self.helper("status").get("status") != "present":
            raise RuntimeError("fault table is absent before planned cleanup")
        if readyz_available:
            for attempt in range(1, 9):
                status = self.readyz("fault", attempt)
                if status == "503":
                    break
                if status in ("000", "404"):
                    raise RuntimeError(f"ns-b /readyz disappeared during Redis partition: {status}")
                time.sleep(2)
            else:
                raise RuntimeError("ns-b /readyz did not fail closed during Redis partition")
        self.ssh("ns-a", "fault-federation",
                 "cd /home/lab/northstar && python3 local-vm-lab-federation.py prosody", timeout=45)
        remaining = self.duration - 5 - (time.monotonic() - start)
        if remaining < 0:
            raise RuntimeError("fault observation exceeded its duration")
        time.sleep(remaining)

    def collect(self, since: str) -> None:
        for guest, unit in (("ns-a", "northstar-lab.service"),
                            ("ns-b", "northstar-lab.service"),
                            ("infra", "northstar-lab-redis.service")):
            remote = shlex.join(["journalctl", "--no-pager", "--output=short-iso-precise",
                                  "-u", unit, "--since", since])
            try:
                self.ssh(guest, f"{guest}-journal", remote, timeout=30)
            except Exception as error:
                self.runner.evidence.event("collection_error", guest=guest, error=str(error))


def execute(lab: Lab) -> None:
    evidence = lab.runner.evidence
    started = utc_now()
    installed = False
    add_attempted = False
    removed_ns: int | None = None
    readyz_available = False
    error: BaseException | None = None
    try:
        lab.preflight()
        lab.probe("baseline")
        lab.link("ns-a", "connected", "baseline")
        lab.link("ns-b", "connected", "baseline")
        baseline_status = lab.readyz("baseline", 1)
        if baseline_status == "200":
            readyz_available = True
        elif baseline_status in ("000", "404"):
            evidence.event("readiness_endpoint_unavailable_at_baseline", http_status=baseline_status)
        else:
            raise RuntimeError(f"ns-b baseline /readyz is not healthy: {baseline_status}")
        add_attempted = True
        report = lab.helper("add")
        if report.get("status") != "installed":
            raise RuntimeError("fault helper did not confirm installation")
        installed = True
        lab.fault_phase(readyz_available)
    except BaseException as caught:
        error = caught
        evidence.event("fault_or_preflight_error", error_type=type(caught).__name__, error=str(caught))
    finally:
        # Even an ambiguous SSH response from add may mean the rule was added.
        # Always attempt exact-table removal once the guest address is known.
        if add_attempted and "ns-b" in lab.ips and "infra" in lab.ips:
            for attempt in range(1, 4):
                try:
                    report = lab.helper("remove")
                    if report.get("status") != "removed":
                        raise RuntimeError("guest did not confirm fault removal")
                    removed_ns = time.monotonic_ns()
                    evidence.event("fault_removed", attempt=attempt, previously_confirmed=installed)
                    break
                except Exception as cleanup_error:
                    evidence.event("cleanup_error", attempt=attempt, error=str(cleanup_error))
                    if attempt == 3:
                        error = RuntimeError("could not confirm fault removal; guest safety timer remains scheduled")
                    else:
                        time.sleep(1)
    try:
        if error is None:
            if removed_ns is None:
                raise RuntimeError("fault removal was not confirmed")
            lab.recovery(removed_ns, readyz_available)
    except BaseException as caught:
        error = caught
        evidence.event("recovery_error", error_type=type(caught).__name__, error=str(caught))
    finally:
        lab.collect(started)
    if error is not None:
        raise error
    evidence.event("result", status="passed", limitation="one short Redis control-plane partition only")


def self_test() -> None:
    network = "<network><name>northstar-lab</name><bridge name='virbr-nstar'/><ip address='192.168.197.1'/></network>"
    parse_network(network)
    for invalid in (network.replace("</network>", "<forward mode='nat'/></network>"),
                    network.replace("virbr-nstar", "virbr-default")):
        try:
            parse_network(invalid)
        except RuntimeError:
            pass
        else:
            raise AssertionError("unsafe virsh network accepted")
    assert parse_interface_listing("Interface Type Source Model MAC\n---\n vnet0 network northstar-lab virtio 52:54:00:aa:bb:cc") == "52:54:00:aa:bb:cc"
    try:
        parse_interface_listing("vnet0 network northstar-lab virtio 52:54:00:aa:bb:cc\nvnet1 network default virtio 52:54:00:aa:bb:dd")
    except RuntimeError:
        pass
    else:
        raise AssertionError("extra VM interface accepted")
    assert lease_address(" 0 2026-01-01 52:54:00:aa:bb:cc ipv4 192.168.197.101/24 northstar-lab-ns-b 01:02", "ns-b") == "192.168.197.101"
    try:
        check_soak_units("northstar-lab-soak-test.service loaded active running soak")
    except RuntimeError:
        pass
    else:
        raise AssertionError("active soak accepted")
    class MockRunner:
        def __init__(self) -> None:
            self.calls: list[tuple[str, list[str]]] = []
        def call(self, label: str, argv: list[str], **_kwargs: object) -> str:
            self.calls.append((label, argv))
            if argv[:2] == ["virsh", "net-dumpxml"]:
                return network
            if argv[:2] == ["virsh", "net-dhcp-leases"]:
                return "".join(f"0 2026 aa ipv4 192.168.197.{101 + i}/24 northstar-lab-{name} aa\n" for i, name in enumerate(GUESTS))
            if argv[:2] == ["virsh", "domstate"]:
                return "running\n"
            if argv[:2] == ["virsh", "domiflist"]:
                return "vnet0 network northstar-lab virtio 52:54:00:aa:bb:cc\n"
            if argv[0] == "systemctl":
                return ""
            if argv[0] == "ssh":
                if label.startswith("fault-"):
                    return json.dumps({"status": {"fault-preflight": "ready", "fault-add": "installed",
                                                  "fault-status": "present", "fault-remove": "removed"}[label]})
                if label.endswith("-binary"):
                    return "a" * 64 + "  rust-xmpp-server\n"
                if label.endswith("-service"):
                    return "active\n"
                if label.endswith("-redis-link"):
                    return "blocked:TimeoutError" if label.startswith("fault-ns-b") else "connected"
                return "probe passed\n"
            raise AssertionError(f"unexpected mock command: {argv}")
        def call_result(self, label: str, argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
            self.calls.append((label, argv))
            if label == "baseline-readyz-01":
                return subprocess.CompletedProcess(argv, 0, b"HTTP/1.1 200 OK\r\n\r\nready", b"")
            raise AssertionError(f"unexpected result call: {label}")
    class MockEvidence:
        def event(self, *_args: object, **_kwargs: object) -> None:
            pass
    runner = MockRunner()
    runner.evidence = MockEvidence()  # type: ignore[attr-defined]
    lab = Lab(runner, Path("/tmp/mock-key"), "a" * 64, 60, "012345abcdef",
              process_check=lambda: None)  # type: ignore[arg-type]
    lab.preflight()
    assert sum(argv[0] == "virsh" for _, argv in runner.calls) == 14
    assert sum(argv[0] == "ssh" for _, argv in runner.calls) == 13
    class FailAfterAdd(Lab):
        def fault_phase(self, _readyz_available: bool) -> None:
            raise RuntimeError("injected fault-phase failure")
        def collect(self, _since: str) -> None:
            pass
    failed = FailAfterAdd(runner, Path("/tmp/mock-key"), "a" * 64, 60, "fedcba987654",
                          process_check=lambda: None)  # type: ignore[arg-type]
    try:
        execute(failed)
    except RuntimeError as error:
        assert "injected" in str(error)
    else:
        raise AssertionError("injected failure was hidden")
    assert any(label == "fault-remove" for label, _ in runner.calls)
    assert all(argv[0] in ("virsh", "ssh", "systemctl") for _, argv in runner.calls)
    class RecoveryMock(MockRunner):
        def __init__(self, readyz: bytes) -> None:
            super().__init__()
            self.readyz = readyz
            self.evidence = MockEvidence()  # type: ignore[attr-defined]
        def call_result(self, label: str, argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
            self.calls.append((label, argv))
            if label.startswith(("fault-readyz-", "recovery-readyz-")):
                return subprocess.CompletedProcess(argv, 0, self.readyz, b"")
            if label.startswith("recovery-cross-node-attempt-"):
                return subprocess.CompletedProcess(argv, 0, b"delivered\n", b"")
            raise AssertionError(f"unexpected result call: {label}")
    for readyz, available, expected in ((b"HTTP/1.1 200 OK\r\n\r\nready", True,
                                         "recovery-cross-node"),
                                        (b"HTTP/1.1 404 Not Found\r\n\r\n", False,
                                         "recovery-cross-node-attempt-01")):
        recovery_runner = RecoveryMock(readyz)
        recovery_lab = Lab(recovery_runner, Path("/tmp/mock-key"), "a" * 64, 60,
                           "012345abcdef")  # type: ignore[arg-type]
        recovery_lab.ips = {"ns-a": "192.168.197.101", "ns-b": "192.168.197.102",
                            "infra": "192.168.197.103"}
        recovery_lab.recovery(time.monotonic_ns(), available)
        assert any(label == expected for label, _ in recovery_runner.calls)
        assert any(label == "recovery-federation" for label, _ in recovery_runner.calls)
    unavailable_runner = RecoveryMock(b"HTTP/1.1 404 Not Found\r\n\r\n")
    unavailable_lab = Lab(unavailable_runner, Path("/tmp/mock-key"), "a" * 64, 60,
                          "012345abcdef")  # type: ignore[arg-type]
    unavailable_lab.ips = {"ns-a": "192.168.197.101", "ns-b": "192.168.197.102",
                           "infra": "192.168.197.103"}
    try:
        unavailable_lab.recovery(time.monotonic_ns(), True)
    except RuntimeError as error:
        assert "disappeared after baseline" in str(error)
    else:
        raise AssertionError("an unavailable readiness endpoint triggered unsafe fallback")
    assert not any(label.startswith("recovery-cross-node-attempt-")
                   for label, _ in unavailable_runner.calls)
    unavailable_runner.readyz = b"HTTP/1.1 503 Service Unavailable\r\n\r\nnot ready"
    assert unavailable_lab.readyz("fault", 1) == "503"
    print("redis fault host self-test passed (mock virsh/SSH and cleanup)")


def lock_lab() -> int:
    path = Path("/tmp/northstar-lab-redis-fault.lock")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError("lab lock file is not owned by the current user")
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="use mocked virsh and SSH; do not contact VMs")
    parser.add_argument("--execute", action="store_true", help="run the live isolated-VM drill")
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--duration-seconds", type=int, default=75)
    parser.add_argument("--output-root", type=Path, default=Path("/tmp"))
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.execute:
        parser.error("choose --self-test or --execute")
    if not args.expected_binary_sha256 or not re.fullmatch(r"[a-f0-9]{64}", args.expected_binary_sha256):
        parser.error("--expected-binary-sha256 must be a lowercase SHA-256 digest")
    if not 60 <= args.duration_seconds <= 90:
        parser.error("--duration-seconds must be 60..90")
    key = Path(os.environ.get("NORTHSTAR_LAB_SSH_KEY", "/tmp/northstar-lab-keys/id_ed25519"))
    if not key.is_file() or not (key.parent / "known_hosts").is_file():
        parser.error("lab SSH key and known_hosts are required")
    lock_fd = lock_lab()
    old_umask = os.umask(0o077)
    evidence = Evidence(args.output_root)
    os.umask(old_umask)
    run_id = secrets.token_hex(6)
    evidence.event("run", run_id=run_id, expected_binary_sha256=args.expected_binary_sha256,
                   duration_seconds=args.duration_seconds)
    for filename in (__file__, str(GUEST_HELPER), str(HERE / "local-vm-lab-cluster-delivery.py"),
                     str(HERE / "local-vm-lab-federation.py")):
        path = Path(filename)
        evidence.event("source", path=str(path), sha256=digest(path.read_bytes()))
    lab = Lab(Runner(evidence), key, args.expected_binary_sha256, args.duration_seconds, run_id)
    def interrupted(signum: int, _frame: object) -> None:
        raise InterruptedError(f"received signal {signum}")
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        execute(lab)
    except BaseException as error:
        evidence.event("result", status="failed", error_type=type(error).__name__, error=str(error))
        raise
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        evidence.finish()
        os.close(lock_fd)
        print(f"evidence: {evidence.path}", file=sys.stderr)


if __name__ == "__main__":
    main()
