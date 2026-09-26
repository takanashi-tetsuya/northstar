#!/usr/bin/env python3
"""Capture DNSSEC/DANE proof for one selected endpoint in the isolated lab."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone


LAB_IPV4 = ipaddress.ip_network("192.168.197.0/24")
LAB_IPV6 = ipaddress.ip_network("fd7a:6e73:7461:72::/64")
def lab_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = ipaddress.ip_address(value)
    if address not in LAB_IPV4 and address not in LAB_IPV6:
        raise ValueError(f"address is outside the isolated lab network: {value}")
    return address


def lab_name(value: str) -> str:
    name = value.lower().rstrip(".")
    if not name.endswith(".lab.test") or len(name) > 253:
        raise ValueError(f"name is outside lab.test: {value}")
    if any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in name.split(".")
    ):
        raise ValueError(f"invalid DNS name: {value}")
    return name + "."


def answer_records(transcript: str, owner: str, kind: str) -> list[str]:
    records = []
    for line in transcript.splitlines():
        fields = line.split()
        if (
            len(fields) >= 5
            and fields[0].lower() == owner.lower()
            and fields[1].isdigit()
            and fields[2].upper() == "IN"
            and fields[3].upper() == kind
        ):
            records.append(" ".join(fields[4:]))
    return records


def secure_answer(exit_code: int, transcript: str) -> bool:
    return exit_code == 0 and re.search(
        r"(?im)^;+\s*fully validated\s*$", transcript
    ) is not None


def check_answers(
    transcripts: dict[str, tuple[int, str]],
    domain: str,
    target: str,
    selected_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    port: int,
    service: str,
    expected_tlsa: str,
    spki_sha256: str | None,
) -> dict[str, object]:
    srv_owner = f"{service}._tcp.{domain}"
    tlsa_owner = f"_{port}._tcp.{target}"
    address_type = "A" if selected_ip.version == 4 else "AAAA"
    checks: dict[str, object] = {}
    for kind, owner in (("SRV", srv_owner), (address_type, target), ("TLSA", tlsa_owner)):
        status, transcript = transcripts[kind]
        records = answer_records(transcript, owner, kind)
        checks[kind] = {
            "owner": owner,
            "secure": secure_answer(status, transcript),
            "records": records,
        }

    srv = checks["SRV"]
    address = checks[address_type]
    tlsa = checks["TLSA"]
    assert isinstance(srv, dict) and isinstance(address, dict) and isinstance(tlsa, dict)
    srv_match = any(
        len(fields := record.split()) == 4
        and fields[2] == str(port)
        and fields[3].lower() == target.lower()
        for record in srv["records"]
    )
    address_match = str(selected_ip) in address["records"]
    parsed_tlsa = []
    for record in tlsa["records"]:
        fields = record.split()
        if len(fields) >= 4 and all(field.isdigit() for field in fields[:3]):
            parsed_tlsa.append((tuple(map(int, fields[:3])), "".join(fields[3:]).lower()))
    if expected_tlsa == "absent":
        tlsa_match = not tlsa["records"]
    elif expected_tlsa == "unsupported-only":
        tlsa_match = bool(parsed_tlsa) and len(parsed_tlsa) == len(tlsa["records"]) and all(
            usage in (0, 2) for (usage, _, _), _ in parsed_tlsa
        )
    elif expected_tlsa == "wrong-digest":
        tlsa_match = bool(parsed_tlsa) and len(parsed_tlsa) == len(tlsa["records"]) and all(
            fields == (1, 1, 1)
            and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
            and digest != spki_sha256
            for fields, digest in parsed_tlsa
        )
    else:
        usage = 1 if expected_tlsa == "usage1" else 3
        tlsa_match = bool(parsed_tlsa) and len(parsed_tlsa) == len(tlsa["records"]) and all(
            fields == (usage, 1, 1) and digest == spki_sha256
            for fields, digest in parsed_tlsa
        )
    checks["selected_srv_present"] = srv_match
    checks["selected_address_present"] = address_match
    checks["tlsa_rrset_matches_case"] = tlsa_match
    checks["dns_preflight_passed"] = all(
        item["secure"] for item in (srv, address, tlsa)
    ) and srv_match and address_match and tlsa_match
    return checks


def certificate_spki(cert: Path) -> tuple[str, str]:
    leaf = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-outform", "DER"],
        capture_output=True, check=True, timeout=10,
    ).stdout
    public = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"],
        capture_output=True, check=True, timeout=10,
    ).stdout
    spki = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=public, capture_output=True, check=True, timeout=10,
    ).stdout
    return hashlib.sha256(leaf).hexdigest(), hashlib.sha256(spki).hexdigest()


def query(server: str, anchor: Path, owner: str, kind: str) -> tuple[int, str]:
    try:
        result = subprocess.run(
            ["delv", "-a", str(anchor), f"@{server}", "+dnssec", "+trust", owner, kind],
            capture_output=True, text=True, timeout=15, check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired as error:
        partial = error.stdout or b""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", "replace")
        return 124, partial + "\n;; delv timed out after 15 seconds\n"
    return result.returncode, result.stdout + result.stderr


def self_test() -> None:
    digest = "a" * 64
    domain = "prosody.lab.test."
    target = domain
    ip = lab_address("192.168.197.7")
    source = {
        "SRV": (0, f";; fully validated\n_xmpp-server._tcp.{domain} 300 IN SRV 0 5 5269 {target}\n"),
        "A": (0, f";; fully validated\n{target} 300 IN A {ip}\n"),
        "TLSA": (0, f";; fully validated\n_5269._tcp.{target} 300 IN TLSA 1 1 1 {digest}\n"),
    }
    result = check_answers(source, domain, target, ip, 5269, "_xmpp-server", "usage1", digest)
    assert result["dns_preflight_passed"]
    assert not secure_answer(0, ";; not fully validated\n")
    source["SRV"] = (0, source["SRV"][1].replace(f"5269 {target}", "5269 other.lab.test."))
    assert not check_answers(source, domain, target, ip, 5269, "_xmpp-server", "usage1", digest)["dns_preflight_passed"]
    source["SRV"] = (0, f";; fully validated\n_xmpp-server._tcp.{domain} 300 IN SRV 0 5 5269 {target}\n")
    source["A"] = (0, source["A"][1].replace(str(ip), "192.168.197.8"))
    assert not check_answers(source, domain, target, ip, 5269, "_xmpp-server", "usage1", digest)["dns_preflight_passed"]
    source["A"] = (0, f";; fully validated\n{target} 300 IN A {ip}\n")
    source["TLSA"] = (0, source["TLSA"][1].replace(digest, "b" * 64))
    assert check_answers(source, domain, target, ip, 5269, "_xmpp-server", "wrong-digest", digest)["dns_preflight_passed"]
    source["TLSA"] = (0, source["TLSA"][1] + f"_5269._tcp.{target} 300 IN TLSA 1 1 1 {digest}\n")
    assert not check_answers(source, domain, target, ip, 5269, "_xmpp-server", "wrong-digest", digest)["dns_preflight_passed"]
    source["TLSA"] = (0, ";; fully validated\n")
    assert check_answers(source, domain, target, ip, 5269, "_xmpp-server", "absent", None)["dns_preflight_passed"]
    source["TLSA"] = (0, ";; unsigned answer\n")
    assert not check_answers(source, domain, target, ip, 5269, "_xmpp-server", "absent", None)["dns_preflight_passed"]
    source["TLSA"] = (1, source["TLSA"][1])
    assert not check_answers(source, domain, target, ip, 5269, "_xmpp-server", "absent", None)["dns_preflight_passed"]
    source["TLSA"] = (0, f";; fully validated\n_5269._tcp.{target} 300 IN TLSA 1 1 1 malformed\n")
    assert not check_answers(source, domain, target, ip, 5269, "_xmpp-server", "usage1", digest)["dns_preflight_passed"]
    source["TLSA"] = (0, f";; fully validated\n_5269._tcp.{target} 300 IN TLSA 0 1 1 {digest}\n_5269._tcp.{target} 300 IN TLSA 2 1 1 {digest}\n")
    assert check_answers(source, domain, target, ip, 5269, "_xmpp-server", "unsupported-only", digest)["dns_preflight_passed"]
    try:
        lab_address("8.8.8.8")
    except ValueError:
        pass
    else:
        raise AssertionError("public DNS server address accepted")
    print("local DANE proof self-test: ok")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--anchor-file", type=Path)
    parser.add_argument("--dns-server")
    parser.add_argument("--peer-domain")
    parser.add_argument("--target")
    parser.add_argument("--selected-ip")
    parser.add_argument("--port", type=int)
    parser.add_argument("--service", choices=("_xmpp-server", "_xmpps-server"))
    parser.add_argument("--expect-tlsa", choices=("usage1", "usage3", "wrong-digest", "unsupported-only", "absent"))
    parser.add_argument("--served-cert", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    required = ("anchor_file", "dns_server", "peer_domain", "target", "selected_ip", "port", "service", "expect_tlsa", "output_dir")
    if any(getattr(args, name) is None for name in required):
        parser.error("all endpoint and proof arguments are required")
    if args.expect_tlsa != "absent" and args.served_cert is None:
        parser.error("--served-cert is required when a TLSA RRset is expected")
    server = lab_address(args.dns_server)
    address = lab_address(args.selected_ip)
    domain = lab_name(args.peer_domain)
    target = lab_name(args.target)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be 1..65535")
    anchor = args.anchor_file
    if anchor.is_symlink() or not anchor.is_file() or anchor.stat().st_size > 8192:
        parser.error("anchor must be a regular file of at most 8192 bytes")
    anchor_content = anchor.read_text(encoding="ascii")
    if not any(re.match(r"^lab\.test\.\s+(?:\d+\s+)?IN\s+DNSKEY\s+257\s+3\s+13\s+", line, re.I) for line in anchor_content.splitlines()):
        parser.error("anchor must contain the lab.test. KSK DNSKEY")
    cert_hash, spki_hash = certificate_spki(args.served_cert) if args.served_cert else (None, None)
    output = args.output_dir
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    started_at = datetime.now(timezone.utc).isoformat()
    requests = {
        "SRV": f"{args.service}._tcp.{domain}",
        "A" if address.version == 4 else "AAAA": target,
        "TLSA": f"_{args.port}._tcp.{target}",
    }
    transcripts: dict[str, tuple[int, str]] = {}
    for kind, owner in requests.items():
        transcripts[kind] = query(str(server), anchor, owner, kind)
        (output / f"{kind.lower()}.delv.txt").write_text(transcripts[kind][1], encoding="utf-8")
    checks = check_answers(
        transcripts, domain, target, address, args.port, args.service, args.expect_tlsa, spki_hash,
    )
    manifest = {
        "scope": "read-only isolated DNS preflight; not proof of Northstar authorization or stanza delivery",
        "started_at_utc": started_at,
        "finished_at_utc": datetime.now(timezone.utc).isoformat(),
        "dns_server": str(server), "anchor_sha256": hashlib.sha256(anchor_content.encode()).hexdigest(),
        "peer_domain": domain, "target": target, "selected_ip": str(address),
        "port": args.port, "service": args.service, "expected_tlsa": args.expect_tlsa,
        "served_certificate_sha256": cert_hash, "served_spki_sha256": spki_hash,
        "delv_exit_codes": {kind: status for kind, (status, _) in transcripts.items()},
        "checks": checks,
    }
    (output / "proof.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0 if checks["dns_preflight_passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"local DANE proof failed: {error}", file=sys.stderr)
        sys.exit(2)
