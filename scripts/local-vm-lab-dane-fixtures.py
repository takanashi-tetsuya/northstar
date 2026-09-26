#!/usr/bin/env python3
"""Prepare local lab DNSKEY/TLSA records; never edits DNS or guest services."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


LAB_ZONE = "lab.test."
TEST_DNSKEY = (
    "lab.test. 300 IN DNSKEY 257 3 13 "
    "bKhLob4jADrX1HlEAt3htWeadUWng/CYNc9rzLSz9RhUXf1iazgV5r2xnGkwpcbN0ihDyHyqTlpmRNbruj151w=="
)


def parse_dnskey(path: Path, ttl: int) -> str:
    if path.stat().st_size > 8192:
        raise ValueError("DNSKEY file exceeds 8192 bytes")
    lines = [
        line.strip()
        for line in path.read_text(encoding="ascii").splitlines()
        if line.strip() and not line.lstrip().startswith(";")
    ]
    if len(lines) != 1:
        raise ValueError("expected one public lab.test DNSKEY record")
    fields = lines[0].split()
    if len(fields) == 7:
        # BIND's K*.key public-key files commonly omit the owner TTL.
        fields.insert(1, str(ttl))
    if (
        len(fields) != 8
        or fields[0].lower() != LAB_ZONE
        or fields[2].upper() != "IN"
        or fields[3].upper() != "DNSKEY"
        or fields[4:7] != ["257", "3", "13"]
    ):
        raise ValueError("expected a lab.test. KSK DNSKEY with algorithm 13")
    try:
        original_ttl = int(fields[1])
        key = base64.b64decode(fields[7], validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid DNSKEY TTL or public key") from error
    if not 1 <= original_ttl <= 3600 or len(key) != 64:
        raise ValueError("DNSKEY TTL or algorithm-13 public key length is invalid")
    return f"{LAB_ZONE} {ttl} IN DNSKEY 257 3 13 {base64.b64encode(key).decode('ascii')}"


def check_host(host: str) -> str:
    host = host.lower().rstrip(".")
    if not host.endswith(".lab.test") or len(host) > 253:
        raise ValueError("peer host must be beneath lab.test")
    labels = host.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ValueError("peer host contains an invalid DNS label")
    return host


def openssl(*args: str, input_bytes: bytes | None = None) -> bytes:
    environment = {**os.environ, "LC_ALL": "C"}
    result = subprocess.run(
        ["openssl", *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
        timeout=10,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
        raise ValueError(f"OpenSSL rejected {args[0]}: {detail}")
    return result.stdout


def require_hostname_match(report: bytes, host: str) -> None:
    # Some OpenSSL releases exit successfully even when -checkhost reports a
    # mismatch. Require the affirmative result as well as a successful call.
    if report.decode("utf-8", "replace").strip() != f"Hostname {host} does match certificate":
        raise ValueError("certificate does not match the requested peer host")


def peer_spki(cert: Path, host: str) -> tuple[str, str]:
    match = openssl("x509", "-in", str(cert), "-noout", "-checkhost", host)
    require_hostname_match(match, host)
    certificate = openssl("x509", "-in", str(cert), "-outform", "DER")
    public_key = openssl("x509", "-in", str(cert), "-pubkey", "-noout")
    spki = openssl("pkey", "-pubin", "-outform", "DER", input_bytes=public_key)
    if not certificate or not spki:
        raise ValueError("certificate or public key is empty")
    return hashlib.sha256(certificate).hexdigest(), hashlib.sha256(spki).hexdigest()


def write_private(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(content)


def make_fixtures(dnskey: Path, cert: Path, host: str, port: int, ttl: int, output: Path) -> dict:
    host = check_host(host)
    if not 1 <= port <= 65535 or not 1 <= ttl <= 3600:
        raise ValueError("port or TTL is out of range")
    anchor = parse_dnskey(dnskey, ttl)
    cert_hash, spki_hash = peer_spki(cert, host)
    wrong_hash = ("0" if spki_hash[0] != "0" else "1") + spki_hash[1:]
    owner = f"_{port}._tcp.{host}."
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    records = {
        "anchor.dnskey": anchor,
        "tlsa-usage1.rr": f"{owner} {ttl} IN TLSA 1 1 1 {spki_hash}",
        "tlsa-usage3.rr": f"{owner} {ttl} IN TLSA 3 1 1 {spki_hash}",
        "tlsa-wrong-digest.rr": f"{owner} {ttl} IN TLSA 1 1 1 {wrong_hash}",
    }
    for name, value in records.items():
        write_private(output / name, value + "\n")
    manifest = {
        "zone": LAB_ZONE,
        "host": host,
        "port": port,
        "ttl": ttl,
        "certificate_sha256": cert_hash,
        "spki_sha256": spki_hash,
        "anchor_sha256": hashlib.sha256((anchor + "\n").encode()).hexdigest(),
        "dnskey_public_sha256": hashlib.sha256(base64.b64decode(anchor.split()[7])).hexdigest(),
        "files": {name: hashlib.sha256((value + "\n").encode()).hexdigest() for name, value in records.items()},
        "purpose": "candidate records only; authoritative signing and DNSSEC validation are separate",
    }
    write_private(output / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def self_test() -> None:
    try:
        require_hostname_match(
            b"Hostname ejabberd.lab.test does NOT match certificate\n",
            "ejabberd.lab.test",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("OpenSSL's zero-exit mismatch report was accepted")
    with tempfile.TemporaryDirectory(prefix="northstar-lab-dane-") as directory:
        root = Path(directory)
        key = root / "lab.key"
        key.write_text("; BIND public key\n" + TEST_DNSKEY + "\n", encoding="ascii")
        cert = root / "peer.pem"
        openssl(
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", str(root / "peer.key"), "-out", str(cert), "-days", "1",
            "-subj", "/CN=prosody.lab.test", "-addext", "subjectAltName=DNS:prosody.lab.test",
        )
        manifest = make_fixtures(key, cert, "prosody.lab.test", 5269, 300, root / "fixtures")
        output = root / "fixtures"
        assert manifest["spki_sha256"] in (output / "tlsa-usage1.rr").read_text()
        assert manifest["spki_sha256"] in (output / "tlsa-usage3.rr").read_text()
        assert manifest["spki_sha256"] not in (output / "tlsa-wrong-digest.rr").read_text()
        assert (output / "anchor.dnskey").read_text().strip() == TEST_DNSKEY
        for path in output.iterdir():
            assert path.stat().st_mode & 0o077 == 0
        try:
            peer_spki(cert, "ejabberd.lab.test")
        except ValueError:
            pass
        else:
            raise AssertionError("certificate with wrong host was accepted")
        key.write_text(TEST_DNSKEY.replace(" 300 IN ", " IN "))
        assert parse_dnskey(key, 300) == TEST_DNSKEY
        key.write_text(TEST_DNSKEY.replace("lab.test.", "evil.test.", 1))
        try:
            parse_dnskey(key, 300)
        except ValueError:
            pass
        else:
            raise AssertionError("foreign DNSKEY owner was accepted")
        print("local DANE fixture self-test: ok")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--dnskey-file", type=Path)
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--ttl", type=int, default=300)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if any(value is None for value in (args.dnskey_file, args.cert, args.host, args.port, args.output_dir)):
        parser.error("--dnskey-file, --cert, --host, --port and --output-dir are required")
    manifest = make_fixtures(
        args.dnskey_file, args.cert, args.host, args.port, args.ttl, args.output_dir
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
