#!/usr/bin/env python3
"""Check the private lab fixture's public OCSP cases before VM staging.

This reads only local files. It never loads a private key or contacts a
responder. The result describes test inputs, not a Northstar handshake.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import ocsp


def require(condition, message):
    if not condition:
        raise ValueError(message)


def certificate(directory, name):
    return x509.load_pem_x509_certificate((directory / name).read_bytes())


def cert_id(cert, issuer):
    return ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()


def check_case(directory, name, cert, issuer, signer, expected_status, now):
    path = directory / f"{name}.der"
    response = ocsp.load_der_ocsp_response(path.read_bytes())
    require(response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL, f"{name}: response failed")
    require(response.certificate_status == expected_status, f"{name}: unexpected status")
    requested = cert_id(cert, issuer)
    require(response.serial_number == requested.serial_number, f"{name}: wrong serial")
    require(response.issuer_name_hash == requested.issuer_name_hash, f"{name}: wrong issuer name hash")
    require(response.issuer_key_hash == requested.issuer_key_hash, f"{name}: wrong issuer key hash")
    require(response.responder_name == signer.subject, f"{name}: wrong responder name")
    signer.public_key().verify(
        response.signature,
        response.tbs_response_bytes,
        padding.PKCS1v15(),
        response.signature_hash_algorithm,
    )
    start, end = response.this_update_utc, response.next_update_utc
    require(start is not None and end is not None and start < end, f"{name}: unbounded interval")
    if name == "stale":
        require(end < now, "stale: response has not expired")
    else:
        require(start <= now < end, f"{name}: response is not current")
    if name == "revoked":
        require(response.revocation_time_utc is not None, "revoked: missing revocation time")
        require(response.revocation_time_utc <= now, "revoked: future revocation time")
    return {
        "case": name,
        "status": response.certificate_status.name.lower(),
        "serial": format(response.serial_number, "x"),
        "thisUpdateUtc": start.isoformat(),
        "nextUpdateUtc": end.isoformat(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def check_checksums(directory, manifest):
    listed = manifest["publicFileSha256"]
    actual = {p.name for p in directory.iterdir() if p.suffix in (".crt", ".der")}
    require(set(listed) == actual, "manifest public-file list differs from fixture")
    for name, digest in listed.items():
        require(Path(name).name == name, "manifest contains a path")
        require(hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest,
                f"{name}: checksum differs from manifest")
    expected = "".join(f"{digest}  {name}\n" for name, digest in sorted(listed.items()))
    require((directory / "SHA256SUMS").read_text() == expected, "SHA256SUMS differs from manifest")


def main(directory):
    require(directory.is_dir(), "fixture directory is missing")
    require(not (directory / "root.key").exists(), "fixture still contains the root private key")
    require(not (directory / "other-root.key").exists(), "fixture still contains the unrelated root private key")
    manifest = json.loads((directory / "manifest.json").read_text())
    require(manifest["schemaVersion"] == 1, "unsupported fixture manifest")
    check_checksums(directory, manifest)
    root = certificate(directory, "root.crt")
    unrelated_root = certificate(directory, "other-root.crt")
    leaf = certificate(directory, "leaf.crt")
    other_leaf = certificate(directory, "other.crt")
    require(leaf.serial_number != other_leaf.serial_number, "leaf fixtures have the same serial")
    require(root.subject != unrelated_root.subject, "issuer fixtures have the same subject")
    root.public_key().verify(
        leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), leaf.signature_hash_algorithm
    )
    require(leaf.issuer == root.subject, "leaf was not issued by fixture root")
    require(manifest["issuerCertificateSha256"] == root.fingerprint(hashes.SHA256()).hex(),
            "manifest issuer fingerprint differs")
    require(manifest["leafCertificateSha256"] == leaf.fingerprint(hashes.SHA256()).hex(),
            "manifest leaf fingerprint differs")
    now = datetime.now(timezone.utc)
    results = [
        check_case(directory, "good", leaf, root, root, ocsp.OCSPCertStatus.GOOD, now),
        check_case(directory, "revoked", leaf, root, root, ocsp.OCSPCertStatus.REVOKED, now),
        check_case(directory, "stale", leaf, root, root, ocsp.OCSPCertStatus.GOOD, now),
        check_case(directory, "wrong-leaf", other_leaf, root, root, ocsp.OCSPCertStatus.GOOD, now),
        check_case(directory, "wrong-issuer", leaf, unrelated_root, unrelated_root,
                   ocsp.OCSPCertStatus.GOOD, now),
    ]
    print(json.dumps({
        "scope": "offline fixture inputs only; no Northstar handshake or VM result",
        "dnsName": manifest["dnsName"],
        "issuerCertificateSha256": manifest["issuerCertificateSha256"],
        "leafCertificateSha256": manifest["leafCertificateSha256"],
        "cases": results,
    }, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} FIXTURE_DIR")
    try:
        main(Path(sys.argv[1]))
    except (OSError, KeyError, ValueError) as error:
        raise SystemExit(f"OCSP fixture preflight failed: {error}") from error
