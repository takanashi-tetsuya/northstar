#!/usr/bin/env python3
"""Verify the actual cluster fault fixture's Ed25519 envelope with OpenSSL."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def main() -> None:
    spec = importlib.util.spec_from_file_location("northstar_cluster_fixture", ROOT / "cluster-wsl.py")
    fixture = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(fixture)
    with tempfile.TemporaryDirectory(prefix="northstar-cluster-envelope-") as temporary:
        directory = Path(temporary)
        private_text, public_text = directory / "private.b64", directory / "public.b64"
        private, public = directory / "private.der", directory / "public.der"
        subprocess.run(["node", str(ROOT / "generate-cluster-signing-key.mjs"), str(private_text), str(public_text), str(private)],
            stdout=subprocess.DEVNULL, check=True, timeout=10)
        raw_public = decode(public_text.read_text().strip())
        public.write_bytes(bytes.fromhex("302a300506032b6570032100") + raw_public)
        fixture.NODE_B_PRIVATE_KEY_DER = str(private)
        request = {
            "version": 1, "namespace": fixture.DOMAIN, "source_node": "node-a", "destination_node": "node-b",
            "connection_uuid": "10000000-0000-4000-8000-000000000001", "connection_epoch": 1,
            "key_id": "fixture-node-a", "key_epoch": 1,
            "destination_connection_uuid": "20000000-0000-4000-8000-000000000001", "destination_connection_epoch": 1,
            "destination_key_id": fixture.b64url(hashlib.sha256(raw_public).digest()[:12]), "destination_key_epoch": 1,
        }
        try:
            envelope = json.loads(fixture.signed_ack_envelope(request, {
                "request_id": "30000000-0000-4000-8000-000000000001", "status": "delivered",
            }))
        except subprocess.CalledProcessError as error:
            raise RuntimeError(error.stderr.decode(errors="replace")) from error
        signature = directory / "signature"
        signature.write_bytes(decode(envelope.pop("signature")))
        assert signature.stat().st_size == 64, "fixture did not produce an Ed25519 signature"
        message = directory / "message"

        def verify() -> int:
            message.write_text(json.dumps(envelope, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
            return subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
                "-inkey", str(public), "-sigfile", str(signature), "-in", str(message)],
                capture_output=True, check=False, timeout=10).returncode

        assert verify() == 0, "OpenSSL rejected the actual cluster fixture envelope"
        envelope["payload"]["status"] = "tampered"
        assert verify() != 0, "a modified envelope kept its original signature valid"
    print("cluster fixture signing passed: matching runtime v2 and OpenSSL v1 key outputs, seekable input, verified signature, tampering rejected")


if __name__ == "__main__":
    main()