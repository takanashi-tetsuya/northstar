#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ${1:-} == --fixtures-only ]]; then
  [[ $# -ge 2 && $# -le 3 ]] || {
    echo "usage: $0 --fixtures-only NEW_DIRECTORY [DNS_NAME]" >&2
    exit 2
  }
  fixture_dir=$2
  peer_name=${3:-localhost}
  [[ ${#peer_name} -le 253 ]] || {
    echo "invalid fixture DNS name" >&2
    exit 2
  }
  IFS=. read -r -a peer_labels <<< "$peer_name"
  for label in "${peer_labels[@]}"; do
    [[ ${#label} -ge 1 && ${#label} -le 63 && $label =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || {
      echo "invalid fixture DNS name" >&2
      exit 2
    }
  done
  [[ $peer_name != *. ]] || {
    echo "invalid fixture DNS name" >&2
    exit 2
  }
  mkdir -m 700 -- "$fixture_dir"
  fixtures_only=true
else
  [[ $# -eq 0 ]] || {
    echo "usage: $0 [--fixtures-only NEW_DIRECTORY [DNS_NAME]]" >&2
    exit 2
  }
  fixture_dir="$(mktemp -d /tmp/northstar-ocsp-stapling.XXXXXX)"
  peer_name=localhost
  fixtures_only=false
fi
trap 'rm -rf -- "$fixture_dir"' EXIT
umask 077

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3 \
  -subj '/CN=Northstar OCSP test root' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -keyout "$fixture_dir/root.key" -out "$fixture_dir/root.crt" >/dev/null 2>&1
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3 \
  -subj '/CN=Unrelated OCSP issuer' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -keyout "$fixture_dir/other-root.key" -out "$fixture_dir/other-root.crt" >/dev/null 2>&1

cat > "$fixture_dir/leaf.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
authorityKeyIdentifier=keyid,issuer
subjectKeyIdentifier=hash
extendedKeyUsage=serverAuth
subjectAltName=DNS:$peer_name
EOF

for name in leaf other; do
  openssl req -new -newkey rsa:3072 -sha256 -nodes -subj "/CN=$peer_name" \
    -keyout "$fixture_dir/$name.key" -out "$fixture_dir/$name.csr" >/dev/null 2>&1
  openssl x509 -req -in "$fixture_dir/$name.csr" \
    -CA "$fixture_dir/root.crt" -CAkey "$fixture_dir/root.key" -CAcreateserial \
    -days 2 -sha256 -extfile "$fixture_dir/leaf.ext" \
    -out "$fixture_dir/$name.crt" >/dev/null 2>&1
done
cat "$fixture_dir/leaf.crt" "$fixture_dir/root.crt" > "$fixture_dir/chain.crt"

expiry="$(date -u -d '+2 days' +'%y%m%d%H%M%SZ')"
revocation="$(date -u +'%y%m%d%H%M%SZ')"
leaf_serial="$(openssl x509 -in "$fixture_dir/leaf.crt" -noout -serial | cut -d= -f2)"
other_serial="$(openssl x509 -in "$fixture_dir/other.crt" -noout -serial | cut -d= -f2)"
printf 'V\t%s\t\t%s\tunknown\t/CN=%s\n' \
  "$expiry" "$leaf_serial" "$peer_name" > "$fixture_dir/good.index"
printf 'R\t%s\t%s\t%s\tunknown\t/CN=%s\n' \
  "$expiry" "$revocation" "$leaf_serial" "$peer_name" > "$fixture_dir/revoked.index"
printf 'V\t%s\t\t%s\tunknown\t/CN=%s\n' \
  "$expiry" "$other_serial" "$peer_name" > "$fixture_dir/other.index"
: > "$fixture_dir/empty.index"

make_response() {
  local index="$1" cert="$2" output="$3"
  shift 3
  openssl ocsp -index "$fixture_dir/$index.index" \
    -CA "$fixture_dir/root.crt" -rsigner "$fixture_dir/root.crt" \
    -rkey "$fixture_dir/root.key" -issuer "$fixture_dir/root.crt" \
    -cert "$fixture_dir/$cert.crt" -respout "$fixture_dir/$output.der" \
    -no_nonce "$@" >/dev/null 2>&1
}

make_response good leaf good -ndays 1
make_response good leaf too-long -ndays 8
make_response revoked leaf revoked -ndays 1
make_response empty leaf unknown -ndays 1
make_response other other wrong-leaf -ndays 1
make_response good leaf bad-signature -ndays 1 -badsig
make_response good leaf no-next-update
openssl ocsp -index "$fixture_dir/good.index" \
  -CA "$fixture_dir/other-root.crt" -rsigner "$fixture_dir/other-root.crt" \
  -rkey "$fixture_dir/other-root.key" -issuer "$fixture_dir/other-root.crt" \
  -cert "$fixture_dir/leaf.crt" -respout "$fixture_dir/wrong-issuer.der" \
  -no_nonce -ndays 1 >/dev/null 2>&1

openssl verify -x509_strict -CAfile "$fixture_dir/root.crt" \
  "$fixture_dir/leaf.crt" >/dev/null
if $fixtures_only; then
  # The OpenSSL responder CLI cannot emit an already-expired, correctly
  # signed interval. Build that one case separately, keeping the same CA.
  python3 - "$fixture_dir" "$peer_name" <<'PY'
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import json
import subprocess
import sys

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import ocsp

directory = Path(sys.argv[1])
peer_name = sys.argv[2]
issuer = x509.load_pem_x509_certificate((directory / "root.crt").read_bytes())
leaf = x509.load_pem_x509_certificate((directory / "leaf.crt").read_bytes())
key = serialization.load_pem_private_key((directory / "root.key").read_bytes(), None)
unrelated_issuer = x509.load_pem_x509_certificate((directory / "other-root.crt").read_bytes())
unrelated_key = serialization.load_pem_private_key((directory / "other-root.key").read_bytes(), None)
now = datetime.now(timezone.utc)


def signed_good_response(cert, signing_issuer, signing_key, this_update, next_update):
    return (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=cert,
            issuer=signing_issuer,
            algorithm=hashes.SHA1(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=this_update,
            next_update=next_update,
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, signing_issuer)
        .sign(signing_key, hashes.SHA256())
    )


response = signed_good_response(
    leaf, issuer, key, now - timedelta(days=2), now - timedelta(days=1)
)
(directory / "stale.der").write_bytes(response.public_bytes(serialization.Encoding.DER))
# The OpenSSL responder produces UNKNOWN when given a leaf from another CA.
# Sign a GOOD status for that leaf with the unrelated issuer instead, so the
# negative VM case isolates the issuer binding rather than the status check.
wrong_issuer = signed_good_response(
    leaf, unrelated_issuer, unrelated_key, now - timedelta(seconds=1), now + timedelta(days=1)
)
(directory / "wrong-issuer.der").write_bytes(
    wrong_issuer.public_bytes(serialization.Encoding.DER)
)
issuer.public_key().verify(
    response.signature,
    response.tbs_response_bytes,
    padding.PKCS1v15(),
    response.signature_hash_algorithm,
)
assert response.certificate_status == ocsp.OCSPCertStatus.GOOD
assert response.this_update_utc < response.next_update_utc < now
public_files = sorted(
    path for path in directory.iterdir() if path.suffix in {".crt", ".der"}
)
digests = {
    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
    for path in public_files
}
manifest = {
    "schemaVersion": 1,
    "dnsName": peer_name,
    "generatedAtUtc": now.isoformat(),
    "opensslVersion": subprocess.check_output(["openssl", "version"], text=True).strip(),
    "pythonCryptographyVersion": cryptography.__version__,
    "issuerCertificateSha256": issuer.fingerprint(hashes.SHA256()).hex(),
    "leafCertificateSha256": leaf.fingerprint(hashes.SHA256()).hex(),
    "staleThisUpdateUtc": response.this_update_utc.isoformat(),
    "staleNextUpdateUtc": response.next_update_utc.isoformat(),
    "publicFileSha256": digests,
    "note": "Copy only required public certificates, response DER and leaf.key to an isolated peer; never copy a CA private key.",
}
(directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
(directory / "SHA256SUMS").write_text(
    "".join(f"{digest}  {name}\n" for name, digest in digests.items())
)
PY
  rm -f -- "$fixture_dir/root.key" "$fixture_dir/other-root.key" \
    "$fixture_dir/other.key"
  python3 "$project_dir/scripts/verify-ocsp-fixture.py" "$fixture_dir" >&2
  trap - EXIT
  printf '%s\n' "$fixture_dir"
  printf 'Private OCSP fixture retained (mode 0700); remove it when done: %s\n' \
    "$fixture_dir" >&2
  exit 0
fi

TEST_OCSP_FIXTURE_DIR="$fixture_dir" \
  cargo test --manifest-path "$project_dir/Cargo.toml" --bin rust-xmpp-server \
    --locked --offline generated_responses_require_exact_good_fresh_authorized_status \
    -- --ignored --nocapture
TEST_OCSP_FIXTURE_DIR="$fixture_dir" \
  cargo test --manifest-path "$project_dir/Cargo.toml" --bin rust-xmpp-server \
    --locked --offline ocsp_staple_survives_tls12_tls13_and_rejects_bad_reload \
    -- --ignored --nocapture
TEST_OCSP_FIXTURE_DIR="$fixture_dir" \
  cargo test --manifest-path "$project_dir/Cargo.toml" --bin rust-xmpp-server \
    --locked --offline generated_outbound_ocsp_profile_checks_exact_status_and_pkix \
    -- --ignored --nocapture
TEST_OCSP_FIXTURE_DIR="$fixture_dir" \
  cargo test --manifest-path "$project_dir/Cargo.toml" --bin rust-xmpp-server \
    --locked --offline generated_outbound_ocsp_staple_is_required_on_tls12_and_tls13 \
    -- --ignored --nocapture
