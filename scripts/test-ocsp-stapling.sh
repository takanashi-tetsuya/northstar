#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_dir="$(mktemp -d /tmp/northstar-ocsp-stapling.XXXXXX)"
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

cat > "$fixture_dir/leaf.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
authorityKeyIdentifier=keyid,issuer
subjectKeyIdentifier=hash
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
EOF

for name in leaf other; do
  openssl req -new -newkey rsa:3072 -sha256 -nodes -subj '/CN=localhost' \
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
printf 'V\t%s\t\t%s\tunknown\t/CN=localhost\n' \
  "$expiry" "$leaf_serial" > "$fixture_dir/good.index"
printf 'R\t%s\t%s\t%s\tunknown\t/CN=localhost\n' \
  "$expiry" "$revocation" "$leaf_serial" > "$fixture_dir/revoked.index"
printf 'V\t%s\t\t%s\tunknown\t/CN=localhost\n' \
  "$expiry" "$other_serial" > "$fixture_dir/other.index"
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

TEST_OCSP_FIXTURE_DIR="$fixture_dir" \
  cargo test --manifest-path "$project_dir/Cargo.toml" --bin rust-xmpp-server \
    --locked --offline generated_responses_require_exact_good_fresh_authorized_status \
    -- --ignored --nocapture
TEST_OCSP_FIXTURE_DIR="$fixture_dir" \
  cargo test --manifest-path "$project_dir/Cargo.toml" --bin rust-xmpp-server \
    --locked --offline ocsp_staple_survives_tls12_tls13_and_rejects_bad_reload \
    -- --ignored --nocapture
