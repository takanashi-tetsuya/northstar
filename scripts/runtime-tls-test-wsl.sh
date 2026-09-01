#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_dir="$(mktemp -d /tmp/northstar-runtime-tls.XXXXXX)"
cleanup() {
  case "$test_dir" in
    /tmp/northstar-runtime-tls.*) rm -rf -- "$test_dir" ;;
  esac
}
trap cleanup EXIT

cd "$project_dir"
bash scripts/generate-development-certificate.sh \
  "$test_dir/server.crt" "$test_dir/server.key" >/dev/null

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 90 \
  -subj '/CN=Northstar Runtime Test Root' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$test_dir/root.key" -out "$test_dir/root.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:3072 -sha256 -nodes \
  -subj '/CN=runtime.northstar.internal' \
  -keyout "$test_dir/public.key" -out "$test_dir/public.csr" >/dev/null 2>&1
cat > "$test_dir/leaf.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=critical,serverAuth
subjectAltName=DNS:runtime.northstar.internal
EOF
openssl x509 -req -sha256 -days 60 \
  -in "$test_dir/public.csr" \
  -CA "$test_dir/root.crt" -CAkey "$test_dir/root.key" -CAcreateserial \
  -extfile "$test_dir/leaf.ext" -out "$test_dir/public.crt" >/dev/null 2>&1

make_client_leaf() {
  local name="$1"
  local common_name="$2"
  local san="$3"
  openssl req -new -newkey rsa:3072 -sha256 -nodes \
    -subj "/CN=$common_name" \
    -keyout "$test_dir/$name.key" -out "$test_dir/$name.csr" >/dev/null 2>&1
  {
    echo 'basicConstraints=critical,CA:FALSE'
    echo 'keyUsage=critical,digitalSignature'
    echo 'extendedKeyUsage=critical,clientAuth'
    if [[ -n "$san" ]]; then
      echo "subjectAltName=$san"
    fi
  } > "$test_dir/$name.ext"
  openssl x509 -req -sha256 -days 60 \
    -in "$test_dir/$name.csr" \
    -CA "$test_dir/root.crt" -CAkey "$test_dir/root.key" -CAcreateserial \
    -extfile "$test_dir/$name.ext" -out "$test_dir/$name.crt" >/dev/null 2>&1
}
make_client_leaf client-xmpp alice-cn-only \
  'otherName:1.3.6.1.5.5.7.8.5;UTF8:Alice@LOCALHOST'
make_client_leaf client-wrong-domain alice-local \
  'otherName:1.3.6.1.5.5.7.8.5;UTF8:alice@other.test'
make_client_leaf client-cn-only alice@localhost ''

chmod 600 "$test_dir/server.key" "$test_dir/public.key" "$test_dir/root.key" \
  "$test_dir/client-xmpp.key" "$test_dir/client-wrong-domain.key" \
  "$test_dir/client-cn-only.key"

# The broad `tls::tests::generated_` filter also includes the atomic CRL
# reload regression. Generate that fixture before invoking the filter and pass
# every external path it requires; otherwise the ignored test is selected but
# fails before exercising reload behavior.
crl_fixture="$(bash scripts/generate-crl-fixture-wsl.sh "$test_dir")"
TEST_TLS_CERT_PATH="$test_dir/server.crt" \
TEST_TLS_KEY_PATH="$test_dir/server.key" \
TEST_PUBLIC_TLS_CERT_PATH="$test_dir/public.crt" \
TEST_PUBLIC_TLS_KEY_PATH="$test_dir/public.key" \
TEST_PUBLIC_TLS_CA_PATH="$test_dir/root.crt" \
TEST_PUBLIC_TLS_DOMAIN=runtime.northstar.internal \
TEST_C2S_CLIENT_CA_PATH="$test_dir/root.crt" \
TEST_C2S_CLIENT_CERT_PATH="$test_dir/client-xmpp.crt" \
TEST_C2S_WRONG_DOMAIN_CERT_PATH="$test_dir/client-wrong-domain.crt" \
TEST_C2S_CN_ONLY_CERT_PATH="$test_dir/client-cn-only.crt" \
TEST_TLS_RELOAD_CERT_PATH="$crl_fixture/valid-server-chain.pem" \
TEST_TLS_RELOAD_KEY_PATH="$crl_fixture/valid-server.key" \
TEST_TLS_RELOAD_ROOT_PATH="$crl_fixture/root.pem" \
TEST_TLS_RELOAD_CRL_PATH="$crl_fixture/crl.pem" \
TEST_TLS_RELOAD_RENEWED_CRL_PATH="$crl_fixture/renewed-crl.pem" \
  cargo test --locked \
  tls::tests::generated_ \
  -- --ignored --nocapture

# Exercise the real OpenSSL-issued CRL fixtures as part of the normal TLS
# runtime gate. The Rust test remains #[ignore] because it requires external
# fixture paths, so every case must be invoked explicitly here.
run_crl_case() {
  local leaf="$1"
  local crl="$2"
  local role="$3"
  local expected="$4"
  TEST_CRL_PATH="$crl_fixture/$crl" \
  TEST_CRL_ROOT_PATH="$crl_fixture/root.pem" \
  TEST_CRL_LEAF_PATH="$crl_fixture/$leaf" \
  TEST_CRL_ROLE="$role" \
  TEST_CRL_EXPECT_VALID="$expected" \
    cargo test --locked \
    crl::tests::validates_generated_server_or_client_revocation_fixture \
    -- --ignored --exact --nocapture
}

run_crl_case valid-server.pem crl.pem server true
run_crl_case revoked-server.pem crl.pem server false
run_crl_case valid-client.pem crl.pem client true
run_crl_case revoked-client.pem crl.pem client false
run_crl_case valid-server.pem expired-crl.pem server false
run_crl_case valid-server.pem unknown-issuer-crl.pem server false
run_crl_case valid-server.pem crl.pem client false
run_crl_case valid-client.pem crl.pem server false
