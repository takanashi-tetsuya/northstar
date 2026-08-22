#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export RUSTUP_HOME="$project_dir/.rustup-linux"
export CARGO_HOME="$project_dir/.cargo-local"
export CARGO_TARGET_DIR="$project_dir/target-wsl"
cd "$project_dir"

schema_a="federation_a_it"
schema_b="federation_b_it"
for schema in "$schema_a" "$schema_b"; do
  PGPASSWORD=xmpp-test-password psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    --set ON_ERROR_STOP=1 \
    --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE; CREATE SCHEMA \"$schema\";" >/dev/null
done

mkdir -p certs data/federation-a data/federation-b
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Northstar Federation Test CA" \
  -keyout certs/federation-ca.key -out certs/federation-ca.crt >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" -keyout certs/federation-a.key -out certs/federation-a.csr >/dev/null 2>&1
openssl x509 -req -days 1 -in certs/federation-a.csr -CA certs/federation-ca.crt \
  -CAkey certs/federation-ca.key -CAcreateserial -copy_extensions copy \
  -out certs/federation-a.crt >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=remote.localhost" \
  -addext "subjectAltName=DNS:remote.localhost" -keyout certs/federation-b.key -out certs/federation-b.csr >/dev/null 2>&1
openssl x509 -req -days 1 -in certs/federation-b.csr -CA certs/federation-ca.crt \
  -CAkey certs/federation-ca.key -CAcreateserial -copy_extensions copy \
  -out certs/federation-b.crt >/dev/null 2>&1

cargo build --locked --offline
binary="$CARGO_TARGET_DIR/debug/rust-xmpp-server"
pid_a=""
pid_b=""
cleanup() {
  for pid in "$pid_a" "$pid_b"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
  done
  for pid in "$pid_a" "$pid_b"; do
    if [[ -n "$pid" ]]; then wait "$pid" 2>/dev/null || true; fi
  done
}
trap cleanup EXIT

env XMPP_DOMAIN=localhost \
  DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema_a" \
  XMPP_BIND=127.0.0.1:15223 HTTP_BIND=127.0.0.1:18081 S2S_BIND=127.0.0.1:15268 \
  PUBLIC_URL=http://127.0.0.1:18081 UPLOAD_DIR="$project_dir/data/federation-a" \
  TLS_CERT_PATH="$project_dir/certs/federation-a.crt" TLS_KEY_PATH="$project_dir/certs/federation-a.key" \
  OPEN_REGISTRATION=true REQUIRE_ENCRYPTED_ARCHIVE=true REGISTRATION_RATE_PER_HOUR=20 \
  FEDERATION_ENABLED=true FEDERATION_ALLOW_PRIVATE_IPS=true \
  FEDERATION_DNS_OVERRIDES=remote.localhost=127.0.0.1:15269 \
  FEDERATION_EXTRA_ROOT_CERT_PATH="$project_dir/certs/federation-ca.crt" \
  LOG_FORMAT=json RUST_LOG=rust_xmpp_server=debug \
  "$binary" >federation-a.log 2>&1 &
pid_a=$!

env XMPP_DOMAIN=remote.localhost \
  DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$schema_b" \
  XMPP_BIND=127.0.0.1:15224 HTTP_BIND=127.0.0.1:18082 S2S_BIND=127.0.0.1:15269 \
  PUBLIC_URL=http://127.0.0.1:18082 UPLOAD_DIR="$project_dir/data/federation-b" \
  TLS_CERT_PATH="$project_dir/certs/federation-b.crt" TLS_KEY_PATH="$project_dir/certs/federation-b.key" \
  OPEN_REGISTRATION=true REQUIRE_ENCRYPTED_ARCHIVE=true REGISTRATION_RATE_PER_HOUR=20 \
  FEDERATION_ENABLED=true FEDERATION_ALLOW_PRIVATE_IPS=true \
  FEDERATION_DNS_OVERRIDES=localhost=127.0.0.1:15268 \
  FEDERATION_EXTRA_ROOT_CERT_PATH="$project_dir/certs/federation-ca.crt" \
  LOG_FORMAT=json RUST_LOG=rust_xmpp_server=debug \
  "$binary" >federation-b.log 2>&1 &
pid_b=$!

for url in http://127.0.0.1:18081/readyz http://127.0.0.1:18082/readyz; do
  for _ in $(seq 1 150); do
    if curl --silent --fail "$url" >/dev/null; then break; fi
    sleep 0.1
  done
  curl --silent --fail "$url" >/dev/null
done

python3 scripts/federation-wsl.py
