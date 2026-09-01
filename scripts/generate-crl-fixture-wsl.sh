#!/usr/bin/env bash
set -euo pipefail

workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config="$workspace/scripts/fixtures/crl-openssl.cnf"
fixture_parent="${1:-/tmp}"
mkdir -p "$fixture_parent"
fixture="$(mktemp -d "$fixture_parent/northstar-crl.XXXXXX")"

initialize_ca() {
  local directory="$1"
  mkdir -p "$directory/newcerts"
  : > "$directory/index.txt"
  openssl rand -hex 16 > "$directory/serial"
  openssl rand -hex 16 > "$directory/crlnumber"
  CRL_FIXTURE_DIR="$directory" openssl req -new -x509 -newkey rsa:3072 -nodes \
    -days 30 -sha256 -subj "/CN=Northstar CRL Test Root" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$directory/root.key" -out "$directory/root.pem" >/dev/null 2>&1
}

issue_leaf() {
  local directory="$1"
  local name="$2"
  local extension="$3"
  local common_name="$4"
  openssl req -new -newkey rsa:3072 -nodes -sha256 -subj "/CN=$common_name" \
    -keyout "$directory/$name.key" -out "$directory/$name.csr" >/dev/null 2>&1
  CRL_FIXTURE_DIR="$directory" openssl ca -batch -config "$config" \
    -extensions "$extension" -in "$directory/$name.csr" \
    -out "$directory/$name.pem" >/dev/null 2>&1
}

initialize_ca "$fixture"
issue_leaf "$fixture" valid-server server_cert server.example.test
cp "$fixture/valid-server.pem" "$fixture/valid-server-chain.pem"
openssl x509 -in "$fixture/root.pem" -outform PEM >> "$fixture/valid-server-chain.pem"
issue_leaf "$fixture" revoked-server server_cert server.example.test
issue_leaf "$fixture" valid-client client_cert client.example.test
issue_leaf "$fixture" revoked-client client_cert client.example.test
CRL_FIXTURE_DIR="$fixture" openssl ca -batch -config "$config" \
  -revoke "$fixture/revoked-server.pem" >/dev/null 2>&1
CRL_FIXTURE_DIR="$fixture" openssl ca -batch -config "$config" \
  -revoke "$fixture/revoked-client.pem" >/dev/null 2>&1
CRL_FIXTURE_DIR="$fixture" openssl ca -batch -config "$config" \
  -gencrl -out "$fixture/crl.pem" >/dev/null 2>&1
CRL_FIXTURE_DIR="$fixture" openssl ca -batch -config "$config" -gencrl \
  -crl_lastupdate 20200101000000Z -crl_nextupdate 20200102000000Z \
  -out "$fixture/expired-crl.pem" >/dev/null 2>&1
CRL_FIXTURE_DIR="$fixture" openssl ca -batch -config "$config" \
  -gencrl -out "$fixture/renewed-crl.pem" >/dev/null 2>&1

other="$fixture/other"
initialize_ca "$other"
CRL_FIXTURE_DIR="$other" openssl ca -batch -config "$config" \
  -gencrl -out "$fixture/unknown-issuer-crl.pem" >/dev/null 2>&1

printf '%s\n' "$fixture"
