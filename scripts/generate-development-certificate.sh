#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

certificate_path="${1:-certs/server.crt}"
private_key_path="${2:-certs/server.key}"
if [[ -e "$certificate_path" || -L "$certificate_path" || -e "$private_key_path" || -L "$private_key_path" ]]; then
  echo "refusing to overwrite an existing certificate or private key" >&2
  exit 2
fi

mkdir -p "$(dirname "$certificate_path")" "$(dirname "$private_key_path")"
work_dir="$(mktemp -d /tmp/northstar-development-certificate.XXXXXX)"
cleanup() {
  case "$work_dir" in
    /tmp/northstar-development-certificate.*) rm -rf -- "$work_dir" ;;
  esac
}
trap cleanup EXIT
umask 077

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
  -subj "/CN=localhost/OU=Northstar Development Only" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=critical,serverAuth" \
  -addext "subjectAltName=DNS:localhost,DNS:conference.localhost,DNS:upload.localhost,DNS:pubsub.localhost,IP:127.0.0.1,IP:::1" \
  -keyout "$work_dir/server.key" \
  -out "$work_dir/server.crt" >/dev/null 2>&1

openssl x509 -in "$work_dir/server.crt" -noout -checkhost localhost >/dev/null
openssl verify -CAfile "$work_dir/server.crt" "$work_dir/server.crt" >/dev/null
certificate_key_hash="$(openssl x509 -in "$work_dir/server.crt" -pubkey -noout | openssl sha256)"
private_key_hash="$(openssl pkey -in "$work_dir/server.key" -pubout | openssl sha256)"
[[ "$certificate_key_hash" == "$private_key_hash" ]] || {
  echo "generated certificate and private key do not match" >&2
  exit 1
}

install -m 0644 "$work_dir/server.crt" "$certificate_path"
install -m 0600 "$work_dir/server.key" "$private_key_path"
echo "created DEVELOPMENT-ONLY localhost certificate at $certificate_path"
echo "production preflight and public-domain runtime validation will reject this self-signed certificate"
