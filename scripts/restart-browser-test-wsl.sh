#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
expected_binary="$project_dir/target-wsl/debug/rust-xmpp-server"
pid_file="$project_dir/browser-server.pid"

cd "$project_dir"

if [[ ! -x "$expected_binary" ]]; then
  echo "browser test binary is missing; run scripts/verify-wsl.sh all first" >&2
  exit 1
fi

if [[ -f "$pid_file" ]]; then
  previous_pid="$(cat "$pid_file")"
  if [[ ! "$previous_pid" =~ ^[0-9]+$ ]]; then
    echo "invalid browser-server.pid" >&2
    exit 1
  fi
  if kill -0 "$previous_pid" 2>/dev/null; then
    actual_binary="$(readlink "/proc/$previous_pid/exe" 2>/dev/null || true)"
    resolved_expected="$(readlink -f "$expected_binary")"
    if [[ "$actual_binary" != "$resolved_expected" && "$actual_binary" != "$resolved_expected (deleted)" ]]; then
      echo "refusing to stop PID $previous_pid because it is not the browser test server" >&2
      exit 1
    fi
    kill "$previous_pid"
    for _ in $(seq 1 100); do
      kill -0 "$previous_pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$previous_pid" 2>/dev/null; then
      echo "browser test server did not stop cleanly" >&2
      exit 1
    fi
  fi
fi

nohup env \
  XMPP_DOMAIN=localhost \
  DATABASE_URL=postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test \
  XMPP_BIND=127.0.0.1:15222 \
  S2S_BIND=127.0.0.1:15226 \
  HTTP_BIND=0.0.0.0:18080 \
  PUBLIC_URL=http://127.0.0.1:18080 \
  UPLOAD_DIR="$project_dir/data/browser-uploads" \
  TLS_CERT_PATH="$project_dir/certs/browser.crt" \
  TLS_KEY_PATH="$project_dir/certs/browser.key" \
  OPEN_REGISTRATION=true \
  REQUIRE_ENCRYPTED_ARCHIVE=true \
  FEDERATION_ENABLED=false \
  REGISTRATION_RATE_PER_HOUR=20 \
  BOOTSTRAP_ADMIN_USERNAME=admin_it \
  BOOTSTRAP_ADMIN_PASSWORD=integration-admin-password-123 \
  LOG_FORMAT=json \
  RUST_LOG=rust_xmpp_server=info \
  "$expected_binary" \
  >browser-server.log 2>&1 </dev/null &

server_pid=$!
echo "$server_pid" >"$pid_file"

for _ in $(seq 1 100); do
  if curl --silent --fail http://127.0.0.1:18080/readyz >/dev/null; then
    echo "$server_pid"
    exit 0
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat browser-server.log >&2
    exit 1
  fi
  sleep 0.1
done

echo "browser test server did not become ready" >&2
exit 1
