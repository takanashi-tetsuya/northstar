#!/usr/bin/env bash
# Start a disposable, loopback-only MinIO from a verified upstream release.
# The caller owns the private work directory and must call northstar_minio_stop
# from its EXIT trap.

readonly NORTHSTAR_MINIO_RELEASE='RELEASE.2025-09-07T16-13-09Z'
readonly NORTHSTAR_MINIO_DEB_SHA256='eeda08f699f6592d1b868ac8bda864ae2cacdb5ee1b888663366e8c8ff566249'
readonly NORTHSTAR_MINIO_DEB_URL="https://github.com/minio/minio/releases/download/$NORTHSTAR_MINIO_RELEASE/minio_20250907161309.0.0_amd64.deb"

northstar_minio_start() {
  local work_dir=$1 package port console_port binary
  [[ -d "$work_dir" ]] || { echo 'MinIO fixture needs a private work directory' >&2; return 2; }
  [[ -z "${NORTHSTAR_MINIO_PID:-}" ]] || { echo 'MinIO fixture is already running' >&2; return 2; }
  for program in curl dpkg-deb openssl python3 sha256sum; do
    command -v "$program" >/dev/null || { echo "MinIO fixture needs $program" >&2; return 2; }
  done

  NORTHSTAR_MINIO_ACCESS_KEY_FILE="$work_dir/minio-access-key"
  NORTHSTAR_MINIO_SECRET_KEY_FILE="$work_dir/minio-secret-key"
  printf 'northstar%s\n' "$(openssl rand -hex 12)" >"$NORTHSTAR_MINIO_ACCESS_KEY_FILE"
  openssl rand -hex 24 >"$NORTHSTAR_MINIO_SECRET_KEY_FILE"
  chmod 0600 "$NORTHSTAR_MINIO_ACCESS_KEY_FILE" "$NORTHSTAR_MINIO_SECRET_KEY_FILE"

  package="${NORTHSTAR_MINIO_DEB_FILE:-$work_dir/minio.deb}"
  if [[ -z "${NORTHSTAR_MINIO_DEB_FILE:-}" ]]; then
    curl --fail --location --silent --show-error --retry 3 \
      --output "$package" "$NORTHSTAR_MINIO_DEB_URL"
  fi
  printf '%s  %s\n' "$NORTHSTAR_MINIO_DEB_SHA256" "$package" | sha256sum --check --status || {
    echo 'MinIO release checksum mismatch' >&2
    return 1
  }
  dpkg-deb --extract "$package" "$work_dir/minio-release"
  binary="$work_dir/minio-release/usr/local/bin/minio"
  [[ -x "$binary" ]] || { echo 'MinIO release package has no executable' >&2; return 1; }
  mkdir -m 0700 "$work_dir/minio-data"
  read -r port console_port < <(python3 - <<'PY'
import socket
with socket.socket() as api, socket.socket() as console:
    api.bind(('127.0.0.1', 0))
    console.bind(('127.0.0.1', 0))
    print(api.getsockname()[1], console.getsockname()[1])
PY
)
  NORTHSTAR_MINIO_ENDPOINT="http://127.0.0.1:$port"
  NORTHSTAR_MINIO_LOG="$work_dir/minio.log"
  MINIO_ROOT_USER_FILE="$NORTHSTAR_MINIO_ACCESS_KEY_FILE" \
    MINIO_ROOT_PASSWORD_FILE="$NORTHSTAR_MINIO_SECRET_KEY_FILE" \
    MINIO_BROWSER=off HOME="$work_dir" \
    "$binary" server "$work_dir/minio-data" \
      --address "127.0.0.1:$port" --console-address "127.0.0.1:$console_port" \
      >"$NORTHSTAR_MINIO_LOG" 2>&1 &
  NORTHSTAR_MINIO_PID=$!
  local ready=false
  for _ in $(seq 1 60); do
    if curl --silent --fail --max-time 2 "$NORTHSTAR_MINIO_ENDPOINT/minio/health/live" >/dev/null; then
      ready=true
      break
    fi
    if ! kill -0 "$NORTHSTAR_MINIO_PID" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  if [[ "$ready" != true ]]; then
    tail -n 50 "$NORTHSTAR_MINIO_LOG" >&2 || true
    echo 'isolated MinIO did not become healthy' >&2
    return 1
  fi
  echo "isolated MinIO ready on $NORTHSTAR_MINIO_ENDPOINT"
}

northstar_minio_stop() {
  if [[ -n "${NORTHSTAR_MINIO_PID:-}" ]]; then
    kill "$NORTHSTAR_MINIO_PID" 2>/dev/null || true
    wait "$NORTHSTAR_MINIO_PID" 2>/dev/null || true
    NORTHSTAR_MINIO_PID=''
  fi
}
