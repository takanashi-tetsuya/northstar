#!/usr/bin/env bash
# Disposable, versioned MinIO for offline storage integration tests.
# Source this file, call northstar_minio_start, then northstar_minio_stop in
# the caller's EXIT trap. No production bucket or credentials are accepted.

readonly NORTHSTAR_MINIO_IMAGE='quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e'

northstar_minio_start() {
  local work_dir=$1
  [[ -d "$work_dir" ]] || { echo 'MinIO fixture needs a private work directory' >&2; return 2; }
  [[ -z "${NORTHSTAR_MINIO_CONTAINER:-}" ]] || { echo 'MinIO fixture is already running' >&2; return 2; }
  NORTHSTAR_MINIO_ACCESS_KEY_FILE="$work_dir/minio-access-key"
  NORTHSTAR_MINIO_SECRET_KEY_FILE="$work_dir/minio-secret-key"
  printf 'northstar%s\n' "$(openssl rand -hex 12)" >"$NORTHSTAR_MINIO_ACCESS_KEY_FILE"
  openssl rand -hex 24 >"$NORTHSTAR_MINIO_SECRET_KEY_FILE"
  chmod 0600 "$NORTHSTAR_MINIO_ACCESS_KEY_FILE" "$NORTHSTAR_MINIO_SECRET_KEY_FILE"
  local port
  port="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PY
)"
  NORTHSTAR_MINIO_ENDPOINT="http://127.0.0.1:$port"
  NORTHSTAR_MINIO_CONTAINER="northstar-minio-it-$(openssl rand -hex 8)"
  NORTHSTAR_MINIO_ENGINE="${NORTHSTAR_MINIO_ENGINE:-docker}"
  [[ "$NORTHSTAR_MINIO_ENGINE" == docker || "$NORTHSTAR_MINIO_ENGINE" == podman ]] || {
    echo 'MinIO fixture accepts only Docker or Podman' >&2
    return 2
  }
  local fixture_uid fixture_gid fixture_user fixture_tmpfs
  fixture_uid="$(id -u)"
  fixture_gid="$(id -g)"
  fixture_user="$fixture_uid:$fixture_gid"
  fixture_tmpfs="/data:rw,size=512m,mode=0700,uid=$fixture_uid,gid=$fixture_gid"
  if [[ "$NORTHSTAR_MINIO_ENGINE" == podman ]]; then
    # Root inside rootless Podman maps to the ordinary host user who owns
    # the private credential files; its tmpfs does not accept uid/gid options.
    fixture_user='0:0'
    fixture_tmpfs='/data:rw,size=512m,mode=0700'
  fi
  "$NORTHSTAR_MINIO_ENGINE" run --detach --name "$NORTHSTAR_MINIO_CONTAINER" --network host \
    --user "$fixture_user" \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --tmpfs "$fixture_tmpfs" \
    --mount "type=bind,src=$NORTHSTAR_MINIO_ACCESS_KEY_FILE,dst=/run/secrets/access,readonly" \
    --mount "type=bind,src=$NORTHSTAR_MINIO_SECRET_KEY_FILE,dst=/run/secrets/secret,readonly" \
    --env MINIO_ROOT_USER_FILE=/run/secrets/access \
    --env MINIO_ROOT_PASSWORD_FILE=/run/secrets/secret \
    --env HOME=/data --env MINIO_BROWSER=off \
    "$NORTHSTAR_MINIO_IMAGE" server /data --address "127.0.0.1:$port" >/dev/null
  local ready=false
  for _ in $(seq 1 60); do
    if curl --silent --fail --max-time 2 "$NORTHSTAR_MINIO_ENDPOINT/minio/health/live" >/dev/null; then
      ready=true
      break
    fi
    sleep 1
  done
  if [[ "$ready" != true ]]; then
    "$NORTHSTAR_MINIO_ENGINE" logs "$NORTHSTAR_MINIO_CONTAINER" >&2 || true
    echo 'isolated MinIO did not become healthy' >&2
    return 1
  fi
  echo "isolated MinIO ready on $NORTHSTAR_MINIO_ENDPOINT"
}

northstar_minio_stop() {
  if [[ -n "${NORTHSTAR_MINIO_CONTAINER:-}" ]]; then
    "${NORTHSTAR_MINIO_ENGINE:-docker}" rm --force "$NORTHSTAR_MINIO_CONTAINER" >/dev/null 2>&1 || true
    NORTHSTAR_MINIO_CONTAINER=''
  fi
}
