#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
destination="${1:?supply a private output directory}"
mkdir -p "$destination"
if [[ -e "$destination/caddy" ]]; then
  echo "refusing to overwrite an existing Caddy test binary" >&2
  exit 2
fi
cd "$project_dir"
image="$(docker compose config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["caddy"]["image"])')"
[[ "$image" == caddy:*@sha256:* ]] || { echo 'Caddy must be digest-pinned' >&2; exit 2; }
container="$(docker create "$image")"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
docker cp "$container:/usr/bin/caddy" "$destination/caddy"
chmod 0755 "$destination/caddy"
"$destination/caddy" version
