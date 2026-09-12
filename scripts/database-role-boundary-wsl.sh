#!/usr/bin/env bash
set -Eeuo pipefail
set +x

# Local counterpart of the PostgreSQL 17 service job in .github/workflows/ci.yml.
# It creates a private Unix-socket-only cluster, runs the same destructive
# role-boundary fixture there, and removes only the directory that this wrapper
# created. It must never target the developer's shared PostgreSQL.

readonly project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"

if [[ "$(id -u)" -eq 0 ]]; then
  echo "run the database role boundary wrapper as an ordinary WSL user" >&2
  exit 2
fi

for command in bash cargo chmod id install mktemp pg_config realpath rm tail; do
  command -v "$command" >/dev/null || {
    echo "database role boundary wrapper requires: $command" >&2
    exit 2
  }
done

readonly pg_bin="$(pg_config --bindir)"
for command in initdb pg_ctl postgres; do
  [[ -x "$pg_bin/$command" ]] || {
    echo "PostgreSQL server tool is unavailable: $pg_bin/$command" >&2
    exit 2
  }
done

runtime_root="$(mktemp -d /tmp/northstar-database-role-wsl.XXXXXX)"
runtime_root="$(realpath -e -- "$runtime_root")"
[[ "$runtime_root" =~ ^/tmp/northstar-database-role-wsl\.[A-Za-z0-9]{6}$ ]] || {
  echo "refusing unsafe PostgreSQL fixture directory: $runtime_root" >&2
  exit 2
}
readonly runtime_root
readonly data_dir="$runtime_root/data"
readonly socket_dir="$runtime_root/socket"
readonly password_file="$runtime_root/control-password"
readonly postgres_log="$runtime_root/postgres.log"
readonly control_password='northstar-ci-control-password-00000001'
postgres_started=false

cleanup() {
  local original_status=$?
  local cleanup_status=0
  trap - EXIT
  set +e
  if [[ "$postgres_started" == true ]]; then
    "$pg_bin/pg_ctl" -D "$data_dir" -m fast -w stop >/dev/null 2>&1 \
      || cleanup_status=1
    postgres_started=false
  fi
  if [[ "$runtime_root" =~ ^/tmp/northstar-database-role-wsl\.[A-Za-z0-9]{6}$ ]]; then
    rm -rf -- "$runtime_root" || cleanup_status=1
  else
    echo "refusing cleanup of unexpected PostgreSQL fixture: $runtime_root" >&2
    cleanup_status=1
  fi
  if (( original_status != 0 )); then
    exit "$original_status"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT

install -m 0600 /dev/null "$password_file"
printf '%s\n' "$control_password" >"$password_file"
install -d -m 0700 "$socket_dir"

"$pg_bin/initdb" \
  --pgdata="$data_dir" \
  --username=northstar_ci_control \
  --pwfile="$password_file" \
  --auth-local=scram-sha-256 \
  --auth-host=scram-sha-256 \
  --no-instructions >/dev/null

if ! "$pg_bin/pg_ctl" -D "$data_dir" -l "$postgres_log" -w start \
  -o "-c listen_addresses='' -c unix_socket_directories=$socket_dir -c unix_socket_permissions=0700 -c password_encryption=scram-sha-256" \
  >/dev/null; then
  echo "private PostgreSQL fixture failed to start" >&2
  tail -n 80 "$postgres_log" >&2 || true
  exit 1
fi
postgres_started=true

if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/target-wsl}"
fi

CI=true \
NORTHSTAR_DATABASE_ROLE_CI=true \
NORTHSTAR_CI_CONTROL_PASSWORD="$control_password" \
PGHOST="$socket_dir" \
bash scripts/database-role-boundary-db-ci.sh

echo "database role boundary WSL validation passed on a private Unix-socket PostgreSQL cluster"
