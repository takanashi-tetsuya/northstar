#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
database="${XMPP_TEST_DATABASE:-xmpp_test}"
suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
schema="northstar_roster_it_${suffix}"

if [[ "$database" != "xmpp_test" ]] ||
   [[ ! "$schema" =~ ^northstar_roster_it_[a-f0-9]{32}$ ]] ||
   (( ${#schema} > 63 )); then
  echo "refusing unsafe roster-service test target" >&2
  exit 2
fi

db=(--host 127.0.0.1 --username xmpp_test --dbname "$database")
export PGPASSWORD="xmpp-test-password"
created=false
cleanup() {
  if [[ "$created" == "true" ]]; then
    psql "${db[@]}" --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE" >/dev/null
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

exists="$(psql "${db[@]}" --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')")"
[[ "$exists" == "f" ]] || { echo "random schema already exists" >&2; exit 2; }
psql "${db[@]}" --set ON_ERROR_STOP=1 \
  --command "CREATE SCHEMA \"$schema\"" >/dev/null
created=true

cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/$database?options=-csearch_path%3D$schema"

cargo test --locked --offline \
  db::roster::blocking_match_tests::roster_service_snapshot_authorization_and_account_identity_are_fenced \
  -- --ignored --exact --nocapture --test-threads=1
cargo test --locked --offline \
  db::roster::blocking_match_tests::roster_removal_settles_local_mutual_pending_and_federated_state_atomically \
  -- --ignored --exact --nocapture --test-threads=1
cargo test --locked --offline \
  services::presence::tests:: \
  -- --ignored --nocapture --test-threads=1

cleanup
created=false
remaining="$(psql "${db[@]}" --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')")"
[[ "$remaining" == "f" ]] || { echo "roster-service schema cleanup failed" >&2; exit 1; }
trap - EXIT
