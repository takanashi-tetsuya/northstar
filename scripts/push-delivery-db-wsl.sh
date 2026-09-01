#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
database="${XMPP_TEST_DATABASE:-xmpp_test}"
suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
schema="northstar_push_delivery_it_${suffix}"

if [[ "$database" != "xmpp_test" ]] ||
   [[ ! "$schema" =~ ^northstar_push_delivery_it_[a-f0-9]{32}$ ]] ||
   (( ${#schema} > 63 )); then
  echo "refusing unsafe push-delivery test target" >&2
  exit 2
fi

db=(--host 127.0.0.1 --username xmpp_test --dbname "$database")
export PGPASSWORD="xmpp-test-password"
created=false
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ "$created" == "true" ]]; then
    psql "${db[@]}" --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE" >/dev/null || status=1
    remaining="$(psql "${db[@]}" --tuples-only --no-align \
      --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')" \
      2>/dev/null || printf unknown)"
    if [[ "$remaining" != "f" ]]; then
      echo "push-delivery schema cleanup failed: $schema (exists=$remaining)" >&2
      status=1
    fi
  fi
  exit "$status"
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

test_name="db::push::integration_tests::quota_upsert_and_durable_claim_are_atomic"
output="$(cargo test --locked --offline "$test_name" -- --ignored --exact --nocapture --test-threads=1 2>&1)" || {
  printf '%s\n' "$output"
  exit 1
}
printf '%s\n' "$output"
grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$output" || {
  echo "expected exactly one ignored push-delivery test to execute" >&2
  exit 1
}

cleanup
