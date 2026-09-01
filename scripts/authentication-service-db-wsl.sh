#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
database="${XMPP_TEST_DATABASE:-xmpp_test}"
suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
schema="northstar_authentication_it_${suffix}"

if [[ "$database" != "xmpp_test" ]] ||
   [[ ! "$schema" =~ ^northstar_authentication_it_[a-f0-9]{32}$ ]] ||
   (( ${#schema} > 63 )); then
  echo "refusing unsafe AuthenticationService test target" >&2
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

run_exact_ignored() {
  local test_name="$1"
  local output
  output="$(cargo test --locked --offline "$test_name" -- --ignored --exact --nocapture --test-threads=1 2>&1)" || {
    printf '%s\n' "$output"
    exit 1
  }
  printf '%s\n' "$output"
  grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$output" || {
    echo "expected exactly one ignored authentication test to execute: $test_name" >&2
    exit 1
  }
}

run_exact_ignored \
  services::authentication::tests::authentication_service_fences_all_credential_and_inline_state_transitions
run_exact_ignored \
  services::authentication::tests::login_epoch_publication_is_fenced_invisible_and_atomic_with_binding
run_exact_ignored \
  services::authentication::tests::publication_lease_lock_blocks_reserve_release_and_expiry_cleanup
run_exact_ignored \
  db::fast::tests::fast_derivation_integrity_failures_are_side_effect_free

cleanup
created=false
remaining="$(psql "${db[@]}" --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')")"
[[ "$remaining" == "f" ]] || { echo "AuthenticationService schema cleanup failed" >&2; exit 1; }
trap - EXIT
