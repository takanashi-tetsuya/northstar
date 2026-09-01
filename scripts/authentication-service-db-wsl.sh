#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
database="${XMPP_TEST_DATABASE:-xmpp_test}"

if [[ "$database" != "xmpp_test" ]]; then
  echo "refusing unsafe AuthenticationService test target" >&2
  exit 2
fi

db=(--host 127.0.0.1 --username xmpp_test --dbname "$database")
export PGPASSWORD="xmpp-test-password"
active_schema=""
active_schema_created=false

schema_is_safe() {
  local candidate="$1"
  [[ "$candidate" =~ ^northstar_authentication_it_[a-f0-9]{32}$ ]] &&
    (( ${#candidate} <= 63 ))
}

cleanup_active_schema() {
  if [[ "$active_schema_created" == "true" ]]; then
    schema_is_safe "$active_schema" || {
      echo "refusing unsafe AuthenticationService schema cleanup target" >&2
      return 2
    }
    psql "${db[@]}" --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$active_schema\" CASCADE" >/dev/null
    local remaining
    remaining="$(psql "${db[@]}" --tuples-only --no-align \
      --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$active_schema')")"
    [[ "$remaining" == "f" ]] || {
      echo "AuthenticationService schema cleanup failed" >&2
      return 1
    }
    active_schema_created=false
    active_schema=""
  fi
}

cleanup_on_exit() {
  cleanup_active_schema || true
}

create_active_schema() {
  [[ "$active_schema_created" == "false" ]] || {
    echo "refusing to replace a live AuthenticationService test schema" >&2
    return 2
  }
  local suffix
  suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
  active_schema="northstar_authentication_it_${suffix}"
  schema_is_safe "$active_schema" || {
    echo "refusing unsafe AuthenticationService test target" >&2
    return 2
  }
  local exists
  exists="$(psql "${db[@]}" --tuples-only --no-align \
    --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$active_schema')")"
  [[ "$exists" == "f" ]] || {
    echo "random schema already exists" >&2
    return 2
  }
  # Arm cleanup before CREATE so an interrupt immediately after PostgreSQL
  # commits the DDL cannot leave an untracked fixture schema behind.
  active_schema_created=true
  psql "${db[@]}" --set ON_ERROR_STOP=1 \
    --command "CREATE SCHEMA \"$active_schema\"" >/dev/null
  export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/$database?options=-csearch_path%3D$active_schema"
}

trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi

run_exact_ignored() {
  local test_name="$1"
  local output
  # Each exact test gets a fresh migration ledger and capacity authority. In
  # particular, accounts created by one test must not be reinterpreted under a
  # later test's deliberately small 64-shard capacity fixture.
  create_active_schema
  output="$(cargo test --locked --offline "$test_name" -- --ignored --exact --nocapture --test-threads=1 2>&1)" || {
    printf '%s\n' "$output"
    exit 1
  }
  printf '%s\n' "$output"
  grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$output" || {
    echo "expected exactly one ignored authentication test to execute: $test_name" >&2
    exit 1
  }
  cleanup_active_schema
}

run_exact_ignored \
  services::authentication::tests::authentication_service_fences_all_credential_and_inline_state_transitions
run_exact_ignored \
  services::authentication::tests::login_epoch_publication_is_fenced_invisible_and_atomic_with_binding
run_exact_ignored \
  services::authentication::tests::publication_lease_lock_blocks_reserve_release_and_fences_expiry_cleanup
run_exact_ignored \
  db::fast::tests::fast_derivation_integrity_failures_are_side_effect_free

trap - EXIT
