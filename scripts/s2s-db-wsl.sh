#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
random_suffix="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
test_schema="${XMPP_TEST_SCHEMA:-northstar_s2s_it_$random_suffix}"

if [[ "$test_database" != "xmpp_test" ]]; then
  echo "S2S outbox tests are restricted to the dedicated xmpp_test database" >&2
  exit 2
fi
if [[ ! "$test_schema" =~ ^northstar_s2s_it_[a-f0-9]{32}$ ]] ||
   (( ${#test_schema} > 63 )); then
  echo "refusing unsafe or non-random XMPP_TEST_SCHEMA: $test_schema" >&2
  exit 2
fi

database_args=(--host 127.0.0.1 --username xmpp_test --dbname xmpp_test)
test_log="$(mktemp /tmp/northstar-s2s-db.XXXXXX.log)"
created=0

cleanup() {
  status=$?
  trap - EXIT INT TERM
  local inner_schema
  while IFS= read -r inner_schema; do
    [[ "$inner_schema" =~ ^s2s_(ordering|outbox)_test_[a-f0-9]{32}$ ]] || continue
    PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$inner_schema\" CASCADE" >/dev/null || status=1
  done < <(sed -n 's/^isolated_schema_created=\(s2s_\(ordering\|outbox\)_test_[a-f0-9]\{32\}\)$/\1/p' "$test_log" | sort -u)
  if [[ "$created" == 1 ]]; then
    PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$test_schema\" CASCADE" >/dev/null || status=1
    remains="$(PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
      --tuples-only --no-align \
      --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')" \
      2>/dev/null || printf unknown)"
    [[ "$remains" == "f" ]] || status=1
  fi
  rm -f -- "$test_log"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$(PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
  --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")" == "t" ]]; then
  echo "refusing to reuse existing PostgreSQL schema: $test_schema" >&2
  exit 2
fi
PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
  --set ON_ERROR_STOP=1 \
  --command "CREATE SCHEMA \"$test_schema\"" >/dev/null
created=1

cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema"

run_exact_ignored() {
  local test_name="$1"
  local test_output
  if ! test_output="$(cargo test --locked --offline "$test_name" -- --ignored --exact --nocapture 2>&1)"; then
    printf '%s\n' "$test_output" | tee -a "$test_log"
    return 1
  fi
  printf '%s\n' "$test_output" | tee -a "$test_log"
  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$test_output"; then
    echo "expected exactly one ignored test to execute: $test_name" >&2
    return 1
  fi
}

run_exact_ignored db::s2s::tests::claim_preserves_mam_results_before_fin
run_exact_ignored db::s2s::tests::scoped_claims_are_cross_worker_ordered_and_component_safe
