#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
random_suffix="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
test_schema="${XMPP_TEST_SCHEMA:-northstar_message_pow_it_$random_suffix}"

if [[ "$test_database" != "xmpp_test" ]]; then
  echo "refusing to run message PoW tests outside the disposable xmpp_test database" >&2
  exit 2
fi
if [[ ! "$test_schema" =~ ^northstar_message_pow_it_[a-f0-9]{32}$ ]] ||
   (( ${#test_schema} > 63 )); then
  echo "refusing unsafe or non-random XMPP_TEST_SCHEMA: $test_schema" >&2
  exit 2
fi

database_args=(--host 127.0.0.1 --username xmpp_test --dbname xmpp_test)
test_log="$(mktemp /tmp/northstar-message-pow-db.XXXXXX.log)"
created=0

cleanup() {
  status=$?
  trap - EXIT INT TERM
  local inner_schema
  while IFS= read -r inner_schema; do
    [[ "$inner_schema" =~ ^(retraction_service_test|message_acceptance_test)_[a-f0-9]{32}$ ]] || continue
    PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$inner_schema\" CASCADE" >/dev/null || status=1
  done < <(sed -En 's/^isolated_schema=((retraction_service_test|message_acceptance_test)_[a-f0-9]{32})$/\1/p' "$test_log" | sort -u)
  if [[ "$created" == "1" ]]; then
    PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$test_schema\" CASCADE" >/dev/null || status=1
    remains="$(PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
      --tuples-only --no-align \
      --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')" \
      2>/dev/null || printf unknown)"
    if [[ "$remains" != "f" ]]; then
      echo "isolated message PoW schema was not removed: $test_schema (exists=$remains)" >&2
      status=1
    fi
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
  export CARGO_TARGET_DIR="${MESSAGE_POW_TARGET_DIR:-$project_dir/target/message-pow-wsl}"
fi
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema"

cargo test --locked --offline \
  abuse::tests::postgres_v2_intent_mismatch_consumes_but_rollback_restores_proof \
  -- --ignored --nocapture
cargo test --locked --offline \
  abuse::tests::postgres_parallel_message_challenges_are_independent_bounded_and_one_use \
  -- --ignored --nocapture
cargo test --locked --offline \
  abuse::tests::postgres_challenge_capacity_is_concurrent_restart_safe_and_hard_limited \
  -- --ignored --nocapture
cargo test --locked --offline \
  abuse::tests::postgres_message_admission_is_crash_atomic_fenced_and_rotation_safe \
  -- --ignored --nocapture
cargo test --locked --offline \
  abuse::tests::postgres_message_admission_capacity_and_cleanup_are_bounded \
  -- --ignored --nocapture
cargo test --locked --offline \
  db::archive::offline_queue_tests::offline_dedupe_rotation_grace_capacity_and_cleanup_are_bounded \
  -- --ignored --nocapture

run_exact_ignored() {
  local test_name="$1" test_output
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
run_exact_ignored services::retractions::tests::c2s_projection_is_atomic_idempotent_and_retains_replay_intent
run_exact_ignored services::retractions::tests::exact_replay_conflict_and_outbox_failure_are_atomic
run_exact_ignored s2s::inbound::tests::message_acceptance_boundary_prevents_mam_retraction_and_offline_ghosts
