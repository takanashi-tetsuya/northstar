#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
random_suffix="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
test_schema="${XMPP_TEST_SCHEMA:-northstar_pubsub_audit_it_$random_suffix}"

if [[ "$test_database" != "xmpp_test" ]]; then
  echo "refusing to run PubSub integration tests outside the disposable xmpp_test database" >&2
  exit 2
fi
if [[ ! "$test_schema" =~ ^northstar_pubsub_audit_it_[a-f0-9]{32}$ ]]; then
  echo "refusing unsafe or non-random XMPP_TEST_SCHEMA: $test_schema" >&2
  exit 2
fi

database_args=(--host 127.0.0.1 --username xmpp_test --dbname xmpp_test)
creation_authorized=0
umask 077
schema_log="$(mktemp --tmpdir="${TMPDIR:-/tmp}" northstar-pubsub-created-schemas.XXXXXXXX)"
if [[ ! -f "$schema_log" || -L "$schema_log" ]]; then
  echo "failed to create a private regular schema recovery log" >&2
  exit 2
fi
chmod 600 "$schema_log"
export XMPP_TEST_CREATED_SCHEMA_LOG="$schema_log"
outer_schema_token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
if (( ${#outer_schema_token} != 32 )) ||
   [[ ! "$outer_schema_token" =~ ^[a-f0-9]{32}$ ]]; then
  echo "failed to generate an outer PubSub schema ownership token" >&2
  exit 2
fi

valid_internal_schema() {
  local candidate="$1"
  if (( ${#candidate} == 48 )) &&
     [[ "$candidate" =~ ^xmpp_test_vcard_[a-f0-9]{32}$ ]]; then
    return 0
  fi
  if (( ${#candidate} == 57 )) &&
     [[ "$candidate" =~ ^xmpp_test_vcard_audience_[a-f0-9]{32}$ ]]; then
    return 0
  fi
  return 1
}

drop_and_verify_schema() {
  local candidate="$1"
  local label="$2"
  local expected_token="$3"
  local failed=0
  local exists
  local remains
  if ! exists="$(PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
    --set ON_ERROR_STOP=1 --tuples-only --no-align \
    --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$candidate')")"; then
    echo "could not verify whether $label schema exists: $candidate" >&2
    return 1
  fi
  if [[ "$exists" == "f" ]]; then
    return 0
  fi
  if [[ "$exists" != "t" ]]; then
    echo "unexpected existence result for $label schema: $candidate ($exists)" >&2
    return 1
  fi
  if ! PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
    --set ON_ERROR_STOP=1 \
    --command "BEGIN;
               DO \$northstar_schema_cleanup\$
               DECLARE observed_token TEXT;
               BEGIN
                 SELECT token INTO STRICT observed_token
                   FROM \"$candidate\".northstar_test_schema_guard
                  WHERE singleton
                  FOR UPDATE;
                 IF observed_token <> '$expected_token' THEN
                   RAISE EXCEPTION 'schema ownership guard mismatch';
                 END IF;
               END;
               \$northstar_schema_cleanup\$;
               DROP SCHEMA \"$candidate\" CASCADE;
               COMMIT" >/dev/null; then
    echo "refusing or unable to delete $label schema after atomic ownership verification: $candidate" >&2
    return 1
  fi
  if ! remains="$(PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
    --set ON_ERROR_STOP=1 --tuples-only --no-align \
    --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$candidate')")"; then
    remains=unknown
    failed=1
  fi
  if [[ "$remains" != "f" ]]; then
    echo "$label schema was not removed: $candidate (exists=$remains)" >&2
    failed=1
  fi
  return "$failed"
}

cleanup() {
  local status=$?
  local cleanup_failed=0
  trap - EXIT INT TERM
  if [[ -f "$schema_log" && ! -L "$schema_log" ]]; then
    while IFS=' ' read -r registered_schema registered_token trailing ||
          [[ -n "${registered_schema:-}${registered_token:-}${trailing:-}" ]]; do
      [[ -n "${registered_schema:-}${registered_token:-}${trailing:-}" ]] || continue
      if [[ -n "${trailing:-}" ]] ||
         ! valid_internal_schema "$registered_schema" ||
         (( ${#registered_token} != 32 )) ||
         [[ ! "$registered_token" =~ ^[a-f0-9]{32}$ ]]; then
        echo "refusing unsafe entry from PubSub recovery log" >&2
        cleanup_failed=1
        continue
      fi
      drop_and_verify_schema \
        "$registered_schema" "isolated internal PubSub" "$registered_token" || cleanup_failed=1
    done < "$schema_log"
  else
    echo "private PubSub schema recovery log disappeared or became unsafe: $schema_log" >&2
    cleanup_failed=1
  fi
  if [[ "$creation_authorized" == 1 ]]; then
    if (( ${#test_schema} != 58 )) ||
       [[ ! "$test_schema" =~ ^northstar_pubsub_audit_it_[a-f0-9]{32}$ ]]; then
      echo "refusing unsafe outer PubSub schema during cleanup: $test_schema" >&2
      cleanup_failed=1
    else
      drop_and_verify_schema \
        "$test_schema" "isolated outer PubSub" "$outer_schema_token" || cleanup_failed=1
    fi
  fi
  if [[ "$cleanup_failed" == 0 ]]; then
    if ! rm -f -- "$schema_log"; then
      echo "failed to remove the private PubSub schema recovery log: $schema_log" >&2
      cleanup_failed=1
    fi
  fi
  if [[ "$cleanup_failed" == 1 ]]; then
    if [[ -f "$schema_log" && ! -L "$schema_log" ]]; then
      echo "PubSub schema recovery log retained for manual recovery: $schema_log" >&2
    fi
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

existing="$(PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
  --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")"
if [[ "$existing" == "t" ]]; then
  echo "refusing to reuse existing PostgreSQL schema: $test_schema" >&2
  exit 2
fi
if [[ "$existing" != "f" ]]; then
  echo "could not prove the generated PostgreSQL schema is absent: $test_schema" >&2
  exit 2
fi
creation_authorized=1
PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
  --set ON_ERROR_STOP=1 \
  --command "BEGIN;
             CREATE SCHEMA \"$test_schema\";
             CREATE TABLE \"$test_schema\".northstar_test_schema_guard
               (singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton), token TEXT NOT NULL);
             INSERT INTO \"$test_schema\".northstar_test_schema_guard(token)
               VALUES('$outer_schema_token');
             COMMIT" >/dev/null

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
  local output_log command_status
  output_log="$(mktemp --tmpdir="${TMPDIR:-/tmp}" northstar-pubsub-test.XXXXXXXX)"
  if [[ ! -f "$output_log" || -L "$output_log" ]]; then
    echo "failed to create a private PubSub test log" >&2
    return 1
  fi
  chmod 600 "$output_log"

  # Keep Cargo output live. Capturing it in a command substitution hides the
  # compiler/test phase that is actually stuck and can leave a parent timeout
  # with no useful evidence. The CI process-group supervisor still owns this
  # pipeline, while the log retains the exact-one-test assertion below.
  set +e
  cargo test --locked --offline "$test_name" -- --ignored --exact --nocapture 2>&1 | tee "$output_log"
  command_status=${PIPESTATUS[0]}
  set -e
  if (( command_status != 0 )); then
    rm -f -- "$output_log"
    return "$command_status"
  fi
  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' "$output_log"; then
    echo "expected exactly one ignored PubSub/PEP test to execute: $test_name" >&2
    rm -f -- "$output_log"
    return 1
  fi
  rm -f -- "$output_log"
}

run_exact_ignored \
  db::pubsub::integration_tests::graph_cycle_subscription_quota_and_digest_claim_are_atomic
run_exact_ignored \
  db::pubsub::integration_tests::mutation_authority_and_stale_preconditions_are_checked_in_transaction
run_exact_ignored \
  db::pubsub::integration_tests::publish_audience_is_linearizable_with_unsubscribe
run_exact_ignored \
  db::pubsub::integration_tests::retract_graph_outcast_and_last_item_snapshots_are_linearizable
run_exact_ignored \
  db::pubsub::integration_tests::mutation_audiences_are_serialized_with_subscribe_and_unsubscribe
run_exact_ignored \
  db::pubsub::integration_tests::concurrent_config_updates_use_a_locked_expected_snapshot
run_exact_ignored \
  db::pubsub::integration_tests::lease_expiry_is_evaluated_after_a_graph_lock_wait
run_exact_ignored \
  db::pubsub::integration_tests::prohibited_affiliation_wins_atomically_over_owner_subscription_batch
run_exact_ignored \
  db::pubsub::integration_tests::multi_parent_create_emits_one_recursive_audience_snapshot
run_exact_ignored \
  db::pubsub::integration_tests::repeated_associate_is_idempotent_after_a_graph_lock_wait
run_exact_ignored \
  db::pubsub::integration_tests::subscription_and_option_retries_do_not_emit_transitions_after_lock_wait
run_exact_ignored \
  db::pep::integration_tests::pep_node_subscription_and_item_transitions_are_atomic
run_exact_ignored \
  db::vcard::tests::avatar_conversion_is_atomic_across_pep_and_vcard
run_exact_ignored \
  db::vcard::tests::converted_avatar_uses_the_exact_locked_pep_subscription_snapshot
