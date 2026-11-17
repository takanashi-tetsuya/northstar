#!/usr/bin/env bash
# Repository conformance database suite: the ignored northstar-db-it tests that
# hold PostgreSQL adapters to the lock order, snapshot, receipt and rollback
# behaviour their application ports promise. Each test runs alone in a fresh
# random schema owned by an isolated ordinary role (when the control identity
# is privileged), so no test observes another's rows, and the schema and role
# must be gone afterwards.
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
if [[ "$test_database" != "xmpp_test" ]]; then
  echo "repository conformance tests are restricted to the dedicated xmpp_test database" >&2
  exit 2
fi

conformance_tests=(
  abuse::admission_conformance::admission_scopes_and_finalization_facts_match_independent_committed_rows
  abuse::admission_conformance::guard_only_receipts_and_actor_contention_keep_reservation_authority_separate
  archive::mam_guard_conformance::cancelled_mam_lock_wait_and_dropped_guard_close_the_original_backend
  auth::account_repository_registration_guard::conformance::account_repository_recovery_preserves_claim_tokens_and_commits_retry_backoff
  auth::account_repository_registration_guard::conformance::guarded_account_mutations_commit_denial_without_password_or_deletion_effects
  auth::account_repository_registration_guard::conformance::guarded_password_and_deletion_restore_proof_on_stale_generation_and_consume_it_with_the_mutation
  auth::account_repository_registration_guard::conformance::registration_commits_one_reservation_before_guard_and_rejects_before_password_preparation
  auth::publication_conformance::credential_generation_and_stage_observations_match_durable_rows
  auth::publication_conformance::credential_publication_observes_commit_and_both_refusal_rollbacks
  auth::publication_conformance::unbound_credential_receipts_follow_commit_and_preserve_explicit_refusal_sites
  auth::recovery_poll_conformance::recovery_poll_statement_timeout_rolls_back_and_does_not_leak_to_the_pool
  message::retraction_conformance::keyed_owner_evidence_survives_archive_removal_and_fences_key_retirement
  operations::control_conformance::control_reads_keep_the_reserved_backend_under_pool_exhaustion
  operations::read_conformance::federation_replacement_returns_the_cache_image_committed_with_the_exact_command
  operations::read_conformance::sensitive_reads_recheck_changed_actors_and_hold_authority_through_the_projection
  room::cluster_conformance::cluster_settlement_rejects_the_old_claim_and_preserves_the_replacement
  room::cluster_conformance::preclaim_adapter_expires_occupancies_and_dead_letters_with_original_limits
  room::discussion_conformance::discussion_receipts_preserve_all_stored_and_replay_commit_exits
  room::foreground_conformance::foreground_receipts_bind_durable_projection_and_authenticate_replay_after_rollback
  room::pam_conformance::pam_join_and_leave_lock_account_and_capacity_before_business_and_roll_back_both_projections
  room::producer_conformance::committed_reconciliation_survives_a_refused_message_producer
  room::producer_conformance::producers_and_wrappers_take_the_delivery_fence_before_business_rows
  room::producer_conformance::wrappers_preserve_original_presence_and_message_projections_after_the_fence
  room::worker_conformance::claim_row_and_byte_limits_bound_the_acknowledged_sql_allocation
  room::worker_conformance::settlement_receipt_waits_for_the_actual_commit_acknowledgment
  room::worker_conformance::worker_claim_and_settlement_receipts_match_committed_exact_fences
  room::worker_conformance::worker_renewal_and_archive_keep_exact_statement_and_commit_receipts
  roster::snapshot_conformance::roster_body_version_and_annotations_share_the_authorized_snapshot
  session::credential_conformance::binding_credential_receipts_follow_commit_and_keep_reservation_and_fast_refusals
  session::credential_conformance::resume_credential_receipts_keep_activation_privacy_and_fast_rollback_sites
  session::replay_fencing::replay_replacement_preserves_other_resources_and_rejects_stale_tokens
)

control_psql() {
  PGPASSWORD=xmpp-test-password psql \
    --host 127.0.0.1 --username xmpp_test --dbname "$test_database" \
    --set ON_ERROR_STOP=1 "$@"
}

test_schema=""
test_role=""
created=0
role_created=0
cleanup() {
  if [[ "$created" == "1" ]]; then
    control_psql --command "DROP SCHEMA IF EXISTS \"$test_schema\" CASCADE" >/dev/null
    created=0
  fi
  if [[ "$role_created" == "1" ]]; then
    control_psql --command "DROP ROLE \"$test_role\"" >/dev/null
    role_created=0
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

control_is_superuser="$(control_psql --tuples-only --no-align \
  --command 'SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user')"
if [[ "$control_is_superuser" != "t" && "$control_is_superuser" != "f" ]]; then
  echo 'could not determine repository conformance fixture control privileges' >&2
  exit 2
fi

cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi

for test_name in "${conformance_tests[@]}"; do
  random_suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
  test_schema="northstar_conformance_it_$random_suffix"
  test_role="northstar_conformance_role_$random_suffix"
  if [[ ! "$test_schema" =~ ^northstar_conformance_it_[a-f0-9]{32}$ ]]; then
    echo "refusing unsafe or non-random schema: $test_schema" >&2
    exit 2
  fi
  if [[ "$(control_psql --tuples-only --no-align \
    --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")" == "t" ]]; then
    echo "refusing to reuse existing PostgreSQL schema: $test_schema" >&2
    exit 2
  fi
  unset TEST_DATABASE_ROLE
  if [[ "$control_is_superuser" == "t" ]]; then
    # The Docker control identity is privileged; the adapters must execute as
    # an isolated ordinary owner, including after a pool reconnect.
    control_psql --command "CREATE ROLE \"$test_role\" NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS" >/dev/null
    role_created=1
    control_psql --command "CREATE SCHEMA \"$test_schema\" AUTHORIZATION \"$test_role\"" >/dev/null
    export TEST_DATABASE_ROLE="$test_role"
  else
    control_psql --command "CREATE SCHEMA \"$test_schema\"" >/dev/null
  fi
  created=1
  export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/$test_database?options=-csearch_path%3D$test_schema"
  export TEST_DATABASE_SCHEMA="$test_schema"
  test_output="$(cargo test --locked --offline -p northstar-db-it "$test_name" \
    -- --ignored --exact --nocapture --test-threads=1 2>&1)" || {
    printf '%s\n' "$test_output"
    exit 1
  }
  printf '%s\n' "$test_output"
  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$test_output"; then
    echo "expected exactly one repository conformance test: $test_name" >&2
    exit 1
  fi
  cleanup
  if [[ "$(control_psql --tuples-only --no-align \
    --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")" != "f" ]]; then
    echo "isolated repository conformance schema was not removed: $test_schema" >&2
    exit 1
  fi
  if [[ "$control_is_superuser" == "t" && "$(control_psql --tuples-only --no-align \
    --command "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='$test_role')")" != "f" ]]; then
    echo "isolated repository conformance role was not removed: $test_role" >&2
    exit 1
  fi
done
trap - EXIT
echo "repository conformance: ${#conformance_tests[@]} PostgreSQL adapter tests passed"
