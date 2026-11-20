#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$project_dir/scripts/lib/isolated-test-schema.sh"
northstar_start_test_schema "northstar_mix_mam_" "MIX MAM"

cd "$project_dir"
northstar_use_test_toolchain "$project_dir"

for test_name in \
  mix_mam_snapshot_filters_cursors_and_metadata_are_consistent \
  authorized_mix_mam_peer_filter_uses_current_visibility_snapshot \
  federated_mutation_result_and_outbox_share_the_authority_transaction; do
  if ! output="$(TEST_DATABASE_URL="$(northstar_test_database_url_for_schema "$test_schema")" \
    cargo test --locked --offline -p northstar-db-it \
    "room::mix_mam::$test_name" \
    -- --ignored --exact --nocapture 2>&1)"; then
    printf '%s\n' "$output"
    exit 1
  fi
  printf '%s\n' "$output"
  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$output"; then
    echo "expected exactly one ignored MIX test to execute: $test_name" >&2
    exit 1
  fi
done

for test_name in \
  local_mix_mam_uses_the_same_snapshot_after_disable_or_generation_change \
  federated_mix_mam_denies_revocation_committed_while_waiting_for_channel \
  federated_mix_mam_revocation_after_channel_fence_sees_whole_batch \
  federated_mix_mam_quota_rejection_rolls_back_the_result_prefix \
  mix_mam_ids_resolve_in_visible_scope_before_filters \
  mix_mam_keeps_the_stored_publisher_identity_after_visibility_changes; do
  if ! output="$(TEST_DATABASE_URL="$(northstar_test_database_url_for_schema "$test_schema")" \
    cargo test --locked --offline -p northstar-db-it \
    "room::mix_mam_authority::$test_name" \
    -- --ignored --exact --nocapture 2>&1)"; then
    printf '%s\n' "$output"
    exit 1
  fi
  printf '%s\n' "$output"
  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$output"; then
    echo "expected exactly one ignored MIX MAM authority test to execute: $test_name" >&2
    exit 1
  fi
done

for test_name in \
  mix_mam_paging_across_deletion_preserves_surviving_cursors \
  mix_mam_count_pruning_uses_storage_uuid_for_timestamp_ties; do
  if ! output="$(TEST_DATABASE_URL="$(northstar_test_database_url_for_schema "$test_schema")" \
    cargo test --locked --offline -p northstar-db-it \
    "room::mix_mam_paging_deletion::$test_name" \
    -- --ignored --exact --nocapture 2>&1)"; then
    printf '%s\n' "$output"
    exit 1
  fi
  printf '%s\n' "$output"
  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$output"; then
    echo "expected exactly one ignored MIX test to execute: $test_name" >&2
    exit 1
  fi
done
