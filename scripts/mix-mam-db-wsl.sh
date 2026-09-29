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
    cargo test --locked --offline \
    "db::mix::mam_integration_tests::$test_name" \
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
