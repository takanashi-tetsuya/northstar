#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$project_dir/scripts/lib/isolated-test-schema.sh"
northstar_start_test_schema "northstar_pie_it_" "PIE"

cd "$project_dir"
northstar_use_test_toolchain "$project_dir"
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema"

test_name="pie::tests::portable_data_roundtrip_conflicts_and_rollback_are_atomic"
test_output="$(cargo test --locked --offline "$test_name" -- --ignored --exact --nocapture 2>&1)" || {
  printf '%s\n' "$test_output"
  exit 1
}
printf '%s\n' "$test_output"
if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$test_output"; then
  echo "expected exactly one ignored PIE PostgreSQL test" >&2
  exit 1
fi

deletion_test="db::users::tests::account_deletion_atomically_cancels_local_reverse_rosters"
deletion_output="$(cargo test --locked --offline "$deletion_test" -- --ignored --exact --nocapture 2>&1)" || {
  printf '%s\n' "$deletion_output"
  exit 1
}
printf '%s\n' "$deletion_output"
if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$deletion_output"; then
  echo "expected exactly one ignored XEP-0077 PostgreSQL test" >&2
  exit 1
fi
