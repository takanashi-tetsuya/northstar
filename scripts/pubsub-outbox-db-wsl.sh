#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$project_dir/scripts/lib/isolated-test-schema.sh"
northstar_start_test_schema "northstar_pubsub_outbox_it_" "PubSub outbox"

cd "$project_dir"
northstar_use_test_toolchain "$project_dir"
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema"

output="$(cargo test --locked --offline \
  db::pubsub_outbox::tests::commit_claim_lease_takeover_payload_binding_and_ack_are_fenced \
  -- --ignored --exact --nocapture 2>&1)" || {
  printf '%s\n' "$output"
  exit 1
}
printf '%s\n' "$output"
grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$output" || {
  echo "expected exactly one ignored PubSub outbox test to execute" >&2
  exit 1
}
