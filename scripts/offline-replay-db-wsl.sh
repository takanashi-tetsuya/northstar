#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
database="${XMPP_TEST_DATABASE:-xmpp_test}"
suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
schema="northstar_replay_it_${suffix}"

if [[ "$database" != "xmpp_test" ]] ||
   [[ ! "$schema" =~ ^northstar_replay_it_[a-f0-9]{32}$ ]] ||
   (( ${#schema} > 63 )); then
  echo "refusing unsafe offline-replay test target" >&2
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
cargo test --locked --offline \
  db::replay::tests::durable_ack_batch_validates_every_fence_before_deleting_any_row \
  -- --ignored --exact --nocapture --test-threads=1
cargo test --locked --offline \
  db::replay::tests::logical_owner_is_exclusive_crash_recoverable_and_does_not_hold_the_pool \
  -- --ignored --exact --nocapture --test-threads=1
cargo test --locked --offline \
  db::replay::tests::replay_enforces_resource_affinity_and_immutable_ownership \
  -- --ignored --exact --nocapture --test-threads=1
cargo test --locked --offline \
  db::replay::tests::concurrent_resources_replay_without_starvation_and_fence_wrong_claims \
  -- --ignored --exact --nocapture --test-threads=1
cargo test --locked --offline \
  db::replay::tests::repeatable_read_account_claim_serialization_retries_with_fresh_snapshot \
  -- --ignored --exact --nocapture --test-threads=1
cargo test --locked --offline \
  xmpp::protocol::replay::tests::busy_resource_lease_retries_without_second_availability_transition \
  -- --ignored --exact --nocapture --test-threads=1
cargo test --locked --offline \
  db::replay::tests::replay_policy_snapshot_is_consistent_and_missing_policy_rolls_back \
  -- --ignored --exact --nocapture --test-threads=1
cargo test --locked --offline \
  db::replay::tests::replay_high_water_excludes_rows_inserted_after_replay_started \
  -- --ignored --exact --nocapture --test-threads=1
cargo test --locked --offline \
  db::replay::tests::replay_is_paged_exclusive_and_retryable \
  -- --ignored --exact --nocapture --test-threads=1
cargo test --locked --offline \
  db::replay::tests::bosh_delivery_is_owned_by_response_rid_until_a_live_client_ack \
  -- --ignored --exact --nocapture --test-threads=1

cleanup
created=false
remaining="$(psql "${db[@]}" --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')")"
[[ "$remaining" == "f" ]] || { echo "offline-replay schema cleanup failed" >&2; exit 1; }
trap - EXIT
