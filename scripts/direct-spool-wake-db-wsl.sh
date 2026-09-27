#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
database="${XMPP_TEST_DATABASE:-xmpp_test}"
if [[ "$database" != "xmpp_test" ]]; then
  echo "direct-spool wake test requires disposable xmpp_test" >&2
  exit 2
fi

test_log="$(mktemp /tmp/northstar-direct-spool-wake.XXXXXX.log)"
race_log="$(mktemp /tmp/northstar-direct-claim-race.XXXXXX.log)"
db=(--host 127.0.0.1 --port "${PGPORT:-5432}" --username xmpp_test --dbname "$database")
race_schema="direct_claim_test_$(tr -d '-' </proc/sys/kernel/random/uuid)"
race_schema_created=false
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ "$race_schema_created" == "true" ]]; then
    PGPASSWORD=xmpp-test-password psql "${db[@]}" --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$race_schema\" CASCADE" >/dev/null || status=1
  fi
  while IFS= read -r schema; do
    [[ "$schema" =~ ^direct_spool_test_[a-f0-9]{32}$ ]] || continue
    PGPASSWORD=xmpp-test-password psql "${db[@]}" --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE" >/dev/null || status=1
  done < <(sed -En 's/^isolated_schema_created=(direct_spool_test_[a-f0-9]{32})$/\1/p' "$test_log" | sort -u)
  rm -f -- "$test_log" "$race_log"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/$database"

if cargo test --locked --offline --bin rust-xmpp-server \
  db::direct_spool_wake_repository::tests::direct_spool_wake_commit_ack_takeover_and_cleanup_are_fenced \
  -- --ignored --exact --nocapture --test-threads=1 >"$test_log" 2>&1; then
  cat "$test_log"
else
  cat "$test_log" >&2
  exit 1
fi
if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' "$test_log"; then
  echo "direct-spool wake database test did not run" >&2
  exit 1
fi

# Run the exact socket/SM/BOSH claim races in a second disposable schema.
# These fixtures assert that SQLSTATE 42P01 remains a database error, while
# only locked ownership conflicts produce DurableDeliverySuperseded.
if [[ ! "$race_schema" =~ ^direct_claim_test_[a-f0-9]{32}$ ]] ||
   (( ${#race_schema} > 63 )); then
  echo "refusing unsafe direct-claim race schema" >&2
  exit 2
fi
exists="$(PGPASSWORD=xmpp-test-password psql "${db[@]}" --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$race_schema')")"
[[ "$exists" == "f" ]] || { echo "random schema already exists" >&2; exit 2; }
PGPASSWORD=xmpp-test-password psql "${db[@]}" --set ON_ERROR_STOP=1 \
  --command "CREATE SCHEMA \"$race_schema\"" >/dev/null
race_schema_created=true
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/$database?options=-csearch_path%3D$race_schema"

run_race_test() {
  local test_name="$1"
  if cargo test --locked --offline --bin rust-xmpp-server "$test_name" \
    -- --ignored --exact --nocapture --test-threads=1 >"$race_log" 2>&1; then
    cat "$race_log"
  else
    cat "$race_log" >&2
    return 1
  fi
  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' "$race_log"; then
    echo "direct-claim race database test did not run: $test_name" >&2
    return 1
  fi
}

run_race_test db::replay::tests::replay_claim_wins_queued_live_socket_and_bosh_fences_without_stealing
run_race_test db::sm::tests::sm_transfer_yields_to_exact_replay_or_bosh_owner_without_clearing_it
