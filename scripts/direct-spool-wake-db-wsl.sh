#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
database="${XMPP_TEST_DATABASE:-xmpp_test}"
if [[ "$database" != "xmpp_test" ]]; then
  echo "direct-spool wake test requires disposable xmpp_test" >&2
  exit 2
fi

test_log="$(mktemp /tmp/northstar-direct-spool-wake.XXXXXX.log)"
db=(--host 127.0.0.1 --port "${PGPORT:-5432}" --username xmpp_test --dbname "$database")
cleanup() {
  status=$?
  trap - EXIT INT TERM
  while IFS= read -r schema; do
    [[ "$schema" =~ ^direct_spool_test_[a-f0-9]{32}$ ]] || continue
    PGPASSWORD=xmpp-test-password psql "${db[@]}" --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$schema\" CASCADE" >/dev/null || status=1
  done < <(sed -En 's/^isolated_schema_created=(direct_spool_test_[a-f0-9]{32})$/\1/p' "$test_log" | sort -u)
  rm -f -- "$test_log"
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
