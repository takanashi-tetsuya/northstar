#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
random_suffix="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
runner_schema="${XMPP_TEST_SCHEMA:-northstar_mam_it_$random_suffix}"

if [[ "$test_database" != "xmpp_test" ]]; then
  echo "refusing to run MAM tests outside the disposable xmpp_test database" >&2
  exit 2
fi
if [[ ! "$runner_schema" =~ ^northstar_mam_it_[a-f0-9]{32}$ ]] ||
   (( ${#runner_schema} > 63 )); then
  echo "refusing unsafe or non-random XMPP_TEST_SCHEMA: $runner_schema" >&2
  exit 2
fi

database_args=(--host 127.0.0.1 --username xmpp_test --dbname xmpp_test)
test_log="$(mktemp /tmp/northstar-mam-db.XXXXXX.log)"
created=0

cleanup() {
  status=$?
  trap - EXIT INT TERM
  local inner_schema
  while IFS= read -r inner_schema; do
    [[ "$inner_schema" =~ ^history_identity_test_[a-f0-9]{32}$ ]] || continue
    PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$inner_schema\" CASCADE" >/dev/null || status=1
  done < <(sed -n 's/^isolated_schema_created=\(history_identity_test_[a-f0-9]\{32\}\)$/\1/p' "$test_log" | sort -u)
  if [[ "$created" == 1 ]]; then
    PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$runner_schema\" CASCADE" >/dev/null || status=1
    remains="$(PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
      --tuples-only --no-align \
      --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$runner_schema')" \
      2>/dev/null || printf unknown)"
    [[ "$remains" == "f" ]] || status=1
  fi
  rm -f -- "$test_log"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$(PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
  --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$runner_schema')")" == "t" ]]; then
  echo "refusing to reuse existing PostgreSQL schema: $runner_schema" >&2
  exit 2
fi
PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
  --set ON_ERROR_STOP=1 \
  --command "CREATE SCHEMA \"$runner_schema\"" >/dev/null
created=1

cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi

TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$runner_schema" \
  cargo test --locked --offline \
  db::archive::history_identity_pg_tests:: \
  -- --ignored --nocapture --test-threads=1 2>&1 | tee "$test_log"
