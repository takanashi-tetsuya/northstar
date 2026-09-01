#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
random_suffix="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
test_schema="${XMPP_TEST_SCHEMA:-northstar_muc_it_$random_suffix}"

if [[ "$test_database" != "xmpp_test" ]]; then
  echo "refusing to run MUC tests outside the disposable xmpp_test database" >&2
  exit 2
fi
if [[ ! "$test_schema" =~ ^northstar_muc_it_[a-f0-9]{32}$ ]] ||
   (( ${#test_schema} > 63 )); then
  echo "refusing unsafe or non-random XMPP_TEST_SCHEMA: $test_schema" >&2
  exit 2
fi

database_args=(--host 127.0.0.1 --username xmpp_test --dbname xmpp_test)
creation_authorized=0
umask 077
schema_log="$(mktemp --tmpdir="${TMPDIR:-/tmp}" northstar-muc-created-schemas.XXXXXXXX)"
if [[ ! -f "$schema_log" || -L "$schema_log" ]]; then
  echo "failed to create a private regular schema recovery log" >&2
  exit 2
fi
chmod 600 "$schema_log"
export XMPP_TEST_CREATED_SCHEMA_LOG="$schema_log"
outer_schema_token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
if (( ${#outer_schema_token} != 32 )) ||
   [[ ! "$outer_schema_token" =~ ^[a-f0-9]{32}$ ]]; then
  echo "failed to generate an outer MUC schema ownership token" >&2
  exit 2
fi

valid_internal_schema() {
  local candidate="$1"
  if (( ${#candidate} == 51 )) &&
     [[ "$candidate" =~ ^muc_lifecycle_test_[a-f0-9]{32}$ ]]; then
    return 0
  fi
  if (( ${#candidate} == 48 )) &&
     [[ "$candidate" =~ ^muc_invite_test_[a-f0-9]{32}$ ]]; then
    return 0
  fi
  if (( ${#candidate} == 49 )) &&
     [[ "$candidate" =~ ^muc_history_test_[a-f0-9]{32}$ ]]; then
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
        echo "refusing unsafe entry from MUC recovery log" >&2
        cleanup_failed=1
        continue
      fi
      drop_and_verify_schema \
        "$registered_schema" "isolated internal MUC" "$registered_token" || cleanup_failed=1
    done < "$schema_log"
  else
    echo "private MUC schema recovery log disappeared or became unsafe: $schema_log" >&2
    cleanup_failed=1
  fi
  if [[ "$creation_authorized" == 1 ]]; then
    if (( ${#test_schema} != 49 )) ||
       [[ ! "$test_schema" =~ ^northstar_muc_it_[a-f0-9]{32}$ ]]; then
      echo "refusing unsafe outer MUC schema during cleanup: $test_schema" >&2
      cleanup_failed=1
    else
      drop_and_verify_schema \
        "$test_schema" "isolated outer MUC" "$outer_schema_token" || cleanup_failed=1
    fi
  fi
  if [[ "$cleanup_failed" == 0 ]]; then
    if ! rm -f -- "$schema_log"; then
      echo "failed to remove the private MUC schema recovery log: $schema_log" >&2
      cleanup_failed=1
    fi
  fi
  if [[ "$cleanup_failed" == 1 ]]; then
    if [[ -f "$schema_log" && ! -L "$schema_log" ]]; then
      echo "MUC schema recovery log retained for manual recovery: $schema_log" >&2
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
cargo test --locked --offline \
  db::muc::tests::locked_room_configuration_is_atomic_restart_safe_and_bounded \
  -- --ignored --nocapture
cargo test --locked --offline \
  db::muc::tests::durable_invitation_admission_is_atomic_under_injected_failures \
  -- --ignored --nocapture
cargo test --locked --offline \
  db::muc::tests::history_identity_and_mutations_are_atomic_under_replay_and_failure \
  -- --ignored --nocapture
