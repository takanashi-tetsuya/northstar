#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_dir="$(mktemp -d -t northstar-schema-helper-XXXXXX)"
trap 'rm -rf -- "$fixture_dir"' EXIT
mkdir "$fixture_dir/bin"

# Exercise the shell lifecycle without touching a real PostgreSQL instance.
cat >"$fixture_dir/bin/psql" <<'PSQL'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SCHEMA_CALLS"
[[ " $* " == *" --port ${PGPORT:-5432} "* ]] || exit 98
case "$*" in
  *'SELECT EXISTS'*)
    if [[ -e "$SCHEMA_STATE" ]]; then printf 't\n'; else printf 'f\n'; fi ;;
  *'CREATE SCHEMA'*)
    touch "$SCHEMA_STATE" ;;
  *'DROP SCHEMA'*)
    if [[ "${MOCK_DROP_FAIL:-0}" == 1 ]]; then exit 1; fi
    rm -f -- "$SCHEMA_STATE" ;;
  *) exit 99 ;;
esac
PSQL
chmod 700 "$fixture_dir/bin/psql"

run_case() {
  local expected=$1 actual=0
  shift
  rm -f -- "$fixture_dir/calls"
  # Arguments are expanded by the child shell, not this test runner.
  # shellcheck disable=SC2016
  if env PATH="$fixture_dir/bin:$PATH" \
      SCHEMA_STATE="$fixture_dir/state" SCHEMA_CALLS="$fixture_dir/calls" \
      XMPP_TEST_SCHEMA="northstar_retention_it_0123456789abcdef0123456789abcdef" \
      "$@" bash -euo pipefail -c '
        source "$1"
        northstar_start_test_schema "$2" retention
        exit "$3"
      ' _ "$project_dir/scripts/lib/isolated-test-schema.sh" \
        northstar_retention_it_ "${CASE_BODY_STATUS:-0}"; then
    actual=0
  else
    actual=$?
  fi
  if [[ "$actual" != "$expected" ]]; then
    echo "isolated schema case returned $actual instead of $expected" >&2
    exit 1
  fi
}

run_case 0
[[ ! -e "$fixture_dir/state" ]]
[[ "$(wc -l <"$fixture_dir/calls")" == 4 ]]

run_case 0 PGPORT=35845
for port in 0 65536 -1 abc '5432/other' '5432,5433'; do
  run_case 2 PGPORT="$port"
  [[ ! -s "$fixture_dir/calls" ]]
done

CASE_BODY_STATUS=17 run_case 17
[[ ! -e "$fixture_dir/state" ]]

XMPP_TEST_DATABASE=production run_case 2
[[ ! -s "$fixture_dir/calls" ]]

run_case 2 XMPP_TEST_SCHEMA=public
[[ ! -s "$fixture_dir/calls" ]]

touch "$fixture_dir/state"
run_case 2
[[ -e "$fixture_dir/state" ]]
[[ "$(wc -l <"$fixture_dir/calls")" == 1 ]]
rm -f -- "$fixture_dir/state"

run_case 1 MOCK_DROP_FAIL=1
[[ -e "$fixture_dir/state" ]]
rm -f -- "$fixture_dir/state"

# Each migrated runner must still execute its own tests and release its schema.
cat >"$fixture_dir/bin/cargo" <<'CARGO'
#!/usr/bin/env bash
[[ "${TEST_DATABASE_URL:-}" == "postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D"* ]] || exit 98
printf 'test result: ok. %s passed; 0 failed\n' "${MOCK_PASSED_COUNT:-1}"
CARGO
chmod 700 "$fixture_dir/bin/cargo"
for runner in retention pie mix-mam abuse-reporting mix-family pubsub-outbox sm; do
  rm -f -- "$fixture_dir/calls"
  env PATH="$fixture_dir/bin:$PATH" \
    SCHEMA_STATE="$fixture_dir/state" SCHEMA_CALLS="$fixture_dir/calls" \
    XMPP_TEST_SCHEMA= XMPP_TEST_SYSTEM_TOOLCHAIN=true \
    PGPORT=35845 \
    bash "$project_dir/scripts/$runner-db-wsl.sh" >/dev/null
  [[ ! -e "$fixture_dir/state" ]]
  [[ "$(wc -l <"$fixture_dir/calls")" == 4 ]]
done

# A renamed or missing ignored MIX regression must not silently become green.
if env PATH="$fixture_dir/bin:$PATH" \
    SCHEMA_STATE="$fixture_dir/state" SCHEMA_CALLS="$fixture_dir/calls" \
    XMPP_TEST_SCHEMA= XMPP_TEST_SYSTEM_TOOLCHAIN=true PGPORT=35845 MOCK_PASSED_COUNT=0 \
    bash "$project_dir/scripts/mix-mam-db-wsl.sh" >/dev/null 2>&1; then
  echo 'MIX suite accepted zero executed tests' >&2
  exit 1
fi
[[ ! -e "$fixture_dir/state" ]]

echo "isolated test schema lifecycle passed"
