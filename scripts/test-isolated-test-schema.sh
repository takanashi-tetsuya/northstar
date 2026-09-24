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
printf 'test result: ok. 1 passed; 0 failed\n'
CARGO
chmod 700 "$fixture_dir/bin/cargo"
for runner in retention pie mix-mam abuse-reporting mix-family pubsub-outbox sm; do
  rm -f -- "$fixture_dir/calls"
  env PATH="$fixture_dir/bin:$PATH" \
    SCHEMA_STATE="$fixture_dir/state" SCHEMA_CALLS="$fixture_dir/calls" \
    XMPP_TEST_SCHEMA= XMPP_TEST_SYSTEM_TOOLCHAIN=true \
    bash "$project_dir/scripts/$runner-db-wsl.sh" >/dev/null
  [[ ! -e "$fixture_dir/state" ]]
  [[ "$(wc -l <"$fixture_dir/calls")" == 4 ]]
done

echo "isolated test schema lifecycle passed"
