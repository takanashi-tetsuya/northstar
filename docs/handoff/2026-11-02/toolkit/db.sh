#!/usr/bin/env bash
# Usage: PGURL=<url> PKG=<package> PREFIX=<suite> [FILTER=<regex>] [FIRST=<test>] [OPS=1] db.sh
# Runs the ignored PostgreSQL tests of one package, one fresh schema per test (northstar_<PREFIX>_it_<32 hex>). PGURL
# names an empty database with locale C, with no query string, as a role that may create schemas and roles. FIRST runs
# one test before the rest. OPS=1 gives each test the ordinary owner role and the northstar_api_operations_it_ schema
# that operation_mutation_pool demands. Exit 0 only when every test passed.
. "$(dirname "$0")/common.sh"; cd "$ROOT" || exit 1
[ -n "$PGURL" ] && [ -n "$PKG" ] && [ -n "$PREFIX" ] || { echo "set PGURL, PKG and PREFIX"; exit 2; }
L=$RUNS/db; mkdir -p "$L"
BINS=$(cargo test --locked -p "$PKG" --all-targets --all-features --no-run --message-format=json 2>/dev/null | python3 -P -c '
import json, sys
for line in sys.stdin:
    try: m = json.loads(line)
    except ValueError: continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["profile"]["test"]:
        print(m["executable"])
')
[ -n "$BINS" ] || { echo "no test binary for $PKG (does it compile?)"; exit 1; }
export XMPP_TEST_CREATED_SCHEMA_LOG="$L/schemas.log"; : > "$XMPP_TEST_CREATED_SCHEMA_LOG"
sql() { psql -q "$PGURL" -v ON_ERROR_STOP=1 "$@"; }
fail=0; n=0
one() {  # one <binary> <test>
  h=$(tr -d - < /proc/sys/kernel/random/uuid)
  if [ -n "$OPS" ]; then
    s="northstar_api_operations_it_$h"; r="northstar_api_ops_$h"
    sql -c "CREATE ROLE \"$r\" NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS" \
      -c "CREATE SCHEMA \"$s\" AUTHORIZATION \"$r\"" || exit 1
    export TEST_DATABASE_ROLE="$r" TEST_DATABASE_SCHEMA="$s"
  else
    s="northstar_${PREFIX}_it_$h"; sql -c "CREATE SCHEMA \"$s\"" || exit 1
    export TEST_DATABASE_SCHEMA="$s"
  fi
  log="$L/$(echo "$2" | tr -c 'a-z0-9_\n' _).log"
  TEST_DATABASE_URL="$PGURL?options=-csearch_path%3D$s" timeout 300 "$1" --ignored --exact "$2" --test-threads=1 > "$log" 2>&1
  r=$?; n=$((n+1))
  if [ "$r" != 0 ]; then fail=1; echo "$2 exit $r: $(grep -E 'panicked|^test result' "$log" | head -2 | cut -c1-160 | tr '\n' ' ')"; fi
}
for b in $BINS; do
  TESTS=$("$b" --list --ignored 2>/dev/null | sed -n 's/: test$//p' | grep -E "${FILTER:-.}")
  for t in $TESTS; do [ "$t" = "$FIRST" ] && one "$b" "$t"; done
  for t in $TESTS; do [ "$t" = "$FIRST" ] || one "$b" "$t"; done
done
echo "ran $n tests, fail=$fail"
exit $fail
