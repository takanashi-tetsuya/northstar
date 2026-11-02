#!/usr/bin/env bash
# Usage: verify.sh <workstream>: what CI does not check, plus the cheap local copies of what it does. Test names against
# the baseline after applying maps/<workstream>.sed, test selectors in the suite scripts, generated files, Stage 4
# bindings and every gate. Workspace tests, workspace clippy and the database suites run in CI.
. "$(dirname "$0")/common.sh"; cd "$ROOT" || exit 1
[ -s "$BASE/ws.tests" ] || { echo "no baseline: run newbase.sh"; exit 2; }
MAP=$TK/maps/$1.sed; [ -f "$MAP" ] || MAP=/dev/null
O=$RUNS/$1; mkdir -p "$O"
cargo fmt --all --check > "$O/fmt.log" 2>&1; echo "fmt exit $?"
cargo check -q --locked --workspace --lib --bins > "$O/production.log" 2>&1; echo "production exit $?"
cargo check -q --manifest-path fuzz/Cargo.toml --bins --locked > "$O/fuzz.log" 2>&1; echo "fuzz exit $?"
bash "$TK/listtests.sh" "$ROOT" "$O/ws"
for k in tests ignored; do
  sed -f "$MAP" "$BASE/ws.$k" | sort > "$O/expected.$k"
  if cmp -s "$O/expected.$k" "$O/ws.$k"; then echo "$k: names match mapped base ($(wc -l < "$O/ws.$k"))"
  else echo "$k: DIFFER"; diff "$O/expected.$k" "$O/ws.$k" | head -30 | cut -c1-160; fi
done
python3 "$TK/selectors.py" "$ROOT" "$O/ws.tests" "$O/ws.ignored"
node scripts/check-layer-dependencies.mjs > "$O/layers.log" 2>&1; echo "layers exit $?"; head -3 "$O/layers.log"
gen="catalog/crates.yaml docs/architecture/generated"; before=$(find $gen -type f | sort | xargs sha256sum)
node scripts/generate-crate-catalog.mjs > /dev/null
cargo run -q --locked -p architecture-validator -- validate --write > "$O/validator.log" 2>&1; echo "validator exit $?"
[ "$before" = "$(find $gen -type f | sort | xargs sha256sum)" ] && echo "generated: current" || echo "generated: STALE"
python3 "$TK/stage4bind.py" "$ROOT"
bash "$TK/gates.sh" "$ROOT" > "$O/gates" 2>&1
if diff "$BASE/gates.base" "$O/gates" > "$O/gates.diff"; then echo "GATES == BASE"; else echo "GATES DIFFER"; cut -c1-200 "$O/gates.diff" | head -12; fi
