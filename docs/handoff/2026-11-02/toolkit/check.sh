#!/usr/bin/env bash
# Usage: [LINT="<package>..."] [ROOTF="<filter>..."] check.sh <package...>: the loop for one commit. Formats, records new
# workspace crates in Cargo.lock, regenerates the catalog and the generated docs, lints and tests each named package,
# lints the LINT packages without testing them, tests the root crate filtered by ROOTF, and compiles the production
# targets of the workspace. Each package is tested alone because feature unification hides a missing dependency feature
# in a workspace build. Run it before committing.
. "$(dirname "$0")/common.sh"; cd "$ROOT" || exit 1
cargo fmt --all; echo "fmt exit $?"
before=$(git show HEAD:Cargo.lock | grep -c '^name = ')
cargo metadata --format-version 1 > /dev/null; echo "metadata exit $?"
node scripts/generate-crate-catalog.mjs > /dev/null; echo "catalog exit $?"
cargo run -q --locked -p architecture-validator -- validate --write > /dev/null; echo "validator exit $?"
git diff Cargo.lock | grep -B2 '^+source = ' | grep '^+name = ' | sed 's/^+name = /external package added: /'
echo "lock packages $before -> $(grep -c '^name = ' Cargo.lock)"
args=(); for p in "$@" ${LINT}; do args+=(-p "$p"); done
if [ ${#args[@]} -gt 0 ]; then
  cargo clippy -q --locked --all-targets --all-features "${args[@]}" -- -D warnings 2>&1 | tail -60; echo "clippy exit ${PIPESTATUS[0]}"
fi
for p in "$@"; do
  cargo test -q --locked -p "$p" 2>&1 | grep -E 'test result|FAILED|panicked|^error' | grep -v ' 0 passed; 0 failed' | head -8; echo "$p tests exit ${PIPESTATUS[0]}"
done
for f in ${ROOTF}; do
  out=$(cargo test -q --locked -p rust-xmpp-server "$f" 2>&1); r=$?
  echo "$out" | grep -E 'test result|FAILED|panicked|^error' | grep -v ' 0 passed; 0 failed' | head -8
  echo "$out" | grep -qE ' [1-9][0-9]* passed' || echo "root $f selected no test"
  echo "root $f tests exit $r"
done
cargo check -q --locked --workspace --lib --bins 2>&1 | grep -E '^error' -A3 | head -20; echo "production exit ${PIPESTATUS[0]}"
