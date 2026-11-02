#!/usr/bin/env bash
# Usage: listtests.sh <checkout> <out-prefix>: every workspace test as "<binary>:<name>", for normal and ignored tests.
# <binary> is the test binary's crate name without its hash (the root crate's bin, lib and test targets included).
W=$1; P=$2; cd "$W" || exit 1
label() { awk '/Running|Doc-tests/ { b=$0; sub(/.*\(/, "", b); sub(/\).*/, "", b); n=split(b, a, "/"); b=a[n]; sub(/-[0-9a-f]+$/, "", b); if ($1=="Doc-tests") b="doc:" $2 }
               / test$/ { sub(/: test$/, ""); print b ":" $0 }' | sort; }
cargo test --workspace --all-targets --all-features --locked -- --list 2>&1 | label > "$P.tests"
cargo test --workspace --all-targets --all-features --locked -- --ignored --list 2>&1 | label > "$P.ignored"
echo "$(wc -l < "$P.tests") tests, $(wc -l < "$P.ignored") ignored"
