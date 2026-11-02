#!/usr/bin/env bash
# Usage: gates.sh <checkout>: runs every scripts/check-*.mjs|sh and test-*.mjs and prints one result line for each.
cd "$1" || exit 1
for g in scripts/check-*.mjs; do timeout 300 node "$g" > /dev/null 2>&1; echo "exit $? $g"; done
for g in scripts/check-*.sh; do timeout 300 bash "$g" > /dev/null 2>&1; echo "exit $? $g"; done
for t in scripts/test-*.mjs; do r=$(timeout 300 node --test --test-reporter=spec "$t" 2>&1 | grep -E '^ℹ fail' | awk '{print $3}'); echo "fail=${r:-?} $t"; done
sed -e '/^redis_dir=/,$d' -e 's|^project_dir=.*|project_dir="$PWD"|' scripts/muc-cluster-wsl.sh | bash > /dev/null 2>&1; echo "exit $? muc-cluster-wsl-static"
