#!/usr/bin/env bash
# Exercise the real Buf CLI against isolated Git histories, including failures.
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
unset CONTRACT_HEAD_SHA CONTRACT_BASELINE_SHA CONTRACT_PR_BASE_SHA CONTRACT_EVENT_BEFORE GITHUB_EVENT_PATH
bash "$script_dir/resolve-contract-baseline.sh" --self-test
temp_root="$(mktemp -d "${TMPDIR:-/tmp}/northstar-contract-compatibility.XXXXXX")"
trap 'rm -rf -- "$temp_root"' EXIT
repo="$temp_root/repository"
git init -q "$repo"
git -C "$repo" config user.email 'contract-test@northstar.invalid'
git -C "$repo" config user.name 'Northstar contract compatibility test'
cd "$repo"
printf 'fixture\n' > README
git add README
git commit -q -m 'before first contracts'
empty_sha="$(git rev-parse HEAD)"
mkdir -p contracts/proto/example/v1
cat > buf.yaml <<'YAML'
version: v2
modules:
  - path: contracts/proto
breaking:
  use:
    - FILE
YAML
proto=contracts/proto/example/v1/example.proto
printf 'syntax = "proto3";\npackage example.v1;\nmessage Snapshot { string value = 1; }\n' > "$proto"
git add buf.yaml contracts/proto
git commit -q -m 'introduce valid contracts'
baseline_sha="$(git rev-parse HEAD)"

check() {
  env CONTRACT_EVENT_NAME=pull_request CONTRACT_PR_BASE_SHA="$1" \
    CONTRACT_HEAD_SHA="$(git rev-parse HEAD)" \
    bash "$script_dir/check-contract-compatibility.sh"
}
reject() {
  local baseline="$1" name="$2" expected="$3"
  if check "$baseline" > "$temp_root/result.log" 2>&1; then
    printf 'Contract regression unexpectedly passed: %s\n' "$name" >&2
    exit 1
  fi
  if ! grep -Eq "$expected" "$temp_root/result.log"; then
    cat "$temp_root/result.log" >&2
    printf 'Contract regression failed for an unexpected reason: %s\n' "$name" >&2
    exit 1
  fi
  [[ -z "$(git for-each-ref --format='%(refname)' 'refs/heads/northstar-contract-baseline-*')" ]]
}

check "$empty_sha"
printf 'invalid protobuf\n' > "$proto"
git add "$proto"
git commit -q -m 'invalid initial contracts'
reject "$empty_sha" 'invalid first introduction' 'example.proto'

printf 'syntax = "proto3";\npackage example.v1;\nmessage Snapshot { string value = 1; string added = 2; }\n' > "$proto"
git add "$proto"
git commit -q -m 'add compatible field'
check "$baseline_sha"

printf 'syntax = "proto3";\npackage example.v1;\nmessage Snapshot { int32 value = 1; }\n' > "$proto"
git add "$proto"
git commit -q -m 'break field wire type'
reject "$baseline_sha" 'breaking existing field' 'changed type from "string" to "int32"'

printf 'syntax = "proto3";\npackage example.v1;\nmessage Replacement {}\n' > "$proto"
git add "$proto"
git commit -q -m 'delete existing message'
reject "$baseline_sha" 'deleted existing message' 'Previously present message'

git rm -qr contracts/proto
git commit -q -m 'remove module'
reject "$baseline_sha" 'removed current module' 'current HEAD does not contain contracts/proto'
printf 'real Buf contract compatibility regressions passed\n'
