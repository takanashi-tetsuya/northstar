#!/usr/bin/env bash
# Resolve the immutable Git commit used by the Buf breaking-change check.
#
# The result is deliberately a commit SHA, never a branch name. The caller may
# create a short-lived local ref from this SHA because Buf 1.50 accepts Git
# module references by branch name.

set -Eeuo pipefail

readonly ZERO_SHA='0000000000000000000000000000000000000000'
readonly SCRIPT_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/$(basename -- "${BASH_SOURCE[0]}")"

die() {
  printf 'contract baseline resolution failed: %s\n' "$*" >&2
  exit 2
}

event_json_value() {
  local query="$1"
  if [[ -z "${GITHUB_EVENT_PATH:-}" || ! -r "${GITHUB_EVENT_PATH}" ]]; then
    return 1
  fi
  command -v jq >/dev/null 2>&1 || return 1
  jq -er "$query" "$GITHUB_EVENT_PATH" 2>/dev/null
}

require_sha() {
  local label="$1"
  local sha="$2"

  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die "$label is not a lowercase 40-character commit SHA"
  [[ "$sha" != "$ZERO_SHA" ]] || die "$label must not be the all-zero GitHub before SHA"
  git cat-file -e "${sha}^{commit}" 2>/dev/null || die "$label commit object is unavailable (the checkout may be incomplete)"
}

resolve_baseline() {
  local event_name="${CONTRACT_EVENT_NAME:-${GITHUB_EVENT_NAME:-}}"
  local ref_name="${CONTRACT_REF_NAME:-${GITHUB_REF_NAME:-}}"
  local baseline=""

  case "$event_name" in
    pull_request|pull_request_target)
      baseline="${CONTRACT_PR_BASE_SHA:-}"
      if [[ -z "$baseline" ]]; then
        baseline="$(event_json_value '.pull_request.base.sha' || true)"
      fi
      [[ -n "$baseline" ]] || die "pull-request event has no base SHA"
      ;;
    workflow_dispatch)
      baseline="${CONTRACT_BASELINE_SHA:-}"
      [[ -n "$baseline" ]] || die "workflow_dispatch requires CONTRACT_BASELINE_SHA"
      ;;
    push)
      if [[ "$ref_name" == "dev" || "$ref_name" == "main" ]]; then
        baseline="${CONTRACT_EVENT_BEFORE:-}"
        if [[ -z "$baseline" ]]; then
          baseline="$(event_json_value '.before' || true)"
        fi
        [[ -n "$baseline" ]] || die "push to ${ref_name} has no event before SHA"
      else
        git show-ref --verify --quiet refs/remotes/origin/dev \
          || die "task-branch comparison requires refs/remotes/origin/dev"
        baseline="$(git merge-base HEAD refs/remotes/origin/dev)" \
          || die "cannot determine merge-base against origin/dev"
      fi
      ;;
    schedule)
      baseline="$(git rev-parse HEAD^ 2>/dev/null)" \
        || die "scheduled compatibility check requires a parent commit"
      ;;
    *)
      die "unsupported event '${event_name:-unset}'"
      ;;
  esac

  printf '%s\n' "$baseline"
}

resolve_and_print() {
  local current_sha expected_head baseline baseline_tree current_tree tree_type baseline_mode history

  current_sha="$(git rev-parse HEAD)" || die "cannot resolve HEAD"
  expected_head="${CONTRACT_HEAD_SHA:-}"
  if [[ -n "$expected_head" ]]; then
    require_sha 'event head SHA' "$expected_head"
    [[ "$expected_head" == "$current_sha" ]] || die "event head SHA does not match checked-out HEAD"
  fi

  baseline="$(resolve_baseline)"
  require_sha 'baseline' "$baseline"
  [[ "$baseline" != "$current_sha" ]] || die "baseline must not equal current HEAD"

  if baseline_tree="$(git rev-parse --verify "${baseline}:contracts/proto" 2>/dev/null)"; then
    tree_type="$(git cat-file -t "$baseline_tree" 2>/dev/null)" \
      || die "cannot inspect baseline contracts/proto"
    [[ "$tree_type" == 'tree' ]] || die "baseline contracts/proto is not a tree"
    baseline_mode=existing
  else
    # An initial schema has no earlier messages to compare. Prove that this is
    # an introduction, not incomplete history, a removed module or a relocation
    # of an older .proto API. Never substitute HEAD as a passing baseline.
    [[ "$(git rev-parse --is-shallow-repository)" == false ]] \
      || die "initial contracts require complete baseline history"
    git merge-base --is-ancestor "$baseline" "$current_sha" \
      || die "initial contract baseline must be an ancestor of HEAD"
    history="$(git log --full-history --max-count=1 --format=%H "$baseline" -- contracts/proto '*.proto')" \
      || die "cannot inspect baseline contract history"
    [[ -z "$history" ]] || die "baseline lacks contracts/proto but has prior contract history"
    baseline_mode=initial
    baseline_tree=absent
  fi

  current_tree="$(git rev-parse "${current_sha}:contracts/proto" 2>/dev/null)" \
    || die "current HEAD does not contain contracts/proto"
  [[ "$(git cat-file -t "$current_tree")" == tree ]] \
    || die "current HEAD contracts/proto is not a tree"

  printf 'current_sha=%s\n' "$current_sha"
  printf 'current_contract_tree=%s\n' "$current_tree"
  printf 'baseline_sha=%s\n' "$baseline"
  printf 'baseline_contract_tree=%s\n' "$baseline_tree"
  printf 'baseline_mode=%s\n' "$baseline_mode"
}

expect_baseline() {
  local repo="$1"
  local expected="$2"
  local name="$3"
  local mode="$4"
  shift 4
  local output actual

  output="$(cd "$repo" && env "$@" bash "$SCRIPT_PATH")" \
    || die "self-test ${name} unexpectedly failed"
  actual="$(awk -F= '$1 == "baseline_sha" { print $2 }' <<<"$output")"
  [[ "$actual" == "$expected" ]] \
    || die "self-test ${name} resolved '${actual:-missing}', expected '$expected'"
  [[ "$output" == *"baseline_mode=$mode"* ]] \
    || die "self-test ${name} did not use expected mode '$mode'"
}

expect_failure() {
  local repo="$1"
  local name="$2"
  shift 2
  if (cd "$repo" && env "$@" bash "$SCRIPT_PATH") >/dev/null 2>&1; then
    die "self-test ${name} unexpectedly succeeded"
  fi
}

self_test() {
  local temp_root repo empty_sha baseline_sha head_sha removed_sha malformed_sha legacy_sha unrelated_sha
  temp_root="$(mktemp -d "${TMPDIR:-/tmp}/northstar-contract-baseline.XXXXXX")"
  trap 'rm -rf -- "${temp_root:-}"' EXIT
  repo="${temp_root}/repository"

  git init -q "$repo"
  git -C "$repo" config user.email 'contract-test@northstar.invalid'
  git -C "$repo" config user.name 'Northstar contract baseline test'
  printf 'fixture\n' >"${repo}/README"
  git -C "$repo" add README
  git -C "$repo" commit -q -m 'empty fixture'
  empty_sha="$(git -C "$repo" rev-parse HEAD)"

  mkdir -p "${repo}/contracts/proto/example/v1"
  printf 'syntax = "proto3";\npackage example.v1;\nmessage Snapshot { string value = 1; }\n' \
    >"${repo}/contracts/proto/example/v1/example.proto"
  git -C "$repo" add contracts/proto
  git -C "$repo" commit -q -m 'add contracts'
  baseline_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" branch dev "$baseline_sha"
  git -C "$repo" remote add origin "$repo"
  git -C "$repo" fetch -q origin dev:refs/remotes/origin/dev

  printf 'head\n' >"${repo}/marker"
  git -C "$repo" add marker
  git -C "$repo" commit -q -m 'advance fixture'
  head_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" branch task/baseline-test "$head_sha"
  git -C "$repo" switch -q task/baseline-test

  expect_baseline "$repo" "$baseline_sha" 'pull request' existing \
    CONTRACT_EVENT_NAME=pull_request CONTRACT_PR_BASE_SHA="$baseline_sha"
  expect_baseline "$repo" "$baseline_sha" 'dev push' existing \
    CONTRACT_EVENT_NAME=push CONTRACT_REF_NAME=dev CONTRACT_EVENT_BEFORE="$baseline_sha"
  expect_baseline "$repo" "$baseline_sha" 'task branch' existing \
    CONTRACT_EVENT_NAME=push CONTRACT_REF_NAME=task/baseline-test
  expect_baseline "$repo" "$baseline_sha" 'manual dispatch' existing \
    CONTRACT_EVENT_NAME=workflow_dispatch CONTRACT_BASELINE_SHA="$baseline_sha"
  expect_baseline "$repo" "$baseline_sha" 'scheduled run' existing \
    CONTRACT_EVENT_NAME=schedule

  expect_failure "$repo" 'missing dispatch baseline' CONTRACT_EVENT_NAME=workflow_dispatch
  expect_failure "$repo" 'all-zero before SHA' \
    CONTRACT_EVENT_NAME=push CONTRACT_REF_NAME=dev CONTRACT_EVENT_BEFORE="$ZERO_SHA"
  expect_failure "$repo" 'unavailable baseline object' \
    CONTRACT_EVENT_NAME=workflow_dispatch CONTRACT_BASELINE_SHA=1111111111111111111111111111111111111111
  expect_failure "$repo" 'baseline equal to HEAD' \
    CONTRACT_EVENT_NAME=workflow_dispatch CONTRACT_BASELINE_SHA="$head_sha"
  expect_baseline "$repo" "$empty_sha" 'first contract PR' initial \
    CONTRACT_EVENT_NAME=pull_request CONTRACT_PR_BASE_SHA="$empty_sha"
  expect_baseline "$repo" "$empty_sha" 'first main contract push' initial \
    CONTRACT_EVENT_NAME=push CONTRACT_REF_NAME=main CONTRACT_EVENT_BEFORE="$empty_sha"
  expect_failure "$repo" 'mismatched checkout' \
    CONTRACT_EVENT_NAME=pull_request CONTRACT_PR_BASE_SHA="$empty_sha" CONTRACT_HEAD_SHA="$baseline_sha"

  git -C "$repo" rm -qr contracts/proto
  git -C "$repo" commit -q -m 'remove contracts'
  removed_sha="$(git -C "$repo" rev-parse HEAD)"
  expect_failure "$repo" 'removed current contracts' \
    CONTRACT_EVENT_NAME=pull_request CONTRACT_PR_BASE_SHA="$baseline_sha"
  git -C "$repo" checkout "$head_sha" -- contracts/proto
  git -C "$repo" commit -q -m 'reintroduce contracts'
  expect_failure "$repo" 'removed historical contracts' \
    CONTRACT_EVENT_NAME=pull_request CONTRACT_PR_BASE_SHA="$removed_sha"

  git -C "$repo" switch -q -c malformed "$empty_sha"
  mkdir -p "$repo/contracts"
  printf 'not a directory\n' >"$repo/contracts/proto"
  git -C "$repo" add contracts/proto
  git -C "$repo" commit -q -m 'malformed contract path'
  malformed_sha="$(git -C "$repo" rev-parse HEAD)"
  expect_failure "$repo" 'malformed current contracts' \
    CONTRACT_EVENT_NAME=pull_request CONTRACT_PR_BASE_SHA="$empty_sha"
  git -C "$repo" switch -q task/baseline-test
  expect_failure "$repo" 'malformed baseline contracts' \
    CONTRACT_EVENT_NAME=pull_request CONTRACT_PR_BASE_SHA="$malformed_sha"

  git -C "$repo" switch -q -c legacy "$empty_sha"
  printf 'syntax = "proto3";\n' >"$repo/legacy.proto"
  git -C "$repo" add legacy.proto
  git -C "$repo" commit -q -m 'legacy contract location'
  legacy_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" checkout "$head_sha" -- contracts/proto
  git -C "$repo" commit -q -m 'add module beside legacy contracts'
  expect_failure "$repo" 'older contract outside module' \
    CONTRACT_EVENT_NAME=pull_request CONTRACT_PR_BASE_SHA="$legacy_sha"

  git -C "$repo" switch -q -c unrelated "$empty_sha"
  printf 'unrelated\n' >"$repo/unrelated"
  git -C "$repo" add unrelated
  git -C "$repo" commit -q -m 'unrelated baseline'
  unrelated_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" switch -q task/baseline-test
  expect_failure "$repo" 'unrelated empty baseline' \
    CONTRACT_EVENT_NAME=pull_request CONTRACT_PR_BASE_SHA="$unrelated_sha"

  git clone -q --depth=1 --branch task/baseline-test "file://$repo" "$temp_root/shallow"
  git -C "$temp_root/shallow" fetch -q origin "$empty_sha"
  expect_failure "$temp_root/shallow" 'shallow history' \
    CONTRACT_EVENT_NAME=pull_request CONTRACT_PR_BASE_SHA="$empty_sha"

  printf 'contract baseline resolver self-test passed\n'
}

case "${1:-}" in
  --self-test)
    self_test
    ;;
  '')
    resolve_and_print
    ;;
  *)
    die "unknown argument '$1'"
    ;;
esac
