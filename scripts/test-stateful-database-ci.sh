#!/usr/bin/env bash
# Exercise the shard runner without PostgreSQL. The fixtures deliberately
# cover ordinary failure, per-suite timeout, cancellation propagated by an
# inner runner, and a direct parent TERM. Every manifest entry must have one
# terminal result; a cancellation must never start a later suite.
set -Eeuo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/northstar-stateful-ci-test.XXXXXXXX")"
term_runner_pid=""

cleanup() {
  local status=$?
  trap - EXIT
  # Only a private session PID created below is ever targeted. This is a
  # fixture safety net, not name-based or global process cleanup.
  if [[ -n "$term_runner_pid" ]]; then
    kill -KILL -- "-$term_runner_pid" 2>/dev/null || true
  fi
  rm -rf -- "$runtime_dir"
  exit "$status"
}
trap cleanup EXIT

fail() {
  printf 'Stateful database CI continuation fixture failed: %s\n' "$1" >&2
  exit 1
}

assert_manifest_mapping_guard() {
  # The static checker must reject a set-preserving swap: the old independent
  # ID and script lists would both have passed even though MUC and Privacy had
  # exchanged their test coverage.  Keep this regression entirely in the
  # temporary fixture so it cannot alter the checked repository manifest.
  local manifest_copy="$runtime_dir/stateful-database-ci.mapping-guard.sh"
  local checker_output="$runtime_dir/stateful-database-ci.mapping-guard.output"
  cp "$project_dir/scripts/stateful-database-ci.sh" "$manifest_copy"
  node - "$manifest_copy" <<'NODE'
const fs = require('node:fs');
const path = process.argv[2];
let manifest = fs.readFileSync(path, 'utf8');
const mucScript = 'muc-db-wsl.sh';
const privacyScript = 'privacy-db-wsl.sh';
const marker = '__mapping-guard-marker__.sh';
if (!manifest.includes(mucScript) || !manifest.includes(privacyScript)) {
  process.exit(2);
}
manifest = manifest
  .replace(mucScript, marker)
  .replace(privacyScript, mucScript)
  .replace(marker, privacyScript);
fs.writeFileSync(path, manifest);
NODE
  if NORTHSTAR_STATEFUL_DATABASE_MANIFEST="$manifest_copy" \
    node "$project_dir/scripts/check-stateful-database-ci.mjs" >"$checker_output" 2>&1; then
    fail 'stateful manifest checker accepted a suite_id-to-script mapping swap'
  fi
  grep -Fq 'mismatchedManifestEntries' "$checker_output" \
    || fail 'stateful manifest checker did not report the swapped suite mapping'
}

assert_manifest_mapping_guard

wait_for_file() {
  local path="$1" label="$2" attempt
  for ((attempt = 0; attempt < 100; attempt += 1)); do
    [[ -s "$path" ]] && return 0
    sleep 0.05
  done
  fail "$label did not create $path"
}

mkdir -p "$runtime_dir/scripts"
cp "$project_dir/scripts/stateful-database-ci.sh" "$runtime_dir/scripts/"
cat >"$runtime_dir/scripts/github-ci-run.sh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
title="$1"
shift

if [[ -n "${STATEFUL_FIXTURE_TIMEOUT_LOG:-}" ]]; then
  printf '%s|%s\n' "$title" "${NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS:-missing}" \
    >>"$STATEFUL_FIXTURE_TIMEOUT_LOG"
fi

case "${STATEFUL_FIXTURE_MODE:-normal-failure}" in
  timeout)
    if [[ "$title" == 'PIE database' ]]; then
      printf '%s\n' 'intentional-stateful-suite-timeout' >&2
      exit 124
    fi
    ;;
  child-cancellation)
    if [[ "$title" == 'PIE database' ]]; then
      printf '%s\n' 'intentional-inner-runner-cancellation' >&2
      exit 143
    fi
    ;;
esac

printf 'fixture-wrapper-start title=%q\n' "$title"
"$@"
EOF
chmod 0700 "$runtime_dir/scripts/github-ci-run.sh"

for suite in roster-service-db-wsl.sh muc-db-wsl.sh pie-db-wsl.sh privacy-db-wsl.sh upload-db-wsl.sh muc-cluster-wsl.sh; do
  cat >"$runtime_dir/scripts/$suite" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case "${0##*/}" in
  pie-db-wsl.sh)
    case "${STATEFUL_FIXTURE_MODE:-normal-failure}" in
      normal-failure)
        printf '%s\n' 'intentional-stateful-suite-failure' >&2
        exit 23
        ;;
      term-cancellation)
        : "${STATEFUL_FIXTURE_READY_FILE:?term fixture requires a ready file}"
        printf '%s\n' "$$" >"$STATEFUL_FIXTURE_READY_FILE"
        trap 'exit 143' TERM
        while :; do sleep 1; done
        ;;
    esac
    ;;
esac
printf '%s\n' "fixture-completed:${0##*/}"
EOF
  chmod 0700 "$runtime_dir/scripts/$suite"
done

declare -a suite_ids=(roster-service muc pie privacy http-upload muc-cluster)
declare -A expected_timeouts=(
  ['Roster service database']=480
  ['MUC database']=600
  ['PIE database']=480
  ['Privacy database']=600
  ['HTTP Upload database']=600
  ['MUC cluster database']=600
)

assert_terminal_results_once() {
  local output_file="$1" suite_id count total
  for suite_id in "${suite_ids[@]}"; do
    count="$(grep -Ec "^phase=database_suite_result .* suite_id=${suite_id} " "$output_file" || true)"
    [[ "$count" == 1 ]] || fail "suite_id=$suite_id emitted $count terminal results, expected exactly one"
  done
  total="$(grep -Ec '^phase=database_suite_result ' "$output_file" || true)"
  [[ "$total" == "${#suite_ids[@]}" ]] \
    || fail "fixture emitted $total terminal result records, expected ${#suite_ids[@]}"
}

assert_result() {
  local output_file="$1" suite_id="$2" result="$3" stage="$4" exit_status="$5" blocked_by="${6:-}"
  local expected="suite_id=$suite_id result=$result stage=$stage exit_status=$exit_status"
  if [[ -n "$blocked_by" ]]; then
    expected+=" blocked_by=$blocked_by"
  fi
  grep -Fq "$expected" "$output_file" \
    || fail "missing terminal result: $expected"
}

assert_not_started() {
  local output_file="$1" suite_id="$2"
  ! grep -Fq "phase=database_suite_started shard=collaboration-storage suite_id=$suite_id " "$output_file" \
    || fail "suite_id=$suite_id started after cancellation"
}

assert_timeout_contract() {
  local timeout_file="$1" title seconds
  declare -A observed=()
  while IFS='|' read -r title seconds; do
    [[ -n "$title" && "$seconds" =~ ^[0-9]+$ ]] \
      || fail "malformed suite timeout record: $title|$seconds"
    [[ -n "${expected_timeouts[$title]+present}" ]] \
      || fail "unexpected suite timeout record for $title"
    [[ -z "${observed[$title]+present}" ]] \
      || fail "duplicate suite timeout record for $title"
    observed["$title"]="$seconds"
  done <"$timeout_file"
  for title in "${!expected_timeouts[@]}"; do
    [[ "${observed[$title]:-missing}" == "${expected_timeouts[$title]}" ]] \
      || fail "timeout for $title was ${observed[$title]:-missing}, expected ${expected_timeouts[$title]}"
  done
  [[ "${#observed[@]}" == "${#expected_timeouts[@]}" ]] \
    || fail "timeout fixture recorded ${#observed[@]} suites, expected ${#expected_timeouts[@]}"
}

run_fixture() {
  local mode="$1" output_file="$2" timeout_file="$3" status
  set +e
  STATEFUL_FIXTURE_MODE="$mode" \
    STATEFUL_FIXTURE_TIMEOUT_LOG="$timeout_file" \
    RUNNER_TEMP="$runtime_dir" \
    NORTHSTAR_CI_DIAGNOSTICS_DIR="$runtime_dir/diagnostics" \
    bash "$runtime_dir/scripts/stateful-database-ci.sh" collaboration-storage >"$output_file" 2>&1
  status=$?
  set -e
  printf '%s\n' "$status"
}

normal_output="$runtime_dir/normal.output"
normal_timeouts="$runtime_dir/normal.timeouts"
normal_status="$(run_fixture normal-failure "$normal_output" "$normal_timeouts")"
[[ "$normal_status" == 1 ]] \
  || fail "ordinary failure returned $normal_status, expected aggregate failure 1"
assert_terminal_results_once "$normal_output"
assert_result "$normal_output" pie failed command-exit 23
for suite_id in roster-service muc privacy http-upload muc-cluster; do
  assert_result "$normal_output" "$suite_id" passed command-completed 0
done
grep -Fq 'phase=database_shard_completed shard=collaboration-storage passed=5 failed=1 total=6' "$normal_output" \
  || fail 'ordinary failure aggregate did not describe the complete suite manifest'
assert_timeout_contract "$normal_timeouts"

timeout_output="$runtime_dir/timeout.output"
timeout_timeouts="$runtime_dir/timeout.timeouts"
timeout_status="$(run_fixture timeout "$timeout_output" "$timeout_timeouts")"
[[ "$timeout_status" == 1 ]] \
  || fail "timeout returned $timeout_status, expected aggregate failure 1"
assert_terminal_results_once "$timeout_output"
assert_result "$timeout_output" pie timeout command-deadline 124
for suite_id in roster-service muc privacy http-upload muc-cluster; do
  assert_result "$timeout_output" "$suite_id" passed command-completed 0
done
grep -Fq 'phase=database_shard_completed shard=collaboration-storage passed=5 failed=1 total=6' "$timeout_output" \
  || fail 'timeout aggregate did not describe the complete suite manifest'
assert_timeout_contract "$timeout_timeouts"

child_cancel_output="$runtime_dir/child-cancel.output"
child_cancel_timeouts="$runtime_dir/child-cancel.timeouts"
child_cancel_status="$(run_fixture child-cancellation "$child_cancel_output" "$child_cancel_timeouts")"
[[ "$child_cancel_status" == 143 ]] \
  || fail "inner runner cancellation returned $child_cancel_status, expected 143"
assert_terminal_results_once "$child_cancel_output"
assert_result "$child_cancel_output" roster-service passed command-completed 0
assert_result "$child_cancel_output" muc passed command-completed 0
assert_result "$child_cancel_output" pie cancelled process-group-cancellation 143 runner-exit-signal-TERM
for suite_id in privacy http-upload muc-cluster; do
  assert_result "$child_cancel_output" "$suite_id" not-run process-group-cancellation 143 runner-exit-signal-TERM
  assert_not_started "$child_cancel_output" "$suite_id"
done

term_fixture_supported=false
if command -v python3 >/dev/null 2>&1 \
  && python3 -c 'import os, sys; sys.exit(0 if hasattr(os, "setsid") else 1)'; then
  term_fixture_supported=true
fi

if [[ "$term_fixture_supported" == true ]]; then
  term_output="$runtime_dir/term.output"
  term_timeouts="$runtime_dir/term.timeouts"
  term_ready="$runtime_dir/term.ready"
  set +e
  STATEFUL_FIXTURE_MODE=term-cancellation \
    STATEFUL_FIXTURE_READY_FILE="$term_ready" \
    STATEFUL_FIXTURE_TIMEOUT_LOG="$term_timeouts" \
    RUNNER_TEMP="$runtime_dir" \
    NORTHSTAR_CI_DIAGNOSTICS_DIR="$runtime_dir/diagnostics" \
    python3 -c 'import os, sys; os.setsid(); os.execvpe("bash", ["bash", sys.argv[1], "collaboration-storage"], os.environ)' \
      "$runtime_dir/scripts/stateful-database-ci.sh" >"$term_output" 2>&1 &
  term_runner_pid=$!
  set -e
  wait_for_file "$term_ready" 'TERM cancellation fixture'
  kill -TERM -- "-$term_runner_pid"
  set +e
  wait "$term_runner_pid"
  term_status=$?
  set -e
  term_runner_pid=""
  [[ "$term_status" == 143 ]] \
    || fail "parent TERM cancellation returned $term_status, expected 143"
  assert_terminal_results_once "$term_output"
  assert_result "$term_output" roster-service passed command-completed 0
  assert_result "$term_output" muc passed command-completed 0
  assert_result "$term_output" pie cancelled process-group-cancellation 143 parent-signal-TERM
  for suite_id in privacy http-upload muc-cluster; do
    assert_result "$term_output" "$suite_id" not-run process-group-cancellation 143 parent-signal-TERM
    assert_not_started "$term_output" "$suite_id"
  done
else
  printf '%s\n' 'Stateful database CI TERM cancellation fixture skipped: python3 os.setsid is unavailable'
fi

printf '%s\n' 'Stateful database CI continuation and cancellation fixtures PASS'
