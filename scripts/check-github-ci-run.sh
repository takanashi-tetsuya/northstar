#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
wrapper="$project_dir/scripts/github-ci-run.sh"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/northstar-ci-wrapper-test.XXXXXX")"
trap 'rm -rf -- "$temporary_root"' EXIT

fail() {
  printf 'GitHub CI wrapper self-test failed: %s\n' "$1" >&2
  exit 1
}

run_wrapper() {
  local expected_status="$1" output_variable="$2"
  shift 2
  local captured status
  set +e
  captured="$(GITHUB_ACTIONS=true RUNNER_TEMP="$temporary_root" \
    bash "$wrapper" "$@" 2>&1)"
  status=$?
  set -e
  [[ "$status" == "$expected_status" ]] \
    || fail "expected status $expected_status, observed $status"
  printf -v "$output_variable" '%s' "$captured"
}

success_output=""
run_wrapper 0 success_output 'wrapper success' \
  bash -c 'printf "%s\n" success-marker'
[[ "$success_output" == *success-marker* ]] || fail 'successful output was lost'
[[ "$success_output" != *'::error '* ]] || fail 'success emitted an error annotation'

failure_output=""
run_wrapper 23 failure_output 'wrapper failure' \
  bash -c 'printf "%s\n" "ERROR: root-failure-marker"; exit 23'
[[ "$failure_output" == *root-failure-marker* ]] || fail 'failed output was lost'
[[ "$failure_output" == *'::error title=wrapper failure::'* ]] \
  || fail 'failure emitted no named annotation'

missing_output=""
run_wrapper 127 missing_output 'wrapper missing command' \
  northstar-command-that-does-not-exist
[[ "$missing_output" == *'::error title=wrapper missing command::'* ]] \
  || fail 'missing command emitted no annotation'

input_file="$temporary_root/input"
printf '%s\n' stdin-marker >"$input_file"
set +e
stdin_output="$(GITHUB_ACTIONS=true RUNNER_TEMP="$temporary_root" \
  bash "$wrapper" 'wrapper stdin' \
  bash -Eeuo pipefail -c 'read -r value; [[ "$value" == stdin-marker ]]' \
  <"$input_file" 2>&1)"
stdin_status=$?
set -e
[[ "$stdin_status" == 0 ]] || fail "stdin propagation returned $stdin_status"
[[ "$stdin_output" != *'::error '* ]] || fail 'stdin propagation emitted an error annotation'

fake_bin="$temporary_root/fake-bin"
mkdir -- "$fake_bin"
printf '%s\n' '#!/usr/bin/env bash' 'exit 99' >"$fake_bin/python3"
chmod 0700 "$fake_bin/python3"
set +e
fallback_output="$(PATH="$fake_bin:$PATH" GITHUB_ACTIONS=true RUNNER_TEMP="$temporary_root" \
  bash "$wrapper" 'wrapper summarizer failure' \
  bash -c 'printf "%s\n" failure-with-broken-summarizer; exit 19' 2>&1)"
fallback_status=$?
set -e
[[ "$fallback_status" == 19 ]] \
  || fail "summarizer failure replaced command status with $fallback_status"
[[ "$fallback_output" == *'title=Northstar CI command failed'* ]] \
  || fail 'summarizer failure emitted no fixed safe fallback'
[[ "$fallback_output" != *'title=wrapper summarizer failure'* ]] \
  || fail 'summarizer fallback reused caller-controlled annotation metadata'

printf 'GitHub CI wrapper self-test passed\n'
