#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
wrapper="$project_dir/scripts/github-ci-run.sh"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/northstar-ci-wrapper-test.XXXXXX")"
trap 'rm -rf -- "$temporary_root"' EXIT
supervisor_python="$(command -v python3 || true)"
[[ -n "$supervisor_python" ]] || {
  echo 'GitHub CI wrapper self-test requires python3 for process supervision' >&2
  exit 1
}

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
[[ "$success_output" == *'phase=command_completed title=wrapper success'* ]] \
  || fail 'success emitted no completed phase record'
[[ "$success_output" != *'::error '* ]] || fail 'success emitted an error annotation'

failure_output=""
run_wrapper 23 failure_output 'wrapper failure' \
  bash -c 'printf "%s\n" "ERROR: root-failure-marker"; exit 23'
[[ "$failure_output" == *root-failure-marker* ]] || fail 'failed output was lost'
[[ "$failure_output" == *'::error title=wrapper failure::'* ]] \
  || fail 'failure emitted no named annotation'
[[ "$failure_output" == *'phase=command_failed title=wrapper failure'* ]] \
  || fail 'failure emitted no failed phase record'

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
fallback_output="$(env -u NORTHSTAR_CI_SUMMARIZER_PYTHON PATH="$fake_bin:$PATH" GITHUB_ACTIONS=true RUNNER_TEMP="$temporary_root" \
  NORTHSTAR_CI_SUPERVISOR_PYTHON="$supervisor_python" \
  bash "$wrapper" 'wrapper summarizer failure' \
  bash -c 'printf "%s\n" failure-with-broken-summarizer; exit 19' 2>&1)"
fallback_status=$?
set -e
[[ "$fallback_status" == 19 ]] \
  || fail "summarizer failure replaced command status with $fallback_status"
[[ "$fallback_output" == *'title=Northstar CI command failed'* ]] \
  || fail 'summarizer failure emitted no fixed safe fallback'
[[ "$fallback_output" != *'::error title=wrapper summarizer failure::'* ]] \
  || fail 'summarizer fallback reused caller-controlled annotation metadata'

# Failure annotation construction is itself a bounded private lifecycle. A
# malformed or blocked transcript must not leave the wrapper waiting on an
# ordinary background summary process after its primary command has stopped.
hanging_summarizer="$temporary_root/hanging-summarizer"
cat >"$hanging_summarizer" <<'EOF'
#!/usr/bin/env bash
trap '' TERM
while :; do
  sleep 1
done
EOF
chmod 0700 "$hanging_summarizer"
summary_timeout_started=$SECONDS
set +e
summary_timeout_output="$(NORTHSTAR_CI_SUMMARY_TIMEOUT_SECONDS=1 \
  NORTHSTAR_CI_SUMMARIZER_PYTHON="$hanging_summarizer" \
  GITHUB_ACTIONS=true RUNNER_TEMP="$temporary_root" \
  bash "$wrapper" 'wrapper bounded summary' \
  bash -c 'printf "%s\\n" primary-failure-before-summary; exit 37' 2>&1)"
summary_timeout_status=$?
set -e
summary_timeout_elapsed=$((SECONDS - summary_timeout_started))
[[ "$summary_timeout_status" == 37 ]] \
  || fail "bounded summarizer changed primary status to $summary_timeout_status"
(( summary_timeout_elapsed < 9 )) \
  || fail "bounded summarizer took $summary_timeout_elapsed seconds"
[[ "$summary_timeout_output" == *'primary-failure-before-summary'* ]] \
  || fail 'bounded summarizer did not preserve the primary command output'
[[ "$summary_timeout_output" == *'phase=command_deadline_reached'*'timeout_seconds=1'* ]] \
  || fail 'bounded summarizer did not honor its configured one-second deadline'
[[ "$summary_timeout_output" == *'phase=command_grace_elapsed'* ]] \
  || fail 'TERM-ignoring bounded summarizer did not exercise private SIGKILL escalation'
[[ "$summary_timeout_output" == *'title=Northstar CI command failed'* ]] \
  || fail 'bounded summarizer emitted no fixed safe fallback after expiry'

# Exit status 124 belongs to the child unless the supervisor's private outcome
# record says its own deadline fired. It must never be mislabeled as expiry.
for natural_deadline in none 5; do
  natural_124_output=""
  set +e
  if [[ "$natural_deadline" == none ]]; then
    natural_124_output="$(GITHUB_ACTIONS=true RUNNER_TEMP="$temporary_root" \
      bash "$wrapper" 'wrapper natural 124' bash -c 'exit 124' 2>&1)"
  else
    natural_124_output="$(NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS="$natural_deadline" \
      GITHUB_ACTIONS=true RUNNER_TEMP="$temporary_root" \
      bash "$wrapper" 'wrapper natural 124' bash -c 'exit 124' 2>&1)"
  fi
  natural_124_status=$?
  set -e
  [[ "$natural_124_status" == 124 ]] \
    || fail "natural exit 124 with deadline=$natural_deadline returned $natural_124_status"
  [[ "$natural_124_output" == *'phase=command_failed title=wrapper natural 124'* ]] \
    || fail "natural exit 124 with deadline=$natural_deadline was not a normal failure"
  [[ "$natural_124_output" != *'phase=command_expired title=wrapper natural 124'* ]] \
    || fail "natural exit 124 with deadline=$natural_deadline was mislabeled as expiry"
done

# The outer wrapper must not infer timeout provenance from exit status 124. A
# missing or malformed control-plane record is a supervisor failure, even when
# a substituted supervisor returns the conventional timeout code.
fake_supervisor="$temporary_root/fake-supervisor"
cat >"$fake_supervisor" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

# The real wrapper invokes a configured interpreter with the supervisor path
# as its first argument. Consume that path and find the private outcome path
# without executing the supplied fixture command.
shift
outcome_file=""
while (( $# > 0 )); do
  case "$1" in
    --outcome-file)
      (( $# >= 2 )) || exit 2
      outcome_file="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

case "${NORTHSTAR_TEST_OUTCOME_MODE:-missing}" in
  missing)
    ;;
  malformed)
    [[ -n "$outcome_file" ]] || exit 2
    printf 'version=0\ntermination=deadline\n' >"$outcome_file"
    ;;
  *)
    exit 2
    ;;
esac

# Deliberately use the ambiguity that used to be classified as a timeout.
exit 124
EOF
chmod 0700 "$fake_supervisor"

for outcome_mode in missing malformed; do
  outcome_output=""
  set +e
  outcome_output="$(NORTHSTAR_TEST_OUTCOME_MODE="$outcome_mode" \
    NORTHSTAR_CI_SUPERVISOR_PYTHON="$fake_supervisor" \
    GITHUB_ACTIONS=false RUNNER_TEMP="$temporary_root" \
    bash "$wrapper" "wrapper ${outcome_mode} supervisor outcome" \
      bash -c true 2>&1)"
  outcome_status=$?
  set -e
  [[ "$outcome_status" == 1 ]] \
    || fail "$outcome_mode supervisor outcome returned $outcome_status instead of 1"
  [[ "$outcome_output" == *'phase=command_supervisor_outcome_invalid action=fail_command'* ]] \
    || fail "$outcome_mode supervisor outcome was not rejected"
  [[ "$outcome_output" == *'phase=command_failed title=wrapper '* ]] \
    || fail "$outcome_mode supervisor outcome emitted no failed phase record"
  [[ "$outcome_output" != *'phase=command_expired title=wrapper '* ]] \
    || fail "$outcome_mode supervisor outcome was mislabeled as expiry"
done

timeout_output=""
set +e
timeout_output="$(NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS=1 GITHUB_ACTIONS=true RUNNER_TEMP="$temporary_root" \
  bash "$wrapper" 'wrapper timeout' bash -c 'trap "exit 0" TERM; while :; do sleep 1; done' 2>&1)"
timeout_status=$?
set -e
[[ "$timeout_status" == 124 ]] \
  || fail "timed-out command returned $timeout_status instead of 124"
[[ "$timeout_output" == *'phase=command_expired title=wrapper timeout'* ]] \
  || fail 'timeout emitted no expiry phase record'
[[ "$timeout_output" == *'::error title=wrapper timeout::'* ]] \
  || fail 'timeout emitted no named annotation'

invalid_timeout_output=""
set +e
invalid_timeout_output="$(NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS=0 RUNNER_TEMP="$temporary_root" \
  bash "$wrapper" 'wrapper invalid timeout' bash -c true 2>&1)"
invalid_timeout_status=$?
set -e
[[ "$invalid_timeout_status" == 2 ]] \
  || fail "invalid timeout returned $invalid_timeout_status instead of 2"
[[ "$invalid_timeout_output" == *'must be an integer from 1 through 7200'* ]] \
  || fail 'invalid timeout was not diagnosed'

invalid_log_cap_output=""
set +e
invalid_log_cap_output="$(NORTHSTAR_CI_DIAGNOSTIC_MAX_BYTES=0 RUNNER_TEMP="$temporary_root" \
  bash "$wrapper" 'wrapper invalid log cap' bash -c true 2>&1)"
invalid_log_cap_status=$?
set -e
[[ "$invalid_log_cap_status" == 2 ]] \
  || fail "invalid diagnostic cap returned $invalid_log_cap_status instead of 2"
[[ "$invalid_log_cap_output" == *'NORTHSTAR_CI_DIAGNOSTIC_MAX_BYTES must be an integer from 1024 through 67108864'* ]] \
  || fail 'invalid diagnostic cap was not diagnosed'

printf 'GitHub CI wrapper self-test passed\n'
