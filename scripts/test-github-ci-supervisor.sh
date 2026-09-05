#!/usr/bin/env bash
# Regression coverage for the CI process-group supervisor. Each fixture owns
# only PIDs it records, so cleanup never uses global process matching.
set -Eeuo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
supervisor="$project_dir/scripts/github_ci_supervisor.py"
runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/northstar-ci-supervisor.XXXXXXXX")"
tracked_pids=()

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  local child_pid child_state
  for child_pid in "${tracked_pids[@]:-}"; do
    if [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$child_pid" 2>/dev/null; then
      child_state="$(ps -o stat= -p "$child_pid" 2>/dev/null | tr -d '[:space:]')"
      if [[ "$child_state" != Z* ]]; then
        kill -KILL "$child_pid" 2>/dev/null || true
        status=1
      fi
    fi
  done
  rm -rf -- "$runtime_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  printf 'GitHub CI supervisor self-test failed: %s\n' "$1" >&2
  exit 1
}

assert_pid_gone_or_zombie() {
  local child_pid="$1" label="$2" child_state
  [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] || fail "$label recorded an invalid child PID: $child_pid"
  if kill -0 "$child_pid" 2>/dev/null; then
    child_state="$(ps -o stat= -p "$child_pid" 2>/dev/null | tr -d '[:space:]')"
    [[ "$child_state" == Z* ]] || fail "$label left a descendant alive: $child_pid state=$child_state"
  fi
}

wait_for_file() {
  local path="$1" label="$2"
  local attempt
  for ((attempt = 0; attempt < 100; attempt += 1)); do
    [[ -s "$path" ]] && return 0
    sleep 0.05
  done
  fail "$label did not create $path"
}

run_supervisor() {
  local expected_status="$1" label="$2" timeout_seconds="$3" kill_after_seconds="$4"
  shift 4
  local output_file="$runtime_dir/$label.stdout"
  local error_file="$runtime_dir/$label.stderr"
  local log_file="$runtime_dir/$label.log"
  local status
  set +e
  python3 "$supervisor" \
    --timeout-seconds "$timeout_seconds" \
    --kill-after-seconds "$kill_after_seconds" \
    --log-file "$log_file" \
    -- "$@" >"$output_file" 2>"$error_file"
  status=$?
  set -e
  [[ "$status" == "$expected_status" ]] \
    || fail "$label returned $status, expected $expected_status"
}

# Deadline cleanup must kill ordinary descendants as one private process group.
deadline_child_file="$runtime_dir/deadline-child.pid"
run_supervisor 124 deadline 1 1 \
  bash -c 'sleep 30 & child=$!; printf "%s\\n" "$child" > "$1"; wait "$child"' \
  bash "$deadline_child_file"
wait_for_file "$deadline_child_file" deadline
deadline_child="$(<"$deadline_child_file")"
tracked_pids+=("$deadline_child")
assert_pid_gone_or_zombie "$deadline_child" deadline
grep -Fq 'phase=command_deadline_reached' "$runtime_dir/deadline.stderr" \
  || fail 'deadline emitted no deadline phase record'

# An ordinary command that owns no residual worker remains successful.
run_supervisor 0 clean-exit 5 1 bash -c 'printf "clean-exit-marker\\n"'
grep -Fq 'clean-exit-marker' "$runtime_dir/clean-exit.stdout" \
  || fail 'clean exit lost command output'

# The direct shell can exit successfully while a background child remains.
# That is a fixture lifecycle violation: clean it without an unbounded wait,
# but return a failure rather than hiding the escaped worker.
parent_exit_child_file="$runtime_dir/parent-exit-child.pid"
run_supervisor 1 parent-exit 5 1 \
  bash -c 'sleep 30 & child=$!; printf "%s\\n" "$child" > "$1"; exit 0' \
  bash "$parent_exit_child_file"
wait_for_file "$parent_exit_child_file" parent-exit
parent_exit_child="$(<"$parent_exit_child_file")"
tracked_pids+=("$parent_exit_child")
assert_pid_gone_or_zombie "$parent_exit_child" parent-exit
grep -Fq 'phase=command_parent_exited_with_residual_group' "$runtime_dir/parent-exit.stderr" \
  || fail 'parent-exit emitted no residual-group phase record'
grep -Fq 'phase=command_residual_group_cleaned outcome=failed_fixture_lifecycle' "$runtime_dir/parent-exit.stderr" \
  || fail 'parent-exit did not report the lifecycle failure'

# A descendant that ignores TERM must receive SIGKILL after the configured
# grace period. The supervisor still returns the command deadline status.
term_ignoring_child_file="$runtime_dir/term-ignoring-child.pid"
run_supervisor 124 term-ignoring 1 1 \
  bash -c "bash -c 'trap \"\" TERM; while :; do sleep 1; done' & child=\$!; printf '%s\\n' \"\$child\" > \"\$1\"; wait \"\$child\"" \
  bash "$term_ignoring_child_file"
wait_for_file "$term_ignoring_child_file" term-ignoring
term_ignoring_child="$(<"$term_ignoring_child_file")"
tracked_pids+=("$term_ignoring_child")
assert_pid_gone_or_zombie "$term_ignoring_child" term-ignoring
grep -Fq 'phase=command_grace_elapsed' "$runtime_dir/term-ignoring.stderr" \
  || fail 'TERM-ignoring descendant did not exercise SIGKILL escalation'

# A child that keeps stdout open after the direct parent exits used to leave
# the output copier blocked forever. It must be killed and finalization must
# finish within a small fixed bound.
pipe_holding_child_file="$runtime_dir/pipe-holding-child.pid"
pipe_started="$(date +%s)"
run_supervisor 1 pipe-holding 5 1 \
  bash -c "bash -c 'trap \"\" TERM; while :; do sleep 1; done' & child=\$!; printf '%s\\n' \"\$child\" > \"\$1\"; exit 0" \
  bash "$pipe_holding_child_file"
pipe_elapsed=$(( $(date +%s) - pipe_started ))
(( pipe_elapsed < 5 )) || fail "pipe-holding output finalization took $pipe_elapsed seconds"
wait_for_file "$pipe_holding_child_file" pipe-holding
pipe_holding_child="$(<"$pipe_holding_child_file")"
tracked_pids+=("$pipe_holding_child")
assert_pid_gone_or_zombie "$pipe_holding_child" pipe-holding

# Parent cancellation crosses nested supervisors: the outer supervisor sends
# TERM to its child group, the inner supervisor forwards it to its own group,
# and both perform their bounded TERM -> KILL cleanup.
nested_child_file="$runtime_dir/nested-child.pid"
nested_outer_log="$runtime_dir/nested-outer.log"
nested_inner_log="$runtime_dir/nested-inner.log"
set +e
python3 "$supervisor" \
  --timeout-seconds 30 --kill-after-seconds 1 --log-file "$nested_outer_log" -- \
  python3 "$supervisor" \
    --timeout-seconds 30 --kill-after-seconds 1 --log-file "$nested_inner_log" -- \
    bash -c "bash -c 'trap \"\" TERM; while :; do sleep 1; done' & child=\$!; printf '%s\\n' \"\$child\" > \"\$1\"; wait \"\$child\"" \
    bash "$nested_child_file" \
  >"$runtime_dir/nested.stdout" 2>"$runtime_dir/nested.stderr" &
nested_outer_pid=$!
set -e
tracked_pids+=("$nested_outer_pid")
wait_for_file "$nested_child_file" nested
kill -TERM "$nested_outer_pid"
set +e
wait "$nested_outer_pid"
nested_status=$?
set -e
[[ "$nested_status" == 143 ]] || fail "nested cancellation returned $nested_status, expected 143"
nested_child="$(<"$nested_child_file")"
tracked_pids+=("$nested_child")
assert_pid_gone_or_zombie "$nested_child" nested
grep -Fq 'phase=command_cancelled_by_parent' "$runtime_dir/nested.stderr" \
  || fail 'nested cancellation emitted no parent-cancel phase record'

# A single short line must reach the caller while the command is still alive.
# The former buffered ``read(64 KiB)`` implementation only forwarded it after
# EOF, so this probes a one-second window during a two-second command.
low_output_file="$runtime_dir/low-output.stdout"
set +e
python3 "$supervisor" \
  --timeout-seconds 5 --kill-after-seconds 1 --log-file "$runtime_dir/low-output.log" -- \
  bash -c 'printf "low-output-ready\\n"; sleep 2' \
  >"$low_output_file" 2>"$runtime_dir/low-output.stderr" &
low_output_supervisor_pid=$!
set -e
tracked_pids+=("$low_output_supervisor_pid")
low_output_seen=false
for ((attempt = 0; attempt < 20; attempt += 1)); do
  if grep -Fq 'low-output-ready' "$low_output_file" 2>/dev/null; then
    low_output_seen=true
    break
  fi
  sleep 0.05
done
[[ "$low_output_seen" == true ]] || fail 'low-volume output was not forwarded before command completion'
set +e
wait "$low_output_supervisor_pid"
low_output_status=$?
set -e
[[ "$low_output_status" == 0 ]] || fail "low-output fixture returned $low_output_status"

printf 'GitHub CI supervisor process-group regression tests passed\n'
