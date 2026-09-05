#!/usr/bin/env bash
# Prove the deadline is process-group scoped: a fixture's shell and a child it
# starts both disappear at the same deadline.  This is intentionally separate
# from protocol suites so a regression in generic CI supervision is local and
# fast to diagnose.
set -Eeuo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/northstar-ci-supervisor.XXXXXXXX")"
child_pid_file="$runtime_dir/child.pid"
log_file="$runtime_dir/fixture.log"

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -f "$child_pid_file" ]]; then
    child_pid="$(<"$child_pid_file")"
    if [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$child_pid" 2>/dev/null; then
      child_state="$(ps -o stat= -p "$child_pid" 2>/dev/null | tr -d '[:space:]')"
      if [[ "$child_state" != Z* ]]; then
        kill -KILL "$child_pid" 2>/dev/null || true
        status=1
      fi
    fi
  fi
  rm -rf -- "$runtime_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

set +e
python3 "$project_dir/scripts/github_ci_supervisor.py" \
  --timeout-seconds 1 \
  --kill-after-seconds 1 \
  --log-file "$log_file" \
  -- bash -c 'sleep 30 & child=$!; printf "%s\\n" "$child" > "$1"; wait "$child"' \
  bash "$child_pid_file"
status=$?
set -e

[[ "$status" == 124 ]] || {
  echo "supervisor deadline returned $status, expected 124" >&2
  exit 1
}
[[ -s "$child_pid_file" ]] || {
  echo "fixture did not record its child PID" >&2
  exit 1
}
child_pid="$(<"$child_pid_file")"
[[ "$child_pid" =~ ^[1-9][0-9]*$ ]] || {
  echo "fixture recorded an invalid child PID" >&2
  exit 1
}
if kill -0 "$child_pid" 2>/dev/null; then
  # A zombie has already exited; it cannot retain a port, lock, or test
  # database connection while the system reaper collects it.
  child_state="$(ps -o stat= -p "$child_pid" 2>/dev/null | tr -d '[:space:]')"
  if [[ "$child_state" != Z* ]]; then
    echo "supervisor left a descendant process alive: $child_pid state=$child_state" >&2
    exit 1
  fi
fi
echo "CI supervisor process-group deadline PASS"
