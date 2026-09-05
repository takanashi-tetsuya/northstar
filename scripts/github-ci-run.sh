#!/usr/bin/env bash
# Run one CI command with an observable private-process lifecycle. A configured
# command deadline is an additional safety net, but every invocation is still
# supervised so cancellation, residual descendants, and diagnostic output have
# one consistent owner. The wrapper preserves exact command status, emits phase
# boundaries, and retains a private runner-side log for failures or expiry.
set -uo pipefail

if (( $# < 2 )); then
  echo "usage: $0 <annotation-title> <command> [args ...]" >&2
  exit 2
fi

annotation_title="$1"
shift

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
temporary_root="${RUNNER_TEMP:-/tmp}"
diagnostic_root="${NORTHSTAR_CI_DIAGNOSTICS_DIR:-${temporary_root%/}/northstar-ci-diagnostics}"
timeout_seconds="${NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS:-}"
# The raw runner-local transcript is deliberately capped. It is a diagnostic
# aid rather than an unbounded data sink; crossing the cap is a fixture failure
# and the private process-group supervisor performs deterministic cleanup.
diagnostic_max_bytes="${NORTHSTAR_CI_DIAGNOSTIC_MAX_BYTES:-16777216}"
# A failure annotation is a separate, small helper process. It receives its
# own short private lifecycle so a malformed or blocked diagnostic transcript
# cannot keep an already-failed CI job alive indefinitely.
summary_timeout_seconds="${NORTHSTAR_CI_SUMMARY_TIMEOUT_SECONDS:-30}"
summary_max_bytes="${NORTHSTAR_CI_SUMMARY_MAX_BYTES:-131072}"
# The override exists for hermetic/self-hosted runners. GitHub-hosted Linux
# runners use the pinned platform `python3` command by default.
summarizer_python="${NORTHSTAR_CI_SUMMARIZER_PYTHON:-python3}"
supervisor_python="${NORTHSTAR_CI_SUPERVISOR_PYTHON:-python3}"

if [[ -n "$timeout_seconds" ]] && ! [[ "$timeout_seconds" =~ ^[1-9][0-9]{0,3}$ ]] \
  || [[ -n "$timeout_seconds" && "$timeout_seconds" -gt 7200 ]]; then
  echo "NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS must be an integer from 1 through 7200" >&2
  exit 2
fi

validate_positive_integer_range() {
  local variable_name="$1" value="$2" minimum="$3" maximum="$4"
  if ! [[ "$value" =~ ^[1-9][0-9]{0,8}$ ]] \
    || (( value < minimum || value > maximum )); then
    echo "$variable_name must be an integer from $minimum through $maximum" >&2
    exit 2
  fi
}

validate_positive_integer_range \
  NORTHSTAR_CI_DIAGNOSTIC_MAX_BYTES "$diagnostic_max_bytes" 1024 67108864
validate_positive_integer_range \
  NORTHSTAR_CI_SUMMARY_TIMEOUT_SECONDS "$summary_timeout_seconds" 1 300
validate_positive_integer_range \
  NORTHSTAR_CI_SUMMARY_MAX_BYTES "$summary_max_bytes" 1024 67108864

umask 077
mkdir -p -- "$diagnostic_root"
log_file="$(mktemp "${diagnostic_root%/}/northstar-ci-command.XXXXXX.log")"
outcome_file="$(mktemp "${diagnostic_root%/}/northstar-ci-outcome.XXXXXX")"
summary_log_file=""
retain_log=false
supervisor_pid=""
active_child_pid=""
wrapper_signal=""
wrapper_signal_status=0
supervisor_termination=""
supervisor_outcome_valid=false

cleanup() {
  rm -f -- "$outcome_file"
  if [[ "$retain_log" != true ]]; then
    rm -f -- "$log_file"
    if [[ -n "$summary_log_file" ]]; then
      rm -f -- "$summary_log_file"
    fi
  fi
}
trap cleanup EXIT

read_supervisor_termination() {
  local source_file="$1"
  local -a lines=()
  [[ -f "$source_file" ]] || return 1
  mapfile -t lines <"$source_file" || return 1
  (( ${#lines[@]} == 2 )) || return 1
  [[ "${lines[0]}" == 'version=1' ]] || return 1
  [[ "${lines[1]}" =~ ^termination=[a-z_]+$ ]] || return 1
  printf '%s' "${lines[1]#termination=}"
}

forward_wrapper_signal() {
  local signal_name="$1" signal_status="$2"
  if [[ -z "$wrapper_signal" ]]; then
    wrapper_signal="$signal_name"
    wrapper_signal_status="$signal_status"
    retain_log=true
    echo "phase=wrapper_cancellation_received signal=$signal_name action=forward_to_owned_child" >&2
  fi

  # A signal can arrive after the child fork but before `$!` is assigned. In
  # that case remember it above; the launch path forwards it immediately once
  # the exact child PID is known. Never use name matching or broad cleanup.
  if [[ -n "$active_child_pid" ]]; then
    kill -s "$wrapper_signal" -- "$active_child_pid" 2>/dev/null || true
  fi
}

wait_for_owned_child() {
  local child_pid="$1" result_name="$2" status
  while true; do
    wait "$child_pid"
    status=$?
    # `wait` is interruptible by a trap. Do not let that interrupt make the
    # wrapper exit before its direct child has completed bounded cleanup.
    if [[ -n "$wrapper_signal" ]] && kill -0 "$child_pid" 2>/dev/null; then
      forward_wrapper_signal "$wrapper_signal" "$wrapper_signal_status"
      continue
    fi
    printf -v "$result_name" '%s' "$status"
    return 0
  done
}

trap 'forward_wrapper_signal HUP 129' HUP
trap 'forward_wrapper_signal INT 130' INT
trap 'forward_wrapper_signal TERM 143' TERM

started_epoch="$(date +%s)"
started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "::group::Northstar CI command: $annotation_title"
echo "phase=command_started title=$annotation_title started_at=$started_utc timeout_seconds=${timeout_seconds:-none} max_log_bytes=$diagnostic_max_bytes"

set +e
if [[ -n "$wrapper_signal" ]]; then
  command_status="$wrapper_signal_status"
else
  supervisor_args=(
    --kill-after-seconds 15
    --max-log-bytes "$diagnostic_max_bytes"
    --log-file "$log_file"
    --outcome-file "$outcome_file"
    --require-linux-subreaper
  )
  if [[ -n "$timeout_seconds" ]]; then
    supervisor_args=(--timeout-seconds "$timeout_seconds" "${supervisor_args[@]}")
  fi
  "$supervisor_python" "$script_directory/github_ci_supervisor.py" \
    "${supervisor_args[@]}" -- "$@" 0<&0 &
  supervisor_pid=$!
  active_child_pid="$supervisor_pid"
  if [[ -n "$wrapper_signal" ]]; then
    forward_wrapper_signal "$wrapper_signal" "$wrapper_signal_status"
  fi
  wait_for_owned_child "$supervisor_pid" command_status
  active_child_pid=""
  supervisor_pid=""
  if [[ -n "$wrapper_signal" ]]; then
    command_status="$wrapper_signal_status"
  elif supervisor_termination="$(read_supervisor_termination "$outcome_file")"; then
    supervisor_outcome_valid=true
  else
    # Do not infer deadline state from a child exit code or merged output. A
    # missing/malformed private control record is a supervisor lifecycle
    # failure, not a successful or expired command.
    command_status=1
    echo "phase=command_supervisor_outcome_invalid action=fail_command" >&2
  fi
fi
set -e

finished_epoch="$(date +%s)"
duration_seconds=$((finished_epoch - started_epoch))
if [[ -n "$wrapper_signal" ]]; then
  retain_log=true
  echo "phase=command_cancelled title=$annotation_title duration_seconds=$duration_seconds signal=$wrapper_signal diagnostic_log=$log_file" >&2
elif [[ "$supervisor_outcome_valid" != true ]]; then
  retain_log=true
  echo "phase=command_failed title=$annotation_title duration_seconds=$duration_seconds exit_status=$command_status diagnostic_log=$log_file supervisor_outcome=invalid" >&2
elif (( command_status == 124 )) && [[ "$supervisor_termination" == deadline ]]; then
  retain_log=true
  echo "phase=command_expired title=$annotation_title duration_seconds=$duration_seconds timeout_seconds=$timeout_seconds diagnostic_log=$log_file" >&2
elif [[ "$supervisor_termination" == deadline ]]; then
  retain_log=true
  command_status=1
  echo "phase=command_supervisor_outcome_inconsistent action=fail_command" >&2
  echo "phase=command_failed title=$annotation_title duration_seconds=$duration_seconds exit_status=$command_status diagnostic_log=$log_file" >&2
elif (( command_status != 0 )); then
  retain_log=true
  echo "phase=command_failed title=$annotation_title duration_seconds=$duration_seconds exit_status=$command_status diagnostic_log=$log_file" >&2
else
  echo "phase=command_completed title=$annotation_title duration_seconds=$duration_seconds"
fi
echo "::endgroup::"

if (( command_status != 0 )) && [[ -z "$wrapper_signal" ]] && [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
  # The complete output is already visible above. Promote only a bounded,
  # redacted, root-cause-first summary into GitHub's 4 KiB annotation channel.
  # A fixed fallback deliberately contains no log or caller-controlled text.
  redacted_log="${log_file%.log}.redacted.log"
  if ! summary_log_file="$(mktemp "${diagnostic_root%/}/northstar-ci-summary.XXXXXX.log")"; then
    echo "::error title=Northstar CI command failed::The command failed and its diagnostic summarizer could not start. Inspect the ordinary job log."
    exit "$command_status"
  fi
  set +e
  "$supervisor_python" "$script_directory/github_ci_supervisor.py" \
    --timeout-seconds "$summary_timeout_seconds" \
    --kill-after-seconds 3 \
    --max-log-bytes "$summary_max_bytes" \
    --log-file "$summary_log_file" \
    --require-linux-subreaper \
    -- "$summarizer_python" "$script_directory/github_ci_summary.py" \
      --title "$annotation_title" --redacted-copy "$redacted_log" "$log_file" &
  active_child_pid=$!
  if [[ -n "$wrapper_signal" ]]; then
    forward_wrapper_signal "$wrapper_signal" "$wrapper_signal_status"
  fi
  wait_for_owned_child "$active_child_pid" summarizer_status
  active_child_pid=""
  set -e
  if [[ -n "$wrapper_signal" ]]; then
    command_status="$wrapper_signal_status"
  elif (( summarizer_status != 0 )); then
    echo "::error title=Northstar CI command failed::The command failed and its diagnostic summarizer could not run. Inspect the ordinary job log."
  fi
fi

exit "$command_status"
