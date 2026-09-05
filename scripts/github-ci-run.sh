#!/usr/bin/env bash
# Run one CI command with a bounded, observable lifecycle.  A job-level
# timeout remains the final safety net, but it cannot tell an operator which
# nested command stopped making progress.  This wrapper keeps the exact exit
# status, emits phase boundaries, and preserves a private runner-side log for
# every failed or expired command.
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
# The override exists for hermetic/self-hosted runners. GitHub-hosted Linux
# runners use the pinned platform `python3` command by default.
summarizer_python="${NORTHSTAR_CI_SUMMARIZER_PYTHON:-python3}"

if [[ -n "$timeout_seconds" ]] && ! [[ "$timeout_seconds" =~ ^[1-9][0-9]{0,3}$ ]] \
  || [[ -n "$timeout_seconds" && "$timeout_seconds" -gt 7200 ]]; then
  echo "NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS must be an integer from 1 through 7200" >&2
  exit 2
fi

umask 077
mkdir -p -- "$diagnostic_root"
log_file="$(mktemp "${diagnostic_root%/}/northstar-ci-command.XXXXXX.log")"
retain_log=false

cleanup() {
  if [[ "$retain_log" != true ]]; then
    rm -f -- "$log_file"
  fi
}
trap cleanup EXIT

started_epoch="$(date +%s)"
started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "::group::Northstar CI command: $annotation_title"
echo "phase=command_started title=$annotation_title started_at=$started_utc timeout_seconds=${timeout_seconds:-none}"

set +e
if [[ -n "$timeout_seconds" ]]; then
  timeout --foreground --signal=TERM --kill-after=15s "${timeout_seconds}s" "$@" 2>&1 | tee "$log_file"
else
  "$@" 2>&1 | tee "$log_file"
fi
command_status=${PIPESTATUS[0]}
set -e

finished_epoch="$(date +%s)"
duration_seconds=$((finished_epoch - started_epoch))
if (( command_status == 124 )); then
  retain_log=true
  echo "phase=command_expired title=$annotation_title duration_seconds=$duration_seconds timeout_seconds=$timeout_seconds diagnostic_log=$log_file" >&2
elif (( command_status != 0 )); then
  retain_log=true
  echo "phase=command_failed title=$annotation_title duration_seconds=$duration_seconds exit_status=$command_status diagnostic_log=$log_file" >&2
else
  echo "phase=command_completed title=$annotation_title duration_seconds=$duration_seconds"
fi
echo "::endgroup::"

if (( command_status != 0 )) && [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
  # The complete output is already visible above. Promote only a bounded,
  # redacted, root-cause-first summary into GitHub's 4 KiB annotation channel.
  # A fixed fallback deliberately contains no log or caller-controlled text.
  redacted_log="${log_file%.log}.redacted.log"
  if ! "$summarizer_python" "$script_directory/github_ci_summary.py" \
    --title "$annotation_title" --redacted-copy "$redacted_log" "$log_file"; then
    echo "::error title=Northstar CI command failed::The command failed and its diagnostic summarizer could not run. Inspect the ordinary job log."
  fi
fi

exit "$command_status"
