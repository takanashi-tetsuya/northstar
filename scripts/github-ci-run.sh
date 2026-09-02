#!/usr/bin/env bash
set -uo pipefail

if (( $# < 2 )); then
  echo "usage: $0 <annotation-title> <command> [args ...]" >&2
  exit 2
fi

annotation_title="$1"
shift

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
temporary_root="${RUNNER_TEMP:-/tmp}"
log_file="$(mktemp "${temporary_root%/}/northstar-ci-command.XXXXXX.log")"

cleanup() {
  rm -f -- "$log_file"
}
trap cleanup EXIT

"$@" 2>&1 | tee "$log_file"
command_status=${PIPESTATUS[0]}

if (( command_status != 0 )) && [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
  # The complete output is already visible above. Promote only a bounded,
  # redacted, root-cause-first summary into GitHub's 4 KiB annotation channel.
  # A fixed fallback deliberately contains no log or caller-controlled text.
  if ! python3 "$script_directory/github_ci_summary.py" \
    --title "$annotation_title" "$log_file"; then
    echo "::error title=Northstar CI command failed::The command failed and its diagnostic summarizer could not run. Inspect the ordinary job log."
  fi
fi

exit "$command_status"
