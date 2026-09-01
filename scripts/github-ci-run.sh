#!/usr/bin/env bash
set -uo pipefail

if (( $# < 2 )); then
  echo "usage: $0 <annotation-title> <command> [args ...]" >&2
  exit 2
fi

annotation_title="$1"
shift

temporary_root="${RUNNER_TEMP:-/tmp}"
log_file="$(mktemp "${temporary_root%/}/northstar-ci-command.XXXXXX.log")"

cleanup() {
  rm -f -- "$log_file"
}
trap cleanup EXIT

"$@" 2>&1 | tee "$log_file"
command_status=${PIPESTATUS[0]}

if (( command_status != 0 )) && [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
  summary="$({
    grep -E -i \
      'error|failed|failure|panic|assert|traceback|timeout|refus|denied|does not exist|mismatch' \
      "$log_file" | tail -n 12
  } || true)"

  if [[ -z "$summary" ]]; then
    summary="$(tail -n 12 "$log_file")"
  fi

  # GitHub already masks registered secrets. Apply an additional local redaction
  # before promoting selected log lines into a check-run annotation.
  summary="$(printf '%s' "$summary" | sed -E \
    -e 's#(postgres(ql)?://)[^/@[:space:]]+@#\1[REDACTED]@#g' \
    -e 's#([Aa]uthorization:)[[:space:]]*[^[:space:]]+#\1 [REDACTED]#g' \
    -e 's#([Pp]assword[=:])[[:space:]]*[^[:space:]]+#\1[REDACTED]#g')"

  summary="${summary//'%'/'%25'}"
  summary="${summary//$'\r'/'%0D'}"
  summary="${summary//$'\n'/'%0A'}"
  echo "::error title=${annotation_title}::${summary}"
fi

exit "$command_status"
