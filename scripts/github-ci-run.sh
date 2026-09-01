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
    sed -E 's/\x1B\[[0-9;]*[mK]//g' "$log_file" |
      grep -E -i -B 8 -A 4 \
        '(^|[^[:alnum:]_])(error|failed|failure|panic|assertion|traceback|timed out|timeout|refused|denied|does not exist|mismatch)([^[:alnum:]_]|$)' |
      tail -n 60
  } || true)"

  if [[ -z "$summary" ]]; then
    summary="$(tail -n 40 "$log_file")"
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
