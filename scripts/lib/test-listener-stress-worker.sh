#!/usr/bin/env bash
# Publish a private-session ownership record before executing one W5 worker.
#
# The parent starts this helper through `setsid`.  A worker may itself launch
# the CI supervisor, which owns a nested fixture group, so the parent needs a
# verified outer session leader to forward cancellation without name matching
# or an unsafe global kill.

set -euo pipefail

if (($# < 2)); then
  echo "usage: $0 <control-file> <command> [args ...]" >&2
  exit 2
fi

control_file="$1"
shift
control_parent="$(dirname -- "$control_file")"
if [[ ! -d "$control_parent" ]]; then
  echo "listener stress worker control parent does not exist: $control_parent" >&2
  exit 2
fi
if [[ -e "$control_file" || -L "$control_file" ]]; then
  echo "listener stress worker refuses to overwrite control record: $control_file" >&2
  exit 2
fi

worker_pid="$$"
worker_pgid="$(ps -o pgid= -p "$worker_pid" | tr -d '[:space:]')"
worker_sid="$(ps -o sid= -p "$worker_pid" | tr -d '[:space:]')"
if [[ "$worker_pid" != "$worker_pgid" || "$worker_pid" != "$worker_sid" ]]; then
  echo "listener stress worker must be launched as a private session leader" >&2
  exit 2
fi

umask 077
temporary="$(mktemp "${control_file}.tmp.XXXXXX")"
cleanup_temporary() {
  rm -f -- "$temporary"
}
trap cleanup_temporary EXIT
printf '%s %s %s\n' "$worker_pid" "$worker_pgid" "$worker_sid" >"$temporary"
# link(2) is an atomic create operation: a stale or substituted control file
# cannot be overwritten between the preflight check and publication.
if ! ln -- "$temporary" "$control_file"; then
  echo "listener stress worker could not atomically publish control record" >&2
  exit 1
fi
rm -f -- "$temporary"
trap - EXIT

exec "$@"
