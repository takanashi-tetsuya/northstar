#!/usr/bin/env bash
# Small deterministic coverage for the shared relay-target handoff contract.
# A mutable relay target is intentionally distinct from a one-shot readiness
# proof: server restarts must replace the complete target atomically, while a
# bad port or a failed chmod must never publish a partial record.

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$project_dir/scripts/lib/test-listener-readiness.sh"

runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/northstar-listener-readiness.XXXXXXXX")"
target="$runtime_dir/relay.target"

cleanup() {
  local status=$?
  trap - EXIT
  case "$runtime_dir" in
    "${TMPDIR:-/tmp}"/northstar-listener-readiness.*)
      rm -rf -- "$runtime_dir"
      ;;
    *)
      echo "refusing to remove unexpected listener readiness test directory: $runtime_dir" >&2
      status=1
      ;;
  esac
  exit "$status"
}
trap cleanup EXIT

fixture_publish_relay_target "$target" 23101
[[ "$(<"$target")" == "127.0.0.1:23101" ]] \
  || { echo "first relay target publication was malformed" >&2; exit 1; }

# A restarted server deliberately replaces the old complete record.  The
# caller has already reaped the previous child, so an atomic same-directory
# rename is the correct target handoff—not a create-only readiness record.
fixture_publish_relay_target "$target" 23102
[[ "$(<"$target")" == "127.0.0.1:23102" ]] \
  || { echo "relay target replacement was malformed" >&2; exit 1; }

if fixture_publish_relay_target "$target" 0; then
  echo "relay target helper accepted port zero" >&2
  exit 1
fi
if fixture_publish_relay_target "$target" 65536; then
  echo "relay target helper accepted an out-of-range port" >&2
  exit 1
fi
if compgen -G "${target}.tmp.*" >/dev/null; then
  echo "relay target helper left a temporary record" >&2
  exit 1
fi

echo "listener readiness relay-target contract PASS"
