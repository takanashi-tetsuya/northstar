#!/usr/bin/env bash
# Exercise the migrated child-owned listener fixtures under deliberate parallel
# startup pressure.  This is an explicit W5 stress target, not a substitute
# for the normal protocol suites: every worker runs a complete two-node MIX or
# federation fixture and records its own isolated transcript.

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/target-wsl}"
fi
cd "$project_dir"

mode="regular"
fixture="federation"
rounds=""
pairs="50"
while (($#)); do
  case "$1" in
    --mode) mode="${2:?missing mode}"; shift 2 ;;
    --fixture) fixture="${2:?missing fixture}"; shift 2 ;;
    --rounds) rounds="${2:?missing rounds}"; shift 2 ;;
    --pairs) pairs="${2:?missing pairs}"; shift 2 ;;
    *) echo "usage: $0 [--mode regular|scheduled] [--fixture federation|mix-federation] [--rounds N] [--pairs N]" >&2; exit 2 ;;
  esac
done

case "$mode" in
  regular) [[ -n "$rounds" ]] || rounds=20 ;;
  scheduled) [[ -n "$rounds" ]] || rounds=100 ;;
  *) echo "mode must be regular or scheduled" >&2; exit 2 ;;
esac
case "$fixture" in
  federation) fixture_script="$project_dir/scripts/federation-wsl.sh"; skip_variable=NORTHSTAR_FEDERATION_SKIP_BUILD ;;
  mix-federation) fixture_script="$project_dir/scripts/mix-federation-runtime-wsl.sh"; skip_variable=NORTHSTAR_MIX_FEDERATION_SKIP_BUILD ;;
  *) echo "fixture must be federation or mix-federation" >&2; exit 2 ;;
esac
[[ "$rounds" =~ ^[1-9][0-9]*$ && "$pairs" =~ ^[1-9][0-9]*$ ]] || {
  echo "rounds and pairs must be positive integers" >&2
  exit 2
}

runtime_dir="$(mktemp -d /tmp/northstar-listener-stress.XXXXXX)"
declare -a workers=()
cleanup() {
  status=$?
  trap - EXIT INT TERM
  for pid in "${workers[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${workers[@]}"; do wait "$pid" 2>/dev/null || true; done
  if ((status != 0)); then
    find "$runtime_dir" -type f -name '*.log' -print0 | while IFS= read -r -d '' log; do
      echo "--- $(basename "$log") (last 80 lines) ---" >&2
      tail -n 80 "$log" >&2 || true
    done
  fi
  case "$runtime_dir" in
    /tmp/northstar-listener-stress.*) rm -rf -- "$runtime_dir" ;;
    *) echo "refusing to remove unexpected stress directory: $runtime_dir" >&2; status=1 ;;
  esac
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Compile exactly once.  Worker fixtures receive the explicit skip flag only
# after this succeeds, so a missing binary is never reported as a port result.
cargo_args=(--locked)
[[ "${XMPP_TEST_OFFLINE:-true}" == false ]] || cargo_args+=(--offline)
cargo build "${cargo_args[@]}"

failed=0
for ((round = 1; round <= rounds; round++)); do
  workers=()
  for ((pair = 1; pair <= pairs; pair++)); do
    log="$runtime_dir/${fixture}.round-${round}.pair-${pair}.log"
    env "$skip_variable=true" "$fixture_script" >"$log" 2>&1 &
    workers+=("$!")
  done
  for ((pair = 1; pair <= pairs; pair++)); do
    if ! wait "${workers[$((pair - 1))]}"; then
      echo "listener stress worker failed: fixture=$fixture round=$round pair=$pair" >&2
      failed=1
    fi
  done
  workers=()
  if grep -R -E 'EADDRINUSE|Address already in use|bind-close-launch' "$runtime_dir" >/dev/null 2>&1; then
    echo "listener stress found a listener ownership collision in round $round" >&2
    failed=1
  fi
  ((failed == 0)) || exit 1
  echo "listener stress round $round/$rounds passed: fixture=$fixture pairs=$pairs"
done

echo "listener readiness stress PASS: mode=$mode fixture=$fixture rounds=$rounds pairs=$pairs"
