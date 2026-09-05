#!/usr/bin/env bash
# Exercise the migrated child-owned listener fixtures under deliberate parallel
# startup pressure.  This is an explicit W5 stress target, not a substitute
# for the normal protocol suites: every worker runs a complete two-node MIX or
# federation fixture and records its own isolated transcript.  Each worker is
# privately process-group supervised; an expired worker is a failure, never a
# reason to retry, serialize, or quietly skip part of the prescribed matrix.

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

# A 50-pair round starts 100 real Northstar children.  The normal runtime
# defaults reserve two database connections per child, which alone exceeds a
# stock CI PostgreSQL instance before any fixture activity begins.  Keep the
# protocol workload intact while using an explicit stress-only pool profile:
# every child opens its normal initial connection, can execute its complete
# fixture with up to two connections, and does not reserve idle capacity.  CI
# raises its isolated PostgreSQL ceiling above the 200-connection upper bound
# plus migrator headroom; neither setting changes production defaults or
# serializes the matrix.
worker_timeout_seconds="${NORTHSTAR_LISTENER_STRESS_WORKER_TIMEOUT_SECONDS:-900}"
database_max_connections="${NORTHSTAR_LISTENER_STRESS_DATABASE_MAX_CONNECTIONS:-2}"
database_min_connections="${NORTHSTAR_LISTENER_STRESS_DATABASE_MIN_CONNECTIONS:-0}"
[[ "$worker_timeout_seconds" =~ ^[1-9][0-9]*$ ]] \
  && ((worker_timeout_seconds <= 7200)) || {
  echo "NORTHSTAR_LISTENER_STRESS_WORKER_TIMEOUT_SECONDS must be 1 through 7200" >&2
  exit 2
}
[[ "$database_max_connections" =~ ^[1-9][0-9]*$ ]] \
  && ((database_max_connections <= 64)) || {
  echo "NORTHSTAR_LISTENER_STRESS_DATABASE_MAX_CONNECTIONS must be 1 through 64" >&2
  exit 2
}
[[ "$database_min_connections" =~ ^[0-9]+$ ]] \
  && ((database_min_connections <= database_max_connections)) || {
  echo "NORTHSTAR_LISTENER_STRESS_DATABASE_MIN_CONNECTIONS must be no greater than the stress maximum" >&2
  exit 2
}

runtime_dir="$(mktemp -d /tmp/northstar-listener-stress.XXXXXX)"
declare -a workers=()
declare -a worker_groups=()

read_worker_group() {
  local control_file="$1" expected_pid="$2" recorded_pid recorded_pgid recorded_sid extra
  [[ -s "$control_file" ]] || return 1
  read -r recorded_pid recorded_pgid recorded_sid extra <"$control_file"
  [[ -z "${extra:-}" && "$recorded_pid" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "$recorded_pid" == "$expected_pid" && "$recorded_pgid" == "$expected_pid" && "$recorded_sid" == "$expected_pid" ]] || return 1
  printf '%s' "$recorded_pgid"
}

wait_for_worker_group() {
  local control_file="$1" expected_pid="$2" group deadline
  deadline=$((SECONDS + 15))
  while ((SECONDS < deadline)); do
    if group="$(read_worker_group "$control_file" "$expected_pid")"; then
      kill -0 "$expected_pid" 2>/dev/null || {
        echo "listener stress worker exited after publishing readiness: pid=$expected_pid" >&2
        return 1
      }
      printf '%s' "$group"
      return 0
    fi
    if ! kill -0 "$expected_pid" 2>/dev/null; then
      echo "listener stress worker exited before publishing private-session ownership: pid=$expected_pid" >&2
      return 1
    fi
    sleep 0.025
  done
  echo "listener stress worker private-session ownership timed out: pid=$expected_pid" >&2
  return 1
}

signal_worker_groups() {
  local signal="$1" group
  for group in "${worker_groups[@]}"; do
    [[ "$group" =~ ^[1-9][0-9]*$ ]] || continue
    # Every recorded group is a private setsid leader whose PID, PGID, and SID
    # were verified before the fixture was allowed to run.  Never use a name
    # match or a system-wide signal for test cleanup.
    kill "-$signal" -- "-$group" 2>/dev/null || true
  done
}

wait_for_workers_to_stop() {
  # A worker's `github-ci-run.sh` supervisor creates a nested fixture session.
  # After outer-session TERM it is entitled to its documented 15-second grace,
  # 2-second KILL/reap, and bounded output drain.  Do not mistake the direct
  # shell leader exiting for group completion.
  local deadline=$((SECONDS + 30)) group still_running
  while ((SECONDS < deadline)); do
    still_running=false
    for group in "${worker_groups[@]}"; do
      if ps -e -o pgid=,stat= | awk -v group="$group" '$1 == group && $2 !~ /^Z/ { found = 1 } END { exit !found }'; then
        still_running=true
        break
      fi
    done
    [[ "$still_running" == false ]] && return 0
    sleep 0.05
  done
  return 1
}

reap_workers() {
  local pid
  for pid in "${workers[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
}

start_stress_worker() {
  local round="$1" pair="$2" log_file="$3" control_file worker_pid worker_group candidate_pgid candidate_sid
  control_file="$runtime_dir/${fixture}.round-${round}.pair-${pair}.session"
  rm -f -- "$control_file"
  setsid bash "$project_dir/scripts/lib/test-listener-stress-worker.sh" "$control_file" \
    env \
      "$skip_variable=true" \
      "DATABASE_MAX_CONNECTIONS=$database_max_connections" \
      "DATABASE_MIN_CONNECTIONS=$database_min_connections" \
      "NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS=$worker_timeout_seconds" \
      bash "$project_dir/scripts/github-ci-run.sh" \
      "Listener readiness stress worker fixture=$fixture round=$round pair=$pair" \
      bash "$fixture_script" >"$log_file" 2>&1 &
  worker_pid=$!
  if ! worker_group="$(wait_for_worker_group "$control_file" "$worker_pid")"; then
    # The helper itself requires direct session leadership.  If it failed
    # before publication, signal the candidate only after independently
    # confirming that it is still exactly that private session leader.
    candidate_pgid="$(ps -o pgid= -p "$worker_pid" 2>/dev/null | tr -d '[:space:]' || true)"
    candidate_sid="$(ps -o sid= -p "$worker_pid" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "$candidate_pgid" == "$worker_pid" && "$candidate_sid" == "$worker_pid" ]]; then
      kill -TERM -- "-$worker_pid" 2>/dev/null || true
      sleep 0.05
      kill -KILL -- "-$worker_pid" 2>/dev/null || true
    fi
    wait "$worker_pid" 2>/dev/null || true
    return 1
  fi
  workers+=("$worker_pid")
  worker_groups+=("$worker_group")
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  signal_worker_groups TERM
  if ! wait_for_workers_to_stop; then
    signal_worker_groups KILL
    if ! wait_for_workers_to_stop; then
      echo "listener stress cleanup left a private worker group alive after scoped KILL" >&2
      status=1
    fi
  fi
  reap_workers
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

command -v setsid >/dev/null || { echo "listener stress requires setsid for private worker groups" >&2; exit 2; }
command -v ps >/dev/null || { echo "listener stress requires ps for private worker verification" >&2; exit 2; }

# Compile exactly once.  Worker fixtures receive the explicit skip flag only
# after this succeeds, so a missing binary is never reported as a port result.
cargo_args=(--locked)
[[ "${XMPP_TEST_OFFLINE:-true}" == false ]] || cargo_args+=(--offline)
cargo build "${cargo_args[@]}"
echo "listener stress profile: worker_timeout_seconds=$worker_timeout_seconds database_max_connections=$database_max_connections database_min_connections=$database_min_connections"

failed=0
for ((round = 1; round <= rounds; round++)); do
  workers=()
  worker_groups=()
  round_logs=()
  for ((pair = 1; pair <= pairs; pair++)); do
    log="$runtime_dir/${fixture}.round-${round}.pair-${pair}.log"
    round_logs+=("$log")
    if ! start_stress_worker "$round" "$pair" "$log"; then
      echo "listener stress worker could not establish private session ownership: fixture=$fixture round=$round pair=$pair" >&2
      failed=1
      break
    fi
  done
  for ((pair = 1; pair <= ${#workers[@]}; pair++)); do
    if ! wait "${workers[$((pair - 1))]}"; then
      echo "listener stress worker failed: fixture=$fixture round=$round pair=$pair" >&2
      failed=1
    fi
  done
  # A direct setsid leader exiting is not proof that its private group is
  # empty: github-ci-run may still be forwarding cancellation to its nested
  # fixture supervisor.  Verify group quiescence before forgetting ownership.
  if ! wait_for_workers_to_stop; then
    echo "listener stress worker group did not quiesce after direct worker exit: fixture=$fixture round=$round" >&2
    signal_worker_groups KILL
    if ! wait_for_workers_to_stop; then
      echo "listener stress worker group survived scoped KILL: fixture=$fixture round=$round" >&2
    fi
    failed=1
  fi
  workers=()
  worker_groups=()
  if grep -E 'EADDRINUSE|Address already in use|bind-close-launch' "${round_logs[@]}" >/dev/null 2>&1; then
    echo "listener stress found a listener ownership collision in round $round" >&2
    failed=1
  fi
  ((failed == 0)) || exit 1
  echo "listener stress round $round/$rounds passed: fixture=$fixture pairs=$pairs"
done

echo "listener readiness stress PASS: mode=$mode fixture=$fixture rounds=$rounds pairs=$pairs"
