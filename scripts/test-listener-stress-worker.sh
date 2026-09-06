#!/usr/bin/env bash
# Regression test for the private process-session protocol used by the W5
# listener/readiness stress driver.  It deliberately runs a TERM-ignoring
# child, then proves a scoped TERM -> KILL of the recorded group reaps it.

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helper="$project_dir/scripts/lib/test-listener-stress-worker.sh"
driver="$project_dir/scripts/listener-readiness-stress-wsl.sh"
command -v setsid >/dev/null || { echo "setsid is required for listener stress lifecycle testing" >&2; exit 2; }
command -v ps >/dev/null || { echo "ps is required for listener stress lifecycle testing" >&2; exit 2; }

# Keep the semantic regression below coupled to the actual stress driver.  A
# future simplification that returns to plain wrapper-PID cleanup must fail
# before it can silently leave a nested CI supervisor or fixture session
# behind.  The dynamic test then proves the same private-session topology on
# Linux with a TERM-ignoring descendant.
grep -Fq 'setsid bash "$project_dir/scripts/lib/test-listener-stress-worker.sh" "$control_file"' "$driver" \
  || { echo "listener stress driver no longer launches verified private sessions" >&2; exit 1; }
grep -Fq 'bash "$project_dir/scripts/github-ci-run.sh"' "$driver" \
  || { echo "listener stress driver no longer uses the bounded CI supervisor per worker" >&2; exit 1; }
grep -Fq 'worker_group="$(wait_for_worker_group "$control_file" "$worker_pid")"' "$driver" \
  || { echo "listener stress driver no longer verifies private session ownership" >&2; exit 1; }
grep -Fq 'kill "-$signal" -- "-$group"' "$driver" \
  || { echo "listener stress driver no longer uses scoped worker-group signalling" >&2; exit 1; }
# Keep the parent-side safety gates coupled to the process-session regression.
# The full 20x50/100x50 workload owns behavioral verification; these checks
# prevent a future edit from reintroducing the already-observed entry failures
# before the worker topology can even start.
grep -Fq 'pg_catalog.host(pg_catalog.inet_server_addr())' "$driver" \
  || { echo "listener stress driver no longer normalizes PostgreSQL inet host output" >&2; exit 1; }
if grep -Fq 'inet_server_addr()::TEXT' "$driver"; then
  echo "listener stress driver compares PostgreSQL inet text with a CIDR suffix" >&2
  exit 1
fi
grep -Fq 'normalize_postgres_boolean()' "$driver" \
  || { echo "listener stress driver no longer has an explicit PostgreSQL boolean parser" >&2; exit 1; }
if grep -Fq 'grep -qx false' "$driver"; then
  echo "listener stress driver still treats an unnormalized PostgreSQL boolean as shell text" >&2
  exit 1
fi
grep -Fq 'retain_parent_diagnostic_artifact()' "$driver" \
  || { echo "listener stress driver no longer retains parent-side redacted evidence" >&2; exit 1; }
workflow="$project_dir/.github/workflows/ci.yml"
grep -Fq 'listener-readiness-stress-smoke:' "$workflow" \
  || { echo "listener stress CI no longer proves the 1x1/1x2 path before pressure" >&2; exit 1; }
for lane in regular scheduled; do
  if ! awk -v lane="$lane" '
    $0 == "  listener-readiness-stress-" lane ":" { in_job = 1; next }
    in_job && /^  [a-zA-Z0-9_-]+:$/ { exit }
    in_job && /needs: listener-readiness-stress-smoke/ { found = 1; exit }
    END { exit !found }
  ' "$workflow"; then
    echo "listener stress $lane lane no longer waits for its isolated 1x1/1x2 proof" >&2
    exit 1
  fi
done
for pairs in 1 2; do
  if ! grep -Fq -- "--rounds 1 --pairs $pairs" "$workflow"; then
    echo "listener stress smoke lane no longer contains its 1x$pairs execution" >&2
    exit 1
  fi
done
for lane in regular scheduled; do
  if ! awk -v lane="$lane" '
    $0 ~ "name: listener-readiness-" lane "-" { in_listener_artifact = 1; next }
    in_listener_artifact && /if-no-files-found: error/ { found = 1; exit }
    in_listener_artifact && /^      - name:/ { exit }
    END { exit !found }
  ' "$workflow"; then
    echo "listener stress $lane diagnostic upload no longer fails closed when its artifact is absent" >&2
    exit 1
  fi
done
binary_gate_line="$(grep -n '^resolve_current_build_binary$' "$driver" | cut -d: -f1 || true)"
database_attestation_line="$(grep -n '^assert_private_database_fixture$' "$driver" | tail -n 1 | cut -d: -f1 || true)"
[[ "$binary_gate_line" =~ ^[1-9][0-9]*$ && "$database_attestation_line" =~ ^[1-9][0-9]*$ \
   && "$binary_gate_line" -lt "$database_attestation_line" ]] \
  || { echo "listener stress driver no longer validates its current binary before database work" >&2; exit 1; }

runtime_dir="$(mktemp -d /tmp/northstar-listener-stress.XXXXXX)"
control_file="$runtime_dir/worker.control"
worker_pid=""
worker_group=""

group_has_live_members() {
  ps -e -o pgid=,stat= | awk -v group="$1" '$1 == group && $2 !~ /^Z/ { found = 1 } END { exit !found }'
}

stop_recorded_group() {
  local signal="$1"
  [[ "$worker_group" =~ ^[1-9][0-9]*$ ]] || return 0
  kill "-$signal" -- "-$worker_group" 2>/dev/null || true
}

stop_unpublished_private_group() {
  # A failed helper must not cause the regression test itself to leak a
  # process.  It is safe to target the launch PID only after proving that it
  # is still the private setsid leader we requested; never fall back to a
  # name-based or inherited process group signal.
  local candidate_pgid candidate_sid
  [[ "$worker_pid" =~ ^[1-9][0-9]*$ ]] || return 0
  candidate_pgid="$(ps -o pgid= -p "$worker_pid" 2>/dev/null | tr -d '[:space:]' || true)"
  candidate_sid="$(ps -o sid= -p "$worker_pid" 2>/dev/null | tr -d '[:space:]' || true)"
  if [[ "$candidate_pgid" == "$worker_pid" && "$candidate_sid" == "$worker_pid" ]]; then
    kill -TERM -- "-$worker_pid" 2>/dev/null || true
    sleep 0.05
    kill -KILL -- "-$worker_pid" 2>/dev/null || true
  fi
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n "$worker_group" ]]; then
    stop_recorded_group TERM
    sleep 0.05
    stop_recorded_group KILL
  else
    stop_unpublished_private_group
  fi
  [[ -z "$worker_pid" ]] || wait "$worker_pid" 2>/dev/null || true
  case "$runtime_dir" in
    /tmp/northstar-listener-stress.*) rm -rf -- "$runtime_dir" ;;
    *) echo "refusing to remove unexpected listener stress test directory: $runtime_dir" >&2; status=1 ;;
  esac
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

setsid bash "$helper" "$control_file" \
  env NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS=60 \
  bash "$project_dir/scripts/github-ci-run.sh" "listener stress worker lifecycle" \
  bash -c 'trap "" TERM; echo listener-stress-lifecycle-child-started; while :; do sleep 1; done' >"$runtime_dir/worker.log" 2>&1 &
worker_pid=$!

for _ in $(seq 1 300); do
  if [[ -s "$control_file" ]]; then
    break
  fi
  if ! kill -0 "$worker_pid" 2>/dev/null; then
    echo "listener stress worker exited before publishing a control record" >&2
    cat "$runtime_dir/worker.log" >&2 || true
    exit 1
  fi
  sleep 0.025
done
[[ -s "$control_file" ]] || { echo "listener stress worker control record timed out" >&2; exit 1; }

read -r recorded_pid recorded_pgid recorded_sid extra <"$control_file"
[[ -z "${extra:-}" && "$recorded_pid" =~ ^[1-9][0-9]*$ ]] || {
  echo "listener stress worker control record was malformed" >&2
  exit 1
}
[[ "$recorded_pid" == "$worker_pid" && "$recorded_pgid" == "$worker_pid" && "$recorded_sid" == "$worker_pid" ]] || {
  echo "setsid worker PID/session ownership was not direct and verifiable" >&2
  exit 1
}
worker_group="$recorded_pgid"

deadline=$((SECONDS + 5))
while ! grep -q 'listener-stress-lifecycle-child-started' "$runtime_dir/worker.log"; do
  if ! group_has_live_members "$worker_group" || ((SECONDS >= deadline)); then
    echo "listener stress worker did not reach the nested supervised child" >&2
    cat "$runtime_dir/worker.log" >&2 || true
    exit 1
  fi
  sleep 0.025
done

# Exercise the exact nesting used by the stress driver: the outer verified
# session owns a github-ci-run shell while its Python supervisor owns a nested
# fixture session.  Group quiescence—not the direct shell PID—is the result.
kill "-TERM" -- "-$worker_group"
deadline=$((SECONDS + 30))
while group_has_live_members "$worker_group" && ((SECONDS < deadline)); do
  sleep 0.05
done
if group_has_live_members "$worker_group"; then
  echo "listener stress private session survived supervisor cancellation" >&2
  stop_recorded_group KILL
  exit 1
fi
nested_fixture_pid="$(sed -n -E 's/.*phase=command_cancelled_by_parent pid=([0-9]+).*/\1/p' "$runtime_dir/worker.log" | tail -n 1)"
[[ "$nested_fixture_pid" =~ ^[1-9][0-9]*$ ]] || {
  echo "listener stress supervisor did not record its nested fixture group" >&2
  cat "$runtime_dir/worker.log" >&2 || true
  exit 1
}
if ps -o stat= -p "$nested_fixture_pid" 2>/dev/null | grep -qv '^[[:space:]]*Z'; then
  echo "listener stress nested fixture group leader remained after outer cancellation" >&2
  exit 1
fi
wait "$worker_pid" 2>/dev/null || true
if ps -e -o pgid=,pid= | awk -v group="$worker_group" '$1 == group { found = 1 } END { exit !found }'; then
  echo "listener stress group retained a descendant after scoped cleanup" >&2
  exit 1
fi

worker_pid=""
worker_group=""
echo "listener stress worker lifecycle PASS"
