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
grep -Fq 'establish_template_public_schema_owner()' "$driver" \
  || { echo "listener stress driver no longer establishes template schema ownership before migration" >&2; exit 1; }
grep -Fq "ALTER SCHEMA public OWNER TO CURRENT_USER;" "$driver" \
  || { echo "listener stress driver no longer assigns public to the migration role" >&2; exit 1; }
grep -Fq 'template_public_schema_is_migration_owned()' "$driver" \
  || { echo "listener stress driver no longer catalog-attests template schema ownership" >&2; exit 1; }
grep -Fq 'pg_catalog.pg_namespace namespace' "$driver" \
  || { echo "listener stress driver no longer attests schema ownership from PostgreSQL catalogs" >&2; exit 1; }
schema_owner_phase_line="$(grep -n '^  establish_template_public_schema_owner "\$database_name" || return 1$' "$driver" | cut -d: -f1 || true)"
template_migrate_phase_line="$(grep -n '^  run_parent_phase "template-migrate-\$database_name"' "$driver" | cut -d: -f1 || true)"
[[ "$schema_owner_phase_line" =~ ^[1-9][0-9]*$ && "$template_migrate_phase_line" =~ ^[1-9][0-9]*$ \
   && "$schema_owner_phase_line" -lt "$template_migrate_phase_line" ]] \
  || { echo "listener stress driver does not establish and attest public ownership before migration" >&2; exit 1; }
grep -Fq 'NORTHSTAR_LISTENER_STRESS_DATABASE_HOST:-127.0.0.1' "$driver" \
  || { echo "listener stress driver no longer supports its loopback endpoint override" >&2; exit 1; }
grep -Fq 'NORTHSTAR_LISTENER_STRESS_DATABASE_PORT:-5432' "$driver" \
  || { echo "listener stress driver no longer supports its explicit database port override" >&2; exit 1; }
grep -Fq 'database_fixture_host" != 127.0.0.1' "$driver" \
  || { echo "listener stress driver no longer rejects a non-loopback database host" >&2; exit 1; }
grep -Fq '10#$database_fixture_port > 65535' "$driver" \
  || { echo "listener stress driver no longer bounds its database port" >&2; exit 1; }
grep -Fq 'only permits loopback host and port overrides; its fixture user and password are fixed' "$driver" \
  || { echo "listener stress driver no longer pins its fixture credentials" >&2; exit 1; }
grep -Fq '"NORTHSTAR_LISTENER_STRESS_DATABASE_HOST=$database_fixture_host"' "$driver" \
  || { echo "listener stress driver no longer propagates the validated host to workers" >&2; exit 1; }
grep -Fq '"NORTHSTAR_LISTENER_STRESS_DATABASE_PORT=$database_fixture_port"' "$driver" \
  || { echo "listener stress driver no longer propagates the validated port to workers" >&2; exit 1; }
for fixture_driver in "$project_dir/scripts/federation-wsl.sh" "$project_dir/scripts/mix-federation-runtime-wsl.sh"; do
  grep -Fq 'stress_database_host="${NORTHSTAR_LISTENER_STRESS_DATABASE_HOST:-127.0.0.1}"' "$fixture_driver" \
    || { echo "listener stress worker no longer consumes its validated host override: $fixture_driver" >&2; exit 1; }
  grep -Fq 'stress_database_port="${NORTHSTAR_LISTENER_STRESS_DATABASE_PORT:-5432}"' "$fixture_driver" \
    || { echo "listener stress worker no longer consumes its validated port override: $fixture_driver" >&2; exit 1; }
  grep -Fq 'database_url_a="postgres://xmpp_test:xmpp-test-password@$database_host:$database_port/' "$fixture_driver" \
    || { echo "listener stress worker no longer applies its endpoint override to database A: $fixture_driver" >&2; exit 1; }
  grep -Fq 'database_url_b="postgres://xmpp_test:xmpp-test-password@$database_host:$database_port/' "$fixture_driver" \
    || { echo "listener stress worker no longer applies its endpoint override to database B: $fixture_driver" >&2; exit 1; }
done
federation_driver="$project_dir/scripts/federation-wsl.sh"
# Every independently launched federation server owns every enabled listener.
# In particular, administration is enabled by default, so relying on its
# inherited default can make two fixture children contend for a host port.
[[ "$(grep -Fc 'WEB_ADMIN_BIND=127.0.0.1:0' "$federation_driver")" == "2" ]] \
  || { echo "federation fixture does not give both child servers an owned ephemeral administration listener" >&2; exit 1; }
mix_federation_driver="$project_dir/scripts/mix-federation-runtime-wsl.sh"
listener_helper="$project_dir/scripts/lib/test-listener-readiness.sh"
grep -Fq 'run_mix_federation_phase()' "$mix_federation_driver" \
  || { echo "MIX federation fixture no longer validates relay ports at each Python phase" >&2; exit 1; }
grep -Fq 'MIX federation relay readiness did not publish a valid HTTP port before $phase' "$mix_federation_driver" \
  || { echo "MIX federation fixture no longer fails closed on an unpublished relay port" >&2; exit 1; }
for phase in setup enqueue finish; do
  grep -Fq "run_mix_federation_phase $phase" "$mix_federation_driver" \
    || { echo "MIX federation fixture no longer injects dynamic ports for phase $phase" >&2; exit 1; }
done
grep -Fq 'fixture_assert_private_log_dir()' "$mix_federation_driver" \
  || { echo "MIX federation fixture no longer attests private child logging" >&2; exit 1; }
grep -Fq 'LOG_DIR="$runtime_dir/logs-a"' "$mix_federation_driver" \
  || { echo "MIX federation fixture no longer gives side A a private log directory" >&2; exit 1; }
grep -Fq 'LOG_DIR="$runtime_dir/logs-b"' "$mix_federation_driver" \
  || { echo "MIX federation fixture no longer gives side B a private log directory" >&2; exit 1; }
grep -Fq 'fixture_assert_private_log_dir a "$pid_a"' "$mix_federation_driver" \
  || { echo "MIX federation fixture no longer verifies side A log containment" >&2; exit 1; }
grep -Fq 'fixture_assert_private_log_dir b "$pid_b"' "$mix_federation_driver" \
  || { echo "MIX federation fixture no longer verifies side B log containment" >&2; exit 1; }
if grep -Eq 'NORTHSTAR_MIX_FEDERATION_(SEED_ACCOUNTS|ACCOUNTS_PRESEEDED)' \
  "$driver" "$mix_federation_driver" "$project_dir/scripts/mix-federation-runtime-wsl.py"; then
  echo "MIX listener stress must not clone registered/login-historical account templates" >&2
  exit 1
fi
grep -Fq 'def register(fixture, username: str) -> None:' "$project_dir/scripts/mix-federation-runtime-wsl.py" \
  || { echo "MIX federation fixture no longer registers accounts in each clean worker database" >&2; exit 1; }
grep -Fq 'NORTHSTAR_MIX_FEDERATION_LOGIN_SLOT_DIR=$mix_login_slot_dir' "$driver" \
  || { echo "listener stress driver no longer passes its private login slot directory to MIX workers" >&2; exit 1; }
grep -Fq 'NORTHSTAR_MIX_FEDERATION_LOGIN_SLOT_COUNT=$login_slot_count' "$driver" \
  || { echo "listener stress driver no longer passes its login slot count to MIX workers" >&2; exit 1; }
for required_parent_function in \
  initialize_mix_federation_phase_barrier \
  await_mix_federation_setup_barrier \
  verify_mix_federation_listener_ledger; do
  grep -Fq "$required_parent_function()" "$driver" \
    || { echo "listener stress driver no longer has $required_parent_function" >&2; exit 1; }
done
# The persistent coordinator owns pending status, process identities, and its
# single deadline. Its fail-closed behavior is exercised by the Python tests.
grep -Fq -- '--phase-parent-await-release' "$driver" \
  || { echo "listener stress MIX barrier lost its persistent coordinator" >&2; exit 1; }
for required_phase_env in \
  NORTHSTAR_MIX_FEDERATION_PHASE_CONTROL_DIR \
  NORTHSTAR_MIX_FEDERATION_PHASE_RUN_NONCE \
  NORTHSTAR_MIX_FEDERATION_PHASE_ROUND \
  NORTHSTAR_MIX_FEDERATION_PHASE_PAIR; do
  grep -Fq "$required_phase_env" "$driver" \
    || { echo "listener stress driver no longer passes $required_phase_env to MIX workers" >&2; exit 1; }
done
grep -Fq 'publish_setup_barrier_ready_and_wait' "$mix_federation_driver" \
  || { echo "MIX fixture no longer waits for the parent-owned setup barrier" >&2; exit 1; }
grep -Fq 'publish_listener_ledger' "$mix_federation_driver" \
  || { echo "MIX fixture no longer records owned listener identities" >&2; exit 1; }
grep -Fq 'fixture_forget_listener_owner "$pid_b"' "$mix_federation_driver" \
  || { echo "MIX fixture no longer forgets B's pre-restart listener identities" >&2; exit 1; }
grep -Fq 'verify_listener_ledger_after_quiescence' "$project_dir/scripts/mix-federation-runtime-wsl.py" \
  || { echo "MIX verifier no longer validates original listener socket identities" >&2; exit 1; }
grep -Fq 'fixture_register_readiness_ports "$FIXTURE_READINESS_OUTPUT" "$pid"' "$listener_helper" \
  || { echo "readiness helper no longer records listener ownership with its publication" >&2; exit 1; }
if grep -Fq 'fixture_assert_no_listeners' "$mix_federation_driver" \
  && ! grep -Fq 'phase_barrier_enabled' "$mix_federation_driver"; then
  echo "MIX fixture regressed to an unconditional port-only residual check" >&2
  exit 1
fi
grep -Fq 'must be set together' \
  "$project_dir/scripts/mix-federation-runtime-wsl.py" \
  || { echo "MIX federation login-slot configuration no longer fails closed on a partial environment" >&2; exit 1; }
grep -Fq 'with claim_login_slot(LOGIN_SLOT_CONFIGURATION, timeout_seconds=None):' \
  "$project_dir/scripts/mix-federation-runtime-wsl.py" \
  || { echo "MIX federation fixture no longer separates phase admission from credential I/O" >&2; exit 1; }
for phase in setup enqueue finish; do
  grep -A 8 -F "def $phase()" "$project_dir/scripts/mix-federation-runtime-wsl.py" | grep -Fq 'with fixture_phase_auth_admission():' \
    || { echo "MIX federation $phase phase no longer admits credential setup through the bounded fixture lane" >&2; exit 1; }
done
if [[ "$(grep -Fc 'deadline=attempt.deadline' "$project_dir/scripts/mix-federation-runtime-wsl.py")" != 3 ]]; then
  echo "MIX registration, REST login, and WebSocket construction must each use a strict absolute authentication deadline" >&2
  exit 1
fi
if grep -Fq 'return login(fixture, username)' "$project_dir/scripts/mix-federation-runtime-wsl.py"; then
  echo "MIX clean-worker registration still creates and discards an unnecessary login session" >&2
  exit 1
fi
grep -Fq 'timeout: float = 10' "$project_dir/scripts/integration-wsl.py" \
  || { echo "integration fixture no longer accepts a bounded authentication I/O budget" >&2; exit 1; }
grep -Fq 'deadline: float | None = None' "$project_dir/scripts/integration-wsl.py" \
  || { echo "integration fixture no longer accepts an absolute authentication deadline" >&2; exit 1; }
grep -Fq 'def _deadline_http_api(' "$project_dir/scripts/integration-wsl.py" \
  || { echo "integration fixture no longer bounds the full authentication HTTP exchange" >&2; exit 1; }
grep -Fq 'def deadline_io_self_test()' "$project_dir/scripts/integration-wsl.py" \
  || { echo "integration fixture no longer proves its deadline I/O behavior" >&2; exit 1; }
# Every direct PostgreSQL assertion in the MIX fixture must use the endpoint
# that the parent listener-stress driver attested.  Falling back to 5432 here
# made a valid isolated fixture appear to target a missing shared database
# after the relay processes had already started.
if grep -Fq 'psql -h 127.0.0.1' "$mix_federation_driver"; then
  echo "MIX federation fixture bypasses its validated PostgreSQL endpoint" >&2
  exit 1
fi
if [[ "$(grep -Fc 'psql -h "$database_host" -p "$database_port"' "$mix_federation_driver")" != 5 ]]; then
  echo "MIX federation fixture does not apply its validated endpoint to every direct PostgreSQL assertion" >&2
  exit 1
fi
mix_start_a_line="$(grep -n '^start_a$' "$mix_federation_driver" | tail -n 1 | cut -d: -f1 || true)"
mix_start_b_line="$(grep -n '^start_b$' "$mix_federation_driver" | head -n 1 | cut -d: -f1 || true)"
mix_setup_line="$(grep -n '^run_mix_federation_phase setup$' "$mix_federation_driver" | cut -d: -f1 || true)"
mix_barrier_line="$(grep -n '^publish_setup_barrier_ready_and_wait$' "$mix_federation_driver" | cut -d: -f1 || true)"
[[ "$mix_start_a_line" =~ ^[1-9][0-9]*$ && "$mix_start_b_line" =~ ^[1-9][0-9]*$ \
   && "$mix_setup_line" =~ ^[1-9][0-9]*$ && "$mix_barrier_line" =~ ^[1-9][0-9]*$ \
   && "$mix_start_a_line" -lt "$mix_start_b_line" && "$mix_start_b_line" -lt "$mix_barrier_line" \
   && "$mix_barrier_line" -lt "$mix_setup_line" ]] \
  || { echo "MIX federation fixture can invoke setup before every pair is parent-released" >&2; exit 1; }
mix_federation_python="$project_dir/scripts/mix-federation-runtime-wsl.py"
grep -Fq 'def required_fixture_http_port(name: str)' "$mix_federation_python" \
  || { echo "MIX federation verifier no longer validates its dynamically supplied relay ports" >&2; exit 1; }
grep -Fq 'def _rename_phase_record_noreplace(' "$mix_federation_python" \
  || { echo "MIX federation phase records no longer use atomic no-replace publication" >&2; exit 1; }
grep -Fq 'RENAME_NOREPLACE = 1' "$mix_federation_python" \
  || { echo "MIX federation phase records no longer require Linux RENAME_NOREPLACE" >&2; exit 1; }
if grep -Fq 'os.link(' "$mix_federation_python"; then
  echo "MIX federation phase records reintroduced a transient hard-link publication window" >&2
  exit 1
fi
grep -Fq 'try:' "$mix_federation_python" \
  || { echo "MIX federation verifier no longer protects caller fixture environment restoration" >&2; exit 1; }
grep -Fq 'finally:' "$mix_federation_python" \
  || { echo "MIX federation verifier no longer restores caller fixture environment after import failure" >&2; exit 1; }
python3 "$mix_federation_python" --phase-self-test
federation_python="$project_dir/scripts/federation-wsl.py"
integration_python="$project_dir/scripts/integration-wsl.py"
grep -Fq 'def resolve_http_port(port: int | None)' "$integration_python" \
  || { echo "integration fixture no longer centralizes late-bound HTTP endpoint resolution" >&2; exit 1; }
grep -Fq 'def endpoint_binding_self_test()' "$integration_python" \
  || { echo "integration fixture no longer proves late-bound HTTP endpoint resolution" >&2; exit 1; }
python3 "$integration_python" --endpoint-binding-self-test
grep -Fq 'def listener_stress_database_endpoint()' "$federation_python" \
  || { echo "federation verifier no longer independently validates its listener database endpoint" >&2; exit 1; }
grep -Fq 'host == "127.0.0.1"' "$federation_python" \
  || { echo "federation verifier no longer rejects a non-loopback listener database host" >&2; exit 1; }
grep -Fq 'DATABASE_HOST, DATABASE_PORT = listener_stress_database_endpoint()' "$federation_python" \
  || { echo "federation verifier no longer receives the listener database endpoint" >&2; exit 1; }
if [[ "$(grep -Fc 'str(DATABASE_PORT)' "$federation_python")" != 2 ]]; then
  echo "federation verifier does not apply the listener database port to every direct psql assertion" >&2
  exit 1
fi
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
grep -Fq 'load_runtime_connection_budget()' "$driver" \
  || { echo "listener stress driver no longer reads the built runtime connection budget" >&2; exit 1; }
grep -Fq '"$binary" --runtime-connection-budget' "$driver" \
  || { echo "listener stress driver no longer derives auxiliary pools from the current binary" >&2; exit 1; }
grep -Fq 'fixture_control_connections_per_pair=1' "$driver" \
  || { echo "listener stress driver no longer accounts for MIX direct control connections" >&2; exit 1; }
grep -Fq 'assert_fixture_connection_capacity()' "$driver" \
  || { echo "listener stress driver no longer attests actual PostgreSQL capacity" >&2; exit 1; }
grep -Fq "SHOW max_connections;" "$driver" \
  || { echo "listener stress driver no longer queries the fixture server capacity" >&2; exit 1; }
grep -Fq 'must exactly match the attested fixture server capacity' "$driver" \
  || { echo "listener stress driver no longer rejects a configured capacity mismatch" >&2; exit 1; }
if grep -Fq 'NORTHSTAR_LISTENER_STRESS_POSTGRES_HEADROOM' "$driver"; then
  echo "listener stress driver still accepts arbitrary PostgreSQL headroom" >&2
  exit 1
fi

# The stress profile is intentionally a real configuration path, not a way to
# bypass the runtime's two-connection primary-pool floor.  This fails before
# build resolution or PostgreSQL work, so it proves the entry guard without
# turning the lifecycle regression into an integration test.
if invalid_pool_output="$(NORTHSTAR_LISTENER_STRESS_DATABASE_MAX_CONNECTIONS=1 \
  bash "$driver" --rounds 1 --pairs 1 2>&1)"; then
  echo "listener stress driver accepted a one-connection primary pool" >&2
  exit 1
fi
[[ "$invalid_pool_output" == *"must be 2 through 60"* ]] \
  || { echo "listener stress driver rejected a one-connection pool for an unexpected reason" >&2; exit 1; }

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
