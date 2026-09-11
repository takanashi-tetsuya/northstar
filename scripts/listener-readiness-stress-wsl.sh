#!/usr/bin/env bash
# Exercise the migrated child-owned listener fixtures under deliberate parallel
# runtime pressure after CPU-bounded cold-start batches. Every worker still
# runs a complete two-node MIX or federation fixture, and all pairs are live
# before business release. This does not claim simultaneous whole-fleet cold
# start capacity. Each worker is privately process-group supervised; failure
# never retries a worker or removes a pair from the prescribed matrix.

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/target-wsl}"
fi
cd "$project_dir"
source "$project_dir/scripts/lib/runtime-test-profile.sh"
# This capacity lane always measures optimized code with development checks.
# Child fixtures receive the exact same profile; ordinary integrations use dev.
fixture_select_runtime_profile runtime-test

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

# A 50-pair round starts 100 real Northstar children. The primary-pool limit
# is a stress-only setting. The fixed auxiliary pool
# facts are queried from the freshly built binary below, rather than copied
# here as a second hand-maintained architecture contract.
worker_timeout_seconds="${NORTHSTAR_LISTENER_STRESS_WORKER_TIMEOUT_SECONDS:-900}"
database_max_connections="${NORTHSTAR_LISTENER_STRESS_DATABASE_MAX_CONNECTIONS:-2}"
database_min_connections="${NORTHSTAR_LISTENER_STRESS_DATABASE_MIN_CONNECTIONS:-0}"
# This is an entry contract, deliberately checked before resolving/building a
# binary or touching the disposable PostgreSQL fixture.  The runtime manifest
# remains authoritative: `load_runtime_connection_budget` below rejects a
# build whose published limits diverge from these bounds.  Keeping this early
# guard explicit gives invalid profiles a deterministic, side-effect-free
# failure path.
readonly listener_stress_primary_pool_min=2
readonly listener_stress_primary_pool_max=60
# Filled from `xmpp-server --runtime-connection-budget` before any fixture
# database work begins.
runtime_auxiliary_connections=""
runtime_connections_per_child=""
runtime_primary_min_connections=""
runtime_primary_max_connections=""
fixture_control_connections_per_pair=0
fixture_control_connections=""
required_fixture_connections=""
fixture_actual_max_connections=""
[[ "$worker_timeout_seconds" =~ ^[1-9][0-9]*$ ]] \
  && ((worker_timeout_seconds <= 7200)) || {
  echo "NORTHSTAR_LISTENER_STRESS_WORKER_TIMEOUT_SECONDS must be 1 through 7200" >&2
  exit 2
}
[[ "$database_max_connections" =~ ^[1-9][0-9]*$ ]] || {
  echo "NORTHSTAR_LISTENER_STRESS_DATABASE_MAX_CONNECTIONS must be a positive decimal integer" >&2
  exit 2
}
[[ "$database_min_connections" =~ ^[0-9]+$ ]] || {
  echo "NORTHSTAR_LISTENER_STRESS_DATABASE_MIN_CONNECTIONS must be a decimal integer" >&2
  exit 2
}
rounds=$((10#$rounds))
pairs=$((10#$pairs))
database_max_connections=$((10#$database_max_connections))
database_min_connections=$((10#$database_min_connections))
((database_max_connections >= listener_stress_primary_pool_min \
   && database_max_connections <= listener_stress_primary_pool_max \
   && database_min_connections <= database_max_connections)) || {
  echo "NORTHSTAR_LISTENER_STRESS_DATABASE_MAX_CONNECTIONS must be ${listener_stress_primary_pool_min} through ${listener_stress_primary_pool_max}, and DATABASE_MIN_CONNECTIONS must not exceed it" >&2
  exit 2
}
readonly stress_child_count=$((pairs * 2))

effective_cpu_count() {
  # nproc respects the process affinity/cpuset; getconf reports the whole
  # machine even when this fixture is assigned fewer CPUs. Also clamp by a
  # cgroup quota, which need not match the number of allowed processors.
  local host_count quota period quota_count v1_quota v1_period
  host_count="$(env -u OMP_NUM_THREADS -u OMP_THREAD_LIMIT nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')"
  [[ "$host_count" =~ ^[1-9][0-9]*$ ]] || host_count=1
  quota_count="$host_count"
  if [[ -r /sys/fs/cgroup/cpu.max ]]; then
    read -r quota period < /sys/fs/cgroup/cpu.max || true
    if [[ "$quota" =~ ^[1-9][0-9]*$ && "$period" =~ ^[1-9][0-9]*$ ]]; then
      quota_count=$(((10#$quota + 10#$period - 1) / 10#$period))
    fi
  elif [[ -r /sys/fs/cgroup/cpu/cpu.cfs_quota_us && -r /sys/fs/cgroup/cpu/cpu.cfs_period_us ]]; then
    v1_quota="$(< /sys/fs/cgroup/cpu/cpu.cfs_quota_us)"
    v1_period="$(< /sys/fs/cgroup/cpu/cpu.cfs_period_us)"
    if [[ "$v1_quota" =~ ^[1-9][0-9]*$ && "$v1_period" =~ ^[1-9][0-9]*$ ]]; then
      quota_count=$(((10#$v1_quota + 10#$v1_period - 1) / 10#$v1_period))
    fi
  fi
  ((quota_count >= 1)) || quota_count=1
  ((quota_count <= host_count)) || quota_count="$host_count"
  printf '%s\n' "$quota_count"
}

# A stress round launches many independent server processes on one CI host.
# Tokio otherwise lets every child assume it owns every available CPU, which
# turns a 100-child matrix on a 16-core host into roughly 1,600 scheduler
# threads.  Derive a small, explicit per-child scheduler budget for this
# fixture only; process/pair concurrency and every protocol operation remain
# unchanged.  Passing the value explicitly also prevents an ambient shell
# setting from silently changing the matrix's resource contract.
effective_cpu_count="$(effective_cpu_count)"
startup_pair_limit="$(python3 "$project_dir/scripts/listener-stress-phases.py" --startup-pair-concurrency "$effective_cpu_count" "$pairs")"
readonly scheduler_reserved_cpus=$(((effective_cpu_count + 3) / 4))
available_scheduler_cpus=$((effective_cpu_count - scheduler_reserved_cpus))
((available_scheduler_cpus >= 1)) || available_scheduler_cpus=1
derived_tokio_worker_threads=$((available_scheduler_cpus / stress_child_count))
((derived_tokio_worker_threads >= 1)) || derived_tokio_worker_threads=1
((derived_tokio_worker_threads <= 2)) || derived_tokio_worker_threads=2
tokio_worker_threads="${NORTHSTAR_LISTENER_STRESS_TOKIO_WORKER_THREADS:-$derived_tokio_worker_threads}"
[[ "$tokio_worker_threads" =~ ^[1-9][0-9]*$ ]] \
  && ((10#$tokio_worker_threads <= 2)) || {
  echo "NORTHSTAR_LISTENER_STRESS_TOKIO_WORKER_THREADS must be 1 or 2" >&2
  exit 2
}
tokio_worker_threads=$((10#$tokio_worker_threads))
# Legacy SASL PLAIN and the REST session endpoint deliberately spend Argon2
# work.  A single-node server's password gate is process-local by design, so
# hundreds of isolated test processes would otherwise launch hundreds of
# independent password-derived setup operations against one host. The slot
# directory below does not serialize server startup, MIX/S2S work, or
# application requests after construction.
derived_login_slots=$((effective_cpu_count / 4))
((derived_login_slots >= 1)) || derived_login_slots=1
((derived_login_slots <= 4)) || derived_login_slots=4
login_slot_count="${NORTHSTAR_LISTENER_STRESS_LOGIN_CONCURRENCY:-$derived_login_slots}"
[[ "$login_slot_count" =~ ^[1-9][0-9]*$ ]] \
  && ((10#$login_slot_count <= effective_cpu_count && 10#$login_slot_count <= 64)) || {
  echo "NORTHSTAR_LISTENER_STRESS_LOGIN_CONCURRENCY must be a positive integer no greater than the effective CPU count or 64" >&2
  exit 2
}
login_slot_count=$((10#$login_slot_count))
resource_profile=standard
resource_override_opt_in="${NORTHSTAR_LISTENER_STRESS_ALLOW_RESOURCE_OVERRIDE:-false}"
case "$resource_override_opt_in" in true|false) ;; *)
  echo "NORTHSTAR_LISTENER_STRESS_ALLOW_RESOURCE_OVERRIDE must be exactly true or false" >&2
  exit 2
  ;;
esac
if { [[ -n "${NORTHSTAR_LISTENER_STRESS_TOKIO_WORKER_THREADS+x}" ]] \
     && ((tokio_worker_threads != derived_tokio_worker_threads)); } \
   || { [[ -n "${NORTHSTAR_LISTENER_STRESS_LOGIN_CONCURRENCY+x}" ]] \
     && ((login_slot_count != derived_login_slots)); }; then
  [[ "$resource_override_opt_in" == true ]] || {
    echo "non-default listener stress resource settings require NORTHSTAR_LISTENER_STRESS_ALLOW_RESOURCE_OVERRIDE=true" >&2
    exit 2
  }
  resource_profile=explicit-override
fi

umask 077
# Parent-side failures happen before a worker reaches github-ci-run.sh, so they
# need their own retained, redacted evidence path.  Keep it outside the private
# runtime directory: cleanup removes that directory because it contains test
# certificates and temporary credentials.
diagnostic_root="${NORTHSTAR_CI_DIAGNOSTICS_DIR:-${RUNNER_TEMP:-/tmp}/northstar-ci-diagnostics}"
if ! mkdir -p -- "$diagnostic_root"; then
  echo "listener stress could not create its diagnostic directory" >&2
  exit 2
fi
runtime_dir="$(mktemp -d /tmp/northstar-listener-stress.XXXXXX)"
runtime_dir_resolved="$(readlink -f -- "$runtime_dir")"
diagnostic_root_resolved="$(readlink -f -- "$diagnostic_root")"
case "$diagnostic_root_resolved" in
  "$runtime_dir_resolved"|"$runtime_dir_resolved"/*)
    echo "listener stress diagnostics must not be placed in its removable runtime directory" >&2
    exit 2
    ;;
esac
parent_diagnostic_raw="$runtime_dir/parent-diagnostics.raw.log"
: >"$parent_diagnostic_raw"
parent_diagnostic_artifact=""
parent_failure_phase=""
parent_query_sequence=0
normalized_postgres_boolean=""
postgres_boolean_result=""
database_exists_result=""
binary=""
readonly parent_diagnostic_max_bytes=524288
readonly parent_phase_log_tail_bytes=131072
declare -a workers=()
declare -a worker_groups=()
declare -a round_databases=()
declare -a template_databases=()
declare -a cleanup_debt=()
declare -A pair_database_a=()
declare -A pair_database_b=()
declare -A failed_pair_databases=()
mix_login_slot_dir=""
mix_phase_dir=""
mix_phase_run_nonce=""
mix_phase_round=""
startup_phase_dir=""
startup_phase_nonce=""

# Every stress worker must own two independent database states: one for each
# federated domain.  Applying the normal migrator from 50 workers would be
# deliberately serialized by the production database-policy advisory lock.
# Instead, this CI/local-loopback-only harness migrates two empty templates
# exactly once, then makes disposable physical database copies for the workers.
# The fixtures still perform their normal runtime ledger/canonicalizer checks;
# they simply receive an already-migrated private database rather than asking
# a live worker to contend for production's migration fence.
# A local developer may bind the disposable Docker PostgreSQL fixture to a
# different loopback port (for example 55432) when 5432 belongs to another
# local service. Only that endpoint is configurable: the test control role,
# its non-production password, and the control database stay fixed so this
# harness cannot be redirected at an arbitrary local PostgreSQL identity.
database_fixture_host="${NORTHSTAR_LISTENER_STRESS_DATABASE_HOST:-127.0.0.1}"
database_fixture_port="${NORTHSTAR_LISTENER_STRESS_DATABASE_PORT:-5432}"
readonly database_fixture_user=xmpp_test
readonly database_fixture_password=xmpp-test-password
readonly database_fixture_control_database=postgres
if [[ -n "${NORTHSTAR_LISTENER_STRESS_DATABASE_USER+x}" \
   || -n "${NORTHSTAR_LISTENER_STRESS_DATABASE_PASSWORD+x}" ]]; then
  echo "listener stress only permits loopback host and port overrides; its fixture user and password are fixed" >&2
  exit 2
fi
if [[ "$database_fixture_host" != 127.0.0.1 ]]; then
  echo "NORTHSTAR_LISTENER_STRESS_DATABASE_HOST must be the IPv4 loopback address 127.0.0.1" >&2
  exit 2
fi
if ! [[ "$database_fixture_port" =~ ^[1-9][0-9]{0,4}$ ]] \
   || ((10#$database_fixture_port > 65535)); then
  echo "NORTHSTAR_LISTENER_STRESS_DATABASE_PORT must be an integer from 1 through 65535" >&2
  exit 2
fi
fixture_name="${fixture//-/_}"
database_run_id="$(openssl rand -hex 8)"
database_prefix="northstar_listener_${fixture_name}_${database_run_id}"
template_database_a="${database_prefix}_template_a"
template_database_b="${database_prefix}_template_b"

private_database_name_is_valid() {
  local database_name="$1"
  [[ "$database_name" =~ ^[a-z][a-z0-9_]{0,62}$ \
     && "$database_name" == "${database_prefix}"_* ]]
}

fixture_admin_psql() {
  PGPASSWORD="$database_fixture_password" psql \
    --host "$database_fixture_host" \
    --port "$database_fixture_port" \
    --username "$database_fixture_user" \
    --dbname "$database_fixture_control_database" \
    --set ON_ERROR_STOP=1 "$@"
}

fixture_database_psql() {
  # The only non-control databases this parent ever connects to are generated
  # by this invocation and validated against its random prefix.  Keeping this
  # guard here makes the schema-owner repair as narrowly scoped as the later
  # clone and cleanup operations.
  local database_name="$1"
  shift
  private_database_name_is_valid "$database_name" || return 2
  PGPASSWORD="$database_fixture_password" psql \
    --host "$database_fixture_host" \
    --port "$database_fixture_port" \
    --username "$database_fixture_user" \
    --dbname "$database_name" \
    --set ON_ERROR_STOP=1 "$@"
}

record_parent_diagnostic() {
  # All callers pass fixed phase labels or generated private database names.
  # Raw command output is written only inside the 0700 runtime directory and is
  # redacted before it reaches the uploadable artifact.
  printf '%s\n' "$*" >>"$parent_diagnostic_raw" || true
}

initialize_mix_federation_login_slots() {
  local slot index resolved_slot_dir expected_slot
  mix_login_slot_dir="$runtime_dir/mix-federation-login-slots"
  mkdir --mode=0700 -- "$mix_login_slot_dir" || return 1
  [[ -d "$mix_login_slot_dir" && ! -L "$mix_login_slot_dir" ]] || return 1
  resolved_slot_dir="$(readlink -f -- "$mix_login_slot_dir")" || return 1
  [[ "$resolved_slot_dir" == "$runtime_dir_resolved/mix-federation-login-slots" ]] || return 1
  for ((index = 0; index < login_slot_count; index++)); do
    expected_slot="$resolved_slot_dir/northstar-mix-login-slot-$(printf '%03d' "$index").lock"
    : >"$expected_slot" || return 1
    chmod 0600 -- "$expected_slot" || return 1
    [[ -f "$expected_slot" && ! -L "$expected_slot" ]] || return 1
  done
  mix_login_slot_dir="$resolved_slot_dir"
  record_parent_diagnostic "phase=mix-federation-login-slots status=ready slots=$login_slot_count"
}

initialize_mix_federation_phase_barrier() {
  [[ "$fixture" == mix-federation ]] || return 0

  local round="$1" pair key resolved_phase_dir
  [[ "$round" =~ ^[1-9][0-9]*$ ]] || return 1
  mix_phase_dir="$runtime_dir/mix-federation-phase-r$(printf '%03d' "$round")"
  mkdir --mode=0700 -- "$mix_phase_dir" || return 1
  [[ -d "$mix_phase_dir" && ! -L "$mix_phase_dir" ]] || return 1
  resolved_phase_dir="$(readlink -f -- "$mix_phase_dir")" || return 1
  [[ "$resolved_phase_dir" == "$runtime_dir_resolved/mix-federation-phase-r$(printf '%03d' "$round")" ]] || return 1
  mix_phase_run_nonce="$(openssl rand -hex 32)" || return 1
  [[ "$mix_phase_run_nonce" =~ ^[0-9a-f]{64}$ ]] || return 1
  for ((pair = 1; pair <= pairs; pair++)); do
    key="$resolved_phase_dir/pair-$(printf '%03d' "$pair").key"
    umask 077
    openssl rand -hex 32 >"$key" || return 1
    chmod 0600 -- "$key" || return 1
    [[ -f "$key" && ! -L "$key" ]] || return 1
  done
  mix_phase_dir="$resolved_phase_dir"
  mix_phase_round="$round"
  record_parent_diagnostic "phase=mix-federation-setup-barrier round=$round status=initialized pairs=$pairs"
}

mix_phase_worker_leaders_alive() {
  local pid state
  for pid in "${workers[@]}"; do
    state="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]' || true)"
    [[ -n "$state" && "$state" != Z* ]] || return 1
  done
}

await_mix_federation_setup_barrier() {
  [[ "$fixture" == mix-federation ]] || return 0

  local expected_pairs="$1" deadline phase_status phase_log
  [[ "$expected_pairs" =~ ^[1-9][0-9]*$ && "$mix_phase_round" =~ ^[1-9][0-9]*$ \
     && -n "$mix_phase_dir" && "$mix_phase_run_nonce" =~ ^[0-9a-f]{64}$ ]] || return 1
  deadline=$((SECONDS + worker_timeout_seconds))
  phase_log="$runtime_dir/parent-mix-federation-setup-barrier-status.raw.log"
  while ((SECONDS < deadline)); do
    # A status of one is the normal "not every pair has published ready"
    # state.  Capture it inside the conditional: reading `$?` after a failed
    # `if` with no `else` observes the status of the compound `if` (zero),
    # which would incorrectly classify normal barrier polling as a fatal
    # record error and tear down the workers before they can publish.
    if python3 "$project_dir/scripts/mix-federation-runtime-wsl.py" --phase-parent-status \
      "$mix_phase_dir" "$mix_phase_run_nonce" "$mix_phase_round" "$expected_pairs" >"$phase_log" 2>&1; then
      phase_status=0
    else
      phase_status=$?
    fi
    if ((phase_status == 0)); then
      if ! run_parent_phase "mix-federation-setup-barrier-release-r$mix_phase_round" \
        python3 "$project_dir/scripts/mix-federation-runtime-wsl.py" --phase-parent-release \
        "$mix_phase_dir" "$mix_phase_run_nonce" "$mix_phase_round" "$expected_pairs"; then
        return 1
      fi
      record_parent_diagnostic "phase=mix-federation-setup-barrier round=$mix_phase_round status=released pairs=$expected_pairs"
      return 0
    fi
    if ((phase_status != 1)); then
      record_parent_phase_failure "mix-federation-setup-barrier-status-r$mix_phase_round" "$phase_status" "$phase_log"
      echo "listener stress MIX setup barrier rejected a readiness record" >&2
      return 1
    fi
    if ! mix_phase_worker_leaders_alive; then
      record_parent_diagnostic "phase=mix-federation-setup-barrier round=$mix_phase_round status=worker_exited_before_release"
      echo "listener stress MIX worker exited before the all-pair setup release" >&2
      return 1
    fi
    sleep 0.025
  done
  record_parent_diagnostic "phase=mix-federation-setup-barrier round=$mix_phase_round status=deadline"
  echo "listener stress MIX setup barrier did not receive every signed readiness record" >&2
  return 1
}

verify_mix_federation_listener_ledger() {
  [[ "$fixture" == mix-federation ]] || return 0

  local expected_pairs="$1"
  [[ "$expected_pairs" =~ ^[1-9][0-9]*$ && "$mix_phase_round" =~ ^[1-9][0-9]*$ \
     && -n "$mix_phase_dir" && "$mix_phase_run_nonce" =~ ^[0-9a-f]{64}$ ]] || return 1
  run_parent_phase "mix-federation-listener-ledger-r$mix_phase_round" \
    python3 "$project_dir/scripts/mix-federation-runtime-wsl.py" --listener-ledger-verify \
    "$mix_phase_dir" "$mix_phase_run_nonce" "$mix_phase_round" "$expected_pairs"
}

record_parent_phase_failure() {
  local phase="$1" status="$2" phase_log="$3"
  [[ -n "$parent_failure_phase" ]] || parent_failure_phase="$phase"
  record_parent_diagnostic "phase=$phase status=$status"
  if [[ -s "$phase_log" ]]; then
    record_parent_diagnostic "--- phase=$phase bounded_output_tail ---"
    tail -c "$parent_phase_log_tail_bytes" -- "$phase_log" >>"$parent_diagnostic_raw" || true
    printf '\n' >>"$parent_diagnostic_raw" || true
  fi
}

run_parent_phase() {
  local phase="$1" phase_log status
  shift
  phase_log="$runtime_dir/parent-${phase//[^a-zA-Z0-9_.-]/_}.raw.log"
  if "$@" >"$phase_log" 2>&1; then
    return 0
  else
    status=$?
  fi
  record_parent_phase_failure "$phase" "$status" "$phase_log"
  echo "listener stress parent phase failed: $phase (status=$status)" >&2
  return "$status"
}

normalize_postgres_boolean() {
  # psql command substitution strips the normal trailing newline.  Anything
  # else (including an empty result, an extra row, or an error accidentally
  # sent to stdout) is not a boolean and must fail closed.
  normalized_postgres_boolean=""
  case "$1" in
    t|true) normalized_postgres_boolean=true ;;
    f|false) normalized_postgres_boolean=false ;;
    *) return 1 ;;
  esac
}

fixture_query_boolean() {
  local phase="$1" sql="$2" output status
  parent_query_sequence=$((parent_query_sequence + 1))
  if output="$(fixture_admin_psql --tuples-only --no-align --command "$sql" 2>>"$parent_diagnostic_raw")"; then
    :
  else
    status=$?
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="$phase"
    record_parent_diagnostic "phase=$phase status=$status query=failed"
    echo "listener stress PostgreSQL boolean query failed: $phase" >&2
    return 1
  fi
  if ! normalize_postgres_boolean "$output"; then
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="$phase"
    record_parent_diagnostic "phase=$phase status=invalid_boolean_output query_sequence=$parent_query_sequence"
    echo "listener stress PostgreSQL boolean query returned an invalid result: $phase" >&2
    return 1
  fi
  postgres_boolean_result="$normalized_postgres_boolean"
}

fixture_database_query_boolean() {
  local database_name="$1" phase="$2" sql="$3" output status
  private_database_name_is_valid "$database_name" || return 1
  parent_query_sequence=$((parent_query_sequence + 1))
  if output="$(fixture_database_psql "$database_name" --tuples-only --no-align --command "$sql" 2>>"$parent_diagnostic_raw")"; then
    :
  else
    status=$?
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="$phase"
    record_parent_diagnostic "phase=$phase status=$status query=failed"
    echo "listener stress PostgreSQL boolean query failed: $phase" >&2
    return 1
  fi
  if ! normalize_postgres_boolean "$output"; then
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="$phase"
    record_parent_diagnostic "phase=$phase status=invalid_boolean_output query_sequence=$parent_query_sequence"
    echo "listener stress PostgreSQL boolean query returned an invalid result: $phase" >&2
    return 1
  fi
  postgres_boolean_result="$normalized_postgres_boolean"
}

database_exists() {
  local database_name="$1"
  database_exists_result=""
  private_database_name_is_valid "$database_name" || return 1
  fixture_query_boolean "database-exists-$database_name" \
    "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname='$database_name')" \
    || return 1
  database_exists_result="$postgres_boolean_result"
}

record_cleanup_debt() {
  local database_name="$1" reason="$2"
  local debt
  for debt in "${cleanup_debt[@]}"; do
    [[ "$debt" == "$database_name:$reason" ]] && return 0
  done
  cleanup_debt+=("$database_name:$reason")
  record_parent_diagnostic "phase=cleanup resource=database resource_name=$database_name ownership=fixture-verified state=$reason"
}

append_runtime_log_tails() {
  # Worker commands own their individual redacted supervisor artifacts.  This
  # parent-side artifact supplements them with a bounded selection of local
  # lifecycle logs, without echoing potentially credential-rich raw logs into
  # the job console during cleanup.
  local log collected=0
  while IFS= read -r -d '' log; do
    [[ "$log" == "$parent_diagnostic_raw" || "$log" == "$runtime_dir/parent-diagnostics.final.raw.log" ]] && continue
    if (( collected >= 12 )); then
      record_parent_diagnostic "runtime_log_tails_truncated=true retained=$collected"
      break
    fi
    record_parent_diagnostic "--- runtime_log=$(basename "$log") bounded_tail ---"
    tail -c 32768 -- "$log" >>"$parent_diagnostic_raw" || true
    printf '\n' >>"$parent_diagnostic_raw" || true
    collected=$((collected + 1))
  # Authority snapshots are already copied into the parent transcript by
  # `append_mix_federation_database_snapshots`.  Keeping their raw scratch
  # files in this generic 12-log selection used to evict the actual worker
  # transcripts precisely when a high-parallelism run failed, making the
  # retained artifact unable to explain the worker failure.
  done < <(find "$runtime_dir" -maxdepth 1 -type f -name '*.log' \
    ! -name 'mix-federation-authority-*.raw.log' -print0 | LC_ALL=C sort -z)

  # Detailed claim eligibility is the last-resort evidence for a durable MIX
  # stall. Append it after ordinary worker logs so the final bounded artifact
  # cannot evict it under a many-worker failure. The producer already limits
  # this to four databases and 49,152 bytes each.
  for log in "$runtime_dir"/mix-federation-authority-detail-*.raw.log; do
    [[ -f "$log" && ! -L "$log" ]] || continue
    record_parent_diagnostic "--- mix_federation_recipient_claim_detail=$(basename "$log") retained_tail ---"
    tail -c 49152 -- "$log" >>"$parent_diagnostic_raw" || true
    printf '\n' >>"$parent_diagnostic_raw" || true
  done

  # Dead-letter evidence is deliberately separate from the recipient-claim
  # view: a terminal delivery has already left that live projection.  Retain
  # only the bounded, scrubbed summary generated below, never its stanza or
  # raw error text, so the parent artifact can distinguish a routing stall
  # from a terminal policy/capability decision without widening disclosure.
  for log in "$runtime_dir"/mix-federation-authority-dead-letter-detail-*.raw.log; do
    [[ -f "$log" && ! -L "$log" ]] || continue
    record_parent_diagnostic "--- mix_federation_dead_letter_detail=$(basename "$log") retained_tail ---"
    tail -c 32768 -- "$log" >>"$parent_diagnostic_raw" || true
    printf '\n' >>"$parent_diagnostic_raw" || true
  done
}

append_mix_federation_database_snapshots() {
  # The MIX federation fixture tears its servers down before the parent drops
  # its private databases.  Preserve a bounded, content-free authority view
  # in that interval when a worker has failed.  This distinguishes an absent
  # delivery projection from a claimed/retrying MIX row or a stranded S2S
  # projection without exposing stanzas, credentials, or raw client payloads.
  [[ "$fixture" == mix-federation ]] || return 0

  local database_name snapshot status own_domain detail_database_count=0 detail_database_limit=4 detail_candidates=0
  for database_name in "${round_databases[@]}"; do
    private_database_name_is_valid "$database_name" || continue
    case "$database_name" in
      *_a) own_domain=localhost ;;
      *_b) own_domain=remote.localhost ;;
      *)
        record_parent_diagnostic "mix_federation_authority_snapshot database=$database_name status=unknown_domain_projection"
        continue
        ;;
    esac
    snapshot="$runtime_dir/mix-federation-authority-${database_name}.raw.log"
    if fixture_database_psql "$database_name" --tuples-only --no-align \
      --field-separator='|' --command "
        SELECT 'mix_delivery_events' AS projection,
               COUNT(*)::text AS total,
               NULL::text AS ready,
               NULL::text AS leased,
               NULL::text AS attempted,
               NULL::text AS failed
          FROM mix_delivery_events
        UNION ALL
        SELECT 'mix_delivery_recipients',
               COUNT(*)::text,
               COUNT(*) FILTER (WHERE lease_token IS NULL
                                 AND next_attempt_at <= clock_timestamp())::text,
               COUNT(*) FILTER (WHERE lease_token IS NOT NULL)::text,
               COUNT(*) FILTER (WHERE attempt_count > 0)::text,
               COUNT(*) FILTER (WHERE last_error IS NOT NULL)::text
          FROM mix_delivery_recipients
        UNION ALL
        SELECT 'mix_delivery_recipients_foreign_domain',
               COUNT(*)::text,
               COUNT(*) FILTER (WHERE lease_token IS NULL
                                 AND next_attempt_at <= clock_timestamp())::text,
               COUNT(*) FILTER (WHERE lease_token IS NOT NULL)::text,
               COUNT(*) FILTER (WHERE attempt_count > 0)::text,
               COUNT(*) FILTER (WHERE last_error IS NOT NULL)::text
          FROM mix_delivery_recipients
         WHERE split_part(recipient_jid, '@', 2) <> '$own_domain'
        UNION ALL
        SELECT 'mix_delivery_recipients_own_domain',
               COUNT(*)::text,
               COUNT(*) FILTER (WHERE lease_token IS NULL
                                 AND next_attempt_at <= clock_timestamp())::text,
               COUNT(*) FILTER (WHERE lease_token IS NOT NULL)::text,
               COUNT(*) FILTER (WHERE attempt_count > 0)::text,
               COUNT(*) FILTER (WHERE last_error IS NOT NULL)::text
          FROM mix_delivery_recipients
         WHERE split_part(recipient_jid, '@', 2) = '$own_domain'
        UNION ALL
        SELECT 'mix_delivery_dead_letters',
               COUNT(*)::text,
               NULL::text,
               NULL::text,
               COUNT(*) FILTER (WHERE attempt_count > 0)::text,
               COUNT(*) FILTER (WHERE last_error IS NOT NULL)::text
          FROM mix_delivery_dead_letters
        UNION ALL
        SELECT 'mix_pam_operations',
               COUNT(*)::text,
               COUNT(*) FILTER (WHERE response_xml IS NOT NULL
                                 AND delivered_at IS NULL
                                 AND dead_lettered_at IS NULL
                                 AND lease_token IS NULL
                                 AND next_delivery_at <= clock_timestamp())::text,
               COUNT(*) FILTER (WHERE lease_token IS NOT NULL)::text,
               COUNT(*) FILTER (WHERE delivery_attempt_count > 0)::text,
               COUNT(*) FILTER (WHERE last_error IS NOT NULL)::text
          FROM mix_pam_operations
        UNION ALL
        SELECT 's2s_outbox',
               COUNT(*)::text,
               COUNT(*) FILTER (WHERE lock_token IS NULL
                                 AND next_attempt_at <= clock_timestamp())::text,
               COUNT(*) FILTER (WHERE lock_token IS NOT NULL)::text,
               COUNT(*) FILTER (WHERE attempt_count > 0)::text,
               COUNT(*) FILTER (WHERE last_error IS NOT NULL)::text
          FROM s2s_outbox
        ORDER BY projection;
      " >"$snapshot" 2>&1; then
      record_parent_diagnostic "--- mix_federation_authority_snapshot database=$database_name ---"
      tail -c 16384 -- "$snapshot" >>"$parent_diagnostic_raw" || true
      printf '\n' >>"$parent_diagnostic_raw" || true
    else
      status=$?
      record_parent_diagnostic "mix_federation_authority_snapshot database=$database_name status=query_failed exit_status=$status"
      tail -c 4096 -- "$snapshot" >>"$parent_diagnostic_raw" || true
      printf '\n' >>"$parent_diagnostic_raw" || true
    fi
    if [[ -n "${failed_pair_databases[$database_name]:-}" ]]; then
      detail_candidates=$((detail_candidates + 1))
      if (( detail_database_count < detail_database_limit )); then
        append_mix_federation_recipient_claim_detail "$database_name" "$own_domain"
        append_mix_federation_dead_letter_detail "$database_name"
        detail_database_count=$((detail_database_count + 1))
      fi
    fi
  done
  if (( detail_candidates == 0 )); then
    # A group-quiescence failure can occur after a wrapper has exited without
    # a single attributable non-zero worker status. Keep a deterministic,
    # small fallback rather than silently omitting the claim evidence.
    for database_name in "${round_databases[@]}"; do
      (( detail_database_count < detail_database_limit )) || break
      private_database_name_is_valid "$database_name" || continue
      case "$database_name" in
        *_a) own_domain=localhost ;;
        *_b) own_domain=remote.localhost ;;
        *) continue ;;
      esac
      append_mix_federation_recipient_claim_detail "$database_name" "$own_domain"
      append_mix_federation_dead_letter_detail "$database_name"
      detail_database_count=$((detail_database_count + 1))
    done
    record_parent_diagnostic "mix_federation_claim_detail_selection=fallback_unattributed databases=$detail_database_count"
  else
    record_parent_diagnostic "mix_federation_claim_detail_selection=failed_workers candidates=$detail_candidates retained=$detail_database_count limit=$detail_database_limit"
  fi
}

append_mix_federation_recipient_claim_detail() {
  # This is intentionally a second query. The aggregate snapshot above must
  # remain available even if an explanatory diagnostic has a schema/query
  # regression. It emits only one-way identifier digests and booleans; no XML,
  # account name, raw JID, token, lease token, IP address, or error text.
  local database_name="$1" own_domain="$2" detail_snapshot status
  private_database_name_is_valid "$database_name" || return 1
  case "$own_domain" in localhost|remote.localhost) ;; *) return 1 ;; esac
  detail_snapshot="$runtime_dir/mix-federation-authority-detail-${database_name}.raw.log"
  if fixture_database_psql "$database_name" --tuples-only --no-align \
    --field-separator='|' --command "
      WITH snapshot_clock AS (SELECT clock_timestamp() AS now_at),
      detail AS (
        SELECT substr(md5(recipient.delivery_id::text),1,16) AS delivery_key,
               substr(md5(recipient.event_id::text),1,16) AS event_key,
               substr(md5(recipient.recipient_jid),1,16) AS recipient_key,
               CASE WHEN split_part(recipient.recipient_jid, '@', 2) = '$own_domain'
                    THEN 'own' ELSE 'foreign' END AS recipient_scope,
               recipient.delivery_sequence,
               recipient.attempt_count,
               (recipient.last_error IS NOT NULL) AS has_error,
               (event.event_id IS NOT NULL) AS event_present,
               COALESCE(event.expires_at > clock.now_at, false) AS event_unexpired,
               (authority.recipient_jid IS NOT NULL) AS authority_present,
               authority.next_sequence AS authority_next_sequence,
               CASE WHEN recipient.lease_token IS NULL THEN 'none'
                    WHEN recipient.lease_until > clock.now_at THEN 'active'
                    ELSE 'expired' END AS lease_state,
               (recipient.next_attempt_at <= clock.now_at) AS attempt_due,
               COALESCE(previous.preceding_count, 0) AS preceding_count,
               previous.nearest_sequence,
               previous.nearest_lease_state,
               previous.nearest_attempt_due,
               previous.nearest_event_present,
               previous.nearest_event_unexpired,
               (event.event_id IS NOT NULL
                 AND event.expires_at > clock.now_at
                 AND authority.recipient_jid IS NOT NULL
                 AND (recipient.lease_until IS NULL OR recipient.lease_until <= clock.now_at)
                 AND recipient.next_attempt_at <= clock.now_at
                 AND COALESCE(previous.preceding_count, 0) = 0) AS claim_predicate_true,
               recipient.created_at
          FROM mix_delivery_recipients recipient
          CROSS JOIN snapshot_clock clock
          LEFT JOIN mix_delivery_events event ON event.event_id=recipient.event_id
          LEFT JOIN mix_delivery_recipient_sequences authority
            ON authority.recipient_jid=recipient.recipient_jid
          LEFT JOIN LATERAL (
            SELECT earlier.delivery_sequence AS nearest_sequence,
                   count(*) OVER ()::bigint AS preceding_count,
                   CASE WHEN earlier.lease_token IS NULL THEN 'none'
                        WHEN earlier.lease_until > clock.now_at THEN 'active'
                        ELSE 'expired' END AS nearest_lease_state,
                   (earlier.next_attempt_at <= clock.now_at) AS nearest_attempt_due,
                   (earlier_event.event_id IS NOT NULL) AS nearest_event_present,
                   COALESCE(earlier_event.expires_at > clock.now_at, false) AS nearest_event_unexpired
              FROM mix_delivery_recipients earlier
              LEFT JOIN mix_delivery_events earlier_event ON earlier_event.event_id=earlier.event_id
             WHERE earlier.recipient_jid=recipient.recipient_jid
               AND earlier.delivery_sequence < recipient.delivery_sequence
             ORDER BY earlier.delivery_sequence DESC
             LIMIT 1
          ) previous ON TRUE
      )
      SELECT 'mix_delivery_recipient_claim_detail_v1',delivery_key,event_key,recipient_key,
             recipient_scope,delivery_sequence,attempt_count,has_error,event_present,
             event_unexpired,authority_present,authority_next_sequence,lease_state,attempt_due,
             preceding_count,nearest_sequence,nearest_lease_state,nearest_attempt_due,
             nearest_event_present,nearest_event_unexpired,claim_predicate_true
        FROM detail
       ORDER BY CASE WHEN claim_predicate_true THEN 1 ELSE 0 END,
                created_at,delivery_sequence,delivery_key
       LIMIT 128;
    " >"$detail_snapshot" 2>&1; then
    record_parent_diagnostic "--- mix_federation_recipient_claim_detail database=$database_name bounded ---"
    tail -c 49152 -- "$detail_snapshot" >>"$parent_diagnostic_raw" || true
    printf '\n' >>"$parent_diagnostic_raw" || true
  else
    status=$?
    record_parent_diagnostic "mix_federation_recipient_claim_detail database=$database_name status=query_failed exit_status=$status"
    tail -c 4096 -- "$detail_snapshot" >>"$parent_diagnostic_raw" || true
    printf '\n' >>"$parent_diagnostic_raw" || true
  fi
}

append_mix_federation_dead_letter_detail() {
  # A dead letter no longer has a row in `mix_delivery_recipients`, so the
  # claim diagnostic above cannot explain why it became terminal.  Keep this
  # view bounded and metadata-only: database identity is in the enclosing
  # header, terminal reason is accepted only in its canonical program-owned
  # form, and `last_error` is reduced to a coarse class plus a correlation
  # fingerprint.  In particular, never select `stanza_template`, a JID,
  # channel name, raw error text, or any client-controlled XML.
  local database_name="$1" detail_snapshot status
  private_database_name_is_valid "$database_name" || return 1
  detail_snapshot="$runtime_dir/mix-federation-authority-dead-letter-detail-${database_name}.raw.log"
  if fixture_database_psql "$database_name" --tuples-only --no-align \
    --field-separator='|' --command "
      WITH bounded AS (
        SELECT CASE
                 WHEN terminal_reason ~ '^[a-z][a-z0-9-]{0,63}$'
                   THEN terminal_reason
                 ELSE 'noncanonical'
               END AS terminal_reason,
               CASE
                 WHEN last_error IS NULL OR btrim(last_error)='' THEN 'none'
                 WHEN last_error ILIKE '%capabilit%' THEN 'capability'
                 WHEN last_error ILIKE '%timeout%'
                   OR last_error ILIKE '%timed out%'
                   OR last_error ILIKE '%deadline%' THEN 'timeout'
                 WHEN last_error ILIKE '%federat%'
                   OR last_error ILIKE '%s2s%'
                   OR last_error ILIKE '%remote%'
                   OR last_error ILIKE '%tls%' THEN 'federation'
                 WHEN last_error ILIKE '%database%'
                   OR last_error ILIKE '%postgres%'
                   OR last_error ILIKE '%sql%' THEN 'database'
                 WHEN last_error ILIKE '%session%'
                   OR last_error ILIKE '%resource%' THEN 'session'
                 WHEN last_error ILIKE '%policy%'
                   OR last_error ILIKE '%block%' THEN 'policy'
                 ELSE 'other'
               END AS error_class,
               CASE
                 WHEN last_error IS NULL OR btrim(last_error)='' THEN 'none'
                 ELSE substr(md5(last_error),1,24)
               END AS error_fingerprint,
               archive,encrypted,attempt_count
          FROM mix_delivery_dead_letters
         ORDER BY failed_at DESC,dead_letter_id DESC
         LIMIT 128
      )
      SELECT 'mix_delivery_dead_letter_detail_v1',terminal_reason,error_class,
             error_fingerprint,archive,encrypted,
             min(attempt_count),max(attempt_count),count(*)
        FROM bounded
       GROUP BY terminal_reason,error_class,error_fingerprint,archive,encrypted
       ORDER BY count(*) DESC,terminal_reason,error_class,error_fingerprint
       LIMIT 128;
    " >"$detail_snapshot" 2>&1; then
    record_parent_diagnostic "--- mix_federation_dead_letter_detail database=$database_name bounded ---"
    tail -c 32768 -- "$detail_snapshot" >>"$parent_diagnostic_raw" || true
    printf '\n' >>"$parent_diagnostic_raw" || true
  else
    status=$?
    record_parent_diagnostic "mix_federation_dead_letter_detail database=$database_name status=query_failed exit_status=$status"
    tail -c 4096 -- "$detail_snapshot" >>"$parent_diagnostic_raw" || true
    printf '\n' >>"$parent_diagnostic_raw" || true
  fi
}

retain_parent_diagnostic_artifact() {
  local exit_status="$1" source_file artifact temporary_artifact target_artifact debt

  source_file="$runtime_dir/parent-diagnostics.final.raw.log"
  {
    printf 'listener_readiness_stress_failure=true\n'
    printf 'fixture=%s mode=%s exit_status=%s\n' "$fixture" "$mode" "$exit_status"
    printf 'first_failure_phase=%s\n' "${parent_failure_phase:-unknown}"
    if (( ${#cleanup_debt[@]} > 0 )); then
      printf 'cleanup_debt_count=%s\n' "${#cleanup_debt[@]}"
      for debt in "${cleanup_debt[@]}"; do
        printf 'cleanup_debt=%s\n' "$debt"
      done
    fi
    printf '%s\n' '--- bounded parent diagnostic tail ---'
    tail -c "$parent_diagnostic_max_bytes" -- "$parent_diagnostic_raw" 2>/dev/null || true
  } >"$source_file"

  if ! temporary_artifact="$(mktemp "$diagnostic_root_resolved/listener-readiness-${fixture}.XXXXXX")"; then
    echo "listener stress could not allocate a sanitized diagnostic artifact" >&2
    return 1
  fi
  artifact="${temporary_artifact}.redacted.log"
  if ! mv -- "$temporary_artifact" "$artifact"; then
    echo "listener stress could not name its sanitized diagnostic artifact" >&2
    rm -f -- "$temporary_artifact"
    return 1
  fi

  # Reuse the repository's control-character and credential redactor.  A
  # minimal safe fallback still records ownership and phase metadata if the
  # redactor itself is unavailable; it never uploads the raw transcript.
  if ! python3 "$project_dir/scripts/github_ci_summary.py" \
    --title "Listener readiness stress parent failure" \
    --redacted-copy "$artifact" "$source_file" >/dev/null 2>&1; then
    {
      printf 'listener_readiness_stress_failure=true\n'
      printf 'fixture=%s mode=%s exit_status=%s\n' "$fixture" "$mode" "$exit_status"
      printf 'first_failure_phase=%s\n' "${parent_failure_phase:-unknown}"
      for debt in "${cleanup_debt[@]}"; do
        printf 'cleanup_debt=%s\n' "$debt"
      done
      printf '%s\n' 'diagnostic_redactor_failed=true'
    } >"$artifact"
  fi
  chmod 600 -- "$artifact" 2>/dev/null || true
  if [[ ! -s "$artifact" ]]; then
    echo "listener stress sanitized diagnostic artifact is empty: $artifact" >&2
    return 1
  fi
  # A preflight/template failure is recorded before cleanup starts, then this
  # same file is atomically refreshed after cleanup so its retained evidence
  # includes any owned-resource debt and sanitized PostgreSQL failure output.
  if [[ -n "$parent_diagnostic_artifact" ]]; then
    target_artifact="$parent_diagnostic_artifact"
    if ! mv -f -- "$artifact" "$target_artifact"; then
      echo "listener stress could not refresh its sanitized diagnostic artifact" >&2
      return 1
    fi
    artifact="$target_artifact"
  fi
  parent_diagnostic_artifact="$artifact"
  echo "listener stress sanitized diagnostic artifact retained: $artifact" >&2
}

assert_private_database_fixture() {
  local identity status
  identity="$(fixture_admin_psql --tuples-only --no-align --command "
    SELECT pg_catalog.host(pg_catalog.inet_server_addr()) || '|' || current_user || '|' ||
           (SELECT rolcreatedb::TEXT FROM pg_catalog.pg_roles WHERE rolname=current_user)
  " 2>>"$parent_diagnostic_raw")" || {
    status=$?
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=database-fixture-attestation
    record_parent_diagnostic "phase=database-fixture-attestation status=$status query=failed"
    echo "listener stress database fixture attestation query failed" >&2
    return 1
  }
  [[ "$identity" == "127.0.0.1|xmpp_test|true" ]] || {
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=database-fixture-attestation
    record_parent_diagnostic "phase=database-fixture-attestation status=unexpected_identity"
    echo "listener stress database fixture must be loopback xmpp_test with CREATEDB, got ${identity:-unknown}" >&2
    return 1
  }
}

assert_fixture_connection_capacity() {
  # The fixture database has already been attested as the dedicated loopback
  # xmpp_test instance.  Query its actual server setting rather than trusting
  # an optional caller-provided number: otherwise an ad-hoc local run could
  # silently overcommit PostgreSQL even though CI supplied a correct value.
  local reported configured status
  reported="$(fixture_admin_psql --tuples-only --no-align --command 'SHOW max_connections;' \
    2>>"$parent_diagnostic_raw")" || {
    status=$?
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=database-capacity-attestation
    record_parent_diagnostic "phase=database-capacity-attestation status=$status query=failed"
    echo "listener stress database capacity query failed" >&2
    return 1
  }
  [[ "$reported" =~ ^[1-9][0-9]*$ ]] || {
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=database-capacity-attestation
    record_parent_diagnostic "phase=database-capacity-attestation status=invalid_output"
    echo "listener stress database returned an invalid max_connections value" >&2
    return 1
  }
  fixture_actual_max_connections=$((10#$reported))
  if [[ -n "${NORTHSTAR_LOOPBACK_POSTGRES_MAX_CONNECTIONS:-}" ]]; then
    configured="${NORTHSTAR_LOOPBACK_POSTGRES_MAX_CONNECTIONS}"
    [[ "$configured" =~ ^[1-9][0-9]*$ ]] \
      && ((10#$configured == fixture_actual_max_connections)) || {
      [[ -n "$parent_failure_phase" ]] || parent_failure_phase=database-capacity-attestation
      record_parent_diagnostic "phase=database-capacity-attestation status=configured_mismatch"
      echo "NORTHSTAR_LOOPBACK_POSTGRES_MAX_CONNECTIONS must exactly match the attested fixture server capacity" >&2
      return 1
    }
  fi
  ((fixture_actual_max_connections >= required_fixture_connections)) || {
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=database-capacity-attestation
    record_parent_diagnostic "phase=database-capacity-attestation status=insufficient required=$required_fixture_connections actual=$fixture_actual_max_connections"
    echo "fixture PostgreSQL max_connections=$fixture_actual_max_connections is below the required $required_fixture_connections for $stress_child_count children × $runtime_connections_per_child runtime connections plus $fixture_control_connections fixture-control connections" >&2
    return 1
  }
  record_parent_diagnostic "phase=database-capacity-attestation status=validated actual=$fixture_actual_max_connections required=$required_fixture_connections"
}

database_owner_is_fixture_user() {
  local database_name="$1" owner status
  private_database_name_is_valid "$database_name" || return 1
  owner="$(fixture_admin_psql --tuples-only --no-align --command "
    SELECT pg_catalog.pg_get_userbyid(datdba)
      FROM pg_catalog.pg_database
     WHERE datname='$database_name'
  " 2>>"$parent_diagnostic_raw")" || {
    status=$?
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="database-owner-$database_name"
    record_parent_diagnostic "phase=database-owner-$database_name status=$status query=failed"
    echo "listener stress database ownership query failed: $database_name" >&2
    return 2
  }
  [[ "$owner" == "$database_fixture_user" ]]
}

drop_private_database() {
  local database_name="$1" owner_status
  private_database_name_is_valid "$database_name" || {
    echo "refusing to drop an unexpected listener stress database: $database_name" >&2
    return 1
  }
  if database_owner_is_fixture_user "$database_name"; then
    :
  else
    owner_status=$?
    # An absent database is already clean; any other owner or an ownership
    # lookup failure is an audit failure rather than a target for destructive
    # fixture cleanup.
    if (( owner_status >= 2 )); then
      record_cleanup_debt "$database_name" owner-query-failed
      return 1
    fi
    if ! database_exists "$database_name"; then
      record_cleanup_debt "$database_name" existence-query-failed
      return 1
    fi
    if [[ "$database_exists_result" == false ]]; then
      return 0
    fi
    record_cleanup_debt "$database_name" owner-mismatch
    echo "listener stress database is not owned by the fixture identity: $database_name" >&2
    return 1
  fi
  # Worker names are generated by this run and checked above. FORCE is an
  # intentional backstop for a killed child that left only connections to its
  # own disposable database; it never targets the shared control database.
  if ! run_parent_phase "cleanup-drop-$database_name" \
    fixture_admin_psql --command "DROP DATABASE \"$database_name\" WITH (FORCE);"; then
    record_cleanup_debt "$database_name" drop-failed
    return 1
  fi
  if ! database_exists "$database_name"; then
    record_cleanup_debt "$database_name" post-drop-existence-query-failed
    return 1
  fi
  if [[ "$database_exists_result" != false ]]; then
    record_cleanup_debt "$database_name" post-drop-still-exists
    echo "listener stress database remained after its owned cleanup: $database_name" >&2
    return 1
  fi
  return 0
}

create_private_database_from_template() {
  local database_name="$1" template_name="$2"
  private_database_name_is_valid "$database_name" \
    && private_database_name_is_valid "$template_name" || {
    echo "listener stress refused unsafe database template names" >&2
    return 1
  }
  if ! database_exists "$database_name"; then
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="clone-preflight-$database_name"
    record_parent_diagnostic "phase=clone-preflight-$database_name status=existence_query_failed"
    echo "listener stress could not determine whether a private database name is occupied: $database_name" >&2
    return 1
  fi
  [[ "$database_exists_result" == false ]] || {
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="clone-preflight-$database_name"
    record_parent_diagnostic "phase=clone-preflight-$database_name status=name_occupied"
    echo "listener stress database name was unexpectedly occupied: $database_name" >&2
    return 1
  }
  database_owner_is_fixture_user "$template_name" || {
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="clone-preflight-$database_name"
    record_parent_diagnostic "phase=clone-preflight-$database_name status=template_not_fixture_owned template=$template_name"
    echo "listener stress migration template is missing or not owned by the fixture identity: $template_name" >&2
    return 1
  }
  run_parent_phase "clone-create-$database_name" \
    fixture_admin_psql --command "CREATE DATABASE \"$database_name\" WITH TEMPLATE \"$template_name\" OWNER \"$database_fixture_user\";" \
    || return 1
  if ! database_owner_is_fixture_user "$database_name"; then
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="clone-create-$database_name"
    # The database name is owned by this invocation, but deletion remains
    # forbidden until PostgreSQL proves that the fixture identity owns it.
    record_parent_diagnostic "phase=clone-create-$database_name resource=database resource_name=$database_name ownership=unverified state=created_not_eligible_for_cleanup"
    echo "listener stress clone did not retain fixture ownership: $database_name" >&2
    return 1
  fi
}

template_database_url() {
  local database_name="$1"
  private_database_name_is_valid "$database_name" || return 1
  printf 'postgres://%s:%s@%s:%s/%s?options=-csearch_path%%3Dpublic' \
    "$database_fixture_user" "$database_fixture_password" \
    "$database_fixture_host" "$database_fixture_port" "$database_name"
}

template_public_schema_is_migration_owned() {
  local database_name="$1" phase
  private_database_name_is_valid "$database_name" || return 1
  phase="template-schema-attestation-$database_name"
  # Do not accept PostgreSQL 15's default pg_database_owner indirection here:
  # the migrations deliberately require the physical installation schema and
  # its protected relations to be owned by the exact migration role.  The
  # catalog predicate is fail-closed for a missing schema, an unexpected owner,
  # or an unexpected connection identity.
  fixture_database_query_boolean "$database_name" "$phase" "
    SELECT EXISTS(
      SELECT 1
        FROM pg_catalog.pg_namespace namespace
        JOIN pg_catalog.pg_roles owner ON owner.oid=namespace.nspowner
       WHERE namespace.nspname='public'
         AND owner.rolname=current_user
         AND current_user='$database_fixture_user'
    )
  " || return 1
  [[ "$postgres_boolean_result" == true ]] || {
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="$phase"
    record_parent_diagnostic "phase=$phase status=unexpected_schema_owner"
    echo "listener stress template public schema is not owned by the migration role: $database_name" >&2
    return 1
  }
}

establish_template_public_schema_owner() {
  local database_name="$1" phase
  private_database_name_is_valid "$database_name" || return 1
  phase="template-schema-owner-$database_name"
  # PostgreSQL 15+ creates public owned by the pg_database_owner predefined
  # role.  That is intentionally insufficient for Northstar's strict 0114
  # installation-schema ownership audit, which compares nspowner directly to
  # the migration role.  Make the role explicit before the migrator touches
  # this disposable, prefix-validated database and immediately attest it.
  run_parent_phase "$phase" \
    fixture_database_psql "$database_name" \
      --command 'ALTER SCHEMA public OWNER TO CURRENT_USER;' \
    || return 1
  template_public_schema_is_migration_owned "$database_name"
}

create_migration_template() {
  local database_name="$1" domain="$2" database_url
  private_database_name_is_valid "$database_name" || return 1
  if [[ -z "$binary" || ! -x "$binary" ]]; then
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=template-preflight
    record_parent_diagnostic "phase=template-preflight status=validated_binary_missing"
    echo "listener stress refuses to create a template before validating its current binary" >&2
    return 1
  fi
  [[ "$domain" == localhost || "$domain" == remote.localhost ]] || {
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=template-preflight
    record_parent_diagnostic "phase=template-preflight status=unexpected_domain"
    echo "listener stress refused an unexpected template domain: $domain" >&2
    return 1
  }
  if ! database_exists "$database_name"; then
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="template-preflight-$database_name"
    record_parent_diagnostic "phase=template-preflight-$database_name status=existence_query_failed"
    echo "listener stress could not determine whether a template database name is occupied: $database_name" >&2
    return 1
  fi
  [[ "$database_exists_result" == false ]] || {
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="template-preflight-$database_name"
    record_parent_diagnostic "phase=template-preflight-$database_name status=name_occupied"
    echo "listener stress template name was unexpectedly occupied: $database_name" >&2
    return 1
  }
  run_parent_phase "template-create-$database_name" \
    fixture_admin_psql --command "CREATE DATABASE \"$database_name\" OWNER \"$database_fixture_user\";" \
    || return 1
  # Arm cleanup as soon as the private database exists.  A migration failure
  # must not strand an owned template simply because it never reached the
  # worker-provisioning stage.
  template_databases+=("$database_name")
  if ! database_owner_is_fixture_user "$database_name"; then
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="template-create-$database_name"
    record_parent_diagnostic "phase=template-create-$database_name resource=database resource_name=$database_name ownership=unverified state=not_eligible_for_schema_setup"
    echo "listener stress template did not retain fixture database ownership: $database_name" >&2
    return 1
  fi
  establish_template_public_schema_owner "$database_name" || return 1
  database_url="$(template_database_url "$database_name")"
  run_parent_phase "template-migrate-$database_name" \
    env NORTHSTAR_DISABLE_DOTENV=true \
      XMPP_DOMAIN="$domain" \
      MIGRATOR_DATABASE_URL="$database_url" \
      MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true \
      "$binary" migrate \
    || return 1
}

quiesce_migration_template() {
  local database_name="$1"
  private_database_name_is_valid "$database_name" || return 1
  # Clones must be made from a quiescent seed.  Disabling normal connections
  # also prevents a worker from being accidentally pointed at the template.
  run_parent_phase "template-quiesce-$database_name" \
    fixture_admin_psql --command "ALTER DATABASE \"$database_name\" WITH ALLOW_CONNECTIONS false;" \
    || return 1
  if ! database_owner_is_fixture_user "$database_name"; then
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase="template-verify-$database_name"
    record_parent_diagnostic "phase=template-verify-$database_name resource=database resource_name=$database_name ownership=unverified state=not_eligible_for_cleanup"
    return 1
  fi
}

provision_pair_databases() {
  local round="$1" pair="$2" key database_a database_b
  key="${round}:${pair}"
  database_a="${database_prefix}_r${round}_p${pair}_a"
  database_b="${database_prefix}_r${round}_p${pair}_b"
  private_database_name_is_valid "$database_a" && private_database_name_is_valid "$database_b" || {
    echo "listener stress generated an invalid private database name" >&2
    return 1
  }
  if ! create_private_database_from_template "$database_a" "$template_database_a"; then
    return 1
  fi
  round_databases+=("$database_a")
  if ! create_private_database_from_template "$database_b" "$template_database_b"; then
    # Keep A recorded for the caller's normal owned-name cleanup path.  That
    # path verifies ownership before it uses the targeted FORCE backstop.
    return 1
  fi
  round_databases+=("$database_b")
  pair_database_a["$key"]="$database_a"
  pair_database_b["$key"]="$database_b"
}

drop_round_databases() {
  local database_name failed=0
  local -a remaining=()
  for database_name in "${round_databases[@]}"; do
    if ! drop_private_database "$database_name"; then
      remaining+=("$database_name")
      failed=1
    fi
  done
  round_databases=("${remaining[@]}")
  if (( failed == 0 )); then
    pair_database_a=()
    pair_database_b=()
  fi
  return "$failed"
}

drop_template_databases() {
  local database_name failed=0
  local -a remaining=()
  for database_name in "${template_databases[@]}"; do
    if ! drop_private_database "$database_name"; then
      remaining+=("$database_name")
      failed=1
    fi
  done
  template_databases=("${remaining[@]}")
  return "$failed"
}

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
  local round="$1" pair="$2" log_file="$3" database_a="$4" database_b="$5" control_file worker_pid worker_group candidate_pgid candidate_sid
  local -a fixture_environment=(
    "NORTHSTAR_RUNTIME_TEST_PROFILE=$fixture_cargo_profile"
    "NORTHSTAR_LISTENER_STRESS_PHASE_DIR=$startup_phase_dir"
    "NORTHSTAR_LISTENER_STRESS_PHASE_NONCE=$startup_phase_nonce"
    "NORTHSTAR_LISTENER_STRESS_PHASE_ROUND=$round"
    "NORTHSTAR_LISTENER_STRESS_PHASE_PAIR=$pair"
    "NORTHSTAR_MIX_FEDERATION_LOGIN_SLOT_DIR=$mix_login_slot_dir"
    "NORTHSTAR_MIX_FEDERATION_LOGIN_SLOT_COUNT=$login_slot_count"
  )
  private_database_name_is_valid "$database_a" && private_database_name_is_valid "$database_b" || {
    echo "listener stress worker received an invalid private database name" >&2
    return 1
  }
  if [[ "$fixture" == mix-federation ]]; then
    [[ -n "$mix_phase_dir" && "$mix_phase_run_nonce" =~ ^[0-9a-f]{64}$ \
       && "$mix_phase_round" == "$round" ]] || {
      echo "listener stress MIX worker was started without its parent phase barrier" >&2
      return 1
    }
    fixture_environment+=(
      "NORTHSTAR_MIX_FEDERATION_PHASE_CONTROL_DIR=$mix_phase_dir"
      "NORTHSTAR_MIX_FEDERATION_PHASE_RUN_NONCE=$mix_phase_run_nonce"
      "NORTHSTAR_MIX_FEDERATION_PHASE_ROUND=$mix_phase_round"
      "NORTHSTAR_MIX_FEDERATION_PHASE_PAIR=$pair"
    )
  fi
  control_file="$runtime_dir/${fixture}.round-${round}.pair-${pair}.session"
  rm -f -- "$control_file"
  setsid bash "$project_dir/scripts/lib/test-listener-stress-worker.sh" "$control_file" \
    env \
      "$skip_variable=true" \
      "NORTHSTAR_LISTENER_STRESS_DATABASE_A=$database_a" \
      "NORTHSTAR_LISTENER_STRESS_DATABASE_B=$database_b" \
      "NORTHSTAR_LISTENER_STRESS_DATABASE_HOST=$database_fixture_host" \
      "NORTHSTAR_LISTENER_STRESS_DATABASE_PORT=$database_fixture_port" \
      "DATABASE_MAX_CONNECTIONS=$database_max_connections" \
      "DATABASE_MIN_CONNECTIONS=$database_min_connections" \
      "TOKIO_WORKER_THREADS=$tokio_worker_threads" \
      "NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS=$worker_timeout_seconds" \
      "${fixture_environment[@]}" \
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
  # Do this before any potentially slow database cleanup.  A migration or
  # preflight failure must leave redacted evidence even if its later cleanup
  # cannot make progress; the artifact is refreshed below once cleanup returns.
  if ((status != 0)); then
    if ! retain_parent_diagnostic_artifact "$status"; then
      echo "listener stress failed to retain its initial sanitized parent diagnostic artifact" >&2
      status=1
    fi
  fi
  signal_worker_groups TERM
  if ! wait_for_workers_to_stop; then
    signal_worker_groups KILL
    if ! wait_for_workers_to_stop; then
      echo "listener stress cleanup left a private worker group alive after scoped KILL" >&2
      status=1
    fi
  fi
  reap_workers
  if ! drop_round_databases; then
    echo "listener stress cleanup could not remove every private worker database" >&2
    status=1
  fi
  if ! drop_template_databases; then
    echo "listener stress cleanup could not remove every private migration template" >&2
    status=1
  fi
  if ((status != 0)); then
    append_runtime_log_tails
    if ! retain_parent_diagnostic_artifact "$status"; then
      echo "listener stress failed to retain its sanitized parent diagnostic artifact" >&2
      status=1
    fi
  fi
  case "$runtime_dir" in
    /tmp/northstar-listener-stress.*)
      if ! rm -rf -- "$runtime_dir"; then
        echo "listener stress could not remove its owned runtime directory: $runtime_dir" >&2
        record_parent_diagnostic "phase=cleanup resource=runtime_directory resource_name=$runtime_dir state=remove_failed"
        if [[ -n "$parent_diagnostic_artifact" ]]; then
          printf '%s\n' 'cleanup_runtime_directory=remove_failed' >>"$parent_diagnostic_artifact" || true
        elif ! retain_parent_diagnostic_artifact 1; then
          echo "listener stress could not retain cleanup-failure evidence" >&2
        fi
        status=1
      fi
      ;;
    *) echo "refusing to remove unexpected stress directory: $runtime_dir" >&2; status=1 ;;
  esac
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! command -v setsid >/dev/null; then
  parent_failure_phase=preflight-setsid
  record_parent_diagnostic "phase=preflight-setsid status=missing_command"
  echo "listener stress requires setsid for private worker groups" >&2
  exit 2
fi
if ! command -v ps >/dev/null; then
  parent_failure_phase=preflight-ps
  record_parent_diagnostic "phase=preflight-ps status=missing_command"
  echo "listener stress requires ps for private worker verification" >&2
  exit 2
fi

resolve_current_build_binary() {
  local configured_target_dir candidate resolved_target_dir resolved_binary
  local -a cargo_args
  configured_target_dir="${CARGO_TARGET_DIR:-$project_dir/target}"
  if [[ "$configured_target_dir" != /* ]]; then
    configured_target_dir="$project_dir/$configured_target_dir"
  fi

  # Compile exactly once and resolve the binary immediately afterwards.  Cargo
  # fingerprints make a successful build authoritative even when the file was
  # already up to date; there is no fallback to an unrelated/default target
  # directory or a previously discovered executable.
  run_parent_phase preflight-profile python3 "$project_dir/scripts/check-runtime-test-profile.py" \
    --manifest "$project_dir/Cargo.toml" --check-environment || return 1
  cargo_args=(--locked --profile "$fixture_cargo_profile" --message-format=json-render-diagnostics)
  [[ "${XMPP_TEST_OFFLINE:-true}" == false ]] || cargo_args+=(--offline)
  run_parent_phase preflight-build cargo build "${cargo_args[@]}" --bin rust-xmpp-server || return 1

  candidate="$configured_target_dir/$fixture_cargo_profile_directory/rust-xmpp-server"
  if [[ ! -f "$candidate" || ! -x "$candidate" ]]; then
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=preflight-binary
    record_parent_diagnostic "phase=preflight-binary status=missing_or_not_executable"
    echo "listener stress current build did not produce an executable: $candidate" >&2
    return 1
  fi
  if ! resolved_target_dir="$(readlink -f -- "$configured_target_dir")" \
    || ! resolved_binary="$(readlink -f -- "$candidate")"; then
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=preflight-binary
    record_parent_diagnostic "phase=preflight-binary status=path_resolution_failed"
    echo "listener stress could not resolve its current build output" >&2
    return 1
  fi
  if [[ "$resolved_binary" != "$resolved_target_dir/$fixture_cargo_profile_directory/rust-xmpp-server" ]]; then
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=preflight-binary
    record_parent_diagnostic "phase=preflight-binary status=resolved_outside_expected_target"
    echo "listener stress refused a binary resolved outside CARGO_TARGET_DIR" >&2
    return 1
  fi
  run_parent_phase preflight-build-profile python3 "$project_dir/scripts/check-runtime-test-profile.py" \
    --build-log "$runtime_dir/parent-preflight-build.raw.log" \
    --binary "$resolved_binary" --source "$project_dir/src/main.rs" || return 1
  binary="$resolved_binary"
  record_parent_diagnostic "phase=preflight-binary status=validated profile=$fixture_cargo_profile opt_level=2 debug_assertions=true overflow_checks=true target_directory=$resolved_target_dir"
}

load_runtime_connection_budget() {
  # The binary emits these facts directly from src/config.rs.  Parsing the
  # small, versioned document here makes an auxiliary-pool change fail the
  # fixture capacity gate rather than silently undercounting PostgreSQL use.
  local manifest parsed schema_version primary_min primary_max auxiliary
  manifest="$("$binary" --runtime-connection-budget 2>>"$parent_diagnostic_raw")" || {
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=preflight-runtime-budget
    record_parent_diagnostic "phase=preflight-runtime-budget status=binary_command_failed"
    echo "listener stress could not read the runtime connection budget" >&2
    return 1
  }
  parsed="$(printf '%s' "$manifest" | python3 -c '
import json
import sys

document = json.load(sys.stdin)
required = {
    "schema_version",
    "runtime_role_connection_limit",
    "primary_pool_min_connections",
    "primary_pool_max_connections",
    "omemo_recovery_pool_max_connections",
    "sm_authority_listener_max_connections",
    "service_control_pool_max_connections",
    "auxiliary_connections",
}
if set(document) != required or document["schema_version"] != 1:
    raise SystemExit("unsupported runtime connection budget manifest")
numbers = {key: document[key] for key in required if key != "schema_version"}
if any(type(value) is not int or value < 0 for value in numbers.values()):
    raise SystemExit("runtime connection budget contains an invalid value")
if document["primary_pool_min_connections"] < 1 or document["primary_pool_max_connections"] < document["primary_pool_min_connections"]:
    raise SystemExit("runtime connection budget primary range is invalid")
if document["auxiliary_connections"] != (
    document["omemo_recovery_pool_max_connections"]
    + document["sm_authority_listener_max_connections"]
    + document["service_control_pool_max_connections"]
):
    raise SystemExit("runtime connection budget auxiliary total is inconsistent")
print("|".join(str(document[key]) for key in (
    "schema_version",
    "primary_pool_min_connections",
    "primary_pool_max_connections",
    "auxiliary_connections",
)))
' 2>>"$parent_diagnostic_raw")" || {
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=preflight-runtime-budget
    record_parent_diagnostic "phase=preflight-runtime-budget status=manifest_invalid"
    echo "listener stress rejected an invalid runtime connection budget manifest" >&2
    return 1
  }
  IFS='|' read -r schema_version primary_min primary_max auxiliary <<<"$parsed"
  [[ "$schema_version" == 1 && "$primary_min" =~ ^[1-9][0-9]*$ \
     && "$primary_max" =~ ^[1-9][0-9]*$ && "$auxiliary" =~ ^[0-9]+$ ]] || {
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=preflight-runtime-budget
    record_parent_diagnostic "phase=preflight-runtime-budget status=manifest_decode_failed"
    echo "listener stress could not decode the runtime connection budget manifest" >&2
    return 1
  }
  runtime_primary_min_connections=$((10#$primary_min))
  runtime_primary_max_connections=$((10#$primary_max))
  runtime_auxiliary_connections=$((10#$auxiliary))
  ((runtime_primary_min_connections == listener_stress_primary_pool_min \
     && runtime_primary_max_connections == listener_stress_primary_pool_max)) || {
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=preflight-runtime-budget
    record_parent_diagnostic "phase=preflight-runtime-budget status=entry_contract_diverged manifest_min=$runtime_primary_min_connections manifest_max=$runtime_primary_max_connections"
    echo "listener stress rejected a runtime connection budget that diverges from its 2 through 60 entry contract" >&2
    return 1
  }
  ((database_max_connections >= runtime_primary_min_connections \
     && database_max_connections <= runtime_primary_max_connections \
     && database_min_connections <= database_max_connections)) || {
    echo "NORTHSTAR_LISTENER_STRESS_DATABASE_MAX_CONNECTIONS must be ${runtime_primary_min_connections} through ${runtime_primary_max_connections}, and DATABASE_MIN_CONNECTIONS must not exceed it" >&2
    return 1
  }
  case "$fixture" in
    federation) fixture_control_connections_per_pair=0 ;;
    # The MIX fixture's durable-outbox assertion opens one short-lived direct
    # psql connection per pair while both service processes remain live.
    mix-federation) fixture_control_connections_per_pair=1 ;;
    *)
      echo "listener stress has no connection budget declaration for fixture: $fixture" >&2
      return 1
      ;;
  esac
  runtime_connections_per_child=$((database_max_connections + runtime_auxiliary_connections))
  fixture_control_connections=$((pairs * fixture_control_connections_per_pair))
  required_fixture_connections=$((stress_child_count * runtime_connections_per_child + fixture_control_connections))
  record_parent_diagnostic "phase=preflight-runtime-budget status=validated schema_version=$schema_version primary_min=$runtime_primary_min_connections primary_max=$runtime_primary_max_connections auxiliary=$runtime_auxiliary_connections fixture_control_per_pair=$fixture_control_connections_per_pair required=$required_fixture_connections"
}

# This is deliberately before database attestation, template creation, and any
# worker provisioning.  A missing or wrong build artifact is a build failure,
# never a database or listener failure.
resolve_current_build_binary
load_runtime_connection_budget
assert_private_database_fixture
assert_fixture_connection_capacity
record_parent_diagnostic "phase=preflight-resource-profile status=selected profile=$resource_profile effective_cpu_count=$effective_cpu_count tokio_worker_threads=$tokio_worker_threads login_slot_count=$login_slot_count fixture_max_connections=$fixture_actual_max_connections startup_pair_limit=$startup_pair_limit"
echo "listener stress profile: resource_profile=$resource_profile worker_timeout_seconds=$worker_timeout_seconds database_max_connections=$database_max_connections database_min_connections=$database_min_connections runtime_auxiliary_connections=$runtime_auxiliary_connections runtime_connections_per_child=$runtime_connections_per_child stress_child_count=$stress_child_count fixture_control_connections_per_pair=$fixture_control_connections_per_pair fixture_control_connections=$fixture_control_connections required_fixture_connections=$required_fixture_connections fixture_max_connections=$fixture_actual_max_connections effective_cpu_count=$effective_cpu_count scheduler_reserved_cpus=$scheduler_reserved_cpus tokio_worker_threads=$tokio_worker_threads login_slot_count=$login_slot_count startup_pair_limit=$startup_pair_limit"
if ! initialize_mix_federation_login_slots; then
  [[ -n "$parent_failure_phase" ]] || parent_failure_phase=mix-federation-login-slots
  record_parent_diagnostic "phase=mix-federation-login-slots status=failed"
  echo "listener stress could not initialize private MIX authentication slots" >&2
  exit 1
fi
create_migration_template "$template_database_a" localhost
create_migration_template "$template_database_b" remote.localhost
quiesce_migration_template "$template_database_a"
quiesce_migration_template "$template_database_b"
echo "listener stress database templates ready: fixture=$fixture"

failed=0
for ((round = 1; round <= rounds; round++)); do
  workers=()
  worker_groups=()
  round_logs=()
  round_databases=()
  pair_database_a=()
  pair_database_b=()
  failed_pair_databases=()
  for ((pair = 1; pair <= pairs; pair++)); do
    if ! provision_pair_databases "$round" "$pair"; then
      echo "listener stress could not provision private databases: fixture=$fixture round=$round pair=$pair" >&2
      failed=1
      break
    fi
  done
  if ((failed != 0)); then
    drop_round_databases || true
    exit 1
  fi
  if ! initialize_mix_federation_phase_barrier "$round"; then
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=mix-federation-setup-barrier
    record_parent_diagnostic "phase=mix-federation-setup-barrier round=$round status=initialization_failed"
    echo "listener stress could not initialize its parent-owned MIX setup barrier: round=$round" >&2
    exit 1
  fi
  startup_phase_dir="$runtime_dir/startup-phase-r$round"
  startup_phase_nonce="$(openssl rand -hex 32)"
  run_parent_phase "fixture-preparation-init-r$round" \
    python3 "$project_dir/scripts/listener-stress-phases.py" init \
    "$startup_phase_dir" "$startup_phase_nonce" "$round" "$pairs" "$$" "$startup_pair_limit"
  for ((pair = 1; pair <= pairs; pair++)); do
    log="$runtime_dir/${fixture}.round-${round}.pair-${pair}.log"
    round_logs+=("$log")
    key="${round}:${pair}"
    if ! start_stress_worker "$round" "$pair" "$log" "${pair_database_a[$key]}" "${pair_database_b[$key]}"; then
      echo "listener stress worker could not establish private session ownership: fixture=$fixture round=$round pair=$pair" >&2
      failed_pair_databases["${pair_database_a[$key]}"]=1
      failed_pair_databases["${pair_database_b[$key]}"]=1
      failed=1
      break
    fi
  done
  # A failed worker launch must not leave successfully launched MIX workers
  # waiting forever for a release that the parent can no longer safely issue.
  # Exit through the scoped parent cleanup instead of falling into `wait`.
  if ((failed != 0)); then
    exit 1
  fi
  # Prepare every pair first, then admit CPU-bounded batches of cold starts.
  # Each pair keeps its startup slot through both A and B nonce/HTTP readiness.
  # Earlier live children remain supervised while later batches start; only
  # the all-pair live barrier below permits transport or business work.
  run_parent_phase "fixture-preparation-release-r$round" \
    python3 "$project_dir/scripts/listener-stress-phases.py" release \
    "$startup_phase_dir" "$startup_phase_nonce" "$round" prepared \
    "$worker_timeout_seconds" "${workers[@]}"
  record_parent_diagnostic "phase=fixture-preparation round=$round status=released pairs=$pairs"
  run_parent_phase "all-pair-live-release-r$round" \
    python3 "$project_dir/scripts/listener-stress-phases.py" release \
    "$startup_phase_dir" "$startup_phase_nonce" "$round" live \
    "$worker_timeout_seconds" "${workers[@]}"
  record_parent_diagnostic "phase=all-pair-live-barrier fixture=$fixture round=$round status=released pairs=$pairs children=$stress_child_count startup_pair_limit=$startup_pair_limit"
  if [[ "$fixture" == federation ]]; then
    run_parent_phase "federation-transport-release-r$round" \
      python3 "$project_dir/scripts/listener-stress-phases.py" release \
      "$startup_phase_dir" "$startup_phase_nonce" "$round" transport \
      "$worker_timeout_seconds" "${workers[@]}"
    record_parent_diagnostic "phase=federation-transport-barrier round=$round status=released pairs=$pairs"
  fi
  if ! await_mix_federation_setup_barrier "${#workers[@]}"; then
    [[ -n "$parent_failure_phase" ]] || parent_failure_phase=mix-federation-setup-barrier
    failed=1
    exit 1
  fi
  for ((pair = 1; pair <= ${#workers[@]}; pair++)); do
    if ! wait "${workers[$((pair - 1))]}"; then
      echo "listener stress worker failed: fixture=$fixture round=$round pair=$pair" >&2
      [[ -n "$parent_failure_phase" ]] || parent_failure_phase=worker-exit
      record_parent_diagnostic "phase=worker-exit fixture=$fixture round=$round pair=$pair status=nonzero log=$(basename "${round_logs[$((pair - 1))]}")"
      key="${round}:${pair}"
      failed_pair_databases["${pair_database_a[$key]}"]=1
      failed_pair_databases["${pair_database_b[$key]}"]=1
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
  if ((${#workers[@]} > 0)); then
    # This is intentionally after all direct children have exited and every
    # private worker group has quiesced.  Checking only a port during a child
    # cleanup races other pairs; this compares the original owner socket inode
    # against the post-quiescence listener table.
    if ! verify_mix_federation_listener_ledger "${#workers[@]}"; then
      echo "listener stress detected an owned MIX listener after parent quiescence: fixture=$fixture round=$round" >&2
      failed=1
    fi
  fi
  if ((failed != 0)); then
    append_mix_federation_database_snapshots
  fi
  if ! drop_round_databases; then
    echo "listener stress could not remove every private worker database: fixture=$fixture round=$round" >&2
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
