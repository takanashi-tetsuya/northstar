#!/usr/bin/env bash
# Regression coverage for the CI process-group supervisor. Each fixture owns
# only PIDs it records, so cleanup never uses global process matching.
set -Eeuo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
supervisor="$project_dir/scripts/github_ci_supervisor.py"
wrapper="$project_dir/scripts/github-ci-run.sh"
runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/northstar-ci-supervisor.XXXXXXXX")"
tracked_pids=()
declare -A tracked_pid_starts=()

process_start_time() {
  local child_pid="$1" stat_suffix
  [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ -r "/proc/$child_pid/stat" ]] || return 1
  stat_suffix="$(<"/proc/$child_pid/stat")"
  # `comm` is parenthesized and can itself contain spaces or `)`, so retain
  # only the suffix after its final delimiter. Start time is proc(5) field 22,
  # or index 20 after dropping pid/comm.
  stat_suffix="${stat_suffix##*) }"
  set -- $stat_suffix
  [[ "${20:-}" =~ ^[0-9]+$ ]] || return 1
  printf '%s' "${20}"
}

track_pid() {
  local child_pid="$1" start_time
  start_time="$(process_start_time "$child_pid")" \
    || fail "could not record a stable identity for PID $child_pid"
  track_pid_identity "$child_pid" "$start_time"
}

track_pid_identity() {
  local child_pid="$1" start_time="$2"
  [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] \
    || fail "cannot track an invalid PID: $child_pid"
  [[ "$start_time" =~ ^[0-9]+$ ]] \
    || fail "cannot track an invalid PID start time: $start_time"
  tracked_pids+=("$child_pid")
  tracked_pid_starts["$child_pid"]="$start_time"
}

record_process_identity() {
  local child_pid="$1" destination="$2" start_time
  start_time="$(process_start_time "$child_pid")" || return 1
  printf '%s %s\n' "$child_pid" "$start_time" >"$destination"
}

read_recorded_identity() {
  local source_file="$1" label="$2"
  read -r recorded_pid recorded_start <"$source_file" \
    || fail "$label did not write a process identity"
  [[ "$recorded_pid" =~ ^[1-9][0-9]*$ && "$recorded_start" =~ ^[0-9]+$ ]] \
    || fail "$label wrote an invalid process identity"
}

export -f process_start_time record_process_identity

untrack_pid() {
  local child_pid="$1" retained=() tracked
  unset 'tracked_pid_starts[$child_pid]'
  for tracked in "${tracked_pids[@]:-}"; do
    [[ "$tracked" == "$child_pid" ]] || retained+=("$tracked")
  done
  tracked_pids=("${retained[@]}")
}

pid_matches_recorded_identity() {
  local child_pid="$1" expected_start="$2" actual_start
  actual_start="$(process_start_time "$child_pid")" || return 1
  [[ "$actual_start" == "$expected_start" ]]
}

kill_if_recorded_identity() {
  local child_pid="$1" expected_start="$2"
  pid_matches_recorded_identity "$child_pid" "$expected_start" || return 1
  kill -KILL "$child_pid" 2>/dev/null || true
  return 0
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  local child_pid child_state expected_start
  for child_pid in "${tracked_pids[@]:-}"; do
    # An empty array expansion under `set -u` produces one empty iteration in
    # some Bash versions.  Never use that as an associative-array key during
    # failure cleanup; the original fixture error must remain observable.
    [[ -n "$child_pid" ]] || continue
    expected_start="${tracked_pid_starts[$child_pid]:-}"
    if [[ -n "$expected_start" ]] \
      && pid_matches_recorded_identity "$child_pid" "$expected_start"; then
      child_state="$(ps -o stat= -p "$child_pid" 2>/dev/null | tr -d '[:space:]')"
      if [[ "$child_state" != Z* ]]; then
        kill_if_recorded_identity "$child_pid" "$expected_start" || true
        status=1
      fi
    fi
  done
  rm -rf -- "$runtime_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  printf 'GitHub CI supervisor self-test failed: %s\n' "$1" >&2
  exit 1
}

assert_pid_gone_or_zombie() {
  local child_pid="$1" label="$2" child_state expected_start
  [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] || fail "$label recorded an invalid child PID: $child_pid"
  expected_start="${tracked_pid_starts[$child_pid]:-}"
  [[ -n "$expected_start" ]] || fail "$label has no recorded PID identity: $child_pid"
  if [[ -n "$expected_start" ]] \
    && ! pid_matches_recorded_identity "$child_pid" "$expected_start"; then
    # The original process is already gone; a reused numeric PID is never a
    # reason to signal or fail against an unrelated runner process.
    untrack_pid "$child_pid"
    return 0
  fi
  if kill -0 "$child_pid" 2>/dev/null; then
    child_state="$(ps -o stat= -p "$child_pid" 2>/dev/null | tr -d '[:space:]')"
    [[ "$child_state" == Z* ]] || fail "$label left a descendant alive: $child_pid state=$child_state"
  fi
  untrack_pid "$child_pid"
}

assert_pid_live() {
  local child_pid="$1" label="$2" child_state expected_start
  [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] || fail "$label recorded an invalid child PID: $child_pid"
  expected_start="${tracked_pid_starts[$child_pid]:-}"
  [[ -n "$expected_start" ]] || fail "$label has no recorded PID identity: $child_pid"
  pid_matches_recorded_identity "$child_pid" "$expected_start" \
    || fail "$label process exited or its PID was reused before the asserted observation: $child_pid"
  child_state="$(ps -o stat= -p "$child_pid" 2>/dev/null | tr -d '[:space:]')"
  [[ "$child_state" != Z* && -n "$child_state" ]] \
    || fail "$label process was not live: $child_pid state=${child_state:-missing}"
}

kill_recorded_pid() {
  local child_pid="$1" label="$2" attempt expected_start
  expected_start="${tracked_pid_starts[$child_pid]:-}"
  [[ -n "$expected_start" ]] || fail "$label has no recorded PID identity: $child_pid"
  kill_if_recorded_identity "$child_pid" "$expected_start" || {
    untrack_pid "$child_pid"
    return 0
  }
  for ((attempt = 0; attempt < 100; attempt += 1)); do
    if ! pid_matches_recorded_identity "$child_pid" "$expected_start"; then
      untrack_pid "$child_pid"
      return 0
    fi
    if [[ "$(ps -o stat= -p "$child_pid" 2>/dev/null | tr -d '[:space:]')" == Z* ]]; then
      return 0
    fi
    sleep 0.05
  done
  fail "$label recorded descendant did not stop after exact-PID cleanup: $child_pid"
}

wait_for_file() {
  local path="$1" label="$2"
  local attempt
  for ((attempt = 0; attempt < 100; attempt += 1)); do
    [[ -s "$path" ]] && return 0
    sleep 0.05
  done
  fail "$label did not create $path"
}

run_supervisor() {
  local expected_status="$1" label="$2" timeout_seconds="$3" kill_after_seconds="$4"
  shift 4
  local output_file="$runtime_dir/$label.stdout"
  local error_file="$runtime_dir/$label.stderr"
  local log_file="$runtime_dir/$label.log"
  local status
  set +e
  python3 "$supervisor" \
    --timeout-seconds "$timeout_seconds" \
    --kill-after-seconds "$kill_after_seconds" \
    --require-linux-subreaper \
    --log-file "$log_file" \
    -- "$@" >"$output_file" 2>"$error_file"
  status=$?
  set -e
  [[ "$status" == "$expected_status" ]] \
    || fail "$label returned $status, expected $expected_status"
}

# PID numbers are reusable. A stale test-harness entry must never signal the
# currently running shell merely because it inherited the same numeric PID.
self_start_time="$(process_start_time "$$")" \
  || fail 'could not read the test shell process identity'
if kill_if_recorded_identity "$$" "$((self_start_time + 1))"; then
  fail 'PID identity guard accepted a deliberately mismatched start time'
fi
kill -0 "$$" 2>/dev/null || fail 'PID identity guard signaled the test shell'

# Force a cancellation in the narrow interval after Popen has returned a real
# child but before main() assigns that result to its lifecycle variable. The
# preinstalled handler must queue it, then the normal loop must reap the newly
# created private group instead of leaving it behind.
python3 - "$supervisor" <<'PY'
import importlib.util
import os
import signal
import sys
import tempfile
import time
from pathlib import Path

supervisor_path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("northstar_ci_supervisor_startup_test", supervisor_path)
if spec is None or spec.loader is None:
    raise SystemExit("could not load CI supervisor for startup-cancellation regression")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

real_popen = module.subprocess.Popen
created = {}

def cancel_after_spawn(*args, **kwargs):
    child = real_popen(*args, **kwargs)
    created["child"] = child
    os.kill(os.getpid(), signal.SIGTERM)
    return child

module.subprocess.Popen = cancel_after_spawn
with tempfile.TemporaryDirectory() as temporary:
    log_file = Path(temporary) / "startup.log"
    original_argv = sys.argv
    sys.argv = [
        str(supervisor_path),
        "--timeout-seconds", "10",
        "--kill-after-seconds", "1",
        "--require-linux-subreaper",
        "--log-file", str(log_file),
        "--", "bash", "-c", "sleep 30",
    ]
    started = time.monotonic()
    try:
        status = module.main()
    finally:
        sys.argv = original_argv
    child = created.get("child")
    if child is not None and child.poll() is None:
        # This is a test-only failure guard for the exact private PGID created
        # by the injected Popen. It never matches processes by name or scans
        # outside that known group.
        try:
            if os.getpgid(child.pid) == child.pid:
                os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=2)
    if status != 143:
        raise SystemExit(f"startup cancellation returned {status}, expected 143")
    if time.monotonic() - started >= 5:
        raise SystemExit("startup cancellation did not complete within its bounded cleanup window")
    if child is None or child.poll() is None:
        raise SystemExit("startup cancellation left its directly created child unreaped")
PY

# Strict Linux containment must never fall back to a numeric ``killpg`` when
# procfs identity visibility disappears. It may terminate the still-Popen-owned
# direct child, but returns a lifecycle failure because descendants cannot be
# proven. A separate short-command case models the harmless fast-root race:
# absence of the original PID from an otherwise readable snapshot is not itself
# a failure when no live group/adopted descendant is present.
python3 - "$supervisor" <<'PY'
import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
from pathlib import Path

supervisor_path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("northstar_ci_supervisor_visibility_test", supervisor_path)
if spec is None or spec.loader is None:
    raise SystemExit("could not load CI supervisor for visibility regression")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

real_popen = module.subprocess.Popen
real_killpg = module.os.killpg
real_process_table = module.linux_process_table
real_enable_subreaper = module.enable_linux_child_subreaper
original_argv = sys.argv
created = {}

def record_popen(*args, **kwargs):
    child = real_popen(*args, **kwargs)
    created["child"] = child
    return child

try:
    module.enable_linux_child_subreaper = lambda: True
    module.subprocess.Popen = record_popen

    def reject_blind_group_signal(*_args, **_kwargs):
        raise AssertionError("strict visibility loss attempted blind killpg")

    module.os.killpg = reject_blind_group_signal
    module.linux_process_table = lambda: None
    with tempfile.TemporaryDirectory() as temporary:
        stderr = io.StringIO()
        sys.argv = [
            str(supervisor_path),
            "--timeout-seconds", "1",
            "--kill-after-seconds", "1",
            "--require-linux-subreaper",
            "--log-file", str(Path(temporary) / "visibility-lost.log"),
            "--", "bash", "-c", "sleep 30",
        ]
        with contextlib.redirect_stderr(stderr):
            status = module.main()
        child = created.get("child")
        if status != 1:
            raise SystemExit(f"strict visibility loss returned {status}, expected 1")
        if child is None or child.poll() is None:
            raise SystemExit("strict visibility loss left the Popen-owned direct child alive")
        if "phase=command_group_identity_visibility_unavailable" not in stderr.getvalue():
            raise SystemExit("strict visibility loss emitted no deterministic lifecycle phase")

    # The previous implementation required observing the original root PID
    # immediately after Popen. A quick command is allowed to vanish before that
    # observation; a readable empty snapshot proves no surviving group or
    # adopted descendant and must therefore remain a normal success.
    created.clear()
    module.linux_process_table = lambda: {}
    with tempfile.TemporaryDirectory() as temporary:
        sys.argv = [
            str(supervisor_path),
            "--timeout-seconds", "5",
            "--kill-after-seconds", "1",
            "--require-linux-subreaper",
            "--log-file", str(Path(temporary) / "fast-root.log"),
            "--", "bash", "-c", "exit 0",
        ]
        with contextlib.redirect_stderr(io.StringIO()):
            status = module.main()
        child = created.get("child")
        if status != 0:
            raise SystemExit(f"fast root exit returned {status}, expected 0")
        if child is None or child.poll() is None:
            raise SystemExit("fast root exit left its direct child unreaped")
finally:
    child = created.get("child")
    if child is not None and child.poll() is None:
        child.kill()
        child.wait(timeout=2)
    module.subprocess.Popen = real_popen
    module.os.killpg = real_killpg
    module.linux_process_table = real_process_table
    module.enable_linux_child_subreaper = real_enable_subreaper
    sys.argv = original_argv
PY

# The supervisor must not let a stopped downstream console reader strand the
# output copier. This uses an isolated pipe filled to capacity as the helper's
# stdout: the helper receives the framed marker but blocks before its ACK. The
# primary fixture, helper, and private transcript must all reach a bounded,
# observable terminal state without changing this test process's stdout flags.
python3 - "$supervisor" <<'PY'
import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

supervisor_path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("northstar_ci_supervisor_console_test", supervisor_path)
if spec is None or spec.loader is None:
    raise SystemExit("could not load CI supervisor for console-forwarding regression")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

real_popen = module.subprocess.Popen
real_spawn_forwarder = module.spawn_console_forwarder
original_argv = sys.argv
created = {}
blocked_read_fd = -1

def record_fixture_popen(*args, **kwargs):
    child = real_popen(*args, **kwargs)
    created["fixture"] = child
    return child

def spawn_blocked_console_forwarder():
    global blocked_read_fd
    input_read_fd, input_write_fd = os.pipe()
    acknowledgement_read_fd, acknowledgement_write_fd = os.pipe()
    blocked_read_fd, blocked_write_fd = os.pipe()
    os.set_blocking(input_write_fd, False)
    os.set_blocking(acknowledgement_read_fd, False)
    os.set_blocking(blocked_write_fd, False)
    try:
        while True:
            os.write(blocked_write_fd, b"x" * 65536)
    except BlockingIOError:
        pass
    os.set_blocking(blocked_write_fd, True)
    helper = real_popen(
        [
            sys.executable,
            str(supervisor_path),
            "--console-forwarder",
            "--input-fd", str(input_read_fd),
            "--acknowledgement-fd", str(acknowledgement_write_fd),
        ],
        stdin=subprocess.DEVNULL,
        stdout=blocked_write_fd,
        stderr=subprocess.DEVNULL,
        pass_fds=(input_read_fd, acknowledgement_write_fd),
        close_fds=True,
    )
    created["helper"] = helper
    os.close(input_read_fd)
    os.close(acknowledgement_write_fd)
    os.close(blocked_write_fd)
    return module.ConsoleForwarder(
        process=helper,
        input_write_fd=input_write_fd,
        acknowledgement_read_fd=acknowledgement_read_fd,
    )

try:
    module.subprocess.Popen = record_fixture_popen
    module.spawn_console_forwarder = spawn_blocked_console_forwarder
    with tempfile.TemporaryDirectory() as temporary:
        log_file = Path(temporary) / "blocked-console.log"
        sys.argv = [
            str(supervisor_path),
            "--timeout-seconds", "10",
            "--kill-after-seconds", "1",
            "--require-linux-subreaper",
            "--log-file", str(log_file),
            "--", "bash", "-c", "printf 'blocked-console-marker\\n'; sleep 30",
        ]
        stderr = io.StringIO()
        started = time.monotonic()
        with contextlib.redirect_stderr(stderr):
            status = module.main()
        elapsed = time.monotonic() - started
        if status != 1:
            raise SystemExit(f"blocked console forwarding returned {status}, expected 1")
        if elapsed >= 8:
            raise SystemExit(f"blocked console forwarding took {elapsed:.2f}s")
        fixture = created.get("fixture")
        helper = created.get("helper")
        if fixture is None or fixture.poll() is None:
            raise SystemExit("blocked console forwarding left the fixture process alive")
        if helper is None or helper.poll() is None:
            raise SystemExit("blocked console forwarding left the writer helper alive")
        diagnostics = stderr.getvalue()
        if "reason=console_delivery_stalled" not in diagnostics:
            raise SystemExit("blocked console forwarding emitted no stalled-delivery phase")
        if "phase=command_console_forwarder_drain_elapsed" not in diagnostics:
            raise SystemExit("blocked console forwarding did not exercise bounded helper cleanup")
        if "blocked-console-marker" not in log_file.read_text(encoding="utf-8"):
            raise SystemExit("blocked console forwarding did not preserve the durable transcript")
finally:
    for key in ("fixture", "helper"):
        child = created.get(key)
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=2)
    if blocked_read_fd >= 0:
        os.close(blocked_read_fd)
    module.subprocess.Popen = real_popen
    module.spawn_console_forwarder = real_spawn_forwarder
    sys.argv = original_argv
PY

# Deadline cleanup must kill ordinary descendants as one private process group.
deadline_child_file="$runtime_dir/deadline-child.pid"
run_supervisor 124 deadline 1 1 \
  bash -c 'sleep 30 & child=$!; record_process_identity "$child" "$1"; wait "$child"' \
  bash "$deadline_child_file"
wait_for_file "$deadline_child_file" deadline
read_recorded_identity "$deadline_child_file" deadline
deadline_child="$recorded_pid"
track_pid_identity "$deadline_child" "$recorded_start"
assert_pid_gone_or_zombie "$deadline_child" deadline
grep -Fq 'phase=command_deadline_reached' "$runtime_dir/deadline.stderr" \
  || fail 'deadline emitted no deadline phase record'

# An ordinary command that owns no residual worker remains successful.
run_supervisor 0 clean-exit 5 1 bash -c 'printf "clean-exit-marker\\n"'
grep -Fq 'clean-exit-marker' "$runtime_dir/clean-exit.stdout" \
  || fail 'clean exit lost command output'

# A child that terminates itself by signal has a negative Popen return code;
# the supervisor must normalize it to the conventional shell status.
run_supervisor 143 self-term 5 1 bash -c 'kill -TERM "$$"'

# The direct shell can exit successfully while a background child remains.
# That is a fixture lifecycle violation: clean it without an unbounded wait,
# but return a failure rather than hiding the escaped worker.
parent_exit_child_file="$runtime_dir/parent-exit-child.pid"
run_supervisor 1 parent-exit 5 1 \
  bash -c 'sleep 30 & child=$!; record_process_identity "$child" "$1"; exit 0' \
  bash "$parent_exit_child_file"
wait_for_file "$parent_exit_child_file" parent-exit
read_recorded_identity "$parent_exit_child_file" parent-exit
parent_exit_child="$recorded_pid"
track_pid_identity "$parent_exit_child" "$recorded_start"
assert_pid_gone_or_zombie "$parent_exit_child" parent-exit
grep -Fq 'phase=command_parent_exited_with_residual_group' "$runtime_dir/parent-exit.stderr" \
  || fail 'parent-exit emitted no residual-group phase record'
grep -Fq 'phase=command_residual_group_cleaned outcome=failed_fixture_lifecycle' "$runtime_dir/parent-exit.stderr" \
  || fail 'parent-exit did not report the lifecycle failure'

# A descendant that ignores TERM must receive SIGKILL after the configured
# grace period. The supervisor still returns the command deadline status.
term_ignoring_child_file="$runtime_dir/term-ignoring-child.pid"
run_supervisor 124 term-ignoring 1 1 \
  bash -c "bash -c 'trap \"\" TERM; while :; do sleep 1; done' & child=\$!; record_process_identity \"\$child\" \"\$1\"; wait \"\$child\"" \
  bash "$term_ignoring_child_file"
wait_for_file "$term_ignoring_child_file" term-ignoring
read_recorded_identity "$term_ignoring_child_file" term-ignoring
term_ignoring_child="$recorded_pid"
track_pid_identity "$term_ignoring_child" "$recorded_start"
assert_pid_gone_or_zombie "$term_ignoring_child" term-ignoring
grep -Fq 'phase=command_grace_elapsed' "$runtime_dir/term-ignoring.stderr" \
  || fail 'TERM-ignoring descendant did not exercise SIGKILL escalation'

# A child that keeps stdout open after the direct parent exits used to leave
# the output copier blocked forever. It must be killed and finalization must
# finish within a small fixed bound.
pipe_holding_child_file="$runtime_dir/pipe-holding-child.pid"
pipe_started="$(date +%s)"
run_supervisor 1 pipe-holding 5 1 \
  bash -c "bash -c 'trap \"\" TERM; while :; do sleep 1; done' & child=\$!; record_process_identity \"\$child\" \"\$1\"; exit 0" \
  bash "$pipe_holding_child_file"
pipe_elapsed=$(( $(date +%s) - pipe_started ))
(( pipe_elapsed < 5 )) || fail "pipe-holding output finalization took $pipe_elapsed seconds"
wait_for_file "$pipe_holding_child_file" pipe-holding
read_recorded_identity "$pipe_holding_child_file" pipe-holding
pipe_holding_child="$recorded_pid"
track_pid_identity "$pipe_holding_child" "$recorded_start"
assert_pid_gone_or_zombie "$pipe_holding_child" pipe-holding

# A deliberately detached session can retain the inherited output FD after
# every member of the original group exits. The Linux child subreaper must
# adopt, identify, and terminate it rather than waiting for a pipe-drain
# timeout or using a name/global cleanup.
external_pipe_child_file="$runtime_dir/external-pipe-child.pid"
external_pipe_ready_file="$runtime_dir/external-pipe-ready"
external_pipe_started=$SECONDS
set +e
python3 "$supervisor" \
  --timeout-seconds 10 --kill-after-seconds 1 --require-linux-subreaper \
  --log-file "$runtime_dir/external-pipe-holder.log" -- \
  bash -c "setsid bash -c 'trap \"\" TERM; record_process_identity \"\$\$\" \"\$1\"; printf ready > \"\$2\"; exec tail -f /dev/null' bash \"\$1\" \"\$2\" & for ((attempt = 0; attempt < 100; attempt += 1)); do [[ -s \"\$2\" ]] && exit 0; sleep 0.01; done; exit 70" \
  bash "$external_pipe_child_file" "$external_pipe_ready_file" \
  >"$runtime_dir/external-pipe-holder.stdout" 2>"$runtime_dir/external-pipe-holder.stderr" &
external_pipe_supervisor_pid=$!
set -e
track_pid "$external_pipe_supervisor_pid"
wait_for_file "$external_pipe_child_file" external-pipe-holder
read_recorded_identity "$external_pipe_child_file" external-pipe-holder
external_pipe_child="$recorded_pid"
track_pid_identity "$external_pipe_child" "$recorded_start"
assert_pid_live "$external_pipe_child" external-pipe-holder
set +e
wait "$external_pipe_supervisor_pid"
external_pipe_status=$?
set -e
external_pipe_elapsed=$((SECONDS - external_pipe_started))
(( external_pipe_elapsed < 9 )) \
  || fail "external pipe-holder containment took $external_pipe_elapsed seconds"
untrack_pid "$external_pipe_supervisor_pid"
grep -Fq 'phase=command_detached_descendants_detected' "$runtime_dir/external-pipe-holder.stderr" \
  || fail 'external pipe holder was not adopted by the subreaper'
assert_pid_gone_or_zombie "$external_pipe_child" external-pipe-holder
[[ "$external_pipe_status" == 1 ]] \
  || fail "external pipe holder returned $external_pipe_status, expected 1"

# Closing inherited output must not hide a detached descendant. This is the
# false-success shape that a process-group-only supervisor cannot observe.
detached_closed_child_file="$runtime_dir/detached-closed-child.pid"
detached_closed_started=$SECONDS
set +e
python3 "$supervisor" \
  --timeout-seconds 10 --kill-after-seconds 1 --require-linux-subreaper \
  --log-file "$runtime_dir/detached-closed.log" -- \
  bash -c "setsid bash -c 'trap \"\" TERM; record_process_identity \"\$\$\" \"\$1\"; exec >/dev/null 2>&1; while :; do sleep 1; done' bash \"\$1\" & for ((attempt = 0; attempt < 100; attempt += 1)); do [[ -s \"\$1\" ]] && exit 0; sleep 0.01; done; exit 70" \
  bash "$detached_closed_child_file" \
  >"$runtime_dir/detached-closed.stdout" 2>"$runtime_dir/detached-closed.stderr"
detached_closed_status=$?
set -e
wait_for_file "$detached_closed_child_file" detached-closed
read_recorded_identity "$detached_closed_child_file" detached-closed
detached_closed_child="$recorded_pid"
track_pid_identity "$detached_closed_child" "$recorded_start"
detached_closed_elapsed=$((SECONDS - detached_closed_started))
(( detached_closed_elapsed < 8 )) \
  || fail "closed-FD detached descendant containment took $detached_closed_elapsed seconds"
grep -Fq 'phase=command_detached_descendants_detected' "$runtime_dir/detached-closed.stderr" \
  || fail 'closed-FD detached descendant was not detected by the subreaper'
grep -Fq 'phase=command_detached_descendant_grace_elapsed' "$runtime_dir/detached-closed.stderr" \
  || fail 'TERM-ignoring closed-FD descendant did not exercise exact SIGKILL escalation'
assert_pid_gone_or_zombie "$detached_closed_child" detached-closed
[[ "$detached_closed_status" == 1 ]] \
  || fail "closed-FD detached descendant returned $detached_closed_status, expected 1"

# A full diagnostic target must fail the supervisor rather than crash a daemon
# copier and accidentally return the command's success status. GitHub's Linux
# runners provide /dev/full; the test is intentionally Linux-specific because
# the supervisor itself is POSIX-only.
[[ -c /dev/full ]] || fail 'supervisor copier regression requires /dev/full'
copy_failure_stdout="$runtime_dir/copy-failure.stdout"
copy_failure_stderr="$runtime_dir/copy-failure.stderr"
set +e
python3 "$supervisor" \
  --timeout-seconds 10 --kill-after-seconds 1 --require-linux-subreaper --log-file /dev/full -- \
  bash -c 'printf "copy-failure-marker\\n"; sleep 30' \
  >"$copy_failure_stdout" 2>"$copy_failure_stderr"
copy_failure_status=$?
set -e
[[ "$copy_failure_status" == 1 ]] \
  || fail "diagnostic copy failure returned $copy_failure_status, expected 1"
grep -Fq 'phase=command_output_copy_failure_detected' "$copy_failure_stderr" \
  || fail 'diagnostic copy failure did not trigger private-group cleanup'
grep -Fq 'phase=command_output_copy_failed reason=log_write action=fail_supervisor' "$copy_failure_stderr" \
  || fail 'diagnostic copy failure was not surfaced as a failed supervisor'

# A noisy fixture must not turn the private runner transcript or the ordinary
# job stream into an unbounded sink. Crossing the explicit cap is a lifecycle
# failure: the supervisor records the cap, terminates only its private group,
# and preserves no more than the requested byte budget.
log_cap_bytes=1024
log_cap_child_file="$runtime_dir/log-cap-child.pid"
log_cap_log="$runtime_dir/log-cap.log"
log_cap_stdout="$runtime_dir/log-cap.stdout"
log_cap_stderr="$runtime_dir/log-cap.stderr"
set +e
python3 "$supervisor" \
  --timeout-seconds 10 --kill-after-seconds 1 --max-log-bytes "$log_cap_bytes" \
  --require-linux-subreaper \
  --log-file "$log_cap_log" -- \
  bash -c 'bash -c '\''trap "" TERM; while :; do sleep 1; done'\'' & child=$!; record_process_identity "$child" "$1"; for ((chunk = 0; chunk < 256; chunk += 1)); do printf "log-cap-output-%04d................................................\\n" "$chunk"; done; wait "$child"' \
  bash "$log_cap_child_file" \
  >"$log_cap_stdout" 2>"$log_cap_stderr"
log_cap_status=$?
set -e
[[ "$log_cap_status" == 1 ]] \
  || fail "diagnostic log cap returned $log_cap_status, expected 1"
wait_for_file "$log_cap_child_file" diagnostic-log-cap
read_recorded_identity "$log_cap_child_file" diagnostic-log-cap
log_cap_child="$recorded_pid"
track_pid_identity "$log_cap_child" "$recorded_start"
assert_pid_gone_or_zombie "$log_cap_child" diagnostic-log-cap
grep -Fq "phase=command_output_log_limit_reached" "$log_cap_stderr" \
  || fail 'diagnostic log cap emitted no deterministic cap phase record'
grep -Fq "max_log_bytes=$log_cap_bytes logged_bytes=$log_cap_bytes" "$log_cap_stderr" \
  || fail 'diagnostic log cap did not report the exact transcript budget'
log_cap_actual_bytes="$(wc -c <"$log_cap_log" | tr -d '[:space:]')"
(( log_cap_actual_bytes == log_cap_bytes )) \
  || fail "diagnostic log cap wrote $log_cap_actual_bytes bytes, expected $log_cap_bytes"
log_cap_console_bytes="$(wc -c <"$log_cap_stdout" | tr -d '[:space:]')"
(( log_cap_console_bytes <= log_cap_bytes )) \
  || fail "diagnostic log cap forwarded $log_cap_console_bytes bytes, exceeds $log_cap_bytes"

# Parent cancellation crosses nested supervisors: the outer supervisor sends
# TERM to its child group, the inner supervisor forwards it to its own group,
# and both perform their bounded TERM -> KILL cleanup.
nested_child_file="$runtime_dir/nested-child.pid"
nested_outer_log="$runtime_dir/nested-outer.log"
nested_inner_log="$runtime_dir/nested-inner.log"
nested_started=$SECONDS
set +e
python3 "$supervisor" \
  --timeout-seconds 30 --kill-after-seconds 1 --require-linux-subreaper \
  --log-file "$nested_outer_log" -- \
  python3 "$supervisor" \
    --timeout-seconds 30 --kill-after-seconds 1 --require-linux-subreaper \
    --log-file "$nested_inner_log" -- \
    bash -c "printf 'nested-inner-ready\\n'; bash -c 'trap \"\" TERM; while :; do sleep 1; done' & child=\$!; record_process_identity \"\$child\" \"\$1\"; wait \"\$child\"" \
    bash "$nested_child_file" \
  >"$runtime_dir/nested.stdout" 2>"$runtime_dir/nested.stderr" &
nested_outer_pid=$!
set -e
track_pid "$nested_outer_pid"
wait_for_file "$nested_child_file" nested
kill -TERM "$nested_outer_pid"
set +e
wait "$nested_outer_pid"
nested_status=$?
set -e
untrack_pid "$nested_outer_pid"
nested_elapsed=$((SECONDS - nested_started))
[[ "$nested_status" == 143 ]] || fail "nested cancellation returned $nested_status, expected 143"
(( nested_elapsed < 8 )) || fail "nested cancellation took $nested_elapsed seconds"
nested_child=""
read_recorded_identity "$nested_child_file" nested
nested_child="$recorded_pid"
track_pid_identity "$nested_child" "$recorded_start"
assert_pid_gone_or_zombie "$nested_child" nested
grep -Fq 'phase=command_cancelled_by_parent' "$runtime_dir/nested.stderr" \
  || fail 'nested cancellation emitted no parent-cancel phase record'
grep -Fq 'phase=command_cancelled_by_parent' "$runtime_dir/nested.stdout" \
  || fail 'inner supervisor emitted no parent-cancel phase record'
grep -Fq 'nested-inner-ready' "$nested_inner_log" \
  || fail 'inner supervisor diagnostic log did not close with child output'

# Signal the wrapper PID alone (rather than its process group). The wrapper
# must forward that cancellation to the exact supervisor child and wait for its
# private group cleanup even when no command deadline was configured.
wrapper_child_file="$runtime_dir/wrapper-cancel-child.pid"
wrapper_started=$SECONDS
set +e
env -u NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS \
  RUNNER_TEMP="$runtime_dir" \
  NORTHSTAR_CI_DIAGNOSTICS_DIR="$runtime_dir/wrapper-diagnostics" \
  bash "$wrapper" 'wrapper PID cancellation' \
  bash -c 'sleep 30 & child=$!; record_process_identity "$child" "$1"; wait "$child"' \
  bash "$wrapper_child_file" \
  >"$runtime_dir/wrapper-cancel.stdout" 2>"$runtime_dir/wrapper-cancel.stderr" &
wrapper_pid=$!
set -e
track_pid "$wrapper_pid"
wait_for_file "$wrapper_child_file" wrapper-cancellation
read_recorded_identity "$wrapper_child_file" wrapper-cancellation
wrapper_child="$recorded_pid"
track_pid_identity "$wrapper_child" "$recorded_start"
kill -TERM "$wrapper_pid"
set +e
wait "$wrapper_pid"
wrapper_status=$?
set -e
untrack_pid "$wrapper_pid"
wrapper_elapsed=$((SECONDS - wrapper_started))
[[ "$wrapper_status" == 143 ]] \
  || fail "wrapper cancellation returned $wrapper_status, expected 143"
(( wrapper_elapsed < 8 )) || fail "wrapper cancellation took $wrapper_elapsed seconds"
assert_pid_gone_or_zombie "$wrapper_child" wrapper-cancellation
grep -Fq 'phase=wrapper_cancellation_received signal=TERM' "$runtime_dir/wrapper-cancel.stderr" \
  || fail 'wrapper PID cancellation was not recorded by the wrapper'
grep -Fq 'phase=command_cancelled_by_parent' "$runtime_dir/wrapper-cancel.stderr" \
  || fail 'wrapper PID cancellation was not forwarded to the supervisor'

# A single short line must reach the caller while the command is still alive.
# The former buffered ``read(64 KiB)`` implementation only forwarded it after
# EOF, so this probes a one-second window while a three-second command remains
# live and also checks that the same marker reached the diagnostic log.
low_output_file="$runtime_dir/low-output.stdout"
low_output_child_file="$runtime_dir/low-output-child.pid"
set +e
python3 "$supervisor" \
  --timeout-seconds 5 --kill-after-seconds 1 --require-linux-subreaper \
  --log-file "$runtime_dir/low-output.log" -- \
  bash -c 'printf "low-output-ready\\n"; record_process_identity "$$" "$1"; sleep 3' \
  bash "$low_output_child_file" \
  >"$low_output_file" 2>"$runtime_dir/low-output.stderr" &
low_output_supervisor_pid=$!
set -e
track_pid "$low_output_supervisor_pid"
low_output_seen=false
for ((attempt = 0; attempt < 20; attempt += 1)); do
  if grep -Fq 'low-output-ready' "$low_output_file" 2>/dev/null; then
    low_output_seen=true
    break
  fi
  sleep 0.05
done
[[ "$low_output_seen" == true ]] || fail 'low-volume output was not forwarded before command completion'
wait_for_file "$low_output_child_file" low-output
read_recorded_identity "$low_output_child_file" low-output
low_output_child="$recorded_pid"
track_pid_identity "$low_output_child" "$recorded_start"
assert_pid_live "$low_output_child" low-output
grep -Fq 'low-output-ready' "$runtime_dir/low-output.log" \
  || fail 'low-volume output was not mirrored to the diagnostic log'
set +e
wait "$low_output_supervisor_pid"
low_output_status=$?
set -e
untrack_pid "$low_output_supervisor_pid"
[[ "$low_output_status" == 0 ]] || fail "low-output fixture returned $low_output_status"

printf 'GitHub CI supervisor process-group regression tests passed\n'
