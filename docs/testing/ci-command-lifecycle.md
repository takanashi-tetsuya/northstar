# CI command lifecycle

Northstar keeps the security, data-isolation, TLS, and protocol assertions in
its integration suites. Fast feedback comes from making a failed command
bounded and diagnosable, not from deleting or weakening an assertion.

`scripts/github-ci-run.sh` is the common runner for a command with a separate
failure boundary. Each invocation records these structured phases in the job
log:

```text
phase=command_started
phase=command_completed
phase=command_failed
phase=command_expired
```

Set `NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS` for a command with a measured,
scenario-specific budget. The value must be between 1 and 7,200 seconds. A
command deadline sends `TERM`, then allows 15 seconds before forceful
termination. The wrapper returns the conventional `timeout` status `124`; an
expired test is a failure, never a passing result.

The job-level timeout remains an outer safety net only. It must leave enough
time for command cleanup and the PostgreSQL fixture shutdown step.

GitHub's Linux wrapper requires the supervisor to enable
`PR_SET_CHILD_SUBREAPER`. If that containment facility or the required Linux
process identity data is unavailable, the command fails before it can be
reported as clean. This closes the gap where a fixture calls `setsid`, its
direct shell exits, and a descendant would otherwise be reparented outside the
fixture's private process group.

Completion therefore means more than the direct command PID exiting. The
supervisor waits for the private process group to quiesce, then reaps and
checks descendants adopted by the Linux subreaper. It terminates only owned
processes: the private group and adopted descendants whose PID and kernel
start time still match the recorded identity. Both paths use a bounded
`TERM`-then-`KILL` sequence; they never use process-name matching or a global
process sweep. A detached descendant is a failed fixture lifecycle even if it
was cleaned successfully.

The supervisor atomically writes a private outcome record before it exits. The
wrapper labels a command as `command_expired` only when that record says the
supervisor's own deadline fired and the status is `124`. A command which
normally exits `124` remains an ordinary failure. A missing, malformed, or
internally inconsistent outcome record fails closed rather than being inferred
from the exit status or log text.

Likewise, a deadline is not classified as an ordinary expiry if containment or
output finalization itself fails: the supervisor returns a lifecycle failure
instead of concealing a surviving owned process or diagnostic copier behind
status `124`.

Every invocation also limits its runner-local raw transcript to 16 MiB by
default. `NORTHSTAR_CI_DIAGNOSTIC_MAX_BYTES` may set a value from 1,024 through
67,108,864 bytes for a measured fixture need. Reaching that cap is a failed
fixture lifecycle: the supervisor records the cap, terminates its owned
fixture processes as above, and never continues forwarding over-budget output.
This bounds both runner disk use and the later diagnostic parser.

The private transcript is written before console forwarding. Console output
then crosses a one-frame-at-a-time, bounded private pipe to a separately owned
writer helper. The helper must acknowledge that it wrote a frame within one
second. If the runner's downstream stdout consumer stops reading, the
supervisor records a `console_delivery_stalled` lifecycle failure, cleans the
fixture group, and terminates only that known helper by its Popen-owned PID.
This does not change the inherited stdout descriptor or rely on an unbounded
in-memory queue; healthy short output is still forwarded immediately.

On failure or expiry the wrapper retains the raw transcript only on the
ephemeral runner and emits a bounded, redacted annotation. A workflow may
upload the generated `*.redacted.log` copy when diagnosis needs to survive the
runner. Do not upload the raw command log: database URLs, fixture output, or a
future regression may contain material that should not become a long-lived
artifact.

The annotation helper is separately supervised with a 30-second private
lifecycle and a 128 KiB helper transcript. These defaults can be narrowed or
expanded within their bounded ranges with `NORTHSTAR_CI_SUMMARY_TIMEOUT_SECONDS`
(1–300) and `NORTHSTAR_CI_SUMMARY_MAX_BYTES` (1,024–67,108,864). A helper
failure preserves the original command status and emits the fixed safe fallback
annotation instead of leaving the job waiting on an unowned background process.

Runtime fixtures must use child-owned loopback `:0` listeners and the
nonce-bound readiness record described in
[listener-handoff.md](listener-handoff.md). A `:0` request is not a concrete
shared endpoint; the kernel chooses a distinct port for each listener. Fixed
addresses continue to undergo collision validation before any listener binds.

The stateful PostgreSQL/Redis suite is split into four runner-isolated shards:
`auth-identity`, `abuse-delivery`, `collaboration-storage`, and
`pubsub-federation`. `scripts/stateful-database-ci.sh` is the explicit checked
manifest of every required suite. Each shard starts a fresh loopback PostgreSQL
fixture, and its listed suites retain their own schema and Redis-key isolation.
The workflow runs at most three shards at once; suites inside a shard remain
ordered where their own semantics require it. This reduces wall-clock time
without turning shared-state tests into racy parallel tests.

Every listed suite has a 8- or 10-minute command budget, and the shard has a
30-minute budget plus job cleanup margin. A timeout preserves a redacted
diagnostic transcript and fails the shard. Adding a database suite requires
adding it to this manifest rather than appending an unbounded command to a
workflow step.
