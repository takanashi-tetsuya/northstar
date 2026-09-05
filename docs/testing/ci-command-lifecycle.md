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

On failure or expiry the wrapper retains the raw transcript only on the
ephemeral runner and emits a bounded, redacted annotation. A workflow may
upload the generated `*.redacted.log` copy when diagnosis needs to survive the
runner. Do not upload the raw command log: database URLs, fixture output, or a
future regression may contain material that should not become a long-lived
artifact.

Runtime fixtures must use child-owned loopback `:0` listeners and the
nonce-bound readiness record described in
[listener-handoff.md](listener-handoff.md). A `:0` request is not a concrete
shared endpoint; the kernel chooses a distinct port for each listener. Fixed
addresses continue to undergo collision validation before any listener binds.

Database test sharding is intentionally deferred until each shard can prove an
independent schema, Redis-key namespace, and resource budget. Increasing test
threads without that isolation would exchange a visible stall for nondeterministic
data races.
