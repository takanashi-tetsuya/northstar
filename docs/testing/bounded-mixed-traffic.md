# Bounded mixed traffic qualification

`scripts/mixed-traffic-soak.py` runs a private single-node XMPP fixture with two
synthetic users. It checks direct and MUC delivery, opaque OMEMO envelopes,
MAM contents and counts, no-store exclusion, reconnects, readiness, and shutdown.
It never connects to an existing database or starts a production deployment.

Build the binary first, then run the fixture as an ordinary user:

```sh
cargo build --locked --bin rust-xmpp-server
python3 scripts/test-mixed-traffic-soak.py
python3 scripts/mixed-traffic-soak.py \
  --binary target/debug/rust-xmpp-server \
  --duration-seconds 600 \
  --output-dir /tmp/northstar-mixed-qualification
```

The output directory must be new and outside the source checkout. PostgreSQL
server/client tools and OpenSSL must be available. If `initdb` is not on `PATH`,
the fixture uses `pg_config --bindir`. PostgreSQL listens only on loopback TCP;
Unix sockets are disabled. Server listeners use child-owned `:0` addresses and
nonce-bound readiness. `--database-port` can select an unused loopback port.
No application configuration, external database URL, or Redis credential is
inherited from the invoking environment.

## Ownership boundaries

- `OwnedFixture` owns the disposable PostgreSQL cluster, server, copied binary,
  ports and teardown. Only its own paths and child handles are eligible for cleanup
- `MixedTraffic` owns protocol assertions, exact expected delivery identities,
  counters, MAM checks and peer lifecycle. It imports the existing protocol
  helpers without modifying them
- `scripts/lib/soak-failure-diagnostics.py` is a separate observer. It captures
  bounded evidence after an authoritative failure, before peers or server are
  closed, and cannot retry the workload or convert a failure into success

The normal receive deadline remains ten seconds. The graceful server shutdown
budget remains twenty seconds. A longer test duration does not relax either
budget. Runs shorter than 600 seconds provide proportional smoke coverage;
600 seconds requires at least 200 rounds. Neither establishes endurance or a
production-capacity claim.

## Passing requires clean completion

`result.json` records workload and cleanup results independently. A passing
result requires both:

1. All protocol and history assertions passed
2. The server exited with code zero inside its shutdown budget, emitted its
   shutdown-complete event, and every fixture listener closed

A timeout, forced kill, nonzero exit, missing completion event, cleanup error,
or remaining listener fails the fixture even if every message assertion passed.
Original workload failures remain authoritative if diagnostics or teardown also
fail. SIGINT/SIGTERM enters the same owned cleanup path; repeated signals cannot
interrupt cleanup halfway.

The evidence includes the binary hash, helper/harness hashes, source identity,
exact delivery totals, resource samples, and shutdown result. Changing source
while the run is active invalidates that qualification. Keep raw output private:
it is a synthetic fixture, but future failures could include application output.
The fixture retains its private output directory for inspection; do not publish
its disposable database, private TLS key, or copied binary as test evidence.

## Failure evidence and limits

The observer writes each JSONL stage immediately. It samples process and thread
counters, available cgroup/host pressure, readiness, metrics, and bounded
PostgreSQL activity/lock metadata. It excludes process command lines,
environments, SQL text and user payloads. Missing counters are explicitly
unavailable, never interpreted as zero. An eight-second total observer deadline
and separate process group keep a stalled observer from holding up teardown.

The original cloud validation of base commit
`3dfc005657ab0e6f9b09d943a4d2bb4c83972fd2` recorded one non-SM MUC timeout at
round 73 followed by a shutdown requiring SIGKILL. Later bounded runs passed.
That historical failure did not record enough scheduler/database state to
identify its cause. Better diagnostics and subsequent passes do not close it.

A separate SM-association lock hazard was identified in code review: a live
DashMap iterator held a membership shard guard across backend awaits. Association
now snapshots owned membership identities before I/O and retains exact occupant
and database fencing. Its deterministic current-thread regression proves the
old iterator locks the shard and the snapshot releases it. The original failing
soak did not enable SM, so this fix is not attributed to that historical failure.

This fixture does not exercise real-client OMEMO encryption/decryption,
multi-device interoperability, direct TCP TLS clients, federation, production
role separation, representative active-user load, or 24–72 hour endurance.

## Opt-in frame localization

Add `--trace-frames` to enable only the sanitized C2S execution target at DEBUG.
Then run `python3 scripts/summarize-frame-trace.py /path/to/server.log --require-complete`
to verify start/completion pairs and inspect last reached stages. This observation
check is separate from the workload and cleanup result; it cannot turn a failed
fixture into a pass. The [execution map](../architecture/message-execution.md)
defines ownership, fields, stage meanings and diagnostic limits.

## Explicit SM comparison

`--stream-management` enables ordinary, non-resumable XEP-0198 on every new WebSocket stream
before sending initial presence. The fixture explicitly requests `resume=false`; it does not require a device-bound
resume token from legacy authentication or weaken the server’s device policy.
The observer counts every top-level XMPP
message, presence and IQ, including MAM wrapper messages, once per stream. It
acknowledges that exact modulo-2^32 handled count after observation and answers
server `<r/>` requests without counting SM nonzas as stanzas. Reconnected peers
start fresh counters. A terminal SM request/response barrier follows the client
ACKs before close. Counters report enabled streams, received stanzas, client
ACKs and server ACK responses. This comparison does not exercise SM resume;
that belongs to the existing transport-resume fixtures.

Run separate new output directories with and without the flag. Never replace
non-SM coverage with SM coverage: they have different completion boundaries.
Both retain exact live-delivery, MAM, no-store, receive deadline and shutdown
assertions. A failed run remains failed even when a later run passes.

SM ACK writes share the receive operation's remaining deadline. The script
rejects a predicate result if observation/ACK work exhausted that deadline.
The server's returned `h` is checked for protocol syntax only: this fixture
accounts for server-to-client received stanzas and client ACKs, and does not
claim an independent check of server-handled client-to-server counts.
