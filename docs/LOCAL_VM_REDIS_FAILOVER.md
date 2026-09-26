# Isolated Redis failover drill

Run this drill after the active 24-hour soak has finished and its evidence has
been sealed. It is a post-soak `EXT-CLUSTER` experiment on a frozen candidate,
not part of the soak. Do not run it against a production Redis deployment.

## What the current lab can prove

The six-guest lab currently has one Redis 8.0.2 process on `infra`, listening
with mutual TLS on port 6379. PostgreSQL and MinIO also run on that guest.
Stopping `northstar-lab-redis.service` and restarting it tests a process outage;
it cannot test replica promotion. The existing `ns-b` nftables drill tests a
one-sided Redis connection loss. Neither supplies a second writable candidate
or a failover coordinator.

Northstar constructs one Redis client from `REDIS_URL_FILE` when each process
starts. The lab URL points to `infra.lab.test:6379`. The client has no Sentinel
master discovery, and the deployment has no role-aware proxy or movable
endpoint. Promoting a replica while leaving this URL unchanged therefore does
not establish that the application follows the new primary. A Redis election,
operator-directed reconnection, and unattended application recovery are three
different results and must be recorded separately.

## Prepare the same six guests

1. Confirm the soak service has exited successfully, run its finalizer, and
   verify the sealed manifest. Freeze the new experiment's commit, both
   running executable SHA-256 values, VM image/package versions, configuration
   hashes and the intended latency limits before changing a guest. Run
   `bash scripts/local-vm-lab-preflight.sh` to check all six interfaces and
   routes. Keep the libvirt network without forwarding or provisioning NICs.
2. Keep `infra` as the initial Redis primary. Install the same pinned Redis
   build on `ejabberd` as a replica, with a separate persistence directory,
   systemd unit and lab-only TLS listener on port 6379. This guest has the
   larger of the two peer allocations; check its memory headroom and keep
   the ejabberd XMPP service running. Issue a distinct lab-CA server certificate
   for the replica's DNS name and a client certificate for replication. Use
   `tls-replication yes` for the replication link and a dedicated, narrowly
   scoped replication ACL identity. Keep the Northstar namespace ACL and
   mTLS requirement on both data nodes; grant its read-only `ROLE` command so
   the application can reject a demoted replica on pool checkout. Do not copy
   the primary's TLS private key.
3. Put three Sentinel voters on `infra`, `ejabberd` and `dns-ca`, with quorum
   two, separate lab-only TLS endpoints on port 26379, independent writable
   state and Sentinel-specific ACL identities. Pin their Redis version and record the
   exact election and down-after settings. A Sentinel on `infra` is expected
   to disappear when that entire guest fails; the other two must still agree.
   Do not call `SENTINEL FAILOVER` for the outage case: that command requests
   a failover and does not demonstrate automatic failure detection.
4. Before touching Northstar, prove from all three Sentinels that they report
   the same initial primary and see a healthy replica. Verify the primary and
   replica `INFO replication` roles, link state and offsets, and confirm that
   only the primary accepts a write with an exact disposable lab key. Confirm
   the Northstar ACL cannot issue `REPLICAOF`, `FAILOVER`, `CONFIG`, `ACL` or
   Sentinel administration commands. Store credential-bearing output only in
   mode-0700 private evidence, with no passwords in command-line arguments or
   shared logs.

The read-only pre-fault check is
`python3 scripts/local-vm-lab-redis-failover-preflight.py`. Run it **only after
the soak is sealed** and the replica/Sentinel services are installed. It first
checks the isolated six-VM network, then uses SSH to inspect TLS certificates,
private-file permissions, exact ACL command/key/channel scopes, `ROLE`,
`INFO replication`, each Sentinel's `CKQUORUM` and replica view. It requires
`infra` to be the sole primary, `ejabberd` to be its healthy replica, and all
three voters to agree on `infra`. A missing or differing observation fails the
check. The output contains roles and hostnames, never passwords or ACL text.

For this check, keep the data configurations in
`/etc/northstar-lab-redis/` on `infra` and
`/etc/northstar-lab-redis-replica/` on `ejabberd`, each with `redis.conf`,
`users.acl`, `password` and `sentinel-control-password`. The replica's
`masterauth` must match its `replication` ACL password; configure
`masteruser replication`, `masterauth` and `tls-replication yes` on **both**
data nodes so the old primary can rejoin safely as a replica. Set
`replica-announce-ip` to each node's `*.lab.test` name and
`replica-announce-port 6379`; Sentinel must discover the replica by the
same hostname used for TLS. Store each
Sentinel's writable `sentinel.conf`, `users.acl`, `data-password`,
`peer-password` and `observer-password` under
`/etc/northstar-lab-sentinel/`. Use the unit names
`northstar-lab-redis-replica.service` and `northstar-lab-sentinel.service`.
The three Sentinels must use `resolve-hostnames yes`, `announce-hostnames yes`,
`sentinel announce-ip` with their own `*.lab.test` names,
`sentinel announce-port 26379`, quorum two, mTLS on port 26379 and
`tls-replication yes`. Their data ACL user
has access only to `__sentinel__:hello` and the Redis-documented control
commands; the Northstar user never has access to that channel. Install all
secrets and writable Sentinel state with no world access. This contract is
deliberately strict: adapt the checker and review the configuration together
if the pinned Redis build requires a different safe layout.

This layout proves a Redis process failover. It does **not** remove the
`infra` guest as an application dependency: that guest also holds PostgreSQL
and MinIO. Stopping the whole guest would mix three faults and cannot isolate
Redis RTO/RPO. It also does not emulate a managed provider's endpoint until an
endpoint with tested master discovery exists.

## Bounded sequence

Use a dedicated evidence directory and an operator supervising the guests.
Set a deadline shorter than the configured 120-second cluster safety lease for
the role transition; if it expires or the state becomes ambiguous, stop both
Northstar services and preserve the fault state for inspection. Never start a
second writable Redis process as an automatic cleanup action. Prepare the
exact commands to stop the Northstar units before injecting the fault.

1. With both nodes on the same frozen executable, collect `/readyz`, cluster
   state metrics, Redis roles and Sentinel master addresses. Run cross-node
   direct delivery, Prosody federation, a MUC occupancy/message probe and a
   durable-outbox inspection. Give every emitted stanza a unique ID. Record
   UTC and monotonic timestamps and the predeclared RTO/RPO targets.
2. Stop **only** `northstar-lab-redis.service` on `infra`; leave PostgreSQL,
   MinIO and the VM running. Record when Northstar enters fail-closed state.
   Probe that new unsafe admissions are rejected while Redis authority is
   unavailable. Keep any traffic during the gap bounded and uniquely marked.
3. Poll all three Sentinel views until the surviving voters agree on the
   `ejabberd` address. Separately verify on the data nodes that the old
   primary is stopped and the promoted replica reports `role:master` and
   accepts the disposable lab write. An `OK` reply to a trigger or one
   Sentinel address alone is insufficient proof of completed promotion.
   The pre-fault helper is not a post-failover verifier: its expected
   `infra`-primary roles intentionally fail after promotion. Capture fresh
   `ROLE`, replication offsets, Sentinel addresses and ACL/TLS evidence for
   the promoted topology before proceeding.
4. **Current implementation: operator recovery only.** Stop both Northstar
   services, point their secret-backed Redis URLs at the promoted primary's
   certificate-matching DNS name, and start the nodes one at a time. Do not
   edit a shared DNS record to conceal the operator step. Require healthy
   `/readyz`, fresh cluster listener generations, then repeat the baseline
   delivery, federation, MUC and outbox checks. Record manual intervention
   start/end; this is an operator recovery time, not unattended failover RTO.
5. Before restarting the old Redis process, ensure its persisted
   configuration and Sentinel state will make it a **replica** of the new
   authority. If the old process cannot be proven non-writable before it
   rejoins, leave it stopped. After rejoin, require one writable primary,
   healthy replication and agreement among reachable Sentinels. Restore the
   original lab configuration only after stopping Northstar and preserving
   the new authoritative data; do not blindly reload the old primary's AOF.

For an eventual unattended application-failover qualification, add and review
a Sentinel-aware Redis client or an independently reachable, role-aware
endpoint. Repeat this same drill with no secret-file edit, DNS edit or
Northstar process restart between the stop and recovered delivery. Test the
endpoint's TLS name, client certificates, ACL scope, reconnect behavior and
failure when Sentinel voters disagree. The old primary must remain fenced on
rejoin. Only that second run can measure application failover RTO.

## Evidence and pass boundary

Preserve each guest's Redis/Sentinel and Northstar journals, `INFO replication`
snapshots, Sentinel master-address responses, TLS and ACL configuration hashes,
exact probe stanza IDs, `/readyz` transitions, outbox rows, process identities,
and cleanup checks. Hash the raw files and record any missed, duplicated or
unauthorized delivery. Redis replication is asynchronous, so do not infer
zero data loss from a successful promotion or a matching final key count;
compare pre-fault offsets and application-authoritative PostgreSQL records.

Report these outcomes independently:

| Result | Required evidence |
| --- | --- |
| Redis promotion | Two surviving Sentinel voters agree; replica becomes the sole writable primary; old primary rejoins only as replica. |
| Safe application outage | Both Northstar nodes reject unsafe work until authority is reconciled; PostgreSQL-backed work is accounted for by stanza ID. |
| Operator recovery | Explicit URL change and process restarts are timed; all baseline paths recover without unexplained loss or duplicate effects. |
| Unattended failover | No operator endpoint change or Northstar restart; role-aware discovery reconnects to the promoted primary within the predeclared RTO. |

A pass in the first three rows leaves unattended Redis failover and the full
`EXT-CLUSTER` matrix open. Longer/asymmetric and combined partitions,
rolling-version changes, provider-specific behavior and representative load
still need their own evidence. The current lab's six guests share one physical
host, so this run does not prove physical host failure tolerance.

Redis's [TLS configuration](https://redis.io/docs/latest/operate/oss_and_stack/management/security/encryption/)
defines the replication and Sentinel TLS requirements. Its
[Sentinel guide](https://redis.io/docs/latest/operate/oss_and_stack/management/sentinel/)
defines quorum, master discovery and the difference between automatic and
command-triggered promotion.
