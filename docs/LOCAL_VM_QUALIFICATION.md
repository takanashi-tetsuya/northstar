# Isolated VM qualification

This lab qualifies the tested Northstar build and topology without sending
test traffic to the public Internet. It is the environment for the seven
evidence gates in the [execution plan](MODULARIZATION_EXECUTION_PLAN.md#82-isolated-vm-qualification-on-a-frozen-release-candidate).

## Network and guests

`scripts/local-vm-lab-network.sh` creates the persistent `northstar-lab`
libvirt network at `192.168.197.0/24` and `fd7a:6e73:7461:72::/64`. The
network has no libvirt forwarding rule and does not autostart. Guest test
interfaces must be attached only to this network while experiments run.
Package and image downloads, if needed, happen before qualification; record
their digests and detach any provisioning interface before the first test.
`scripts/local-vm-lab-preflight.sh` checks all six guests for extra interfaces
and default routes. `scripts/local-vm-lab-dns.sh` creates the signed zone;
`scripts/local-vm-lab-client-dns.sh` directs the guests to its DNS VM.

| Guest | Suggested memory | Workload |
| --- | ---: | --- |
| `ns-a`, `ns-b` | 3 GiB each | Same candidate binary, separate configuration and logs |
| `prosody`, `ejabberd` | 1 and 2 GiB | Version-pinned independent federation peers |
| `infra` | 4 GiB | PostgreSQL, Redis and versioned MinIO with separate data volumes |
| `dns-ca` | 1 GiB | Authoritative signed lab zone, validating resolver and lab CA |

These allocations total 14 GiB before clients. Keep the existing `debian13`
VM untouched; use clean, checksum-verified guest images rather than cloning
its machine identity or secrets. The lab zone uses reserved `.test` names.
Publish SRV, TLSA, A and AAAA records inside the lab, including deliberately
invalid variants for negative tests. A self-signed lab CA must be installed
only in lab guests, never in the host's general trust store.

## Order and evidence

1. Freeze the commit and artifact digests. Record guest image/package versions,
   guest IDs, network XML and resource allocations. Define expected results,
   latency limits and recovery targets before fault injection.
2. Verify isolation from each guest: expected lab DNS succeeds, an unrelated
   public address is unreachable, and packet capture shows test traffic only
   on `northstar-lab`. Do not infer isolation solely from the network name.
3. Run baseline C2S, bidirectional S2S, component and client cases. Exercise
   Prosody and ejabberd independently. Record negotiated TLS/XMPP features,
   certificate chains, stanza IDs, outbox state and peer logs.
4. Run asymmetric partitions, Redis failover, lease loss, process hard-kill,
   certificate rotation and negative DNS/TLS cases. Check exact occupancy,
   delivery and authorization invariants after recovery.
5. Run restore, encrypted rollback and alert drills. Then run the fixed mixed
   load and 24–72 hour soak without changing the candidate or VM allocations.
6. For each gate, save the command, UTC start/end, expected and observed
   result, raw logs, configuration, metrics and reason for any exclusion.
   A failed run creates a fix and a new candidate; retest affected gates.

An independent security review requires an independent reviewer even when
the penetration test runs inside this lab. A second VM on the same physical
host is not an off-site backup. Monal requires a compatible Apple device on
the isolated network; without one, that client remains untested. Results do
not establish public DNS propagation, public CA trust, Internet routing or
capacity on other hardware. Keep those boundaries visible in
[KNOWN_ISSUES.md](KNOWN_ISSUES.md).

## Current exploratory run

On 2026-09-26 the host exposed KVM and an active libvirt daemon, with roughly
19 GiB of available RAM and 1.4 TiB of free workspace disk. The existing
`debian13` VM was shut off. `northstar-lab` was created and started without a
forwarding rule. Six clean Debian 13 guests were booted from the official
generic image whose SHA-512 is
`a733e7d49442a03e70d03e4eb5aaf3967f3efc69ef70952f9bb10fc1ee2c4876eb95956b5ad2d31350e5fada768feb651352535fb8cd1233f61998a5a7d2e93c`.
All six acquired lab-only DHCP leases. The first guest completed cloud-init,
accepted its lab SSH key and had IPv4/IPv6 addresses but no default route.
The six-guest isolation preflight passed. Prosody `13.0.1-1+deb131u`,
ejabberd `24.12-3+deb13u2`, PostgreSQL 17, Redis `8.0.2` and BIND `9.20.29`
were installed through temporary provisioning interfaces; those interfaces
were removed. The lab zone answers signed A/AAAA and XMPP SRV records. A
`delv` query with the zone's explicit DS trust anchor fully validated an A
response. System resolver output still reports unauthenticated DNS data, so
the DNSSEC behavior of each XMPP implementation has not yet been qualified.

The `ns-a` node now runs the candidate binary against PostgreSQL 17 with
separate migrator, runtime, storage and command roles, TLS-verified connections
and file-backed secrets. `scripts/local-vm-lab-node.sh ns-a` successfully
repeated migration, exact-grant reconciliation and service startup. The runtime
role's account-generation lock accepted the current generation and rejected a
stale generation and a disabled account without gaining account UPDATE rights.

`scripts/local-vm-lab-federation.py` sent unique chat markers from Northstar to
Prosody and ejabberd and back; all four receiving clients observed their
markers. The same four paths passed again after rebuilding the Northstar node.
`scripts/local-vm-lab-peer-recovery.sh` also stopped each independent peer in
turn, observed an S2S outbox entry while it was down, then confirmed the queued
marker reached a client after the peer restarted. This covers one peer-process
outage and retry path, not an asymmetric network partition. The run found and fixed a
runtime-role row-lock gap during C2S bind/message admission and a stream-open
interoperability gap: RFC 6120 requires receivers to ignore an initiator's
`id`, including Prosody's empty value. Both fixes are in the tested source
commit; a separate CI fixture correction is in `c36af2f`.

The infra guest now runs Redis 8.0.2 with mandatory mutual TLS and a
deployment-scoped ACL. A dedicated 10 GiB virtual disk hosts HTTPS MinIO with
bucket versioning. After stopping the standalone node, an exploratory
Local-to-S3 migration committed the upload authority to S3; the manifest had
**zero objects**, so this did not test copying or verifying real uploads.
`scripts/local-vm-lab-cluster.sh` then started `ns-a` as the sole maintenance
owner and `ns-b` as core-only, with separate Ed25519 signing identities and
shared PostgreSQL, Redis and S3. The `local-vm-lab-cluster-delivery.py` probe
delivered direct messages in both directions between resources connected to
different nodes. With Redis stopped, a new session was closed at bind rather
than admitted without cluster authority. After Redis restarted, the probe
recovered and both delivery paths passed. Prosody and ejabberd bidirectional
federation still passed with both Northstar nodes active. A non-empty HTTP
Upload created through `ns-a` was downloaded through `ns-b` with the same
SHA-256
(`ec1fd0735b77f0e49ad119daeede350a9ea9f7ab51e77c41b0c00386ac1fa2a6`).
That first read proves shared S3 access, not migration. Subsequently, both
nodes were stopped and a PostgreSQL dump plus
the original object bytes were saved locally. An unused reservation left by a
failed upload probe initially blocked migration. Its row had no upload, stage,
or object key, and was removed by exact ID after the backup. S3-to-Local then
committed generation 3 with one object (run
`aa2472cb-676a-42d6-8969-c67b45575be8`, manifest
`2ebe7ada55bbd2a9d6379d510a9f4e1e90d1877d87a6b81c998bacc5d99a135d`).
The local file matched the original SHA-256. Local-to-S3 committed generation
4 with one object (run `e92947f4-6c34-46f0-910d-05056dfe0b9b`, manifest
`543cc058c5b1718b59a9d7088ce4d837161719a58a39ee2d1b89b56deae045f9`).
After restart, both nodes read back the same SHA-256 and cross-node direct
delivery still passed. This qualifies one successful non-empty round trip in
the local topology; it does not qualify interruption recovery or an off-site
copy.

A hard `SIGKILL` of core-only `ns-b` left `ns-a` serving bidirectional traffic
with Prosody. An immediate `ns-b` restart was rejected because the previous
process still owned that node ID until 02:40:17 UTC. After the database lease
expired, `ns-b` started at 02:40:36 UTC and two new cross-node direct messages
were delivered. This checks one process-kill fence and rejoin, not a network
partition, a durable-session replay, or a general RTO/RPO bound. A separate
asymmetric partition dropped only `ns-b`'s outbound Redis traffic while
`ns-a` retained access. The surviving node continued bidirectional Prosody
traffic; a new bind on `ns-b` was closed. After removing the firewall rule,
new cross-node direct delivery recovered without restarting either process.
This tests a short control-plane partition, not split-brain behavior under
all combinations of database and object-store reachability.

An attempted migration `SIGKILL` drill was stopped before it created a run:
the debug-only pause requires a loopback PostgreSQL fixture and refuses this
VM's remote database. The authority remained `s3` generation 4, no active
migration was left, and both nodes passed delivery and object-read checks after
restart. The isolated database CI fixture tests this pause and resume path;
the VM lab still needs an interruption drill that does not bypass the guard.

Blocking only `ns-b`'s PostgreSQL port caused its runtime-control worker to
exceed the heartbeat budget and shut down the process. `ns-a` continued
bidirectional Prosody traffic. Once the firewall rule was removed, the lab's
`Restart=no` unit required a manual `ns-b` start. The first direct-delivery
probe after restart timed out, and the next passed both directions; this
reconciliation delay is part of the observed result. No automatic recovery
claim is made for a production service manager.

Stopping MinIO made a committed public upload read fail while the object bytes
remained intact. The first candidate returned HTTP 500. The corrected public
GET handler returned HTTP 503 with a generic service-unavailable response;
after MinIO restarted, the same object again matched SHA-256
`ec1fd0735b77f0e49ad119daeede350a9ea9f7ab51e77c41b0c00386ac1fa2a6`.
That corrected debug binary had SHA-256
`765b77ea843f36aedb6add525a8bae58ec5acc442c7a00998de54dce26546fe7`.
This is a process outage, not a disk-loss or fresh-host restore drill.
Blocking only `ns-b`'s MinIO port left `ns-a` able to read the object. The
partitioned node returned HTTP 503 after its configured 30-second object-read
timeout (30.17 seconds observed); after connectivity returned, it read the
same SHA-256. This does not test partial writes or provider failover.

A 24-hour low-rate mixed smoke soak was started as the host's transient
`northstar-lab-soak-retry.service`. Its first completed observation at
2026-09-26 03:08 UTC passed cross-node delivery and both federation peers,
with `ns-a`/`ns-b` RSS of 109,240/107,356 KiB and PostgreSQL WAL bytes at
46,375,619. The JSONL log is
`/tmp/northstar-lab-evidence-5865007/soak-24h-retry.jsonl`.
The earlier start hit upload `resource-constraint` immediately after a smoke
upload; that failure is preserved in `soak-24h.jsonl`. The restarted run
spaces upload probes 90 minutes apart. It passed through iteration 59, then
stopped at iteration 60 (2026-09-26 04:08 UTC): cross-node delivery passed,
but a Prosody-to-Northstar message did not reach the just-connected Alice
resource within 15 seconds. Prosody logged a stanza error and S2S stream
closure; both Northstar processes stayed active, and a one-off retry passed.
The federation probe had not waited for Alice's new presence to become the
preferred route after the immediately preceding cross-node probe closed two
other Alice resources. The helper now uses a unique resource and waits for
its priority-10 self-presence before sending the inbound test message. This
addresses a plausible probe race; it does not prove the service has no stale
route behavior. The failed JSONL and service logs remain evidence, and a new
full-duration run is required. This traffic lacks MUC, OMEMO, sustained MAM
and mobile push, so a pass will still not close `EXT-CAPACITY`.
The corrected run started at 2026-09-26 04:16 UTC as
`northstar-lab-soak-route-ready.service`, writing
`/tmp/northstar-lab-evidence-5865007/soak-24h-route-ready.jsonl`. The first
observation passed both federation peers and cross-node delivery. The guest
helper matched source SHA-256
`add18a57579a5ab88625b20cb3243b12617c440775127bed8bf139e1136ce48b`;
the binary digest below did not change. Iterations 0–419 passed, but iteration
420 failed at 11:16 UTC, seven hours into the run. The cross-node delivery
check passed; the Prosody-to-Northstar marker did not reach Alice's new
resource. Prosody's debug log shows that it sent the message, then Northstar
closed the S2S stream in the same second. Prosody reported one unacknowledged
stanza and returned a message error to Bob. This is a failed soak, not a slow
pass or proof that the route-readiness change was sufficient.

The five-minute federation-probe interval coincides with Northstar's 300-second
authenticated S2S idle limit. The previous Prosody message was acknowledged at
11:11:20 UTC and the failed message was sent at 11:16:20 UTC. The idle timeout
is a likely cause of the stream close, but Northstar's current INFO-level log
does not identify the exact close branch. The captured evidence is read-only
under
`/tmp/northstar-lab-evidence-5865007/soak-route-ready-failure-20260926T111620Z/`,
with SHA-256 checksums for the run output and surrounding service logs. A fix
needs a targeted idle-boundary test and a new frozen-candidate soak.
The initial federation and cluster probes used source commit
`58650079da8d21408ab6d027127796b7863ccf5c` and binary SHA-256
`b6e898154af264a8e38065d94f340b900be2d5e7b8ed2a1107bd7136e1316ae3`.
The corrected upload outage and soak attempts use the later binary SHA-256
`765b77ea843f36aedb6add525a8bae58ec5acc442c7a00998de54dce26546fe7`.
The host keeps outputs in `/tmp/northstar-lab-evidence-5865007/`. These are
exploratory until the scripts and binary are frozen together and the same
cases rerun with raw logs.

`local-vm-lab-mam.py` also exercised a personal MAM query through a real C2S
session while the soak ran. Alice sent three opaque encrypted-envelope fixtures
to the Prosody peer and queried adjacent archive pages. The 2026-09-26 04:04
UTC probe returned two distinct rows per page, including the newest stanza,
with indexes 2 and 4 and `count=6`. Its raw result is in
`/tmp/northstar-lab-evidence-5865007/mam-personal-smoke.jsonl`. The fixture
tests the archive path, not end-to-end encryption. A plaintext first attempt
correctly produced no archive row because this lab uses the default
encrypted-only archive policy. This one personal-page check does not qualify
MUC or MIX MAM, concurrent visibility changes, or long-term MAM load.
The expanded personal probe at 04:26 UTC also returned the same last page via
an `after` cursor and rejected an unknown cursor with `item-not-found`. The
archive contained nine rows, and adjacent page indexes were 5 and 7.

An exploratory room MAM probe found a runtime-role permission gap before it
could query the archive. After creating and configuring a temporary room, its
first group message closed the C2S stream. PostgreSQL logged `permission
denied for table users` for a direct row-lock query in MUC admission. Migration
`0151` and the matching application change replace that query with an exact
enabled-account name-check capability. The MUC batch affiliation path now
uses the same capability. Affiliation listing still locks the membership rows,
but no longer attempts to lock `users`, whose names are immutable. The initial
`0151` change passed CI on `a7859ed`. At the time of that soak, its binary was
unchanged. The newer binary used in the S2S test below still needs a MUC
recheck.

The lab setup is repeatable in this order: provision the six guests and lab
PKI, run `bash scripts/local-vm-lab-minio.sh` with the pinned Debian package
staged on the host, run `bash scripts/local-vm-lab-minio-bucket.sh`, complete an
offline storage migration, then run `bash scripts/local-vm-lab-cluster.sh`.
The latter requires committed S3 authority
and deliberately refuses to replace lost node signing keys. Run
`local-vm-lab-cluster-delivery.py`, `local-vm-lab-upload.py`,
`local-vm-lab-mam.py` and `local-vm-lab-muc-mam.py` from `ns-a` after copying
them and
`local-vm-lab-federation.py` into
`/home/lab/northstar/`.

Longer and combined partitions, Redis failover, interrupted migration,
DNSSEC/DANE behavior inside Northstar, certificate rotation, native clients,
full mixed-load soak and alert drills remain untested in these VMs. The narrow
component, room MAM and restore checks below do not close their full matrices.
The independent security review and physically separate backup destination
are unavailable. Keep all seven evidence gates open until their complete
matrices pass; this exploratory run does not turn the cluster production-ready.

## S2S idle-boundary regression on a frozen candidate

On 2026-09-26, commit
`3dc7f9669e0af9f4ef23f0ecdf6d4e9e099a58f2` passed all required jobs in
[CI run 36242007596](https://github.com/takanashi-tetsuya/northstar/actions/runs/36242007596).
The runtime artifact ZIP matched GitHub's SHA-256
`44f3f0c01ff1334ad27964f526b0a7b6d32454b3e23e2c36ed3e565cceeca395`.
Its manifest matched that run, the source digest from an immutable checkout
(`bfed9546e9d80dbcba6c704516ce0d34870862b358a8ed1048f3b936028c0c4a`),
and the extracted binary's SHA-256
`c172f20e9b8e6b73f05c0dc788e99da66c475c69a9b88a194d8480186af2436b`.
The same binary was installed on `ns-a` and `ns-b`; both processes still had
that executable digest after the probes. The isolation preflight passed before
deployment.

The first start with the new binary correctly refused the older PostgreSQL
migration ledger. Both nodes were stopped. A fresh custom-format database dump
was parsed with `pg_restore -l` and saved with SHA-256
`8c585da4d4c22712f499e1f6d1dbc377cd27adb6a103b22e868ed34b5fb34a21`.
The candidate's `migrate` command then ran under the migrator role, followed
by its grant reconciliation script. Both commands completed successfully, and
the two services started with their existing configuration and node identities.
The previous binary remains saved on each VM.

The committed `local-vm-lab-s2s-idle-boundary.py` helper (SHA-256
`70e5a2cb468f1d2173433148cfe69bfe6f7e2d6034c7e51f5415b03a41f6c2f4`)
kept only the C2S clients alive between inbound messages. It sent no outbound
S2S stanza during the measured windows. Each peer first passed a bidirectional
baseline, then delivered three inbound chat stanzas just over the 300-second
idle limit:

| Peer | Measured inbound gaps (seconds) | Delivery latency (milliseconds) | Wire evidence |
| --- | --- | --- | --- |
| Prosody | 300.050153, 300.050119, 300.050109 | 4.95, 4.73, 5.57 | Same S2S TCP connection and Prosody stream ID throughout; the complete second and third windows contained no inbound application bytes. |
| ejabberd | 300.050109, 300.050191, 300.050106 | 7.28, 4.49, 6.14 | Same S2S TCP connection throughout; all three complete windows contained no inbound application bytes. |

Prosody's packet capture began partway through its first idle window. Its
first result proves delivery at the measured interval, while the second and
third have complete packet evidence. The ejabberd capture started before its
S2S connection and covers all three windows. Each capture is limited to the
peer-to-Northstar S2S path; the peer logs and raw client frames identify the
delivered stanzas. The captures show one TLS payload at each measured
boundary and no intervening inbound payload on the same TCP connection.

The raw JSONL, SHA-256 sidecars, limited packet captures, peer logs, Northstar
journals, migration record, and machine-readable summary are under
`/tmp/northstar-lab-evidence-5865007/s2s-idle-boundary-3dc7f966-36242007596/`;
`SHA256SUMS` covers the saved files. This qualifies the 300.05-second S2S
edge for these two peers on this candidate. A new full-duration soak has
started but is not complete, and the wider
federation and capacity matrices remain open.

## XEP-0114 component and room MAM narrow run

On 2026-09-26, the same `3dc7f966` runtime-test binary
(`c172f20e9b8e6b73f05c0dc788e99da66c475c69a9b88a194d8480186af2436b`)
remained active on both Northstar guests. The six-guest isolation preflight
passed before and after the run. Debian's signed Trixie package index was
verified with its archive keyring; Slixmpp `1.10.0-1` and its five missing
dependencies were copied to `ns-a` without adding a network interface. The
Slixmpp package SHA-256 was
`3999be5cf9a6d844bc98be75774f963dcfbb0c844b47c8b660c714a2f2a47ea6`.

The temporary XEP-0114 accept listener bound only to `127.0.0.1:5347`. An
independent Slixmpp 1.10.0 component authenticated and echoed a marker sent
over a real C2S connection. A separate wrong-secret attempt disconnected
without authenticating. After `ns-a` restarted, the bounded probe scheduled
one reconnect, authenticated again about one second after the disconnect, and
echoed a new C2S marker. The component's SQLite ledger was reused across its
process runs; both accepted messages carried server-assigned XEP-0359 IDs.
Slixmpp did not reconnect on its own: the probe now performs at most a
configured number of one-second retries and records each attempt. This run
qualifies the accept-mode handshake, delivery and restart path. It does not
qualify connect mode, a disconnected outbox drain, sustained backpressure or
XEP-0225 interoperability. The temporary component configuration and secrets
were removed, `ns-a` restarted, and the component listener disappeared. Both
Northstar services remained active with the frozen executable hash.

After restoring the original service configuration, the single-room MUC/MAM
probe sent three encrypted groupchat messages and read them in adjacent RSM
pages of two and one row. Each archived result retained `<encrypted>` and
used a generic encrypted-message body. The first run failed because its
assertion matched the test marker preserved in a forwarded stanza `id`; the
marker was absent from every archived `<body>`. The assertion now checks body
text specifically, with a self-test that rejects a leaked body. The rerun
passed, including room destruction. Its raw JSONL SHA-256 is
`7cb565195224947b4c539276e19e4468c93bb3ff77c05470476a1a76728d04ae`.
These results cover only the tested room and MAM path, not the full MUC/MIX
matrix.

Raw component and MUC/MAM JSONL, the persistent ledger, guest journals,
package and script digests, service restoration checks, preflight output and
`SHA256SUMS` are under
`/tmp/northstar-lab-evidence-5865007/component-0114-3dc7f966-20260926/`.

## Isolated backup and restore crash drill

On 2026-09-26, the infra VM used the same `3dc7f966` source and verified CI
binary in a disposable PostgreSQL 17 cluster with a private Unix socket. Its
upload and rollback roots were separate from the running service, and a new
MinIO process used a versioned bucket on a random loopback port. The live
`xmpp` database and MinIO namespace were not touched. The first full run
passed signed, age-encrypted local backup and local/S3 recovery at three
SIGKILL points: after the first new local object and after the S3 database
switch, recovery moved forward; after S3 import before commit, it compensated.
The raw log SHA-256 was
`93e4a4e3c0561df236db897f11172e11a482422c60bb50e016e6bf5da9ee4e0c`.

A second full run added separate age recipients for S3 rollback dumps. Each
of the three rollback roots retained `database-before.dump.age` and no
plaintext `database-before.dump`. An independent recovery identity decrypted
every dump for `pg_restore --list`, while the incoming backup identity could
not. The same three crash decisions passed; this run's raw log SHA-256 was
`c4d6a8941caddbe8967f8a052a890320656364083ba1f1ee12f02a7633160ce4`.
The live infra baseline was identical before and after apart from its
observation time: database OID `16389`, 151 migrations, S3 authority
generation 4, seven uploads, MinIO PID `17031` and both service states were
unchanged. Private fixture processes stopped after the runs.

The VM's `/tmp` is a 1.9 GiB tmpfs, so a guest-only fixture copy used an
owner-private work root on ext4, the verified binary in place of a Cargo
build, and the installed pinned MinIO binary. Its initial barrier preflight
rejected the non-`/tmp` socket path before any restore; the guest-only test
was tightened to the exact private path and both full runs then passed. The
equivalent work-parent and encrypted S3 rollback checks have since been added
to the repository fixture. Raw logs, journals,
guest-only diffs,
before/after baselines and a verified `SHA256SUMS` are under
`/tmp/northstar-r1-vm-3dc7.qHwtpI/`.

This qualifies the tested restore decisions and encrypted rollback database
dumps. Old upload objects and cutover copies remained plaintext on the VM's
ext4 filesystem; encrypted-filesystem deployment is still untested. The VM
lacks `cryptsetup`, `losetup`, `dmsetup` and `mkfs.ext4`, so no encrypted
loopback drill was run. A physically separate backup destination and an
independent security review also remain unavailable.

## Short Redis control-plane partition

On the same frozen `3dc7f966` binary, `ns-b` received Debian-signed,
SHA-256-verified nftables packages offline. Its nftables service remained
disabled and inactive. The drill first checked all six VM interfaces and
routes, both running binary hashes, service health, cross-node delivery,
Prosody federation and `/readyz`. It then used a uniquely named nft table on
`ns-b` to drop only traffic to the infra Redis port. A guest timer and host
cleanup each targeted that exact table.

The first run removed the table but probed C2S admission about one second
later, while `ns-b` was still intentionally fail-closed. Its result remains
failed in `/tmp/northstar-lab-evidence-5865007/northstar-redis-fault-eteuqazn/`.
An independent later baseline passed. The probe was then changed to record
the readiness transition before testing delivery, and the second run passed.
The configured duration was 75 seconds; host monotonic time measured 70.362
seconds from rule installation to removal because the script reserves five
seconds for cleanup. `ns-b` returned HTTP 200 before the fault, then HTTP 503
with `cluster policy is not ready` during it. After removal, 15 readiness
checks still returned 503; the sixteenth returned 200 at 32.813 seconds.
Cross-node bidirectional and Prosody delivery passed at 33.639 seconds after
removal. Both Northstar services kept their process identity and binary hash,
their Redis links recovered, and the nft table and timer were absent afterward.

The passing run's 135 hashed evidence files are under
`/tmp/northstar-lab-evidence-5865007/northstar-redis-fault-y6drpurd/`;
the separate 31-file post-check is under
`/tmp/northstar-lab-evidence-5865007/northstar-redis-fault-z72bip1c/`.
This measures one short `ns-b`→Redis control-plane partition. It does not
cover Redis failover, PostgreSQL partition, combined faults or the full
`EXT-CLUSTER` matrix.

## Release-profile mixed soak in progress

A 24-hour low-rate run started at 2026-09-26 14:57 UTC on the frozen
`3dc7f9669e0af9f4ef23f0ecdf6d4e9e099a58f2` source. The release-profile
binary SHA-256 is
`2ae19035fedb46de6c7d4d69f0cb7f4ba7bc50d20b276f55a736f5510df1a6ba`
on both `ns-a` and `ns-b`; this is a separate artifact from the earlier CI
`runtime-test` binary
`c172f20e9b8e6b73f05c0dc788e99da66c475c69a9b88a194d8480186af2436b`.
The host's `northstar-lab-soak-release-3dc7.service` writes private evidence
to `/tmp/northstar-lab-evidence-5865007/release-soak-3dc7-20260926T1451Z/`.
Its verifier reported 73 passing observations through 16:10 UTC, including
cross-node delivery, periodic Prosody/ejabberd traffic, room MAM and upload
checks. This is an in-progress observation, not a passed 24-hour result.
Only after the full duration and successful service exit may the finalizer
seal and verify the raw evidence. This low-rate profile does not contain
OMEMO, Push or sustained active load and cannot close `EXT-CAPACITY`. The
latest `dev` changes also require a new frozen binary and affected-path
retests; this run remains evidence only for its recorded source and binary.
