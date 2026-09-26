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
spaces upload probes 90 minutes apart. No endurance result is claimed until
the full duration and end-state metrics are reviewed. This traffic lacks MUC,
OMEMO, MAM and mobile push, so a pass will still not close `EXT-CAPACITY`.
The initial federation and cluster probes used source commit
`58650079da8d21408ab6d027127796b7863ccf5c` and binary SHA-256
`b6e898154af264a8e38065d94f340b900be2d5e7b8ed2a1107bd7136e1316ae3`.
The corrected upload outage and ongoing soak use the later binary SHA-256
`765b77ea843f36aedb6add525a8bae58ec5acc442c7a00998de54dce26546fe7`.
The host keeps outputs in `/tmp/northstar-lab-evidence-5865007/`. These are
exploratory until the scripts and binary are frozen together and the same
cases rerun with raw logs.

The lab setup is repeatable in this order: provision the six guests and lab
PKI, run `bash scripts/local-vm-lab-minio.sh` with the pinned Debian package
staged on the host, run `bash scripts/local-vm-lab-minio-bucket.sh`, complete an
offline storage migration, then run `bash scripts/local-vm-lab-cluster.sh`.
The latter requires committed S3 authority
and deliberately refuses to replace lost node signing keys. Run
`local-vm-lab-cluster-delivery.py` and `local-vm-lab-upload.py` from `ns-a`
after copying them and `local-vm-lab-federation.py` into
`/home/lab/northstar/`.

Longer and combined partitions, Redis failover, interrupted migration and
restore, DNSSEC/DANE behavior inside Northstar, certificate rotation, external
components, native clients, mixed-load soak, backup/restore and alert drills
remain untested in these VMs.
The independent security review and physically separate backup destination
are unavailable. Keep all seven evidence gates open until their complete
matrices pass; this exploratory run does not turn the cluster production-ready.
