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
`id`, including Prosody's empty value. Those fixes must pass CI and be frozen
in a commit before this run can be cited as release-candidate evidence.

Redis, MinIO, the second Northstar node, cluster faults, DNSSEC/DANE behavior
inside Northstar, certificate rotation, external components, native clients,
mixed-load soak, backup/restore and alert drills remain untested in these VMs.
The independent security review and physically separate backup destination
are unavailable. Keep all seven evidence gates open until their complete
matrices pass; this exploratory run does not turn the cluster production-ready.
