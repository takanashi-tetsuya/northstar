# Isolated federation qualification matrix

This plan covers federation between Northstar, Prosody and ejabberd on the
isolated six-VM `northstar-lab` network. Run it only after the 24-hour soak has
finished and its evidence has been sealed. It does not test public DNS, public
CA trust or Internet routing.

## Gaps to close before the first DANE run

The current lab zone publishes A/AAAA and `_xmpp-server` SRV records. It also
publishes `_xmpps-server` SRV records for the Northstar nodes. It publishes no
TLSA records. The lab CA script creates initial 14-day leaf certificates but
does not rotate them. Existing bidirectional delivery proves basic PKIX
interoperability, not DNSSEC or DANE.

Northstar's DNSSEC resolver uses Hickory's default root trust anchors unless
the lab-only override is explicitly configured. `lab.test` is an isolated
signed zone without a chain from that root.
An explicit `delv` trust anchor can validate the zone for `delv`, but it does
not configure Northstar's resolver. Hickory 0.26.1 accepts DNSKEY records for
custom anchors; the lab's existing DS file is not a suitable input. Do not
label a TLSA test as passed until Northstar itself reports a locally validated
SRV, selected A/AAAA and TLSA chain.

The **opt-in, lab-only** `FEDERATION_DNSSEC_LAB_TRUST_ANCHOR_PATH` setting
loads one protected regular-file DNSKEY record owned by `lab.test.`. The
record must use flags 257, protocol 3 and algorithm 13. The bounded,
stable-file read is performed at startup; leave the setting absent outside
this isolated test.
Reject the setting unless the local XMPP domain ends in `.lab.test`,
`FEDERATION_DANE_MODE=required`, `FEDERATION_ALLOW_PRIVATE_IPS=true`, and a
nonempty allowlist contains only explicit peer names beneath `.lab.test`.
Reject DNS endpoint overrides in this mode. Pass the parsed key to Hickory's
resolver builder with `with_trust_anchor`; merely setting its `ResolverOpts`
path does not establish that the supplied key is used. Test wrong owner,
symlink, mutable file, malformed key, non-lab domain, public target in the
allowlist, omitted allowlist and disabled DANE as startup failures. The
ordinary production resolver must retain its default root anchors when the
setting is absent.

Generate candidate DNSKEY and TLSA records with
`python3 scripts/local-vm-lab-dane-fixtures.py --dnskey-file <BIND public
DNSKEY .key file> --cert <served peer certificate PEM> --host
prosody.lab.test --port 5269 --output-dir <new private directory>`.
`--self-test` uses only temporary local files. This generator does not sign
the zone or prove that Northstar validated it. After publication, obtain the
zone DNSKEY from the running authoritative server, compare its public-key
digest with the pinned anchor (the RR TTL changes in caches), and run `delv`
with that explicit anchor on SRV, selected
A/AAAA and TLSA records before starting Northstar. Include the resulting
proof and the resolver's own secure status in the evidence. Publish only one
of the generated positive or negative TLSA RRsets for a case; publishing both
would leave a valid association in the negative test.

Use a separately signed `fed.lab.test` child zone for negative records and
new test peer names. Publish its DS in `lab.test`; keep PostgreSQL, Redis and
MinIO names outside the changed child zone. Give test virtual hosts matching
XMPP identities and certificates before expecting usage 1 or ordinary PKIX to
pass. An alias with a certificate for only `prosody.lab.test` is not a valid
PKIX positive test for `prosody.fed.lab.test`. Pin and record the lab DNSKEY,
child DS, zone serials, peer package versions and every certificate fingerprint.

The public `federation-external-preflight.sh` is intentionally unsuitable for
this lab: it requires globally routable addresses and public PKIX trust. A
local preflight must inspect the signed zone and the actual Northstar resolver
proof, not an upstream AD bit or a hosts-file answer. Verify the VM's system
resolver reaches only the lab DNS server and preserves DNSSEC records.

## Test sequence

Start from the fixed release binary and restore the same hash on both
Northstar nodes after every case. Save the six-guest isolation preflight,
current service files, zone files, DNSSEC keys, certificate chains and a
PostgreSQL dump before changes. Keep DNS private keys and test credentials on
their guests; retain only public DNSKEY/DS and hashes in host evidence. Validate
each replacement zone with `named-checkzone` and increment its SOA serial.
Stage configuration and certificate replacements as same-filesystem renames,
with a trap that restores the original files and services on failure.

Run one case at a time. Use a unique peer domain and message marker for every
negative case so DNS caches and queued S2S retries from an earlier case cannot
change its result. Use a single SRV method and a single A-only or AAAA-only
target when proving a transport or address family. Observe the selected socket
family and port; a successful stanza alone cannot establish which endpoint was
used. For each row, save signed DNS answers and local proof status, the
selected SRV target/address/TLSA owner, served chain, SNI/ALPN where relevant,
Northstar and peer logs, outbox state and the received stanza marker. A
negative case must show rejection without delivery or a PKIX/Dialback
downgrade, followed by successful delivery after restoring the fixture.

| Case | Direction and fixture | Expected result |
| --- | --- | --- |
| F1 | Northstar → Prosody and ejabberd, DANE off, valid lab CA and SAN, STARTTLS 5269, IPv4 then IPv6 | Both peers receive one fresh marker over the selected family; SASL EXTERNAL and PKIX identity are recorded. |
| F2 | Prosody and ejabberd → Northstar, valid lab CA and SAN, STARTTLS 5269 over both families | Northstar receives the marker and authenticates the expected peer domain. |
| F3 | Peer → Northstar Direct TLS 5270, correct SNI and `xmpp-server` ALPN; also try wrong SNI and missing ALPN | Correct handshake and stanza pass; negative handshakes fail. Record which peer actually supports Direct TLS before claiming peer-to-peer interoperability. |
| F4 | Northstar → each peer, DANE required, secure SRV/address/TLSA usage 1 selector 1 matching 1 and valid PKIX | Stanza passes only when the TLSA SPKI digest, CA path and XMPP identity all match. Repeat with A-only and AAAA-only targets. |
| F5 | Northstar → each peer, DANE required, secure usage 3 selector 1 matching 1 with an otherwise untrusted but structurally valid peer leaf | Stanza passes through the DANE-EE identity path; record that this does not establish PKIX or CA revocation. |
| F6 | Northstar → peer Direct TLS through `_xmpps-server`, if an independent peer supports it | Secure SRV/address/TLSA, SNI and ALPN select port 5270; STARTTLS must not be credited as Direct TLS. If neither peer supports it, retain this row as untested and separately test Northstar's inbound 5270. |
| F7 | Secure but wrong TLSA digest; then a secure RRset containing only unsupported usage 0/2 | Required mode rejects both without PKIX or Dialback fallback; the outbox remains retryable. |
| F8 | Missing TLSA; insecure SRV or address; bogus SRV, address or TLSA signature | Required mode rejects each distinct proof failure. Keep bogus fixtures in the dedicated child zone; BIND inline signing must not silently repair the intended bad response. |
| F9 | TLSA at the wrong port/target, selected address absent from the secure A/AAAA RRset, and explicit SRV no-service `.` | Reject without using a sibling TLSA or implicit A/AAAA port-5269 fallback. |
| F10 | Usage 1 TLSA matches an expired, wrong-domain or untrusted leaf | Reject: usage 1 still requires valid PKIX, time, EKU and XMPP identity. |
| F11 | Usage 3 TLSA matches a malformed or weak leaf | Reject before authentication despite the byte match. |
| F12 | Rotate peer leaf with old and new TLSA associations published together; then remove the old association after its TTL | New handshakes accept the new leaf throughout the overlap. After cache expiry, the old leaf fails. Record DNS serial, cache timing and certificate fingerprints. |
| F13 | Rotate Northstar's own chain and key through authenticated TLS reload, first with a mismatched candidate, then a valid one | Bad reload keeps the previous generation; valid reload changes new S2S handshakes on both listeners while established sessions remain valid. Test ns-a and ns-b separately. |
| F14 | Stop and restart each independent peer after a DANE-positive baseline | Durable outbox retries after peer recovery; the received marker and server-assigned stanza ID identify any at-least-once duplicate. Do not assert exactly-once delivery. |

Northstar's required-DANE policy is outbound. A successful inbound stanza from
Prosody or ejabberd does not prove that those peers validated Northstar's TLSA.
Only claim reverse-direction DANE if the peer is explicitly configured with a
validated lab trust anchor and its DNSSEC/DANE decision appears in peer logs.
The existing peer-recovery test covers a process outage; F14 must repeat it
under the fixed DANE candidate.

## Exit conditions

Every applicable row needs the exact source commit, binary hash, service and
DNS configuration hashes, UTC start/end, expected failure class, raw evidence
and a post-case restoration check. The live soak evidence must be sealed before
changing any service. Finish with the original zone, certificates, service
configuration, process health and two-node binary hashes restored. Keep
`EXT-FEDERATION` open if the trust-anchor integration, independent Direct TLS
peer, reverse DANE validation or any negative row remains untested. Public
deployment remains a separate evidence gate.
