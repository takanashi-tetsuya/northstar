# Isolated client interoperability matrix

Run this matrix only after the 24-hour lab soak has finished and its evidence
has been sealed. It tests the frozen Northstar binary on the isolated
`northstar-lab` network, not public deployment.

## What is available

The host has Gajim `2.6.0-2`, `python3-nbxmpp` `7.4.0-1`, Firefox and
QEMU/libvirt. Gajim's installed OMEMO implementation uses the legacy
`eu.siacs.conversations.axolotl` namespace. It does not provide an OMEMO 2
(`urn:xmpp:omemo:2`) or XEP-0434 Trust Messages test. Its installed code does
include Carbons, MAM and XEP-0198 Stream Management paths; actual negotiation
with the candidate remains untested. No XEP-0352 CSI path was found in this
installed Gajim/nbxmpp build, so record CSI as unsupported unless a live trace
shows otherwise.

Dino, an Android SDK/emulator and a Conversations APK are absent. No Apple
device has been provided or configured for Monal lab tests. The repository's
browser E2E runner expects Chromium and Playwright paths from its Windows/WSL
setup; the host's Firefox does not make that runner available. Existing
server-side protocol fixtures and an earlier unversioned Gajim observation
cannot replace these client runs.

The current lab zone publishes S2S SRV records but no `_xmpp-client` or
`_xmpps-client` SRV records. Northstar's lab HTTP listener defaults to
`127.0.0.1:8080`; its browser client has no ready HTTPS origin on the lab
network. Provision C2S discovery or a documented manual endpoint override,
plus a browser origin, before testing. Record their configuration. Install the
lab CA inside a dedicated client VM or an equally isolated client environment;
never in the host's general trust store. Keep that environment on
`northstar-lab` only, with no default route.
Do not change the six running guests during the soak.

## Minimum run after the soak

Use fresh test accounts and two resources for one account. Pin the Northstar
commit/binary hash, client versions, client VM image/package hashes, CA
fingerprint, DNS records, service configuration and UTC time. For each case,
save a redacted client log or UI observation, negotiated XMPP features,
server log correlation and a unique message marker. Do not archive passwords,
private keys, OMEMO session databases or plaintext encrypted-message content.

| Client | Run if prepared | Do not claim from this client |
| --- | --- | --- |
| Northstar web in a pinned browser | Login over a secure origin; two-device OMEMO 2 send/receive, fingerprint/trust change and XEP-0434 propagation; Carbons, CSI/SM reconnect, MAM paging and encrypted archive replay | Independent native-client interoperability; the web client is part of this repository |
| Gajim 2.6.0 | CA-verified login, two-resource Carbons, XEP-0198 resume, MAM history/paging; legacy OMEMO exchange only as a separate compatibility observation | OMEMO 2, XEP-0434 trust or CSI without a negotiated live trace |
| Dino | Record version and repeat login, OMEMO profile, Carbons, SM/CSI and MAM only after obtaining and installing a pinned package | Any result now: no Dino installation was found |
| Conversations | Run in a version-pinned Android VM only after obtaining the APK and emulator image; cover login, supported OMEMO/trust profile, Carbons, CSI/SM and MAM | Any result now: no Android runner or APK was found |
| Monal | Run only with a compatible Apple device connected to the isolated network | Any result now: no suitable device has been provided |

Start with TLS and account login, then feature discovery and a plain direct
message. Test Carbons with another online resource; test SM by interrupting
and resuming a transport; test MAM after disconnect with a bounded RSM page.
For OMEMO, record the actual namespace, both devices' fingerprints, trust
decision and whether recipients decrypt the same marker. A legacy OMEMO
success is not an OMEMO 2 success. For CSI, require a captured `<active/>` /
`<inactive/>` exchange and resulting delivery behavior, not just server
advertisement. Restore client and server configuration after each run.

The current inventory supports preparation of a browser run and one native
client run. It cannot close `EXT-CLIENT`'s independent-client and OMEMO 2
coverage yet. Leave absent clients and unsupported profiles explicitly
untested; obtain a second suitable native client before claiming the full
matrix.
