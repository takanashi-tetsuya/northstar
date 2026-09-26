# Local VM external-component probe

These probes use independent XEP-0114 and XEP-0225 components on the isolated
lab network. Run them only after the release candidate, guest packages, and
binary hashes are frozen, and after any running soak has stopped. Keep the existing
network isolation preflight and save its result alongside this probe's output.

## XEP-0114 accept: Slixmpp component

[Slixmpp's `ComponentXMPP`](https://slixmpp.readthedocs.io/en/latest/getting_started/component.html)
is a third-party component client. Provision a pinned `python3-slixmpp` package
on `ns-a` before detaching its provisioning interface; record the package
version and digest. The scripts use that library for the wire protocol. Their
small echo handler processes only `component-lab-` markers. It persists
server-assigned XEP-0359 IDs from the expected Northstar sender in a SQLite
ledger across process restarts. It records each accepted message and duplicate
in fsynced JSONL. A stanza
without a server-assigned ID is recorded but cannot be safely deduplicated.

On `ns-a`, save a 32-byte or longer random secret in
`/home/lab/northstar/secrets/component-lab.secret` (mode `0600`, owner `lab`).
Create this owner-only component configuration:

```json
{"components":[{"jid":"gateway.ns-a.lab.test","secret_file":"/home/lab/northstar/secrets/component-lab.secret","connection":"accept","legacy_0114":true,"modern_0225":false}]}
```

Install it as `/home/lab/northstar/secrets/components-lab.json` with mode
`0600`. Add a temporary systemd drop-in on `ns-a`:

```ini
[Service]
Environment=COMPONENTS_ENABLED=true
Environment=COMPONENTS_CONFIG_FILE=/home/lab/northstar/secrets/components-lab.json
Environment=COMPONENT_BIND=127.0.0.1:5347
```

Restart only `ns-a` after confirming its frozen binary SHA-256 and service
configuration. Keep the listener on loopback. Copy
`scripts/local-vm-lab-component.py`,
`scripts/local-vm-lab-component-client.py`, and the matching
`scripts/integration-wsl.py` to `/home/lab/northstar/` on the guest. Run the
component from the same guest, using one evidence directory per candidate:

```sh
cd /home/lab/northstar
python3 local-vm-lab-component.py --self-test
python3 -c 'import importlib.metadata; print(importlib.metadata.version("slixmpp"))'
python3 local-vm-lab-component.py \
  --jid gateway.ns-a.lab.test --host 127.0.0.1 --port 5347 \
  --trusted-by alice@ns-a.lab.test \
  --secret-file /home/lab/northstar/secrets/component-lab.secret \
  --slixmpp-version VERSION_RECORDED_ABOVE \
  --events /home/lab/northstar/component-evidence/peer.jsonl \
  --ledger /home/lab/northstar/component-evidence/seen.sqlite3 \
  --seconds 600 --max-reconnect-attempts 10
```

Create `component-evidence` as a private directory before running. In a
second `ns-a` shell, send one marker through a real XMPP client connection:

```sh
cd /home/lab/northstar
python3 local-vm-lab-component-client.py --self-test
python3 local-vm-lab-component-client.py \
  --component-domain gateway.ns-a.lab.test \
  --password-file /home/lab/northstar/secrets/prosody-test-password \
  --fixture /home/lab/northstar/integration-wsl.py \
  --events /home/lab/northstar/component-evidence/client.jsonl
```

The client must receive the matching echo from
`echo@gateway.ns-a.lab.test`. The observer accepts the marker only in the
direct message body from that exact sender; a matching string elsewhere in
the XML is not delivery evidence. Retain both JSONL files, the SQLite ledger,
Northstar logs, the exact component configuration with secret values redacted,
binary and package hashes, UTC start/end times, and preflight output. Use a
different secret on a separate run and require authentication to fail before
any component message is routed. Keep the correct component disconnected for
that negative run so a duplicate-owner rejection cannot mask the wrong-secret
result.

The probe schedules at most `--max-reconnect-attempts` one-second reconnects
after unexpected disconnects; its JSONL records each attempt and subsequent
authentication. The timer ends the process at `--seconds`, and a normal stop
cannot schedule another reconnect. A server restart qualifies only if a new
`authenticated` event and a matching C2S echo follow it. Slixmpp itself does
not automatically reconnect in this probe; the bounded retry is harness code.

For restart, disconnect the component, queue a uniquely marked message, and
verify the `s2s_outbox` row remains. Restart the same Slixmpp process with the
same ledger, then require the echo and outbox drain. Repeat with a Northstar
process restart after admission. For a bounded paused-consumer check, send at
most 64 markers with the client script while the component process is paused
with `SIGSTOP`; record outbox depth, then `SIGCONT` it and require every
marker to return within the chosen deadline. Queue growth alone demonstrates
a paused consumer, not that a socket write reached kernel backpressure.
Keep this distinction in the result. The ledger reports any observed stable-ID
duplicate, but this procedure does not force the narrow write/completion
crash window and cannot prove duplicates never occur.

## XEP-0114 connect: Prosody as receiving server

[Prosody documents](https://prosody.im/doc/components) its XEP-0114
component listener. On the existing isolated Prosody guest, configure a
separate `Component "outbound.prosody.lab.test"` with a matching 32-byte or
longer `component_secret`. Bind the component listener to that guest's lab
address only, with no forwarding interface. Add a second Northstar credential
with `connection: "connect"`, `legacy_0114: true`, `modern_0225: false`, and
`connect_endpoint: "prosody.lab.test:5347"`. After both services restart,
record Prosody's authenticated component session and Northstar's
`outbound XEP-0114 component authenticated` event. Restart either process and
require a new authenticated session without a second simultaneous owner.

Prosody is a real receiving server for this handshake, but it is not a
gateway application behind that same component domain. This run qualifies
connect-mode authentication/reconnection only. The repository's strict
connect-mode fixture still covers routing, forged origins, and durable
delivery; independent end-to-end connect-mode gateway delivery remains open.

## XEP-0225 accept: Tigase as an independent component

Northstar accepts XEP-0225 connections; it does not initiate them. Its
configuration rejects `connection: "connect"` with `modern_0225: true`. The
XEP-0114 connect test above is a different protocol. Prosody and Slixmpp do
not supply this XEP-0225 peer, but [Tigase documents XEP-0225 external
component mode](https://docs.tigase.net/en/latest/Tigase_Administration/Components/_Components.html),
including a component that initiates a connection to another server. Tigase
is therefore a candidate independent peer, not yet a passed test.

After the soak ends, reuse the isolated `ejabberd` guest with ejabberd stopped
for this separate run. Pin the Tigase package, Java runtime and database
versions and record their digests before detaching the provisioning interface.
Repeat the six-guest isolation preflight. On `ns-a`, generate a fresh secret
with at least 32 random bytes (for example, `openssl rand -hex 32`), save it
in an owner-only file, and use an owner-only configuration containing only
this modern accept credential:

```json
{"components":[{"jid":"muc.ns-a.lab.test","secret_file":"/home/lab/northstar/secrets/tigase-component.secret","connection":"accept","legacy_0114":false,"modern_0225":true}]}
```

Set `COMPONENTS_ENABLED=true`, `COMPONENTS_CONFIG_FILE` to that file and
`COMPONENT_BIND` to `ns-a`'s `192.168.197.0/24` address on port 5347. Do not
combine this run with the loopback-only XEP-0114 accept credential: Northstar
rejects a non-loopback listener whenever a plaintext XEP-0114 accept profile
is present. Limit the VM firewall to the Tigase guest. Tigase must validate
the `ns-a.lab.test` certificate against the isolated lab CA; do not disable
peer-certificate or hostname verification. Record the truststore and selected
TLS version without copying private keys into evidence.

In Tigase's version-pinned `component` deployment, enable its MUC component
and `ext () {}` external-component connector. Use a separate local database;
Tigase's `ext-man` setup assumes a shared Tigase main-server database and
does not apply to Northstar. Configure `muc.ns-a.lab.test` as a `connect`
external component targeting `ns-a.lab.test:5347`, with protocol
`XEP-0225: Component Connections` and the same secret. Tigase's documented
one-time `etc/externalComponentItems` form uses `client` for this protocol:

```text
muc.ns-a.lab.test:<same-hex-secret>:connect:5347:ns-a.lab.test:client
```

Tigase imports and removes that one-time file at startup. It contains the
secret; keep it owner-only, use Tigase's supported configuration path for the
pinned version, and preserve a redacted copy in evidence before starting
Tigase. Do not assume the deployment worked just because both processes
started. Require Tigase's authenticated/bound session, Northstar's
`XEP-0225 component authenticated; hostname binding required` log, and a
fresh C2S response from the bound Tigase MUC domain. Copy
`scripts/local-vm-lab-component-0225-client.py` and the matching
`scripts/integration-wsl.py` to `ns-a`, create the evidence directory with
`install -d -m 700 /home/lab/northstar/component-0225-evidence`, then run:

```sh
python3 local-vm-lab-component-0225-client.py --self-test
python3 local-vm-lab-component-0225-client.py \
  --component-domain muc.ns-a.lab.test \
  --password-file /home/lab/northstar/secrets/prosody-test-password \
  --fixture /home/lab/northstar/integration-wsl.py \
  --events /home/lab/northstar/component-0225-evidence/client.jsonl
```

The observer sends one XEP-0030 query through a real Northstar C2S session
and requires an IQ result from the exact component domain advertising a MUC
identity and feature. It does not implement the component handshake itself.
Save the Tigase and Northstar logs, redacted configurations, TLS certificate
chain, package and binary hashes, preflight, UTC times and raw client JSONL.
Then test wrong-secret rejection with the valid peer stopped, plus component
and Northstar restarts followed by new successful queries. Stop Tigase,
restore the original Northstar component configuration and listener, and
repeat the isolation preflight. Multi-hostname bind/unbind and sustained
delivery under backpressure remain separate cases. Until this VM run is
recorded, the independent XEP-0225 interoperability gate stays open.
