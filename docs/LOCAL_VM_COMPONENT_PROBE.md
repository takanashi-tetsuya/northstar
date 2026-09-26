# Local VM external-component probe

This probe uses an independent XEP-0114 implementation on the isolated lab
network. Run it only after the release candidate, guest packages, and binary
hashes are frozen, and after any running soak has stopped. Keep the existing
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
  --seconds 600
```

Create `component-evidence` as a private directory before running. In a
second `ns-a` shell, send one marker through a real XMPP client connection:

```sh
cd /home/lab/northstar
python3 local-vm-lab-component-client.py \
  --component-domain gateway.ns-a.lab.test \
  --password-file /home/lab/northstar/secrets/prosody-test-password \
  --fixture /home/lab/northstar/integration-wsl.py \
  --events /home/lab/northstar/component-evidence/client.jsonl
```

The client must receive the matching echo from
`echo@gateway.ns-a.lab.test`. Retain both JSONL files, the SQLite ledger,
Northstar logs, the exact component configuration with secret values redacted,
binary and package hashes, UTC start/end times, and preflight output. Use a
different secret on a separate run and require authentication to fail before
any component message is routed. Keep the correct component disconnected for
that negative run so a duplicate-owner rejection cannot mask the wrong-secret
result.

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

## XEP-0225 boundary

[Prosody's support matrix](https://prosody.im/doc/xeplist) says it does not
support XEP-0225. Slixmpp's documented `ComponentXMPP` implements the
XEP-0114 component path. The current strict peer fixture exercises Northstar's
XEP-0225 STARTTLS, SASL PLAIN, hostname bind/unbind, restart, and malformed
requests, but is not independent interoperability evidence. Keep this part of
`EXT-COMPONENT` open until a version-pinned independent XEP-0225 component is
available and run in the isolated lab.
