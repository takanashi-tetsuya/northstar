# External component protocol evidence

This document records Northstar's implemented external-component profile and
the evidence required before changing its support labels. It is scoped to
[XEP-0114 v1.6](https://xmpp.org/extensions/xep-0114.html) and the Deferred
[XEP-0225 v0.2](https://xmpp.org/extensions/xep-0225.html). XEP-0225 remains an
experimental compatibility path; its presence is not a recommendation to use
it for a new production deployment.

## XEP-0114 profile

| Protocol requirement or boundary | Northstar behavior | Evidence |
| --- | --- | --- |
| `jabber:component:accept` stream | A separate, disabled-by-default listener accepts only a configured prepared domain and returns a complete receiving stream before either success or a stream error. Missing/malformed addressing, unknown hosts and duplicate domains fail closed. | `legacy_connection`; `component-runtime-wsl.py` unknown-host, missing-`to`, duplicate and invalid-namespace probes |
| Handshake | The proof is lowercase SHA-1 of the receiving stream ID followed by the shared secret. The supplied 20-byte proof is decoded strictly and compared in constant time. Missing, malformed or wrong proofs close the stream; credential I/O failure is logged separately and fails closed. | `verify_legacy_handshake`; `legacy_hex_decoder_is_strict`; `legacy_handshake_uses_stream_id_plus_mounted_secret`; runtime wrong-secret probe |
| `jabber:component:connect` stream | Northstar can initiate the historical connect namespace. In accordance with the XEP's initiator rule, its opening carries the exact component name in `from`; the receiver must return that name in `to`, may repeat only the same name in `from`, and must supply a bounded stream ID. | `outbound_component_supervisor`; `validate_legacy_connect_opening`; connect-mock forged-`to`/forged-`from` probes |
| Reconnect and capacity | Every configured outbound domain owns one bounded supervisor. DNS plus all connection attempts share one absolute deadline. Exponential backoff has bounded jitter, unsafe resolved addresses are rejected by default, and configuration cannot reserve more supervisors/listener capacity than `MAX_COMPONENT_CONNECTIONS`. | `connect_component_endpoint`; `validate_component_capacity`; SSRF/capacity unit tests; two-session reconnect fixture |
| Stanza authorization | `message`, `presence` and `iq` require syntactically valid `from` and `to`; the prepared `from` domain must be owned by that exact live connection. A component credential never grants S2S authority. Error stanzas are not reflected into loops. | `route_component_stanza`; `invalid_component_stanza`; anti-forgery, island-mode and remote-relay runtime probes |
| Disconnect | Registry entries are incarnation-bound. Disconnect cleanup removes the exact connection's MUC occupants and emits unavailable presence; a reconnect cannot remove a newer incarnation. | `unregister_connection`; `cleanup_component_muc`; drop-safe registry unit tests; MUC disconnect runtime probe |

XEP-0114's handshake does not provide transport encryption and uses historical
SHA-1 as prescribed by the protocol. The accept listener is therefore loopback
only by default. Outbound connect mode accepts private/loopback destinations by
default; resolving to a public address requires `allow_public_connect=true` on
that exact profile.

## XEP-0225 experimental profile

| Protocol requirement or boundary | Northstar behavior | Evidence |
| --- | --- | --- |
| Versioned stream and STARTTLS | The initial domain-only `from` and local `to` are validated before the server advertises required STARTTLS. Any non-STARTTLS frame is a policy violation. The identity and version are revalidated on every stream restart. | `modern_connection`; runtime unknown-host, old-version, STARTTLS-bypass and post-TLS identity-change probes |
| SASL | Only PLAIN is advertised, and only inside TLS. The auth element has an exact shape; authentication and optional authorization identities must both be the configured primary domain. Invalid mechanisms, malformed requests, bad credentials and temporary credential failures remain distinct. Three failed attempts close the stream. | `modern_plain_shape_is_valid`; `verify_modern_plain`; PLAIN unit tests; malformed/wrong/mechanism-ceiling runtime probes |
| Required bind | After SASL restart, the server advertises `<bind xmlns='urn:xmpp:component:0'><required/></bind>`. No hostname means no route authority, and an initial binding deadline prevents an authenticated idle stream from consuming capacity indefinitely. | `drive_component`; no-bind deadline runtime probe |
| Multiple hostnames | Each bind is restricted to the credential's exact configured domain/aliases. Duplicate or concurrently owned names return `conflict`; malformed, unconfigured and never-owned requests return the corresponding IQ error. Multiple configured hostnames may coexist on one connection. | `handle_hostname_binding`; multi-bind/conflict/unknown/unbind runtime probes |
| Unbind and cleanup | Before authority is removed, Northstar removes that hostname's MUC occupants. A cleanup failure returns `internal-server-error` and preserves the binding, avoiding a successful unbind with ghost occupants. Successful unbind immediately revokes stanza authority. | `handle_hostname_binding`; alias MUC unbind and post-unbind forgery runtime probes |

XEP-0225 permits a domain/resource hostname form but deliberately leaves its
routing semantics application-specific. Northstar rejects that optional form
with `not-allowed`; only domain hostnames are supported. SASL mechanisms other
than PLAIN are not part of this experimental profile.

## Durable delivery and restart boundary

Server-to-component messages use the bounded PostgreSQL federation outbox.
Claims are scoped to the domains bound by the exact socket and retain strict
per-domain ordering. A write failure releases the current row and every
remaining row in that claimed batch for retry. Crash/restart evidence uses a
fresh random PostgreSQL schema, queues both accept- and connect-mode messages,
kills Northstar after admission, restarts against the same schema, and verifies
that both transports drain their rows. The fixture always drops its isolated
schema on exit.

Neither XEP defines an application-stanza acknowledgement. A successful socket
write followed by a process or network failure can therefore be observed as an
ambiguous duplicate. Components must implement idempotent application handlers;
Northstar does not claim end-to-end exactly-once delivery.

## Configuration boundary

`COMPONENTS_CONFIG_FILE` is a bounded, non-symlink, owner-only (`0400` or
`0600`) JSON file. Unknown entry fields are rejected. Every entry must provide
exactly one of:

- `secret_file`: preferred for production, re-read and fingerprint-checked at
  every authentication boundary; or
- `secret`: intended for protected local/test configuration and retained only
  in zeroizing memory.

Both forms require 32–4096 bytes and reject NUL. Domain and alias claims are
globally unique. Connect mode requires `legacy_0114=true`,
`modern_0225=false`, and an exact `connect_endpoint`.

The optional Compose overlay is `deploy/docker-compose.components.yml`. It
publishes the host port only on `127.0.0.1` while binding inside the container,
and mounts both the protected configuration and secret. CI runs Compose config
validation; local validation requires a Docker installation.

## Reproducible checks

The focused evidence commands are:

```text
cargo test --locked components::tests
cargo test --locked config::tests::connect_
cargo check --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
bash -n scripts/component-runtime-wsl.sh
python3 -m py_compile scripts/component-runtime-wsl.py
bash scripts/component-runtime-wsl.sh
```

The runtime script is also called by both release-runtime runners and by the
PostgreSQL integration job in `.github/workflows/ci.yml`.

The isolated runtime suite passed on 2026-08-27. It drained the accept,
connect, and XEP-0225 component rows to zero after a forced server restart,
persisted the permitted federation handoff, stopped both server and mock peer,
and left zero `component_runtime_%` PostgreSQL schemas.

## Remaining interoperability boundary

- XEP-0114 remains a plaintext shared-secret protocol even though both of its
  historical connection directions are implemented.
- XEP-0225 remains Deferred and experimental. Only its domain-hostname,
  required-STARTTLS, SASL-PLAIN profile is implemented.
- The automated fixture is a strict protocol peer, not a substitute for a
  compatibility matrix against every third-party gateway.
- A transport write is not proof that a component application processed a
  stanza; retry ambiguity is unavoidable without an application-level receipt.
