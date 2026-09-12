# Migration ledger: `northstar-xep-0215`

## Scope

This crate extracts the capability-free portion of XEP-0215 External Service
Discovery: strict and bounded request parsing, canonical service identities,
public discovery/push builders, credential-response builders with redacted
secret values, extended data forms and deterministic selection plans.

## Legacy mapping

| Legacy location | Extracted responsibility |
| --- | --- |
| `src/xmpp/protocol/extdisco.rs::external_services` | `parse_iq`, `select_services` and `build_services_result` |
| `src/xmpp/protocol/extdisco.rs::parse_credential_requests` | canonical `CredentialsRequest` parsing and bounds |
| `src/xmpp/protocol/extdisco.rs::service_element` | safe public, push and credential response builders |
| `src/services/extdisco.rs` | remains the provider adapter for rate limits, time and TURN credential derivation |
| `src/config.rs` STUN/TURN records | application adapter converts validated configuration to `PublicService` |

## Authority boundary

This crate has no network, DNS, database, session, clock, randomness, HMAC or
long-term secret access. It cannot decide whether a requester is authenticated
or permitted to receive a service. `plan_credential_matches` returns only
configured public identities. The application service must authorize the bound
account and target, rate-limit issuance, obtain time and invoke the credential
provider after a match.

Public discovery and push builders accept only `PublicService`; adding a
password to those responses is impossible through their API. Credential
responses require `CredentialedService`. Password storage is zeroized and its
`Debug` representation is always redacted. The actual TURN shared secret never
enters this crate.

## Protocol decisions

- Service types and transports use bounded XML NCName-like tokens and remain
  case-sensitive registry values.
- DNS hosts are RFC 7622/IDNA-canonicalized; IPv4 and unbracketed IPv6 literals
  are stored as typed addresses.
- Credential selectors accept `transport` in addition to the specification's
  required host/type and optional port. This retains Northstar's existing
  narrowing extension while never allowing credential values in a request.
- Extended service information is represented as bounded XEP-0004 result
  fields; arbitrary pre-rendered XML is not accepted.
- XEP-0082 expiry values must parse as dateTime and end in `Z`; offset-local
  timestamps are rejected.

## Integration steps

1. Remove the temporary crate-local `[workspace]` and add the crate to the root
   workspace.
2. Convert configured STUN/TURN endpoints into immutable `PublicService`
   records during startup.
3. Replace protocol-local parsing/building with this crate and map typed errors
   to stanza conditions.
4. Introduce an external-services application port for requester authorization,
   configured-record snapshots and credential issuance.
5. Keep the TURN shared secret and HMAC implementation private to the provider
   adapter; pass only short-lived `ServiceCredentials` to the response builder.
6. Persist or explicitly scope rate-limit state according to deployment mode;
   the wire crate must not own actor storage.
7. Delete the legacy parser/builders only after discovery filtering,
   credential issuance, multi-resource push and secret-log tests pass.
