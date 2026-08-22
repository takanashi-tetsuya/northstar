# XMPP compatibility matrix

This matrix is the compatibility boundary for Northstar 0.1. `Core` means the implemented profile is suitable for normal use and has automated protocol coverage. `Partial` means a useful, tested subset exists but the standard contains additional behavior or still needs broader third-party interoperability testing. Transparent stanza forwarding alone is not counted as semantic support.

| Standard | Status | Implemented scope and boundary |
| --- | --- | --- |
| RFC 6120 | Partial | Client XML streams, mandatory STARTTLS, SASL SCRAM-SHA-256 plus PLAIN inside TLS, resource binding, IQ/message/presence, stanza limits; full PRECIS and the complete error matrix remain |
| RFC 6120 S2S | Partial | DNS SRV plus fallback, STARTTLS, PKIX domain validation, mutual certificate proof, SASL EXTERNAL and one bounded pooled stream per remote domain; no dialback or durable retry spool |
| RFC 6121 | Partial | Local and federated one-to-one routing, durable roster/subscription state, presence, and highest non-negative resource-priority selection |
| RFC 7395 | Core | XMPP framing over WebSocket with the `xmpp` subprotocol and fragmented UTF-8 handling |
| XEP-0030 | Core | Server, MUC, room and upload service discovery with explicit feature lists |
| XEP-0045 | Partial | Local room discovery/create/join/leave, nickname collision, occupant roster, mediated/direct invitations, group/private messages, subject, room configuration, owner destroy, affiliation/role lists, kick/ban and encrypted join history; password rooms, the complete status/error matrix and federated MUC remain |
| XEP-0049 | Partial | Durable private XML get/set for one namespaced child per request; per-item size limits apply and no per-user quota is implemented |
| XEP-0054 | Partial | Durable `vcard-temp` get/set, including photo data, locally and across federation |
| XEP-0059 | Partial | Stable `before`/`after` paging, count and index for MAM |
| XEP-0060 / XEP-0163 | Partial | Persistent PEP publish/retrieve and roster event fan-out for OMEMO and avatar nodes; not a general-purpose PubSub service |
| XEP-0077 | Partial | TLS-only in-band account registration and authenticated password change; in-band registration is not advertised when administrator invitation tokens are mandatory; account removal remains |
| XEP-0084 | Partial | Browser avatar publication/retrieval through avatar data/metadata PEP nodes, plus vCard fallback |
| XEP-0092 | Core | Software version |
| XEP-0160 | Partial | Local and federated offline messages; encrypted-only under the default policy |
| XEP-0184 | Pass-through | Receipts are routed and archived inside the encrypted envelope; no server-generated receipt state |
| XEP-0191 | Partial | Durable blocklist get/block/unblock/unblock-all, multi-resource pushes, inbound/outbound local and federated enforcement, presence suppression |
| XEP-0198 | Partial | Counters, `r`/`a`, configurable in-memory resumption and unacknowledged replay; MUC occupancy is not resumed and state does not survive process restart |
| XEP-0199 | Core | XMPP Ping |
| XEP-0202 | Core | Entity Time |
| XEP-0203 | Partial | Delay stamps on MAM, offline and MUC history delivery |
| XEP-0280 | Partial | Per-resource enable/disable, sent/received forwarding and private-message exclusion |
| XEP-0313 | Partial | Encrypted archive, query form, `with`/`start`/`end`, stable RSM paging and metadata; configurable archive preferences remain |
| XEP-0333 | Pass-through | Chat markers are routed; read-state indexing remains client-side |
| XEP-0334 | Partial | `no-store` and `no-permanent-store` prevent archive/offline persistence |
| XEP-0357 | Partial | Enable/disable and metadata-minimized summary publish locally or over S2S. The XEP itself is Deferred/experimental and requires an external push service |
| XEP-0363 | Core | Stable 1.2 slot discovery/request, advertised size, opaque bearer header, exact size/type validation, expiring one-use PUT and immutable GET; local disk backend is replaceable |
| XEP-0384 | Partial | Browser OMEMO 2 (`urn:xmpp:omemo:2`) device lists, bundles, X3DH/Double Ratchet sessions, fingerprint/TOFU UI, one-to-one and group encryption; wider native-client interoperability and key backup remain |
| XEP-0389 | Partial | Pre-authentication registration form and credential submission for ordinary open registration; invitation-token and PoW fields are not carried by this protocol path |
| XEP-0420 | Partial | Browser Stanza Content Encryption envelopes protect body and attachment metadata inside OMEMO |
| XEP-0444 | Pass-through | Reactions can be carried in encrypted content; no server-side reaction index |

## Federation security profile

Northstar intentionally does not implement XEP-0220 Server Dialback. Federation uses the stronger RFC 6120 STARTTLS plus SASL EXTERNAL path with certificate-chain and asserted-domain verification. Operators can apply exact or wildcard allow/deny lists. DNS results resolving to loopback, private, link-local, multicast or other special-use addresses are rejected unless explicitly enabled for a controlled test network.

## Honest limits

XMPP has hundreds of optional extensions, so “all XMPP features” is not a finite compatibility claim. A feature moves to `Core` only after its implemented profile has automated tests and the relevant interoperability boundary is documented here.
