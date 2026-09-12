# Northstar privacy model (LINDDUN)

Northstar minimizes identity and content exposure while preserving protocol
interoperability.  Bare/full JID scope is explicit; an occupant ID is derived
from a room-scoped secret and is not a global user identifier.  MAM and audit
queries require an authorization snapshot and retention policy.

| LINDDUN concern | Design response |
|---|---|
| Linkability | class-bound pseudonyms for logs; per-room occupant IDs; no raw tokens in telemetry |
| Identifiability | canonical JID validation and least-privilege views; real JID only in authorized non-anonymous MUC |
| Non-repudiation | audit/outbox correlation IDs and immutable legal-hold records |
| Detectability | private metrics listener/ACL and minimized abuse telemetry |
| Disclosure | TLS/mTLS, E2EE ciphertext retention, SecretBytes/SecretString boundaries |
| Unawareness | documented retention, export and deletion behavior in operator UI |
| Non-compliance | policy snapshots, retention classes, moderation appeal/audit trail |

The server cannot recover OMEMO plaintext and must not claim it can.  A web
client delivered by the same origin remains subject to that origin's release
chain; high-assurance deployments should distribute a separately signed
client.
