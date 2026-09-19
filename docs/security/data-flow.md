# Northstar security data flow

```text
C2S/S2S/Admin client
        │ TLS/mTLS, bounded XML
        ▼
XMPP Edge ── signed AuthGrant/SessionAssertion ──► Identity/Session authority
        │                                             │ private DB + KMS
        ▼                                             ▼
Message Ingress ── one DB transaction ──► accepted_message + outbox
        │                                             │ at-least-once event
        ▼                                             ▼
Delivery Router ──► Edge stream ──► socket       MAM / Federation / Push
        │                                             │ private stores
        └──────────────► event inbox/idempotent effects
```

Edge owns sockets and XML only.  Ingress owns message admission and identity;
Delivery owns per-target tasks and ACKs; MAM owns history; Federation owns the
S2S outbox; Registry owns signed capability snapshots.  Services never query
another service's database.  Every durable write and its outbox record share a
transaction; consumers claim/complete inbox entries in their own transaction.

Data classes are: secret (credentials, tokens, keys), private (message and
contacts), operational (bounded IP/metrics), and public capability metadata.
Secrets are zeroized and never logged; private data is encrypted/retained by
policy; operational data is minimized and expires; public snapshots are signed
and versioned.
