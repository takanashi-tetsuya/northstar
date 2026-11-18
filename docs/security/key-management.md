# Key management

Northstar runs as one server binary: the standalone process, or the core and
maintenance subservers. It has no KMS or HSM client. Each process reads its
key material at startup from mounted files that the operator owns. This
document describes:

- which keys exist;
- how they are loaded;
- how they are kept apart;
- where each rotation procedure lives.

## Loading rules

Every secret is configured by a `*_FILE` variable that names a mounted file.
`northstar_security::secret_files::read_secret_file` refuses to start the
process when the file:

- is a symlink;
- is not a regular file;
- is empty or larger than 64 KiB;
- has permissions other than `0400` or `0600` (on Unix).

Production files live outside the source checkout. The default location is
`/etc/northstar/secrets`, created by `scripts/create-production-secrets.sh`.
That script requires a root-owned `0700` parent directory and never prints a
secret value.

Some variables also have an inline form for tests, such as
`DIALBACK_SECRET`. Production uses the file form only.

A process never generates a replacement for a missing production key.
Process-local ephemeral keys exist only for the development deployment
shape: every listener on loopback, no Redis, a reserved `localhost`,
`*.localhost` or `*.test` domain, and that key's explicit opt-in switch.
Enabling one ephemeral switch does not enable any other.

## Key inventory

| Variable | Purpose | Rotation |
| --- | --- | --- |
| `FAST_TOKEN_SECRET_FILE` | Authenticates and encrypts XEP-0484 FAST token state | Rotating it revokes issued FAST tokens |
| `DUMMY_SCRAM_SECRET_FILE` | Derives dummy SCRAM salt and verifier material for unknown accounts | No credential or token effect |
| `DIALBACK_SECRET_FILE` | XEP-0220 Dialback key generation | Rotate during a controlled reconnect window |
| `ABUSE_STATE_HMAC_KEY_FILE`, `ABUSE_STATE_HMAC_PREVIOUS_KEY_FILE` | HMAC over durable anti-abuse state | Three-phase rolling rotation with `ABUSE_STATE_HMAC_KEY_EPOCH` |
| `CLUSTER_SIGNING_PRIVATE_KEY_FILE`, plus previous and staged-next public keys | Ed25519 signatures on Redis control-plane commands | Prepare, activate, retire with `CLUSTER_SIGNING_KEY_EPOCH` |
| `API_CONTROL_SECRET_FILE`, `API_CONTROL_PREVIOUS_SECRET_FILE` | Root of the REST idempotency and pagination-cursor keyrings | Current and previous secret overlap |
| `TURN_SHARED_SECRET_FILE` | XEP-0215 TURN credential derivation | Coordinate with the TURN server |
| `METRICS_BEARER_TOKEN_FILE`, `WEB_ADMIN_GATEWAY_TOKEN_FILE` | Bearer tokens for `/metrics` and the web administration gateway | Replace and restart |
| `UPLOAD_S3_*_FILE` | Object-store credentials and optional SSE-KMS key ID | Provider-managed |

Database connection strings (`*_DATABASE_URL_FILE`), the Redis URL, TLS
private keys and external-component secrets are mounted the same way. Their
details are in
[production operations](../PRODUCTION_OPERATIONS.md) and
[upload storage](../UPLOAD_STORAGE.md).

## Separation

Each capability has its own secret. Never copy one secret into another file,
derive it from another secret or from a database password, or share it
between capabilities.

The checks that enforce this:

- The secret generator rejects any two independent secrets with the same
  value, and the production preflight rejects exact reuse.
- Configuration loading rejects a web-administration gateway token that
  equals any other mounted secret.

PostgreSQL never stores key material:

- The anti-abuse key generation is recorded only as purpose-separated
  96-bit identifiers.
- The cluster key authority never stores a private key.

Logs and audit records may contain key identifiers, epochs and
verification outcomes. They never contain key bytes, MACs, signatures or
provider credentials.

## Rotation

Each key with overlap support follows the same order:

1. Mount the new key as current and the old key as previous.
2. Advance the epoch where the key has one, and roll every node.
3. Retire the previous key only after every value it protected has expired.

For the anti-abuse and cluster keys, each node checks the epoch against
PostgreSQL. A node with an unrelated key or a skipped epoch fails closed
instead of serving.

The exact procedures:

- anti-abuse HMAC key:
  [production operations](../PRODUCTION_OPERATIONS.md#durable-anti-abuse-state-and-calibration);
- FAST and dummy-SCRAM keys:
  [authentication key separation](../PRODUCTION_OPERATIONS.md#authentication-key-separation);
- Dialback secret:
  [federation credentials](../PRODUCTION_OPERATIONS.md#federation-credentials);
- cluster signing keys: [clustering](../CLUSTERING.md);
- backup signing and encryption keys:
  [backup security](../BACKUP_SECURITY.md).

## Backup and restore

Database backups do not contain the mounted secrets. A restored deployment
must mount the same secret files, or rotate them, before it serves. Back up
the secret directory separately, as the release checklist requires.
