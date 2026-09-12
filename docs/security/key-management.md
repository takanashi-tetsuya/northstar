# Key-management boundary

Northstar treats key material as a provider capability, not as application
configuration. Services receive a short-lived operation result or an opaque
provider handle; they never read a master key, private signing key, or HMAC
secret from `.env`, a database row, or an HTTP request.

## Provider contract

The `foundation-kms` crate defines the provider-neutral interfaces:

- `Signer` signs assertion, registry, audit, or federation payloads by `key_id`.
- `AeadKeyProvider` seals and opens data with associated data binding. The
  wire format and nonce policy belong to the selected KMS/HSM adapter, not to
  the protocol handlers.
- `HmacKeyProvider` computes and verifies short-lived internal MACs such as
  dialback or upload-token proofs.

The interfaces return `KmsError` and fail closed when a key is missing,
revoked, expired, or rejected. They do not expose key bytes.

## Key classes and ownership

Every key has a stable class, owner service, region, environment, algorithm,
creation time, and rotation deadline. The authoritative inventory is
[`catalog/key-classes.yaml`](../../catalog/key-classes.yaml). A key is never
shared merely because two services happen to run in the same PostgreSQL
cluster; sharing requires an explicit provider policy and a separate audit
record.

The supported lifecycle is:

```text
Creating -> Active -> Retired -> Destroyed
                  \-> Revoked -> Destroyed
Retired ----------> Revoked
```

Transitions are monotonic. Rotation creates a new key before retiring the old
one. Verification consumers may accept the retired key only during the
provider's bounded grace window; revoked and destroyed keys are rejected
immediately. Signing always selects the current active key.

## Runtime and deployment rules

- Production adapters must use an external KMS, HSM, or workload-identity
  signer. Cloud-specific clients belong behind `foundation-kms` and are not
  imported by protocol crates.
- SPIFFE/SVID identity authorizes the service to request an operation. A
  service identity alone does not authorize every key class.
- Key identifiers, status, rotation and verification failures are safe audit
  metadata. Key bytes, plaintext, MACs, signatures and provider credentials
  are never logged.
- Backup and restore preserve encrypted ciphertext and metadata only. A
  restore must reacquire active keys from the provider before accepting
  traffic; it must not restore key bytes from the database dump.
- The optional `foundation-kms/memory` provider is compiled only for local
  development tests. It is not enabled by default and is prohibited in a
  production artifact.

## Operational rotation

1. Create and attest the replacement key in the provider.
2. Publish metadata and a signed control-plane change for the owning service.
3. Activate the replacement and retain the previous key for the documented
   verification grace period.
4. Observe signature/MAC failures and replay metrics while both keys are
   accepted.
5. Retire, then revoke the old key after all valid envelopes and tokens have
   expired. Destroy only after the retention and incident-response holds are
   clear.

The application must fail readiness for a missing required active key rather
than silently generating a process-local replacement.
