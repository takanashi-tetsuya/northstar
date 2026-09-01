# One-time browser OMEMO device transfer

Northstar does not escrow OMEMO private keys. Its browser client can instead
**move one existing browser device** to another browser through a local,
passphrase-encrypted package. This is deliberately not advertised as a reusable
backup: restoring two copies of a moving Double Ratchet state can reuse one
OMEMO device identity on divergent ratchets and weaken forward-secrecy and
message-ordering assumptions.

## What crosses the server boundary

The encrypted package is downloaded by the source browser and read locally by
the destination browser. It is never uploaded to Northstar. PostgreSQL stores
only:

- the account and source device identifiers;
- a monotonically increasing transfer generation;
- a client-generated transfer UUID;
- SHA-256 of the final encrypted package;
- a SHA-256 commitment to a client-generated 256-bit destination secret;
- a SHA-256 digest of a separate, account/transfer-bound source poll capability,
  plus lifecycle timestamps.

The server never receives the transfer passphrase, Argon2id output, AEAD key,
package ciphertext or a digest of the plaintext/private state. These metadata
still reveal that an account prepared or completed a device move and must be
covered by the deployment's normal database-access and retention policy.

## Package format and cryptography

Version 1 is canonical JSON bounded to 44 MiB. Its authenticated header binds
the format/version, canonical account, transfer UUID/generation, source OMEMO
device ID, creation/expiry times and the exact cryptographic profile:

- Argon2id v1.3 (`m=65536 KiB`, `t=3`, `p=1`, 32-byte output);
- a random 16-byte salt;
- AES-256-GCM with a random 12-byte nonce and 128-bit tag;
- the complete canonical header as AEAD additional authenticated data.

The passphrase is independent of the account password, has a minimum of 12
Unicode characters and is never retained in application state. JavaScript
strings cannot be reliably erased, but the UI clears every password field
immediately after use and overwrites its encoded and derived byte arrays where
the platform permits. The pinned `hash-wasm` 4.12.0 Argon2id distribution,
tarball, license, SBOM and hashes are verified by CI; its upstream toolchain is
not claimed to be source-reproducible. See
[WEB_CRYPTO_SUPPLY_CHAIN.md](WEB_CRYPTO_SUPPLY_CHAIN.md).

The plaintext contains the exact source device state needed for a move,
including private identity/prekeys and current ratchets. This lets the moved
device continue to decrypt whatever its current ratchet state can legitimately
decrypt; it cannot reverse forward secrecy or recover already-discarded keys.
The parser rejects unknown package fields, altered KDF parameters, noncanonical
Base64url, wrong account/device/generation, expiry, oversized data, excessive
nesting and dangerous object keys before installation.

Argon2id, AES-GCM, UTF-8 conversion and package JSON work run only inside a
short-lived dedicated module Web Worker. The main thread applies a conservative
working-set model before creating the worker: it combines the 64 MiB Argon2
allocation with a four-times package/state expansion and at most 20% of
`navigator.deviceMemory` (with fixed 128–512 MiB bounds). A browser without
Worker support, or a package that exceeds that device budget, fails closed.
Worker crashes terminate the operation, transferred input buffers are erased
where the platform permits, and passphrases are never returned to the main
thread. Export can be cancelled after the source is frozen; cancellation and a
two-minute hard deadline terminate the worker and leave the durable marker
frozen rather than resuming an uncertain ratchet. JavaScript strings remain
subject to the platform erasure limitation.

## Transaction and rollback fence

Migration `0093_omemo_recovery_transfer.sql` gives each account one active
transfer and a permanent consumed-generation high-water mark. The flow is:

1. the source first acquires a browser-wide exclusive Web Lock, records the
   authenticated consumed-generation baseline, and durably freezes its ratchets
   with the transfer ID and a random 256-bit poll secret;
2. the authenticated source allocates a generation for its current device. The
   server stores only a poll-secret digest bound to the account and transfer;
   the secret is explicitly removed from the encrypted destination snapshot;
3. it records the generation in sealed local state, encrypts the package
   locally and seals only its SHA-256 on the server;
4. the destination authenticates and decrypts locally, checks account, expiry,
   digest and the prepared server record, then explicitly confirms replacement;
   before any destructive action it also validates the exact state schema
   version, top-level fields, device identity, Curve25519 key-pair lengths,
   signed/prekey counts and timestamps, and decodes every serialized Double
   Ratchet record through the pinned libomemo adapter. Unknown future state
   versions, noncanonical sessions, malformed ratchet key material and unsafe
   complexity fail closed;
5. **before** retracting or deleting anything, the destination commits an
   independent IndexedDB replacement journal containing only the destination
   commitment and public transfer metadata. It then retracts and erases its
   temporary device, stores the moved state under a new non-exportable local
   AES wrapping key, and consumes using the 256-bit secret;
6. in that same PostgreSQL transaction Northstar revalidates the exact API
   session and authorization generation, advances the durable high-water mark,
   increments `auth_generation`, records only the destination commitment, and
   invalidates prior API, FAST and resumable XMPP credentials;
7. post-commit teardown disconnects only sessions authenticated below that
   generation cutoff, locally and across the cluster. An exact replay never
   disconnects a destination that has since authenticated at the new generation;
8. every browser holding a transferred marker checks the high-water mark before
   initialization, reconnect publication and message processing. A source with
   an absent/mismatched consumer is fenced, drains writes and erases its sealed
   state, wrapping key and encrypted outbox.

The browser records these crash-recovery phases explicitly in sealed state and,
for replacement, in the independent journal: `source-frozen`,
`server-prepared`, `package-sealed`, `destination-installed`,
`consume-uncertain`, `consumed-confirmed`, and `retirement-complete`. Login
reconstructs authority from those records instead of assuming logout rolled an
operation back. The account-wide Web Lock remains held while the destination
retires its temporary device, installs the moved ratchet, and either confirms
consume or reaches a durable fail-closed uncertain state; another tab therefore
cannot advance or republish the replaced state in that window.

If the browser crashes after the local source marker commits but before server
prepare commits (or before its response arrives), login retains the authenticated
session and reconstructs a frozen recovery screen. It checks the exact transfer
first. An existing row supplies the missing generation and resumes observation;
an absent row permits local cancellation only when the permanent high-water is
still equal to the baseline sealed before the freeze. Anonymous poll `404` is
never interpreted as permission to unfreeze. Preparing and prepared transfers
remain visible and cancellable instead of entering generic login failure and
token revocation.

If the high-water advanced beyond that baseline, a matching latest transfer ID
proves that this source was consumed and triggers fail-closed key erasure. An
advance attributed to another transfer leaves the browser in the explicit
`authority-advanced` locked state; it is neither silently re-enabled nor routed
through generic logout. Local reinitialization is allowed only after server
authority proves that this device is retired.

The browser does not retain a second plaintext or encrypted copy of a downloaded
package. Consequently, recovery of a prepared transfer cannot regenerate bytes
under its immutable digest. To download again, the authenticated source first
revokes that transfer, observes revoked authority with no high-water advance,
then allocates a fresh UUID/generation and seals a fresh package while retaining
the same account Web Lock and frozen source ratchet. The authority watcher and
reconnect path are paused first. Clearing its timer is not sufficient: the
browser advances a watcher epoch, marks the recovery transition active and
awaits any callback already inside an authority request. That callback checks
the epoch, transfer ID and transition flag after every asynchronous boundary and
before marker deletion, readiness changes, retirement or reconnect; stale work
exits without committing state. A dedicated marker-replacement operation
quiesces every ratchet producer, verifies the old row is revoked and the
high-water has not advanced, then replaces the old marker with the new frozen
marker in one sealed write; it never calls the generic revoked path that would
temporarily delete the marker or set `ready=true`. Polling resumes only after
that write. A crash therefore observes either the old marker or the new marker,
never an unfrozen gap, and a failed new prepare leaves the new marker recoverable.

The high-water mark survives cleanup of terminal request rows, so a source that
was offline longer than the transfer-row retention period cannot resurrect.
Exact same-secret/digest retries are accepted; a second consumer, changed
digest, stale generation, expired package or newer transfer fails closed.
Per-account terminal rows are bounded, and expiry/terminal cleanup runs through
the supervised retention worker.

A different prepare UUID cannot silently replace an active package; the user
must explicitly revoke it or wait for expiry. This prevents another endpoint
holding the same REST bearer from invalidating an in-flight package merely by
allocating a newer one.

## Trust reset and failure handling

Import preserves ratchet material but converts every cached remote identity to
explicitly untrusted state, clears deferred automatic-trust messages and blocks
outbound content-key distribution until the user re-verifies fingerprints.
The destination's old encrypted outbox is erased because those ciphertexts were
created by the replaced device state.

If local installation succeeds but server consumption is definitively rejected,
the destination copy and its wrapping key are erased and the user must sign in
to create a fresh temporary device before retrying. If the HTTP result is
uncertain, the independent replacement journal prevents the old destination
from reviving and the sealed moved state remains frozen until the user signs in
again. Its sealed marker retains the consumer secret only until an authenticated
authority check confirms the commitment; it then durably drops the secret. On
that next authenticated login the destination first replays the exact consume
with its sealed 256-bit secret, then decides the result using the exact transfer
record and permanent high-water mark. A lost HTTP response is therefore not
treated as either success or rollback.

Bundle retirement is followed by bounded read-after-write convergence of the
device list. This removes a stale ID republished concurrently by another
endpoint after its private bundle has already been retracted; failure to
converge blocks completion instead of leaving a silent ghost device.

Consumption intentionally revokes the source's ordinary bearer, so the source
does not poll with that stale credential. It uses the separate read-only
capability, which returns only state and generation, supports repeated reads
after a lost response, and expires no later than 24 hours after terminal state
or 24 hours after normal transfer expiry. A consumed result causes local key
and outbox erasure. Revoked/expired results safely unfreeze the source. The
capability secret remains only in the sealed source marker and is never placed
inside the exported package.

The public poll path resolves client IPs with the same explicit trusted-proxy
policy as the rest of the HTTP API. It applies a 30-request sliding one-minute
window per resolved IP, caps active window keys, and uses an independent global
four-request semaphore before its single indexed PostgreSQL lookup. The lookup
uses a fail-closed, isolated two-connection pool and a 1.5-second statement
timeout, so public polling cannot consume the primary application pool. Aggregate
request, rate-limit, concurrency-rejection and uniform-not-found counters are
fixed-cardinality metrics and never contain IPs, accounts or transfer IDs.

## Security and availability limits

- Possession of the file plus its passphrase grants the private capabilities of
  that OMEMO device. Transfer through an authenticated out-of-band channel,
  import it once, then securely delete every copy.
- A weak passphrase remains susceptible to offline guessing; server-side rate
  limits cannot protect a stolen local package.
- The serving web origin remains in the browser E2EE trust base and could serve
  modified JavaScript. High-risk deployments should use an independently
  installed, signed and reproducible client.
- The server can fence network use and instruct the bundled browser to erase;
  it cannot prove physical erasure on an offline, copied or modified client.
- This feature moves a Northstar browser device only. It is not an XMPP XEP and
  does not import arbitrary Gajim/Conversations/Dino/Monal databases.
- Full browser, two-device and crash-boundary validation remains a release gate
  until a dated result is recorded for the exact release artifact and isolated
  environment; having the harness in the repository is not execution evidence.

Pure CI checks exercise package round-trip, wrong-passphrase authentication,
account binding, fixed KDF parameters, size limits, server high-water wiring and
the pinned artifact hashes. PostgreSQL race/idempotency fixtures are present but
remain ignored unless an isolated test database is explicitly supplied.
