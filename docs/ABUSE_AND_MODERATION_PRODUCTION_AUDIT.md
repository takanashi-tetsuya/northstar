# Anti-Abuse and Moderation Production Audit

This document records the production audit of Northstar's registration,
authentication, messaging, proof-of-work, invitation, reporting, appeal and
moderation controls. It describes the behavior verified in the source tree; it
is not an independent security certification.

## Decision model

Anti-abuse state, proof-of-work challenges, replay state and cooldown penalties
are durable PostgreSQL records. Decisions use PostgreSQL `clock_timestamp()` so
cluster members do not make security decisions from unsynchronised application
clocks. Actor identifiers are stable HMAC values, not plaintext IP addresses,
JIDs or unsalted hashes. Challenge prefixes contain only a random challenge ID,
the action and random material.

Production deployments must mount a dedicated `ABUSE_STATE_HMAC_KEY_FILE`.
This key is deliberately independent of the FAST authentication token secret.
During a rotation, the former value may be mounted as
`ABUSE_STATE_HMAC_PREVIOUS_KEY_FILE`; Northstar merges the previous opaque actor
state into the current key space before advancing it. During overlap the old
key remains primary for challenge/message/offline artifacts so old-only nodes
can interoperate; the retiring phase fences those nodes and switches the primary
to the new key. PostgreSQL is revalidated by a security-critical worker, and a
mismatch cancels the entire service. Keep the previous key for at least the
30-day tombstone horizon and until the database reports no live old-key
challenge, message-admission, or offline-admission reference; a queued offline
row with no expiry can extend the rotation. Follow the exact query and rollout
in `PRODUCTION_OPERATIONS.md` rather than removing the key after a wall-clock
guess.

The default policies are:

| Action | Normal allowance | Escalation |
| --- | --- | --- |
| Registration | One attempt per window | Strict IP policy and invitation validation when enabled |
| Login/SASL | Five attempts | Account-primary failure penalty; shared IP is only a high-volume signal |
| Password/account change | Three attempts | Separate high-value-operation policy |
| Message | 60 per window (`ABUSE_MESSAGE_FREE_BURST`) | Operation `n` after the burst costs `n^2 * base` |
| Report | No free attempt | Proof-of-work starts at twice the base factor |
| Appeal | No free attempt | Eight times the base factor and at least a 15-second wait |

Escalation is stepwise and exponentially increasing. Intermediate steps add
hard waits (0, 2, 10, 30 and 120 seconds) so a spammer cannot bypass the policy
by adding compute. The configured global wait cap is applied. Cooldown removes
one step at a time rather than resetting an actor abruptly.

Authenticated traffic is account/device-behavior primary. A shared IP signal is
diluted 20:1, cannot copy an account penalty or hard wait to another account,
and is excluded from the single-use challenge sequence. This preserves a
high-volume circuit breaker while avoiding ordinary NAT-wide lockouts.
Registration remains intentionally IP-primary.

## Standards-compatible fallback and capable clients

Proof-of-work is a Northstar extension, not an XMPP standard. A standard XMPP
client needs no solver during the normal allowance. When it exceeds a policy it
receives the standard retryable `wait/resource-constraint` stanza error and can
continue after cooldown. SASL anti-abuse backend failures return
`temporary-auth-failure`; they are not misreported as an incorrect password.
Message and registration backend failures fail closed before the acceptance
boundary with standard retryable errors.

The HTTP/browser client can prefetch a challenge for registration, login,
message, password change, report or appeal, inspect the advertised work ceiling
and wait, solve it, and consume it once. A replay is rejected. The default
`POW_MAX_WORK_FACTOR` is the enforced ceiling. `POW_MAX_DEVICE_SECONDS=8` is an
operator calibration target, not a timing guarantee: device speed, thermal
throttling and solver implementation all affect runtime. Operators must
benchmark the slowest supported phone before changing the work factors.

PoW action intent v2 binds a challenge to the server-reconstructed method or
XMPP action, canonical path and pow-less body digest in addition to actor,
subject, work factor, issue/expiry times, random nonce and key generation.
Challenge deletion, actor advancement, the idempotent mutation or durable
message admission and its recovery marker remain one transaction. The
challenge endpoint receives only the digest, never the password, report text
or encrypted stanza. `POW_V1_COMPATIBILITY_UNTIL` is an explicit, expiring
migration exception; the default is v2-only. See
[`POW_INTENT_V2.md`](POW_INTENT_V2.md) for the canonicalization and cutover
contract.

## Invitations, registration and authentication

Invitation consumption, user creation and their audit entry commit in one
transaction. A rollback cannot consume a token without creating the account.
Plain, SCRAM-SHA-256, SCRAM-SHA-256-PLUS, SASL2 and FAST authentication paths
all enter the login policy. Failed passwords, malformed exchanges and invalid
proofs record failures. Database outages remain distinguishable in server
metrics and do not appear in logs as mass incorrect-password events.

Password changes and account removal enter a separate high-value-operation
policy. REST clients may submit a challenge solution; ordinary XMPP clients
retain the standards-only allowance and retryable error behavior.

## Report evidence and appeals

A report references between 1 and 20 personal archive rows. In the report
transaction Northstar proves that each row:

1. exists in the reporter's own archive;
2. belongs to the conversation with the reported bare JID; and
3. matches an optional client message identifier when one is supplied.

The archive stanza is the authority for the sender, timestamp, message ID,
encryption marker and plaintext body. Northstar stores the archive row ID and a
SHA-256 digest of the archived stanza. Client-supplied plaintext cannot replace
ordinary archived plaintext.

OMEMO is an explicit limitation: the server can prove and hash the archived
ciphertext, but cannot verify user-decrypted plaintext. Such text is labeled
`user_decrypted_omemo_unverified`; historical evidence created before this
model remains labeled `legacy_client_submitted_unverified`. Neither label is a
claim that the server verified encrypted plaintext.

A reporter may appeal a terminal result once. The database uniqueness
constraint, ownership check and row locks enforce this under concurrency.
Administrator transitions use a serialized state machine; terminal cases
cannot be silently reopened. Report creation, appeal creation and moderation
transitions write their audit entries in the same transaction as the state
change, so an audit write failure rolls back the operation instead of returning
a false failure after a committed change.

## Retention, bounds and operations

`MODERATION_RETENTION_DAYS` defaults to 365; zero disables automated moderation
purging. A terminal report becomes eligible only when its latest appeal is also
terminal and older than the cutoff. Pending/reviewing and recently resolved
appeals retain the case. Evidence and appeals cascade when an eligible case is
removed; the operator audit trail remains subject to its separate legal and
operational retention policy.

Cleanup uses bounded batches (maximum 10,000) and `SKIP LOCKED`. Anti-abuse
maintenance removes at most 1,000 expired rows from each state table per tick.
No proof search or imposed wait is performed inside a database transaction; the
server verifies only the submitted digest and makes a short atomic decision.

Monitor:

- `xmpp_anti_abuse_backend_failures_total` (a supplied alert fires on any
  increase over five minutes); and
- `xmpp_retention_moderation_cases_deleted_total`.

## Verification evidence

The following gates passed on 2026-08-26:

- `cargo fmt --all -- --check`;
- all-target compilation;
- 344 Rust tests passed and 26 explicitly environment-gated tests were skipped;
- strict Clippy with warnings denied;
- JavaScript syntax validation for the browser client and PoW worker;
- OpenAPI and Docker Compose YAML parsing plus abuse-secret mount assertions;
- production-secret generation, ownership and mode regression tests as WSL
  root; and
- tracked-secret scanning (the only private-key-shaped text is an intentional
  invalid test fixture in `src/tls.rs`).

The isolated PostgreSQL suite additionally passed:

- durable single-use challenge consumption, replay rejection, restart safety,
  HMAC rotation and bounded cleanup;
- 1,000 independent durable actor decisions in 1.78 seconds in an unoptimised
  WSL build (about 562 decisions/second); and
- report evidence binding, concurrent terminal moderation, one-appeal
  enforcement and moderation retention/cascade behavior (1.20 seconds).

These figures validate behavior and provide a regression baseline; they are not
a production capacity guarantee. Load tests on the final deployment topology,
phone-specific PoW calibration, PostgreSQL monitoring and an independent
security review remain required before treating the service as hardened for an
untrusted public Internet deployment.
