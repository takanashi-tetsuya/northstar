# Proof-of-work action intent v2

Northstar PoW is a private anti-abuse extension, not an XMPP standard. Version
2 makes a challenge a one-use commitment to one exact operation instead of a
transferable payment for any operation in the same broad action class.

## Challenge request

`POST /api/v1/anti-abuse/challenge` accepts the ordinary `action` and login
identity fields plus:

```json
{
  "intent": {
    "version": 2,
    "method": "POST",
    "path": "/api/v1/reports",
    "body_sha256": "unpadded-base64url-sha256"
  }
}
```

Only the 32-byte digest is submitted. Passwords, invitation tokens, report
text, decrypted evidence, OMEMO envelopes and message contents are never sent
to the challenge endpoint. TLS and the normal bearer policy still apply.

The server accepts only an uppercase `POST`, `PATCH` or `XMPP` method and an ASCII,
absolute, query-free canonical path. Each action has a closed route set:

| Action | Method and canonical path |
| --- | --- |
| registration | `POST /api/v1/register`, semantic XMPP profile `/xmpp/register` |
| login | `POST /api/v1/login` |
| message | `XMPP /xmpp/message` |
| report | `POST /api/v1/reports` |
| appeal | `POST /api/v1/reports/{lowercase UUID}/appeals` |
| password change/account removal | `PATCH /api/v1/me/password`, `XMPP /xmpp/password-change`, `XMPP /xmpp/account-remove` |

An issued response returns version, challenge UUID, proof prefix, irreversible
key ID, issue and expiry times, random server nonce, the committed public
intent and the current work requirement. The proof remains
`SHA-256(prefix || decimal_nonce)` against the advertised factor.

## HTTP canonical body

Mutation handlers reconstruct the commitment from their parsed request and do
not trust intent fields repeated in the proof. The canonical JSON profile is:

1. remove the top-level `pow` member;
2. represent every schema field semantically; optional fields are explicit
   JSON `null` when absent;
3. sort every object key by Unicode code point;
4. retain array order;
5. serialize strings and scalar JSON values without insignificant whitespace;
6. hash the UTF-8 bytes with SHA-256 and encode without base64 padding.

The bundled browser implements this profile locally. In particular, the
password participates in the digest but only the digest crosses the challenge
API boundary.

## XMPP message canonical body

For `XMPP /xmpp/message`, the digest covers the exact UTF-8 client stanza after
Northstar removes direct `urn:northstar:pow:1` children and unauthenticated
direct XEP-0203 delay assertions. It is computed before the server asserts or
canonicalizes routing attributes. A capable client therefore builds the final
stanza without `<pow/>`, hashes those exact bytes, obtains and solves the
challenge, and inserts the direct `<pow/>` child without changing any other
byte. The bundled browser exposes one stanza builder for both the commitment
and the actual WebSocket send, preventing serialization drift. The digest, not
the encrypted stanza, is sent to the HTTP challenge endpoint.

OMEMO encryption can advance a Double Ratchet before the ciphertext digest is
known. The browser therefore writes that ciphertext (never plaintext) to its
bounded ciphertext IndexedDB outbox before requesting v2 work. A challenge or
page failure leaves the exact ciphertext and origin-id queued. Reconnect obtains
a fresh challenge for those same bytes, adds only the private PoW child and
then sends; this prevents a lost first/pre-key ciphertext from stranding the
session merely because PoW was unavailable.

The outbox uses the `preferences` object store key
`encrypted-outbox:<canonical bare JID>`, retains at most 100 entries with an
ASCII OMEMO payload limit of 1,000,000 bytes each (leaving room below the
server's 1 MiB stanza/admission limit), and expires unsent entries after seven
days. Its message payload is
already OMEMO ciphertext, but the outbox record is not wrapped with a second
at-rest key: destination, type, IDs and timestamps remain visible to the
browser origin. Normal logout clears only memory and deliberately retains the
per-account ciphertext queue for a later login; it advances a write-generation
fence, and the next login drains older queued writes before loading that queue.
Explicit local-device removal or authenticated remote retirement first
fences/drains pending writes and then deletes the persistent queue. This does
not protect against same-origin XSS,
malicious extensions or a replaced web client; those remain part of the web
E2EE trust boundary.

An XEP-0198 ACK means that the server handled the stanza, not necessarily that
the application operation succeeded. The browser therefore waits 1.5 seconds
before deleting an ACKed ciphertext. A correlated `<message type='error'>`
before or during that ordered verdict window cancels deletion. Retryable
`wait` errors retain the exact pow-less ciphertext and origin-id, discard the
old proof and request a fresh v2 challenge. Automatic server-error retries are
capped at four; permanent errors and exhausted retries are retained as terminal
outbox records, surfaced through an error notice, and are not sent in an
unbounded loop.

## Durable and rotation semantics

PostgreSQL stores the protocol version, method, path, digest, nonce, key ID,
actor sequence snapshot, subject HMAC, work factor and times. The prefix also
contains an HMAC binding over the action, raw actor/subject scope, intent,
difficulty, times and nonce under the selected abuse-key generation. During a
key overlap, new challenges use the database-authorized primary generation and
either current/previous generation can verify its own rows.

Proof deletion, actor advancement and an idempotent HTTP mutation or durable
message admission still share one database transaction. A rollback restores
the proof. An exact idempotency replay uses its already committed guard marker
and does not consume a second challenge. Changing method, path, body, subject
or actor fails after atomically consuming and penalizing the invalid attempt.

## v1 migration window

The secure default is v2-only. Operators may temporarily set
`POW_V1_COMPATIBILITY_UNTIL` to a canonical UTC RFC 3339 timestamp such as
`2026-10-01T00:00:00Z`. Before that instant, mutation handlers may consume an
old unbound v1 row; after it, v1 issuance and consumption fail closed while v2
continues normally. Keep the window short, deploy capable clients first, and
remove the setting after expiry. A deadline close to an already-issued
challenge can invalidate that challenge; allow at least the documented
two-minute challenge lifetime when scheduling cutover.

XEP-0077 and XEP-0389 no longer issue an unbound challenge before the client
supplies registration fields. The initial form represents the ordinary free
allowance. If that submission reaches a metered step, the server returns a
second form/error containing a v2 challenge committed to the submitted
username, password and normalized invitation token. A capable client retries
those exact values with the challenge UUID and solved nonce. Standards-only
clients can still use the ordinary allowance and otherwise observe the normal
`resource-constraint`/cooldown behavior.

The XMPP registration digest is SHA-256 over the ASCII domain separator
`northstar/xmpp-registration-intent/v1` followed by a NUL byte and three
length-prefixed fields in this order: username, password, invitation token.
Each present field is encoded as byte `0x01`, an unsigned 64-bit big-endian
UTF-8 byte length and the UTF-8 bytes. An absent invitation is encoded as the
single byte `0x00`; username and password are always present. This semantic
profile is shared by XEP-0077 and XEP-0389, avoids XML serializer drift and
does not retain a password copy in a JSON or XML value.

The XMPP account service reserves bounded password-work capacity before it
opens PostgreSQL state. It then verifies/consumes the v2 proof, runs
Argon2/SCRAM only for an allowed request, consumes the invitation, enforces
registration capacity and inserts the user in one transaction. A crash rolls
the proof and every account side effect back together; at most the bounded
active password-worker count can hold connections during hashing.

Authenticated XEP-0077 password changes and account removals do not share that
form-before-body limitation. A capable client may request a v2 HTTP challenge
for `XMPP /xmpp/password-change` or `XMPP /xmpp/account-remove`, hashing the
exact `<query/>` after omitting its direct PoW child, and then include the proof
in the submitted query. Password proof consumption and credential rotation are
one PostgreSQL transaction. For account removal, proof consumption, disabling
the account, advancing its authentication generation, and revoking API/FAST
credentials are likewise one transaction. The remaining operation is
explicitly multi-phase because durable stream teardown must complete before the
account row can be deleted; a crash after the boundary leaves a disabled,
recoverable account rather than a consumed proof with no protected mutation.
