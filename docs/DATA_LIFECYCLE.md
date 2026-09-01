# Data lifecycle, legal hold, and audit evidence

This document is the normative engineering description of Northstar's data
retention controls. It is not legal advice. An operator must choose retention,
access, export-signing, and disclosure rules with its own counsel and must test
them on a restored copy before production use.

## Effective retention policy

The operator values remain hard ceilings:

- `MAM_RETENTION_DAYS` controls personal XEP-0313 archives;
- `MUC_MAM_RETENTION_DAYS` controls each room's shared archive;
- `OFFLINE_MESSAGE_TTL_DAYS` controls the durable delivery queue;
- `MODERATION_RETENTION_DAYS` controls terminal reports, appeals, and copied
  evidence;
- `AUDIT_LOG_RETENTION_DAYS` independently bounds insert-only audit metadata.

A zero content ceiling disables inherited cleanup. It does not mean "delete
immediately". A user may still opt into a finite, shorter content period. Audit
retention is always finite and must be between 30 and 36,500 days.

`user_retention_policies` stores optional personal-MAM, offline, and moderation
evidence overrides. `muc_retention_policies` stores one optional override for a
room's shared archive. At the exact SQL statement which locks cleanup
candidates, Northstar resolves:

```text
explicit subject/room days, otherwise non-zero operator days
```

A normal account may only move its effective cutoff earlier. Clearing an
override or choosing a larger value is an extension and is rejected. An
administrator can authorize an extension up to, but never beyond, the operator
ceiling. Moderation evidence has a 30-day user-policy floor. A MUC archive is a
shared resource: only a room owner or server administrator can set its policy;
ordinary participants cannot delete shared history by changing a personal
setting.

Cleanup is chronological, bounded to `RETENTION_CLEANUP_BATCH_SIZE`, and uses
`FOR UPDATE ... SKIP LOCKED`. Personal MAM, MUC MAM, offline rows, terminal
moderation cases, released-hold snapshots, and the audit log have separate
retryable batches. Offline cleanup also excludes every XEP-0198 and BOSH
delivery fence and active delivery claim.

## Typed legal holds

`legal_holds` is an append-only case header. Its exact target tables are:

- `legal_hold_personal_archives`;
- `legal_hold_muc_archives`;
- `legal_hold_offline_messages`;
- `legal_hold_report_evidence`.

The controlled scope table permits only these subject scopes:

- `personal_archive_owner` (user UUID);
- `muc_archive_room` (room UUID);
- `offline_message_recipient` (user UUID);
- `report_evidence_report` (report UUID).

Arbitrary table names, predicates, SQL fragments, JID patterns, or tenant-wide
wildcards are not accepted. A hold contains at most 1,000 declared exact/scope
targets.

Exact hold creation locks the target record before the typed link is inserted.
Scope creation takes a short PostgreSQL `SHARE` lock on the corresponding data
table. Consequently, cleanup and hold creation cannot pass one another in an
ambiguous window: cleanup either commits first, or the hold commits first and
cleanup observes it. Retention queries check `NOT EXISTS` for an active exact
or scoped hold while locking the same candidate. Database triggers are a
second fail-closed layer against a missed deletion or payload mutation.

An offline queue row is operational state, so permanently blocking its ACK
would cause repeat delivery. Before an actively held offline row is deleted by
transport completion, a trigger atomically copies the exact server-visible
stanza into `legal_hold_offline_snapshots`. The queue ACK can then complete.
The snapshot is immutable while the hold is active and returns to the
recipient's original effective cutoff after release.

Account deletion fails closed while that account has an active personal,
offline, or report-evidence hold. Room destruction fails closed while its MUC
archive is held. The API must return a conflict and the operator must export
and release the hold through the audited workflow; disabling a trigger is not
a supported deletion procedure. Backups and restores include all policy,
hold, target, snapshot, release, and audit tables. Restore validation must run
the complete migration chain before service is made ready.

## Authorization, idempotency, and access audit

Self-retention changes require a current bearer session. Room policy changes
require room-owner or administrator authorization. Hold create, list, export,
and release and audit export require a current administrator session and
re-check authorization in the database transaction.

Every mutation and export requires `Idempotency-Key`. The request fingerprint
binds method, canonical route, principal, target and exact JSON bytes. A
completed retry returns the stored response with `Idempotency-Replayed: true`.
Creation/release request UUIDs are also unique in the hold schema. Hold list,
every hold-export page, every audit-export page, retention changes, creation,
and release write an audit event. Read access is therefore visible rather than
silent. Each export page uses a fresh idempotency key; an exact retry of that
page can still replay its stored body after the continuation cursor expires.

The hold-list `GET` also requires an explicit key. Because it is a live read,
Northstar does not replay a stale list: normal GET semantics make the result
idempotent, while every actual access remains a distinct audit event. Only a
SHA-256 digest of the caller-supplied key is stored in that event, so operators
can correlate an intentional retry without retaining the visible key.

Release is the only permitted update to a hold header. It atomically adds
actor, request, timestamp and non-empty reason. The creation fields, released
header, typed links, and target UUID manifest cannot subsequently be edited or
deleted by application SQL.

An export page, its access-audit event, its lease transition, and its exact
idempotent replay body commit atomically. Northstar never truncates one held
record to make it fit. If the serialized response exceeds the 1 MiB
replay-storage bound, the whole transaction returns a clear `400`, including
no access event or partial replay entry; retry with a new idempotency key and a
smaller `max_rows`. The hash-chain metadata therefore always describes exactly
the records returned to the caller.

Migration 0092 adds `governance_export_leases`. A signed cursor is bound to the
endpoint, administrator UUID, hold or audit filters, immutable snapshot, exact
keyset boundary, and the preceding page's 32-byte SHA-256 root. Tampering,
changing administrator/filter/hold, crossing endpoint types, an expired lease,
or a missing/completed lease all return the same `invalid_cursor` response.
Cursors and leases use the database clock and one fixed 15-minute deadline;
continuation never extends it. Abandoning an export can therefore delay a hold
release for at most that bounded window, not indefinitely.

For an active hold, the first page takes short `SHARE` barriers over the four
source tables, fixes `snapshot_at`, and creates a lease while retaining a lock
on the hold header. Scope rows are limited to `record_created_at <= snapshot_at`.
Active-hold triggers freeze those rows and their server-visible payload, and a
release conflicts until the last page atomically completes the lease or the
lease expires. A released hold no longer supplies that payload fence: it is
exported only if the entire result fits in one page; otherwise the API returns
`409` instead of promising an unstable continuation.

## OMEMO boundary

Northstar never asks for an OMEMO private key. A held encrypted personal/MUC
archive or offline row retains and exports only the encrypted XMPP stanza that
the server already possessed. `legal_hold_offline_snapshots` has no decrypted
text column. Existing report evidence is a different trust boundary: a user
may have submitted unverified decrypted text during reporting. When that
evidence is marked encrypted, legal-hold export deliberately omits the body
rather than presenting user-supplied plaintext as authoritative ciphertext.

Database administrators and authorized export recipients can still see
server-visible plaintext and metadata. Legal hold is not zero knowledge.

## Audit immutability and export

Migration 0087 removes the live user foreign key from `audit_log.actor_id` so
account deletion preserves the historical actor UUID instead of rewriting
every event. A trigger rejects application `UPDATE` and ordinary `DELETE`.
Only `northstar_purge_audit_log(retention_days,batch_size)` may identify itself
as bounded cleanup, and it enforces the 30-to-36,500-day range and a 10,000-row
batch maximum.

The first audit page briefly takes a `SHARE` barrier on `audit_log`, then fixes
the database `snapshot_at` and inclusive `snapshot_max_id`. That barrier waits
out every earlier INSERT/retention DELETE, closing the otherwise subtle case in
which an uncommitted lower sequence ID could appear on a later page. Subsequent
pages use `id > after_id AND id <= snapshot_max_id`. Every page's access event
is inserted only after the high-water mark is chosen, and the frozen query
also excludes `data.audit.export` events carrying that fresh export UUID. It
therefore cannot enter the same export even if a database owner has moved the
sequence behind existing rows. An unfinished audit lease temporarily excludes
its bounded range from retention; completion or the non-renewable expiry
removes that fence.

Audit and held-data pages sort deterministically and build one continuous,
length-delimited, domain-separated SHA-256 chain. `chain_start_sha256` on page
N+1 equals `chain_root_sha256` on page N; the signed cursor carries that binary
root. `next_cursor=null` and `complete=true` mark the final root. This detects
modification, omission, reordering, or cross-export splicing relative to an
anchored root; it is not by itself an independent signature. Production
operators should immediately sign or timestamp the root with an organizational
KMS/HSM and write the export to access-controlled WORM storage.

The v2 chain is reproducible without a server secret. UUIDs are their 16-byte
network representation, integers are signed 64-bit big-endian, timestamps are
signed Unix microseconds, and an optional timestamp is one byte (`0` absent,
`1` present) followed by that integer when present:

```text
legal genesis = SHA-256("northstar/legal-hold-export/v2\0" ||
                       export_uuid || admin_uuid || hold_uuid || snapshot_us)
audit genesis = SHA-256("northstar/audit-export/v2\0" || export_uuid ||
                       admin_uuid || snapshot_us || snapshot_max_id ||
                       optional_start || optional_end)
next          = SHA-256(previous_32_bytes || u64be(json_byte_length) ||
                       canonical_row_json_utf8)
```

Canonical row JSON is compact Serde JSON with the field order shown by
`HeldRecordHashPayload` or `AuditHashPayload` in `src/db/data_lifecycle.rs`;
UUIDs are lowercase hyphenated strings, UTC timestamps use Chrono's RFC 3339
Serde representation, option absence is JSON `null`, and strings use standard
JSON escaping. `serde_json` is built without `preserve_order`, so decoded JSONB
object keys are emitted in lexical order. The response's `previous_hash` and
`entry_hash` expose every step. Implementations must hash the payload described
by those structs, not the response wrapper (which also contains the two hash
fields). Any future serialization change requires a new domain/version rather
than silently changing the v2 chain.

A PostgreSQL owner or superuser can disable triggers or rewrite tables. That is
an explicit external trust boundary. Use a separate least-privilege runtime
role, PostgreSQL audit logging, restricted migration credentials, independent
backups, and off-system root anchoring when protection from a database
administrator is required.

## Monitoring and response

The private metrics listener exposes fixed-cardinality counters/gauges only:

- `xmpp_legal_holds_active`;
- `xmpp_legal_hold_preserved_offline_records`;
- `xmpp_legal_hold_operations_total` and
  `xmpp_legal_hold_operation_failures_total`;
- `xmpp_audit_export_operations_total` and
  `xmpp_audit_export_operation_failures_total`;
- `xmpp_governance_export_leases_active` and
  `xmpp_governance_export_leases_expired_incomplete`;
- `xmpp_governance_export_cursor_rejections_total`;
- `xmpp_retention_legal_hold_snapshots_deleted_total`;
- `xmpp_retention_audit_log_deleted_total`;
- `xmpp_retention_governance_export_leases_deleted_total`;
- the shared `xmpp_retention_cleanup_failures_total`.

No hold ID, authority reference, user, room, JID, report, or request ID is a
metric label. On a cleanup alert, leave the guards enabled, inspect worker and
PostgreSQL errors, verify active hold state, and retry the bounded worker. On a
hold operation alert, reconcile the idempotency request and audit event before
retrying. Never use direct SQL deletion as an alert workaround.

## Verification boundary

Pure unit tests cover retention monotonicity, closed target kinds, export chain
domain separation and cross-page continuity, signed digest cursor shapes,
filter separation, fixed lease limits, policy-aware SQL shape, hold exclusion,
and route/OpenAPI agreement. The ignored isolated-PostgreSQL fixture is
responsible for migration upgrade, concurrent cleanup/hold races,
account/room fail-closed deletion, offline ACK snapshotting, active-export
release fencing, multi-page chain continuation, immutable release history,
post-release cleanup, and audit deletion gates. Static/unit success is not a
claim that a production database, restore, or legal workflow was exercised.
