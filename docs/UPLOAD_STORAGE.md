# HTTP Upload storage and recovery contract

This document is the authoritative storage contract for XEP-0363 uploads. It
describes both the secure single-process filesystem backend and the shared
S3-compatible backend introduced by migration `0091_shared_upload_storage`.
An implementation in this checkout is not, by itself, evidence that a specific
cloud, MinIO release, latency envelope or disaster-recovery procedure has been
qualified. Those are release gates listed below.

## Backends and deployment boundary

`UPLOAD_STORAGE_BACKEND=local` is the default. It keeps immutable files under
`UPLOAD_DIR`, restricts the directory to mode `0700` on Unix, creates stages
with `create_new` and mode `0600`, rejects symlink roots, and promotes by an
atomic create-only hard link. It is suitable only when every request for an
upload is served by the one process/filesystem that owns that directory.

`UPLOAD_STORAGE_BACKEND=s3` uses Apache `object_store` 0.14.1's maintained AWS
client and SigV4 implementation. It is required for a public Redis cluster.
Every node must use the same endpoint, region, bucket, prefix and addressing
mode. Startup hashes those non-secret settings and compares the digest with the
singleton PostgreSQL `upload_storage_authority` row. A node with a different
namespace fails before accepting traffic. Credentials are excluded from this
digest so credential rotation does not change object authority.

Keys are server-generated and canonical:

```text
<prefix>/objects/<upload UUID>/<attempt UUID>
```

No filename, JID, header or other user input becomes an object key. The local
backend retains the historical bare `<upload UUID>` committed filename so old
backups remain addressable; its stage remains `<UUID>.<attempt>.part`.

## Lifecycle and transaction boundaries

The authoritative states are:

```text
reserved -> writing -> staged -> promoting -> committed -> deleting
                  \---------------------------------------> deleting
```

The lifecycle deliberately does not hold a PostgreSQL row lock while awaiting
filesystem or object-store I/O:

1. PostgreSQL claims a reservation, increments `storage_fence`, assigns a new
   attempt UUID and records its exact stage and destination keys as `writing`.
2. The backend streams at most the reserved byte count plus one byte while
   computing SHA-256. Short, oversized, canceled and failed bodies cannot be
   accepted as a completed stage.
3. One PostgreSQL transaction changes the exact fenced attempt to `staged` and
   inserts its immutable `promote` job. From this commit onward, the durable
   worker—not an HTTP task's destructor—owns recovery.
4. S3 writes directly to the private, immutable attempt-qualified `objects`
   key. A claimant changes metadata to `promoting`, then reads that **exact
   recorded version** and verifies its full size and SHA-256 outside the
   transaction. There is no CopyObject request and therefore no late copy that
   can materialize after a timed-out future. Local storage alone promotes its
   private temporary file to the historical bare UUID with a create-only hard
   link.
5. Only after that verification does a PostgreSQL transaction mark the row
   `committed`, record backend/key/version/size/digest/fence, remove the exact
   promotion job. For S3, stage and committed key are the same, so successful
   commit never enqueues deletion of that key. Local storage enqueues deletion
   of its distinct temporary stage.
6. Lost-authority/deletion cleanup remains durable. S3 absence must be observed
   across a quiet confirmation interval before its tombstone is retired; a
   late multipart completion is consequently deleted by a later pass instead
   of becoming an unreferenced object after one transient NotFound.

Only `committed` and upgraded `legacy_committed` rows are downloadable. GET
loads the exact backend/key/version named by PostgreSQL and verifies object
size before returning bytes. A missing object, wrong version or wrong size
fails closed; a node never falls back to a local path or guesses another key.
The destination SHA-256 was verified before the committed state became
visible. The supervised worker also claims at most two due committed S3
manifest rows per pass (therefore at most twice `UPLOAD_MAX_BYTES` of scrub
input per pass) and re-verifies the exact version, full size and SHA-256
without listing the bucket. Twenty-four hours is the next-due target, not a
claim that the defaults can scrub one million maximum-sized objects per day.
Due depth is counted with a capped indexed query and an oldest-overdue item
beyond 24 hours degrades readiness. Successful rows are scheduled 24 hours later;
failed rows remain committed but make worker health fail closed for operator
investigation. GET validates the exact version and size but deliberately does
not hash the whole object on every download.

## Fencing, retries and crash behavior

The database fence and attempt UUID are carried by every stage, promotion and
cleanup projection. Storage job leases last 240 seconds and each individual
storage future is bounded to 180 seconds. A timed-out owner leaves the durable
job claimed until its lease expires; this quiet interval prevents a second
claimant from overlapping a storage request that may still be completing at
the provider.

| Stop or retry point | Durable recovery |
| --- | --- |
| Before any stage bytes exist | Expired `writing` metadata queues exact, idempotent stage cleanup. |
| During multipart upload | The writer requests multipart abort. Provider lifecycle rules are the final bound for parts left by a hard process/host failure. |
| Stage completed before `staged` transaction | The pre-recorded `writing` key is cleaned after lease expiry; cancellation also attempts exact cleanup. |
| After `staged` transaction | The durable promotion job retries without a bucket listing. |
| During verification | No storage mutation occurs; retry re-reads the same version. |
| After verification, before DB commit | The promotion job verifies and commits the same immutable attempt. |
| After DB commit, before stage delete | The exact `delete_stage` job observes/deletes the stage. |
| Duplicate PUT | A live attempt returns bounded retry guidance. A committed replay is accepted only after the request body and stored object match the committed digest. |
| Delete races with a writer | The row becomes non-public and the exact cleanup projection is delayed beyond the maximum writer window. |
| Delete races with promotion | Cleanup cannot touch storage while the same attempt/fence still has a promotion job. The promotion owner retires that job only after exact-version verification and its fenced database transition finish. |
| Cleanup claimant loses its lease | It cannot remove database metadata; completion requires the still-live exact queue lease and exact slot locator/fence. |

A stale claimant is allowed to discover that an exact immutable key is already
absent. It is never allowed to overwrite a destination, delete a different
version, retarget a queue row, or complete metadata for a different fence.
Migration triggers make storage-job and cleanup-queue identity fields
immutable; only lease, retry time, attempt count and sanitized error text may
change.

The worker scans bounded PostgreSQL queues (`LIMIT 4` per queue claim and a
bounded expired-row batch). It never lists an S3 bucket. Local startup retains
one bounded, canonical `.part` name scan solely to upgrade/recover legacy local
stages. The worker is registered as a security-critical continuous worker.
Transient provider failures remain inside its bounded retry loop and degrade
readiness, but a stopped worker or expired heartbeat triggers supervised
service shutdown because proven namespace-authority drift can cause
wrong-prefix deletion. Transient database/provider errors do not stop it: they
are retried and degrade readiness. Its liveness silence budget is 600 seconds,
longer than a bounded scrub batch containing 180-second storage operations. Retries are finite;
exhausted rows are dead-lettered for operator
repair rather than retried forever. Dead letters, an oldest pending age over
the SLO, or a full persistent queue keep readiness degraded even while
exponential backoff means no row is presently due.

Migration 0091 maintains an O(1), trigger-protected physical capacity ledger
covering slot rows, orphaned cleanup projections, bytes, both durable queue
classes, and cleanup-obligation debt. The first transition that gives a slot
an external stage/object locator reserves exactly one debt unit. Creating its
authoritative cleanup projection atomically converts that unit from debt to
pending; duplicate `ON CONFLICT` enqueue does not fire the insert trigger, and
final confirmed projection deletion releases pending. Thus writing,
committed, retention, account-deletion and orphan recovery never have an
unreserved crash window or count the same future cleanup twice.
Debt conversion is authorized only when the durable slot exactly matches the
projection's backend, lifecycle state/action, attempt, fence, stage/object
keys and versions, expected size and digest (`IS NOT DISTINCT FROM` is used
for nullable identity fields). The fixed-search-path trigger then clears the
slot's reservation in the same transaction. An exact `ON CONFLICT` replay is
neutral; a changed projection is rejected by immutable-identity guards and
cannot consume another slot's debt. Queue-table mutation is not granted to
`PUBLIC`. The current packaged deployment still runs migrations and runtime
queries through the configured database owner, so this is defense in depth,
not a claim that queue DML has already been separated from the application.
A future non-owner runtime role must receive an explicit minimal grant set,
while schema migrations use separate credentials; this release does not
revoke connection TEMP privileges or pretend that role split is complete.

New-slot admission evaluates `pending + debt`, locks that one row with a 50 ms lock timeout (then
the account row in fixed order), enforces configured retained-file/byte
ceilings and stops at 75% of the configured durable job ceiling. On first
startup PostgreSQL binds `UPLOAD_STORAGE_MAX_PENDING_JOBS` (128–100,000), a
25% recovery reserve and the independent 100,000-row disaster ceiling; every
later node must match that immutable policy generation. The reserved quarter
is for promotion and mandatory deletion; at the configured hard ceiling those maintenance
transactions fail closed and leave the slot/obligation durable for a later
bounded pass rather than creating untracked work. Per-account quotas include
expired/deleting rows until physical reconciliation. Due cleanup debt and its
oldest age are queried through bounded indexed windows and affect readiness.
During migration, legacy cleanup rows obtain `expected_size` from their
matching slot. If any orphan has no recoverable size, migration fails with an
operator-repair error; it never records unknown historical debt as zero.

A legacy migration is allowed to discover more obligations than either the
requested deployment limit or the absolute disaster ceiling. Binding the
policy never silently raises either authority: PostgreSQL persists
`legacy_overcommit_draining`, readiness stays degraded, alerts fire, and all
fresh admission/non-converting queue work remains blocked. An existing debt
may still convert atomically to pending because that operation leaves
`pending + debt` unchanged. Exact confirmed deletion then reduces the total
until it falls below both limits, at which point the draining marker clears.
This exception is deliberately one-way and cannot create another obligation.

## Durable deletion and legal holds

Expiry, user deletion, account deletion and XEP-0227 replacement all enqueue
the exact backend, object/stage keys, provider versions, attempt, size, digest
and fence before metadata can disappear. Physical deletion is retried with a
bounded exponential delay. Metadata is removed only after both the committed
object and any stage are absent and the same cleanup lease still owns the
queue row.

Existing account/data-lifecycle legal-hold gates remain authoritative: a held
account cannot enter the destructive account-deletion path. Object storage is
not an independent legal-hold database. Provider Object Lock, retention and
backup policies must be aligned with the application's legal policy; a
provider-enforced retention error keeps the cleanup row pending and readiness
observable rather than pretending deletion completed.

S3 versioning deserves special treatment. `object_store` 0.14.1 can read an
exact S3 version but its generic delete API deletes the current key (normally
creating a delete marker) rather than targeting an arbitrary historical
version. Northstar verifies that the committed version is current before
deletion and verifies that the current key is absent afterwards. Noncurrent
versions therefore belong to the provider backup/retention boundary and must
have a reviewed expiration or Object Lock policy. Do not claim cryptographic
erasure or immediate destruction of noncurrent provider versions. A future
client API that supports version-qualified delete is required before that
boundary can be closed inside Northstar.

An unversioned compatible store returns no version identifier. Northstar still
binds the canonical attempt key, exact size and SHA-256 and fails closed on a
scrub mismatch, but it cannot ask that provider for a historical immutable
generation. Production qualification must therefore either enable provider
versioning/immutability or prove with bucket/IAM policy that no principal can
overwrite Northstar attempt keys. This is an explicit provider trust boundary,
not an application guarantee.

## Configuration and credentials

| Variable | Meaning |
| --- | --- |
| `UPLOAD_STORAGE_BACKEND` | `local` (default) or `s3`; public clustered mode requires `s3`. |
| `UPLOAD_DIR` | Private local root; ignored for S3 object data but retained by existing local backup tooling. |
| `UPLOAD_S3_BUCKET` | Required lowercase DNS-style bucket. |
| `UPLOAD_S3_REGION` | Signing region, default `us-east-1`. |
| `UPLOAD_S3_PREFIX` | Optional canonical relative namespace prefix. |
| `UPLOAD_S3_ENDPOINT` | Optional absolute HTTPS S3-compatible endpoint with no credentials, path, query or fragment. |
| `UPLOAD_S3_PATH_STYLE` | Enable path-style addressing for a compatible provider. |
| `UPLOAD_S3_ALLOW_HTTP` | Explicit development-only exception; accepted only when every listener is loopback, Redis is disabled and the XMPP domain is localhost/test. |
| `UPLOAD_S3_CREDENTIAL_MODE` | `files` or `ambient`. |
| `UPLOAD_S3_CREDENTIAL_BUNDLE_FILE` | Production file-mode JSON bundle containing a positive monotonic `generation`, access key, secret, and optional session token; replace this one file atomically. |
| `UPLOAD_S3_ACCESS_KEY_ID_FILE` | Legacy development-only access-key file; required with the secret file. |
| `UPLOAD_S3_SECRET_ACCESS_KEY_FILE` | Owner-only mounted secret-key file. |
| `UPLOAD_S3_SESSION_TOKEN_FILE` | Optional owner-only session-token file in `files` mode. |
| `UPLOAD_S3_SSE_KMS_KEY_ID_FILE` | Optional mounted KMS key ID; SSE-KMS is server-side encryption, not end-to-end encryption. |
| `UPLOAD_DOWNLOAD_MAX_CONCURRENT` / `UPLOAD_DOWNLOAD_MAX_PER_IP` | Independent GET concurrency ceilings. |
| `UPLOAD_DOWNLOAD_READ_TIMEOUT_SECONDS` / `UPLOAD_DOWNLOAD_MAX_SECONDS` | Initial/read idle timeout and whole-response deadline, including downstream backpressure. |
| `UPLOAD_STORAGE_MAX_PENDING_JOBS` | Durable deployment-wide limit (128–100,000), bound once in PostgreSQL; new admission stops at 75%, maintenance may use the reserved quarter, and no path may exceed this configured limit or the independent 100,000 disaster ceiling. |
| `UPLOAD_STORAGE_MAX_RETAINED_FILES` / `UPLOAD_STORAGE_MAX_RETAINED_BYTES` | Physical retained projection ceilings maintained by the O(1) database ledger. |

Production rejects `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and
`AWS_SESSION_TOKEN` environment secrets. File mode reads secrets with the same
owner/permission checks as other Northstar mounted secrets. Production file
mode requires the single JSON bundle; the older multi-file form is accepted
only in explicit loopback development because multiple secret files cannot be
read atomically. The supervised worker rebuilds a client and swaps it only
after parsing a complete bundle whose generation is strictly newer. A partial,
invalid, replayed or rolled-back bundle leaves the old client active. In-flight
operations retain their old `Arc`; keep both credential generations valid for
at least the maximum operation and lease window.

Ambient mode accepts the maintained client's web-identity pair
(`AWS_WEB_IDENTITY_TOKEN_FILE` plus `AWS_ROLE_ARN`), ECS relative credential
URI, or IMDSv2. It rejects the full-URI, endpoint, metadata-endpoint, unsigned
payload, HTTP and signature-skip overrides that could widen SSRF or transport
policy. When ambient mode is off and no complete file credential pair exists,
client construction fails; the builder cannot silently fall back to IMDS.

Endpoint, region, bucket, prefix, path style, TLS policy and SSE selection are
configuration, not credential rotation. Change them with a controlled restart.
Changing a namespace is rejected while any live object or reconciliation row
exists; an explicit object migration plus validation is required.

## Bucket and IAM policy

Use a dedicated bucket or dedicated prefix. Grant only the object operations
needed for attempt-key multipart creation/abort, exact reads and
deletes under that prefix. Deny public access and require TLS. Do not grant
bucket-policy changes, ACL writes or access outside the prefix. Where SSE-KMS
is used, restrict the principal to the one KMS key and retain the KMS policy
with the backup.

Configure a provider lifecycle rule that aborts incomplete multipart uploads
after a short reviewed interval. If bucket versioning is enabled, configure a
separate reviewed noncurrent-version/delete-marker policy consistent with
legal holds and backup retention. Bucket listing is not required at runtime and
should not be granted merely for reconciliation.

OMEMO-encrypted attachments remain ciphertext only if the client encrypts the
payload before upload and shares its key out of band in the encrypted stanza.
SSE-S3/SSE-KMS protects provider media at rest but the provider/server trust
boundary remains; it must never be described as E2EE.

## Backup and restore boundary

The repository's backup format v2 and `backup.sh` archive **local** committed
upload files and validate them against a PostgreSQL snapshot. They do not and
must not claim to include S3 bytes. Running the same tar workflow while using
the S3 backend creates, at most, a database/control-plane backup.

An S3 deployment needs two coordinated artifacts:

1. a PostgreSQL backup whose upload manifest contains `id`, backend, committed
   object key/version, exact size, SHA-256, fence and expiry; and
2. a provider-native, independently protected snapshot/replication/versioned
   backup of the named bucket and prefix.

Restore into an isolated namespace first. Restore PostgreSQL, restore or map
the exact object versions, then run a bounded manifest validator that HEADs and
streams every live committed reference to confirm version, size and SHA-256.
Only after every reference validates may the namespace authority be activated
and traffic enabled. Missing, substituted or mismatched objects are a failed
restore, not entries to skip. Provider credentials, KMS key policy/material,
Object Lock configuration and noncurrent-version retention are separate backup
dependencies and are never embedded in the local upload tar.

Migration from local to S3 is not an in-place configuration toggle: startup
will reject it while local locators exist. Copy each immutable object to a new
attempt-qualified S3 key, verify the bytes, update locators in a purpose-built
transactional migration, drain exact cleanup jobs, then advance the namespace
authority. No such online migration command is claimed in this release.

### Offline namespace-authority v1 to v2 upgrade

Authority v2 additionally binds canonical absolute `UPLOAD_DIR` for local
storage and the SSE/KMS policy identity for S3. Ordinary startup never rewrites
an existing v1 authority. To upgrade, stop **every** Northstar node, verify the
database has no locator whose backend differs from the expected namespace,
back up PostgreSQL, and use a dedicated migration-owner session. Temporarily
grant that maintenance identity execute on
`offline_upgrade_upload_storage_authority_v1_to_v2(text,bytea,bytea,text)`;
pass the exact currently stored v1 SHA-256, independently calculated v2
SHA-256, expected backend, and literal confirmation
`ALL_NORTHSTAR_NODES_STOPPED_AND_NAMESPACE_VERIFIED`. The protected function
rechecks the old digest/backend and every durable locator, transactionally
disables/re-enables the immutable trigger, and increments authority generation. Revoke execute
immediately, start one node, then start the remainder only after its authority
check succeeds. Never grant this function to the ordinary runtime role.

## Observability and release gates

Alert on the common worker-registry readiness signal and on all of the
following conditions once the corresponding Prometheus series are enabled:

- storage reconciliation or credential-refresh failures;
- any nonzero dead-letter or persistent manifest-scrub-failure gauge;
- due cleanup/scrub obligation counts and their oldest overdue age;
- oldest ready job or cleanup age approaching the retention/deletion SLO;
- growing `promote`, `delete_stage` or cleanup queue depth;
- a nonzero `xmpp_upload_storage_legacy_overcommit_draining` gauge;
- repeated digest/version/size mismatch or create-only conflict;
- incomplete multipart bytes/age at the provider;
- provider authorization, KMS, Object Lock or lifecycle failures.

Downloads have independent global and per-IP concurrency guards and a bounded
initial lookup/per-read timeout plus `UPLOAD_DOWNLOAD_MAX_SECONDS`, whose total
deadline also advances while socket backpressure prevents the bounded producer
from being polled. PUT capacity cannot be consumed to exhaust the GET guard.
Northstar is not a full bandwidth-shaping CDN: public deployments should put
an authenticated, origin-shielding CDN/reverse proxy in front, preserve the
application authorization boundary, and apply egress/range/cache policy there.
The database committed gate remains authoritative, so direct public bucket
URLs must stay disabled.

The repository contains pure/in-memory tests for canonical keys, canceled and
length-mismatched local writes, create-only duplicate promotion, two clients
sharing one fake store, client swapping and each durable transition. The
loopback-only MinIO fixture is
[`deploy/docker-compose.minio-test.yml`](../deploy/docker-compose.minio-test.yml),
and its Rust round-trip test is ignored by default.

Before production qualification, execute and retain results for all of these
on the exact release commit and target provider:

- migration 0091 upgrade and rollback-from-backup rehearsal;
- MinIO and chosen cloud round trips, including path/virtual-host style;
- duplicate PUT, canceled body, process kill at every transition and stale
  lease/fence races across two nodes;
- credential rotation with in-flight multipart/verify/read/delete operations;
- provider outage, latency and retry exhaustion without PostgreSQL pool
  starvation;
- account/user/retention deletion with and without legal holds;
- S3 manifest backup, isolated restore and full size/SHA/version validation;
- versioning, delete-marker, Object Lock, multipart lifecycle and KMS policy.

Until those runtime gates pass, `CLU-STORAGE` is implemented and statically
reviewed but not production-qualified for a particular provider.
