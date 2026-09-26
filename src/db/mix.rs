use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use northstar_archive_application::MAX_MAM_PAGE_SIZE;
use northstar_archive_core::{finish_mam_page, plan_mam_page, ResolvedMamRsmPage};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicU64, Ordering},
};
use uuid::Uuid;

pub const NODE_MESSAGES: &str = "urn:xmpp:mix:nodes:messages";
pub const NODE_PRESENCE: &str = "urn:xmpp:mix:nodes:presence";
pub const NODE_PARTICIPANTS: &str = "urn:xmpp:mix:nodes:participants";
pub const NODE_INFO: &str = "urn:xmpp:mix:nodes:info";
pub const NODE_CONFIG: &str = "urn:xmpp:mix:nodes:config";
pub const NODE_ALLOWED: &str = "urn:xmpp:mix:nodes:allowed";
pub const NODE_BANNED: &str = "urn:xmpp:mix:nodes:banned";
pub const NODE_JIDMAP: &str = "urn:xmpp:mix:nodes:jidmap";
pub const NODE_AVATAR_DATA: &str = "urn:xmpp:avatar:data";
pub const NODE_AVATAR_METADATA: &str = "urn:xmpp:avatar:metadata";

pub const ALL_NODES: [&str; 10] = [
    NODE_MESSAGES,
    NODE_PRESENCE,
    NODE_PARTICIPANTS,
    NODE_INFO,
    NODE_CONFIG,
    NODE_ALLOWED,
    NODE_BANNED,
    NODE_JIDMAP,
    NODE_AVATAR_DATA,
    NODE_AVATAR_METADATA,
];

pub(crate) use crate::services::mix::valid_stable_participant_id;

pub(crate) use crate::services::mix::mix_timestamp_item_id;

pub(crate) use crate::services::mix::MixChannel;

pub(crate) use crate::services::mix::MixParticipant;

#[derive(Clone, Debug)]
pub struct MixEvent {
    pub id: Uuid,
    pub item_id: String,
    pub payload: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct MixEventPage {
    pub events: Vec<MixEvent>,
}

#[derive(Clone, Debug)]
pub enum MixReadOutcome<T> {
    Found(T),
    Unauthorized,
    NotFound,
}

#[derive(Clone, Debug)]
pub struct MixMamPage {
    pub events: Vec<MixEvent>,
    pub total: i64,
    pub first_index: i64,
    pub complete: bool,
}

#[derive(Clone, Debug)]
pub struct MixPresenceProbeTarget {
    pub channel_jid: String,
    pub participant_jid: String,
}

#[derive(Clone, Debug)]
pub struct ExpiredMixPresence {
    pub channel_id: Uuid,
    pub participant: MixParticipant,
    pub item_id: String,
    pub payload: String,
    pub source_full_jid: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PamMembership {
    pub id: Uuid,
    pub user_id: Uuid,
    pub channel_jid: String,
    pub participant_id: Option<String>,
    pub state: String,
    pub request_id: Option<String>,
    pub client_request_id: Option<String>,
    pub requester_full_jid: Option<String>,
    pub subscriptions: Vec<String>,
}

pub(crate) use crate::services::mix::MixParticipantPreference;

/// Authenticated federation identity and durable reply policy attached to one
/// mutating MIX IQ.  A successful repository mutation must journal its exact
/// result and enqueue that result before the business transaction commits.
/// Keeping this context explicit avoids task-local state leaking across
/// unrelated async work and makes every mutation boundary reviewable.
pub(crate) use crate::services::mix::FederatedMixMutation;

/// Typed successful effects from which the application serializer produces
/// the exact IQ result persisted by the mutation transaction.
pub(crate) use crate::services::mix::FederatedMixSuccess;

pub(crate) use crate::services::mix::MixPresenceDelivery;

pub(crate) use crate::services::mix::PamJoinResult;

/// Application-layer serializer used while a durable MIX mutation is still
/// inside its database transaction. Persistence owns atomic storage, but it
/// never constructs protocol XML or interpolates untrusted stanza values.
pub(crate) use crate::services::mix::MixEventPayloadRenderer;

#[derive(Clone, Debug)]
pub struct ClaimedMixDelivery {
    pub delivery_id: Uuid,
    pub event_id: Uuid,
    pub channel_id: Uuid,
    pub channel_jid: String,
    pub recipient: MixParticipant,
    pub stanza: String,
    pub authoritative_stanza_id: Option<Uuid>,
    pub archive: bool,
    pub encrypted: bool,
    pub attempt_count: i32,
    pub lease_token: Uuid,
    /// Durable route-wake epoch observed while this exact recipient head was
    /// leased. A later epoch prevents this worker from parking an available
    /// route behind its recovery backoff.
    pub route_wake_generation: i64,
}

/// Durable completion of one leased MIX delivery retry.
///
/// The repository owns the terminal decision because the claimed attempt
/// snapshot can be stale by the time the worker releases its lease.  In
/// particular, a committed route wake at the attempt limit is a durable
/// routing fact which gets one fresh claim before the normal terminal path.
pub(crate) use crate::services::mix::MixDeliveryRetryOutcome;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PamOperationReplay {
    Miss,
    Pending,
    Replay(String),
    Conflict,
}

#[derive(Clone, Debug)]
pub struct ClaimedPamResult {
    pub operation_id: Uuid,
    pub user_id: Uuid,
    pub requester_full_jid: String,
    pub response_xml: String,
    pub attempt_count: i32,
    pub lease_token: Uuid,
}

#[derive(Clone, Debug)]
pub struct RemotePamCompletion {
    pub response_xml: String,
    pub membership: Option<PamMembership>,
    pub applied: bool,
    pub roster_removed: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct MixDeliveryDeadLetter {
    pub dead_letter_id: Uuid,
    pub delivery_id: Uuid,
    pub event_id: Uuid,
    pub channel_id: Uuid,
    pub channel_jid: String,
    pub recipient_jid: String,
    pub attempt_count: i32,
    pub terminal_reason: String,
    pub last_error: Option<String>,
    pub failed_at: DateTime<Utc>,
}

const MIX_DELIVERY_MAX_ROWS: i64 = 100_000;
const MIX_DELIVERY_MAX_BYTES: i64 = 268_435_456;
const MIX_DELIVERY_RECIPIENT_OVERHEAD: i64 = 128;
const MIX_DELIVERY_DEAD_LETTER_LIMIT: i64 = 10_000;
const MIX_DELIVERY_LEASE_SECONDS: i64 = 90;
// Direct sockets have no peer acknowledgement below XEP-0198. Keep a
// separate bounded lease for the interval after the writer has fenced the
// source but before the OS accepts the bytes. It is deliberately longer than
// the transport write deadline and shorter than a normal worker lease; a
// failed process therefore recovers through the same ordered claim path.
const MIX_SOCKET_WRITE_FENCE_SECONDS: i64 = 30;

static MIX_DELIVERY_CAPACITY_REJECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static MIX_DELIVERY_LEASE_LOST_TOTAL: AtomicU64 = AtomicU64::new(0);
static MIX_DELIVERY_DEAD_LETTERS_TOTAL: AtomicU64 = AtomicU64::new(0);
static MIX_DELIVERY_RETRIES_TOTAL: AtomicU64 = AtomicU64::new(0);

pub(crate) fn mix_delivery_capacity_rejections_total() -> u64 {
    MIX_DELIVERY_CAPACITY_REJECTIONS_TOTAL.load(Ordering::Relaxed)
}

pub(crate) fn mix_delivery_lease_lost_total() -> u64 {
    MIX_DELIVERY_LEASE_LOST_TOTAL.load(Ordering::Relaxed)
}

pub(crate) fn mix_delivery_dead_letters_total() -> u64 {
    MIX_DELIVERY_DEAD_LETTERS_TOTAL.load(Ordering::Relaxed)
}

pub(crate) fn mix_delivery_retries_total() -> u64 {
    MIX_DELIVERY_RETRIES_TOTAL.load(Ordering::Relaxed)
}

/// Fail-closed startup proof for the MIX delivery capacity protocol. Pending
/// release facts are still charged to the ledger until the next admission
/// folds them, so the invariant is exact without mutating recovery state.
pub async fn audit_mix_delivery_capacity_ledger(pool: &PgPool) -> Result<()> {
    let audit = sqlx::query(
        "WITH recipient_facts AS (
             SELECT (get_byte(uuid_send(delivery_id),0) % 64)::smallint AS bucket,
                    COUNT(*)::bigint AS queued_rows,
                    SUM(octet_length(recipient_jid)+128)::bigint AS queued_bytes
               FROM mix_delivery_recipients GROUP BY bucket
         ), event_facts AS (
             SELECT (get_byte(uuid_send(event_id),0) % 64)::smallint AS bucket,
                    SUM(octet_length(stanza_template))::bigint AS queued_bytes
               FROM mix_delivery_events GROUP BY bucket
         ), release_facts AS (
             SELECT capacity_bucket AS bucket,
                    SUM(released_rows)::bigint AS queued_rows,
                    SUM(released_bytes)::bigint AS queued_bytes
               FROM mix_delivery_capacity_releases GROUP BY capacity_bucket
         ), expected AS (
             SELECT bucket::smallint AS bucket,
                    COALESCE(recipient.queued_rows,0)
                      + COALESCE(release.queued_rows,0) AS queued_rows,
                    COALESCE(recipient.queued_bytes,0)
                      + COALESCE(event.queued_bytes,0)
                      + COALESCE(release.queued_bytes,0) AS queued_bytes
               FROM generate_series(0,63) AS generated(bucket)
               LEFT JOIN recipient_facts recipient USING(bucket)
               LEFT JOIN event_facts event USING(bucket)
               LEFT JOIN release_facts release USING(bucket)
         )
         SELECT (SELECT COUNT(*) FROM mix_delivery_capacity)::bigint AS ledger_buckets,
                (SELECT COALESCE(SUM(queued_rows),0)::bigint
                   FROM mix_delivery_capacity) AS ledger_rows,
                (SELECT COALESCE(SUM(queued_bytes),0)::bigint
                   FROM mix_delivery_capacity) AS ledger_bytes,
                COUNT(*) FILTER (
                    WHERE capacity.bucket IS NULL
                       OR capacity.queued_rows<>expected.queued_rows
                       OR capacity.queued_bytes<>expected.queued_bytes
                )::bigint AS mismatch_buckets
           FROM expected
           LEFT JOIN mix_delivery_capacity capacity USING(bucket)",
    )
    .fetch_one(pool)
    .await?;
    let ledger_buckets: i64 = audit.get("ledger_buckets");
    let ledger_rows: i64 = audit.get("ledger_rows");
    let ledger_bytes: i64 = audit.get("ledger_bytes");
    let mismatch_buckets: i64 = audit.get("mismatch_buckets");
    anyhow::ensure!(
        ledger_buckets == 64
            && mismatch_buckets == 0
            && (0..=MIX_DELIVERY_MAX_ROWS).contains(&ledger_rows)
            && (0..=MIX_DELIVERY_MAX_BYTES).contains(&ledger_bytes),
        "MIX delivery capacity ledger audit failed: {ledger_buckets} buckets, {mismatch_buckets} mismatches, {ledger_rows} rows, {ledger_bytes} bytes"
    );
    Ok(())
}

/// Fail-closed startup proof for the database-maintained MIX-PAM capacity
/// authority. The counter tables are deliberately read-only to the runtime;
/// every operation insert/delete is projected by owner-held triggers.
pub async fn audit_mix_pam_operation_capacity(pool: &PgPool) -> Result<()> {
    let audit = sqlx::query(
        "WITH actual_by_user AS (
             SELECT user_id,COUNT(*)::bigint AS operation_count
               FROM mix_pam_operations GROUP BY user_id
         ), user_mismatches AS (
             SELECT COUNT(*)::bigint AS mismatch_count
               FROM actual_by_user actual
               FULL OUTER JOIN mix_pam_operation_user_capacity authority
                 USING(user_id)
              WHERE actual.operation_count IS DISTINCT FROM authority.operation_count
                 OR COALESCE(authority.operation_count,0) NOT BETWEEN 1 AND 64
         )
         SELECT (SELECT COUNT(*) FROM mix_pam_operation_capacity)::bigint
                    AS authority_rows,
                COALESCE((SELECT operation_count
                            FROM mix_pam_operation_capacity WHERE singleton),-1)::bigint
                    AS authority_count,
                COALESCE((SELECT max_operations
                            FROM mix_pam_operation_capacity WHERE singleton),-1)::bigint
                    AS max_operations,
                COALESCE((SELECT max_per_user
                            FROM mix_pam_operation_capacity WHERE singleton),-1)::bigint
                    AS max_per_user,
                (SELECT COUNT(*) FROM mix_pam_operations)::bigint AS actual_count,
                (SELECT mismatch_count FROM user_mismatches)::bigint AS user_mismatches",
    )
    .fetch_one(pool)
    .await?;
    let authority_rows: i64 = audit.get("authority_rows");
    let authority_count: i64 = audit.get("authority_count");
    let max_operations: i64 = audit.get("max_operations");
    let max_per_user: i64 = audit.get("max_per_user");
    let actual_count: i64 = audit.get("actual_count");
    let user_mismatches: i64 = audit.get("user_mismatches");
    anyhow::ensure!(
        authority_rows == 1
            && authority_count == actual_count
            && max_operations == 10_000
            && max_per_user == 64
            && (0..=max_operations).contains(&actual_count)
            && user_mismatches == 0,
        "MIX-PAM capacity authority audit failed: {authority_rows} global rows, authority={authority_count}, actual={actual_count}, max={max_operations}, per-user max={max_per_user}, user mismatches={user_mismatches}"
    );
    Ok(())
}

/// Proof that this transaction acquired the schema-local delivery admission
/// authority before taking any MIX business or sequence row lock.
struct MixDeliveryAdmissionFence(());

/// Proof that orphan reclamation and release-journal folding committed before
/// the producer transaction began. This phase must never share the producer's
/// rollback fate: a capacity rejection cannot resurrect the same false-full
/// ledger state for the next attempt.
struct MixDeliveryReconciliationCommitted(());

async fn acquire_mix_delivery_admission_fence_tx(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<MixDeliveryAdmissionFence> {
    // Only admissions mutate the capacity ledger. Delivery completion emits
    // immutable release facts and never takes this fence, so a completed
    // socket delivery cannot fail because an unrelated producer is reserving
    // capacity. The resolved capacity relation OID gives each installed schema
    // a distinct fence while PostgreSQL scopes advisory locks to its database.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(
                    hashtextextended(
                        'mix-delivery-capacity-v3:' ||
                        ('mix_delivery_capacity'::regclass)::oid::text,
                        0
                    )
                )",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(MixDeliveryAdmissionFence(()))
}

async fn begin_mix_delivery_fenced_transaction(
    pool: &PgPool,
) -> Result<(Transaction<'_, Postgres>, MixDeliveryAdmissionFence)> {
    let mut transaction = pool.begin().await?;
    // This is deliberately the first SQL statement in the transaction. A
    // cross-process waiter therefore owns no channel, participant, event or
    // sequence lock while it waits, which makes the blocking database fence a
    // deadlock-safe authority for experimental multi-process deployments.
    let fence = acquire_mix_delivery_admission_fence_tx(&mut transaction).await?;
    Ok((transaction, fence))
}

async fn reconcile_mix_delivery_capacity_committed(
    pool: &PgPool,
) -> Result<MixDeliveryReconciliationCommitted> {
    let mut transaction = pool.begin().await?;
    // The owner-held function takes the schema-local admission fence as its
    // first database action, removes every committed orphan (the hard ledger
    // bounds the set), and folds the resulting immutable release facts.
    let _: i64 = sqlx::query_scalar("SELECT northstar_mix_delivery_capacity_reconcile()")
        .fetch_one(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(MixDeliveryReconciliationCommitted(()))
}

async fn begin_mix_delivery_admission(
    pool: &PgPool,
) -> Result<(Transaction<'_, Postgres>, MixDeliveryAdmissionFence)> {
    let _committed = reconcile_mix_delivery_capacity_committed(pool).await?;
    begin_mix_delivery_fenced_transaction(pool).await
}

fn mix_delivery_capacity_bucket(id: Uuid) -> i16 {
    i16::from(id.as_bytes()[0] & 63)
}

fn add_mix_delivery_capacity_delta(
    deltas: &mut BTreeMap<i16, (i64, i64)>,
    bucket: i16,
    rows: i64,
    bytes: i64,
) -> Result<()> {
    let entry = deltas.entry(bucket).or_default();
    entry.0 = entry
        .0
        .checked_add(rows)
        .context("MIX delivery row accounting overflow")?;
    entry.1 = entry
        .1
        .checked_add(bytes)
        .context("MIX delivery byte accounting overflow")?;
    Ok(())
}

/// Merge committed release facts into the admission ledger while the exact
/// schema-local capacity fence is held. A delete and its release fact commit
/// atomically; deleting a fact and decrementing the ledger do too, so a crash
/// can only leave conservative over-accounting, never reusable phantom space.
async fn drain_mix_delivery_capacity_releases_tx(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    // The owner-held capability is the only DELETE surface on the write-once
    // release journal. It consumes the complete bounded fact set, applies all
    // credits atomically and raises inside PostgreSQL on any ledger underflow,
    // so a caller cannot commit a forged or partially-applied drain.
    let _: i64 = sqlx::query_scalar("SELECT northstar_mix_delivery_capacity_drain()")
        .fetch_one(&mut **transaction)
        .await?;
    Ok(())
}

async fn prune_empty_mix_delivery_events_tx(
    transaction: &mut Transaction<'_, Postgres>,
    limit: i64,
) -> Result<()> {
    // Recipient release facts are an indexed candidate set: the final physical
    // recipient delete always leaves one. Avoid scanning/sorting the complete
    // event table on every worker tick. A skipped locked orphan keeps its
    // recipient fact during the subsequent drain and is retried later.
    let candidates: Vec<Uuid> = sqlx::query_scalar(
        "WITH candidates AS (
             SELECT DISTINCT event.event_id
               FROM mix_delivery_capacity_releases release
               JOIN mix_delivery_events event
                 ON event.event_id=release.parent_event_id
              WHERE release.release_kind=1
                AND release.parent_event_id IS NOT NULL
                AND NOT EXISTS(
                    SELECT 1 FROM mix_delivery_recipients recipient
                     WHERE recipient.event_id=event.event_id
                )
              ORDER BY event.event_id
              LIMIT $1
         )
         SELECT event.event_id
               FROM mix_delivery_events event
               JOIN candidates candidate USING(event_id)
              WHERE NOT EXISTS(
                        SELECT 1 FROM mix_delivery_recipients recipient
                         WHERE recipient.event_id=event.event_id
                    )
              ORDER BY event.event_id
              FOR UPDATE OF event SKIP LOCKED",
    )
    .bind(limit.clamp(1, 4_096))
    .fetch_all(&mut **transaction)
    .await?;
    // Requeue can renew an existing orphan event and append a recipient
    // after our candidate snapshot. Recheck only after holding its row lock
    // with a fresh statement snapshot, or ON DELETE CASCADE could discard
    // that newly committed recipient along with the formerly empty event.
    if !candidates.is_empty() {
        sqlx::query(
            "DELETE FROM mix_delivery_events event
          WHERE event.event_id=ANY($1::uuid[])
            AND NOT EXISTS(
                SELECT 1 FROM mix_delivery_recipients recipient
                 WHERE recipient.event_id=event.event_id
            )",
        )
        .bind(&candidates)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn prune_empty_mix_delivery_events(pool: &PgPool, limit: i64) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await?;
    prune_empty_mix_delivery_events_tx(&mut transaction, limit).await?;
    transaction.commit().await?;
    Ok(())
}

async fn reserve_mix_delivery_capacity_tx(
    transaction: &mut Transaction<'_, Postgres>,
    _fence: &MixDeliveryAdmissionFence,
    deltas: &BTreeMap<i16, (i64, i64)>,
) -> Result<()> {
    if deltas.is_empty() {
        return Ok(());
    }
    // Orphan reclamation was committed before this producer transaction began.
    // The typed fence guarantees the blocking database authority was then
    // acquired before this transaction took any business lock. ACKs never take
    // it and continue to append authentic release facts concurrently.
    drain_mix_delivery_capacity_releases_tx(transaction).await?;
    let buckets = deltas.keys().copied().collect::<Vec<_>>();
    let added_rows = deltas.values().try_fold(0_i64, |total, delta| {
        total
            .checked_add(delta.0)
            .context("MIX delivery row accounting overflow")
    })?;
    let added_bytes = deltas.values().try_fold(0_i64, |total, delta| {
        total
            .checked_add(delta.1)
            .context("MIX delivery byte accounting overflow")
    })?;
    let totals = sqlx::query(
        "SELECT COALESCE(SUM(queued_rows),0)::bigint AS queued_rows,
                COALESCE(SUM(queued_bytes),0)::bigint AS queued_bytes
           FROM mix_delivery_capacity",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let queued_rows: i64 = totals.get("queued_rows");
    let queued_bytes: i64 = totals.get("queued_bytes");
    if queued_rows
        .checked_add(added_rows)
        .is_none_or(|rows| rows > MIX_DELIVERY_MAX_ROWS)
        || queued_bytes
            .checked_add(added_bytes)
            .is_none_or(|bytes| bytes > MIX_DELIVERY_MAX_BYTES)
    {
        MIX_DELIVERY_CAPACITY_REJECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("MIX delivery outbox capacity exceeded");
    }
    let row_deltas = deltas.values().map(|delta| delta.0).collect::<Vec<_>>();
    let byte_deltas = deltas.values().map(|delta| delta.1).collect::<Vec<_>>();
    let updated = sqlx::query(
        "UPDATE mix_delivery_capacity capacity
            SET queued_rows=capacity.queued_rows+delta.rows,
                queued_bytes=capacity.queued_bytes+delta.bytes,
                updated_at=clock_timestamp()
           FROM unnest($1::smallint[],$2::bigint[],$3::bigint[])
                AS delta(bucket,rows,bytes)
          WHERE capacity.bucket=delta.bucket",
    )
    .bind(&buckets)
    .bind(&row_deltas)
    .bind(&byte_deltas)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        updated == u64::try_from(deltas.len()).unwrap_or(u64::MAX),
        "MIX delivery capacity ledger is incomplete"
    );
    Ok(())
}

struct MixDeliveryProjection<'a> {
    channel: &'a MixChannel,
    event_id: Uuid,
    recipients: &'a [MixParticipant],
    stanza_template: &'a str,
    authoritative_stanza_id: Option<Uuid>,
    archive: bool,
    encrypted: bool,
}

async fn enqueue_mix_deliveries_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MixDeliveryAdmissionFence,
    projection: MixDeliveryProjection<'_>,
) -> Result<()> {
    let MixDeliveryProjection {
        channel,
        event_id,
        recipients,
        stanza_template,
        authoritative_stanza_id,
        archive,
        encrypted,
    } = projection;
    if recipients.is_empty() {
        return Ok(());
    }
    anyhow::ensure!(
        archive == authoritative_stanza_id.is_some(),
        "invalid MIX archive projection"
    );
    anyhow::ensure!(
        recipients.len() <= 5_000,
        "MIX delivery audience exceeds channel bound"
    );
    anyhow::ensure!(
        !stanza_template.is_empty() && stanza_template.len() <= 2_097_152,
        "invalid MIX delivery template"
    );
    // Canonical JID order is the producer lock order. Two channels may contain
    // the same recipients under opposite participant-id order; acquiring the
    // global recipient-sequence authorities in participant order would allow
    // the classic A->B/B->A deadlock before either producer reaches the
    // capacity fence.
    let mut ordered_recipients = recipients.iter().collect::<Vec<_>>();
    ordered_recipients.sort_unstable_by(|left, right| left.jid.cmp(&right.jid));
    let recipient_jids = ordered_recipients
        .iter()
        .map(|recipient| recipient.jid.clone())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        recipient_jids.iter().collect::<BTreeSet<_>>().len() == recipients.len(),
        "duplicate MIX delivery recipient"
    );
    let projected_recipients = ordered_recipients
        .iter()
        .copied()
        .map(|recipient| (Uuid::new_v4(), recipient))
        .collect::<Vec<_>>();
    let mut capacity_deltas = BTreeMap::new();
    add_mix_delivery_capacity_delta(
        &mut capacity_deltas,
        mix_delivery_capacity_bucket(event_id),
        0,
        i64::try_from(stanza_template.len()).context("MIX delivery template size overflow")?,
    )?;
    for (delivery_id, recipient) in &projected_recipients {
        let recipient_bytes = i64::try_from(recipient.jid.len())
            .context("MIX delivery recipient size overflow")?
            .checked_add(MIX_DELIVERY_RECIPIENT_OVERHEAD)
            .context("MIX delivery recipient accounting overflow")?;
        add_mix_delivery_capacity_delta(
            &mut capacity_deltas,
            mix_delivery_capacity_bucket(*delivery_id),
            1,
            recipient_bytes,
        )?;
    }
    sqlx::query(
        "INSERT INTO mix_delivery_events(event_id,channel_id,channel_jid,stanza_template,authoritative_stanza_id,archive,encrypted)
         VALUES($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(event_id)
    .bind(channel.id)
    .bind(channel.jid())
    .bind(stanza_template)
    .bind(authoritative_stanza_id)
    .bind(archive)
    .bind(encrypted)
    .execute(&mut **transaction)
    .await?;

    let sequence_rows = sqlx::query(
        "WITH input AS (
             SELECT jid FROM unnest($1::text[]) AS supplied(jid)
         )
         INSERT INTO mix_delivery_recipient_sequences(recipient_jid,next_sequence)
         SELECT jid,2 FROM input ORDER BY jid
         ON CONFLICT(recipient_jid) DO UPDATE
             SET next_sequence=mix_delivery_recipient_sequences.next_sequence+1
         RETURNING recipient_jid,next_sequence-1 AS delivery_sequence",
    )
    .bind(&recipient_jids)
    .fetch_all(&mut **transaction)
    .await?;
    let sequences = sequence_rows
        .into_iter()
        .map(|row| {
            (
                row.get::<String, _>("recipient_jid"),
                row.get::<i64, _>("delivery_sequence"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    anyhow::ensure!(
        sequences.len() == recipients.len(),
        "duplicate MIX delivery recipient"
    );

    let mut builder = QueryBuilder::<Postgres>::new(
        "INSERT INTO mix_delivery_recipients(delivery_id,event_id,recipient_participant_id,recipient_jid,delivery_sequence) ",
    );
    builder.push_values(
        &projected_recipients,
        |mut row, (delivery_id, recipient)| {
            row.push_bind(*delivery_id)
                .push_bind(event_id)
                .push_bind(recipient.participant_id)
                .push_bind(&recipient.jid)
                .push_bind(
                    *sequences
                        .get(&recipient.jid)
                        .expect("every normalized MIX recipient has a sequence"),
                );
        },
    );
    builder.build().execute(&mut **transaction).await?;
    // Reserve after both projections exist. The admission fence has been held
    // since transaction start, before any channel/sequence/event lock, so
    // another process cannot observe an inverted lock order. Failure rolls
    // every inserted row back with the reservation.
    reserve_mix_delivery_capacity_tx(transaction, fence, &capacity_deltas).await?;
    Ok(())
}

async fn remove_mix_delivery_tx(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: Uuid,
    lease_token: Uuid,
) -> Result<Option<(Uuid, String)>> {
    // Completion owns only its exact leased recipient. It never locks the
    // shared parent event, sequence authority or capacity ledger, so a 5,000
    // recipient broadcast can acknowledge concurrently. Bounded background
    // GC removes an empty event and sequence after all recipient deletes have
    // committed; capacity remains conservatively over-accounted meanwhile.
    let row = sqlx::query(
        "DELETE FROM mix_delivery_recipients
          WHERE delivery_id=$1 AND lease_token=$2
          RETURNING event_id,recipient_jid",
    )
    .bind(delivery_id)
    .bind(lease_token)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let event_id: Uuid = row.get("event_id");
    let recipient_jid: String = row.get("recipient_jid");
    Ok(Some((event_id, recipient_jid)))
}

async fn move_mix_delivery_to_dead_letter_tx(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: Uuid,
    lease_token: Uuid,
    terminal_reason: &str,
    error: &str,
) -> Result<bool> {
    anyhow::ensure!(
        !terminal_reason.is_empty() && terminal_reason.len() <= 64,
        "invalid MIX dead-letter reason"
    );
    let inserted = sqlx::query(
        "INSERT INTO mix_delivery_dead_letters(
             dead_letter_id,delivery_id,event_id,channel_id,channel_jid,
             recipient_participant_id,recipient_jid,delivery_sequence,
             stanza_template,authoritative_stanza_id,archive,encrypted,
             attempt_count,terminal_reason,last_error,
             original_created_at,original_expires_at
         )
         SELECT $5,recipient.delivery_id,event.event_id,event.channel_id,event.channel_jid,
                recipient.recipient_participant_id,recipient.recipient_jid,
                recipient.delivery_sequence,event.stanza_template,
                event.authoritative_stanza_id,event.archive,event.encrypted,
                recipient.attempt_count,$3,left($4,2048),
                recipient.created_at,event.expires_at
           FROM mix_delivery_recipients recipient
           JOIN mix_delivery_events event ON event.event_id=recipient.event_id
          WHERE recipient.delivery_id=$1 AND recipient.lease_token=$2
         ON CONFLICT(delivery_id) DO NOTHING",
    )
    .bind(delivery_id)
    .bind(lease_token)
    .bind(terminal_reason)
    .bind(error)
    .bind(Uuid::new_v4())
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if inserted != 1 {
        return Ok(false);
    }
    anyhow::ensure!(
        remove_mix_delivery_tx(transaction, delivery_id, lease_token)
            .await?
            .is_some(),
        "MIX dead-letter projection lost its delivery fence"
    );
    sqlx::query(
        "DELETE FROM mix_delivery_dead_letters dead
          WHERE dead.dead_letter_id IN (
              SELECT dead_letter_id FROM mix_delivery_dead_letters
               ORDER BY failed_at DESC,dead_letter_id DESC
              OFFSET $1
          )",
    )
    .bind(MIX_DELIVERY_DEAD_LETTER_LIMIT)
    .execute(&mut **transaction)
    .await?;
    Ok(true)
}

async fn dead_letter_expired_mix_deliveries(pool: &PgPool, limit: i64) -> Result<()> {
    let mut transaction = pool.begin().await?;
    let mut moved = 0_u64;
    let rows = sqlx::query(
        "SELECT recipient.delivery_id
           FROM mix_delivery_recipients recipient
           JOIN mix_delivery_events event ON event.event_id=recipient.event_id
          WHERE event.expires_at<=clock_timestamp()
            AND (recipient.lease_until IS NULL OR recipient.lease_until<=clock_timestamp())
            AND NOT EXISTS(
                SELECT 1
                  FROM sm_resume_stanzas stanza
                  JOIN sm_resume_sessions session ON session.id=stanza.session_id
                 WHERE stanza.mix_delivery_id=recipient.delivery_id
                   AND session.expires_at>clock_timestamp()
            )
            AND NOT EXISTS(
                SELECT 1 FROM mix_bosh_delivery_fences fence
                 WHERE fence.delivery_id=recipient.delivery_id
                   AND fence.expires_at>clock_timestamp()
            )
            AND NOT EXISTS(
                SELECT 1 FROM mix_cluster_delivery_fences fence
                 WHERE fence.delivery_id=recipient.delivery_id
                   AND fence.expires_at>clock_timestamp()
            )
          ORDER BY event.expires_at,recipient.delivery_sequence
          LIMIT $1 FOR UPDATE OF recipient SKIP LOCKED",
    )
    .bind(limit.clamp(1, 1_000))
    .fetch_all(&mut *transaction)
    .await?;
    for row in rows {
        let delivery_id: Uuid = row.get("delivery_id");
        let lease_token = Uuid::new_v4();
        let claimed = sqlx::query(
            "UPDATE mix_delivery_recipients
                SET lease_token=$2,lease_until=clock_timestamp()+make_interval(secs=>$3)
              WHERE delivery_id=$1
                AND (lease_until IS NULL OR lease_until<=clock_timestamp())",
        )
        .bind(delivery_id)
        .bind(lease_token)
        .bind(MIX_DELIVERY_LEASE_SECONDS)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if claimed == 1
            && move_mix_delivery_to_dead_letter_tx(
                &mut transaction,
                delivery_id,
                lease_token,
                "expired",
                "MIX delivery exceeded its durable retention window",
            )
            .await?
        {
            moved = moved.saturating_add(1);
        }
    }
    transaction.commit().await?;
    MIX_DELIVERY_DEAD_LETTERS_TOTAL.fetch_add(moved, Ordering::Relaxed);
    Ok(())
}

async fn prune_empty_mix_delivery_sequences(pool: &PgPool, limit: i64) -> Result<()> {
    let mut transaction = pool.begin().await?;
    // The producer updates this authority before inserting its recipients.
    // A single SELECT/DELETE statement can retain a snapshot from before that
    // producer committed, then lock its updated authority and still consider
    // it empty. Hold the candidate locks across a second READ COMMITTED
    // statement so the emptiness check sees every producer that beat us to
    // the lock; later producers must wait until this transaction finishes.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await?;
    let candidates: Vec<String> = sqlx::query_scalar(
        "SELECT authority.recipient_jid
               FROM mix_delivery_recipient_sequences authority
              WHERE NOT EXISTS(
                        SELECT 1 FROM mix_delivery_recipients live
                         WHERE live.recipient_jid=authority.recipient_jid
                    )
                AND NOT EXISTS(
                        SELECT 1 FROM mix_delivery_dead_letters dead
                         WHERE dead.recipient_jid=authority.recipient_jid
                    )
              ORDER BY authority.recipient_jid
              LIMIT $1 FOR UPDATE SKIP LOCKED",
    )
    .bind(limit.clamp(1, 1_024))
    .fetch_all(&mut *transaction)
    .await?;
    if !candidates.is_empty() {
        sqlx::query(
            "DELETE FROM mix_delivery_recipient_sequences authority
              WHERE authority.recipient_jid=ANY($1::text[])
                AND NOT EXISTS(
                    SELECT 1 FROM mix_delivery_recipients live
                     WHERE live.recipient_jid=authority.recipient_jid
                )
                AND NOT EXISTS(
                    SELECT 1 FROM mix_delivery_dead_letters dead
                     WHERE dead.recipient_jid=authority.recipient_jid
                )",
        )
        .bind(&candidates)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

/// Run bounded retention work outside the latency-sensitive delivery claim.
///
/// An expired recipient which has no active worker or durable transport owner
/// must still be terminalized before its successor in the same recipient
/// sequence can advance. This page records that dead-letter projection and
/// then reclaims orphaned event/sequence state. It remains outside the normal
/// first-message claim path: only a predecessor in the same ordering domain
/// waits for this bounded terminalization step.
pub async fn maintain_mix_delivery_retention(pool: &PgPool) -> Result<()> {
    dead_letter_expired_mix_deliveries(pool, 256).await?;
    // Event GC only appends a release fact. It never takes the producer
    // capacity fence, so cleanup remains independent of foreground admission.
    prune_empty_mix_delivery_events(pool, 256).await?;
    prune_empty_mix_delivery_sequences(pool, 256).await
}

pub async fn claim_mix_deliveries(
    pool: &PgPool,
    limit: i64,
    max_bytes: i64,
) -> Result<Vec<ClaimedMixDelivery>> {
    let mut connection = pool.acquire().await?;
    // PostgreSQL locks every relation used by the full claim even when the
    // queue is empty. Its joins and indexes exceed PG17's fast-path lock
    // budget, making otherwise idle servers contend in the shared lock
    // manager. A narrow committed read avoids that work on the empty path.
    // A racing insertion is handled by the retained delivery wake or the
    // unchanged bounded recovery scan; a nonempty queue still uses every
    // lease, transport-owner and ordering predicate below.
    // Checking catalog privileges takes no locks on the joined application
    // tables. Only the normal, writable runtime role may take the shortcut;
    // otherwise the original claim below decides the result. In particular,
    // retain its read-only/permission errors and support for column grants.
    let (authorized, pending): (bool, bool) = sqlx::query_as(
        "SELECT current_setting('transaction_read_only') = 'off'
                AND (SELECT bool_and(has_table_privilege(relation, privilege))
                       FROM (VALUES
                         ('mix_delivery_recipients', 'SELECT'),
                         ('mix_delivery_recipients', 'UPDATE'),
                         ('mix_delivery_events', 'SELECT'),
                         ('mix_delivery_recipient_sequences', 'SELECT'),
                         ('mix_delivery_recipient_sequences', 'UPDATE'),
                         ('sm_resume_stanzas', 'SELECT'),
                         ('sm_resume_sessions', 'SELECT'),
                         ('mix_bosh_delivery_fences', 'SELECT'),
                         ('mix_cluster_delivery_fences', 'SELECT')
                       ) required(relation, privilege)),
                EXISTS(SELECT 1 FROM mix_delivery_recipients)",
    )
    .fetch_one(&mut *connection)
    .await?;
    if authorized && !pending {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "WITH candidates AS (
             SELECT recipient.delivery_id,
                    octet_length(event.stanza_template)+octet_length(recipient.recipient_jid)+128 AS delivery_bytes,
                    event.created_at,
                    recipient.delivery_sequence
               FROM mix_delivery_recipients recipient
               JOIN mix_delivery_events event ON event.event_id=recipient.event_id
               JOIN mix_delivery_recipient_sequences authority
                 ON authority.recipient_jid=recipient.recipient_jid
              WHERE event.expires_at>clock_timestamp()
                AND (recipient.lease_until IS NULL OR recipient.lease_until<=clock_timestamp())
                AND recipient.next_attempt_at<=clock_timestamp()
                AND NOT EXISTS(
                    SELECT 1
                      FROM sm_resume_stanzas stanza
                      JOIN sm_resume_sessions session ON session.id=stanza.session_id
                     WHERE stanza.mix_delivery_id=recipient.delivery_id
                       AND session.expires_at>clock_timestamp()
                )
                AND NOT EXISTS(
                    SELECT 1 FROM mix_bosh_delivery_fences fence
                     WHERE fence.delivery_id=recipient.delivery_id
                       AND fence.expires_at>clock_timestamp()
                )
                AND NOT EXISTS(
                    SELECT 1 FROM mix_cluster_delivery_fences fence
                     WHERE fence.delivery_id=recipient.delivery_id
                       AND fence.expires_at>clock_timestamp()
                )
                AND NOT EXISTS (
                    SELECT 1 FROM mix_delivery_recipients earlier
                     WHERE earlier.recipient_jid=recipient.recipient_jid
                       -- The row remains the ordered head until a durable
                       -- terminal transition removes it. In particular,
                       -- expiry without a lease/SM/BOSH/cluster owner is not
                       -- itself terminal: retention must first record the
                       -- dead-letter projection. This does not put unrelated
                       -- retention ahead of a first delivery.
                       AND earlier.delivery_sequence < recipient.delivery_sequence
                )
              ORDER BY event.created_at,recipient.delivery_sequence,recipient.delivery_id
              LIMIT 512 FOR UPDATE OF recipient,authority SKIP LOCKED
         ), sized AS (
             SELECT delivery_id,delivery_bytes,
                    row_number() OVER (ORDER BY created_at,delivery_sequence,delivery_id) AS candidate_rank,
                    SUM(delivery_bytes) OVER (ORDER BY created_at,delivery_sequence,delivery_id) AS running_bytes
               FROM candidates
         ), eligible AS (
             SELECT delivery_id FROM sized
              WHERE running_bytes<=$2 OR candidate_rank=1
              ORDER BY running_bytes
              LIMIT $1
         ), claimed AS (
             UPDATE mix_delivery_recipients recipient
                SET lease_token=gen_random_uuid(),
                    lease_until=clock_timestamp()+make_interval(secs=>$3)
               FROM eligible WHERE recipient.delivery_id=eligible.delivery_id
             RETURNING recipient.*
         )
         SELECT claimed.delivery_id,event.event_id,event.channel_id,event.channel_jid,
                claimed.recipient_participant_id,claimed.recipient_jid,
                event.stanza_template AS stanza,event.authoritative_stanza_id,
                event.archive,event.encrypted,claimed.attempt_count,
                claimed.lease_token,claimed.route_wake_generation
           FROM claimed JOIN mix_delivery_events event ON event.event_id=claimed.event_id
          ORDER BY event.created_at,claimed.delivery_sequence,claimed.delivery_id",
    )
    .bind(limit.clamp(1, 128))
    .bind(max_bytes.clamp(65_536, 16_777_216))
    .bind(MIX_DELIVERY_LEASE_SECONDS)
    .fetch_all(&mut *connection)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ClaimedMixDelivery {
            delivery_id: row.get("delivery_id"),
            event_id: row.get("event_id"),
            channel_id: row.get("channel_id"),
            channel_jid: row.get("channel_jid"),
            recipient: MixParticipant {
                participant_id: row.get("recipient_participant_id"),
                jid: row.get("recipient_jid"),
                nick: None,
            },
            stanza: row.get("stanza"),
            authoritative_stanza_id: row.get("authoritative_stanza_id"),
            archive: row.get("archive"),
            encrypted: row.get("encrypted"),
            attempt_count: row.get("attempt_count"),
            lease_token: row.get("lease_token"),
            route_wake_generation: row.get("route_wake_generation"),
        })
        .collect())
}

pub async fn acknowledge_mix_delivery(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let removed = remove_mix_delivery_tx(&mut transaction, delivery_id, lease_token)
        .await?
        .is_some();
    transaction.commit().await?;
    if !removed {
        MIX_DELIVERY_LEASE_LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    Ok(removed)
}

/// Consume an optional remote-node fence while holding the recipient row.
///
/// A direct socket, XEP-0198 or BOSH transfer receives the rotated fence
/// token through a signed cluster command. The token is sufficient proof of
/// that exact hand-off, but the fence must be removed before the next local
/// transport owner is recorded. Calling this for a normal local source is a
/// no-op; a different active token is always an ownership violation.
pub(crate) async fn consume_mix_cluster_delivery_fence_tx(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    source: crate::outbound::MixDelivery,
) -> Result<()> {
    let fence = sqlx::query(
        "SELECT lease_token,expires_at>clock_timestamp() AS active
           FROM mix_cluster_delivery_fences
          WHERE delivery_id=$1 FOR UPDATE",
    )
    .bind(source.delivery_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(fence) = fence else {
        return Ok(());
    };
    let fence_token: Uuid = fence.try_get("lease_token")?;
    anyhow::ensure!(
        fence_token == source.lease_token,
        "MIX cluster hand-off fence is owned by a different source lease"
    );
    let removed = sqlx::query(
        "DELETE FROM mix_cluster_delivery_fences
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        removed == 1,
        "MIX cluster hand-off fence changed during local transport transfer"
    );
    Ok(())
}

/// Move an exact claimed source to one authenticated remote node before that
/// node is allowed to enqueue it locally. The source worker's original token
/// becomes invalid in the same transaction, so a lost Redis acknowledgement
/// can only leave a recoverable remote fence rather than two active writers.
pub async fn transfer_mix_delivery_to_cluster(
    pool: &PgPool,
    source: crate::outbound::MixDelivery,
    node_id: &str,
    request_id: Uuid,
    ttl_seconds: u64,
) -> Result<crate::outbound::MixDelivery> {
    anyhow::ensure!(
        !node_id.is_empty() && node_id.len() <= 128 && !node_id.chars().any(char::is_control),
        "MIX cluster hand-off node identifier is invalid"
    );
    let ttl_seconds = i64::try_from(ttl_seconds.clamp(1, 300))
        .context("MIX cluster hand-off TTL is too large")?;
    let mut transaction = pool.begin().await?;
    let recipient = sqlx::query(
        "SELECT lease_until>clock_timestamp() AS active
           FROM mix_delivery_recipients
          WHERE delivery_id=$1 AND lease_token=$2
          FOR UPDATE",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(recipient) = recipient else {
        anyhow::bail!("MIX lease changed before cluster hand-off");
    };
    anyhow::ensure!(
        recipient.try_get::<bool, _>("active")?,
        "MIX lease expired before cluster hand-off"
    );
    let sm_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM sm_resume_stanzas stanza
               JOIN sm_resume_sessions session ON session.id=stanza.session_id
              WHERE stanza.mix_delivery_id=$1
                AND session.expires_at>clock_timestamp()
         )",
    )
    .bind(source.delivery_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        !sm_owned,
        "MIX delivery is already owned by an active XEP-0198 sequence"
    );
    let bosh_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM mix_bosh_delivery_fences
              WHERE delivery_id=$1 AND expires_at>clock_timestamp()
         )",
    )
    .bind(source.delivery_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        !bosh_owned,
        "MIX delivery is already owned by an active BOSH response"
    );
    let existing = sqlx::query(
        "SELECT expires_at>clock_timestamp() AS active
           FROM mix_cluster_delivery_fences
          WHERE delivery_id=$1 FOR UPDATE",
    )
    .bind(source.delivery_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(existing) = existing {
        anyhow::ensure!(
            !existing.try_get::<bool, _>("active")?,
            "MIX delivery is already owned by an active remote node"
        );
        sqlx::query("DELETE FROM mix_cluster_delivery_fences WHERE delivery_id=$1")
            .bind(source.delivery_id)
            .execute(&mut *transaction)
            .await?;
    }
    let transferred = crate::outbound::MixDelivery {
        delivery_id: source.delivery_id,
        lease_token: Uuid::new_v4(),
    };
    let updated = sqlx::query(
        "UPDATE mix_delivery_recipients
            SET lease_token=$3,
                lease_until=clock_timestamp()+make_interval(secs=>$4)
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .bind(transferred.lease_token)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(updated == 1, "MIX lease changed during cluster hand-off");
    let inserted = sqlx::query(
        "INSERT INTO mix_cluster_delivery_fences(
            delivery_id,lease_token,node_id,request_id,expires_at
         ) VALUES($1,$2,$3,$4,clock_timestamp()+make_interval(secs=>$5))",
    )
    .bind(transferred.delivery_id)
    .bind(transferred.lease_token)
    .bind(node_id)
    .bind(request_id)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        inserted == 1,
        "MIX cluster hand-off did not create its fence"
    );
    transaction.commit().await?;
    Ok(transferred)
}

/// Release an exact remote-node hand-off which failed before it became a
/// socket, SM, or BOSH owner. A mismatched token is intentionally harmless:
/// it proves that a later local transport already took responsibility.
pub async fn release_mix_cluster_delivery(
    pool: &PgPool,
    source: crate::outbound::MixDelivery,
    node_id: &str,
    request_id: Uuid,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let recipient = sqlx::query(
        "SELECT lease_token FROM mix_delivery_recipients
          WHERE delivery_id=$1 FOR UPDATE",
    )
    .bind(source.delivery_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(recipient) = recipient else {
        transaction.commit().await?;
        return Ok(false);
    };
    if recipient.try_get::<Option<Uuid>, _>("lease_token")? != Some(source.lease_token) {
        transaction.commit().await?;
        return Ok(false);
    }
    let fence = sqlx::query(
        "SELECT lease_token FROM mix_cluster_delivery_fences
          WHERE delivery_id=$1 AND node_id=$2 AND request_id=$3 FOR UPDATE",
    )
    .bind(source.delivery_id)
    .bind(node_id)
    .bind(request_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(fence) = fence else {
        transaction.commit().await?;
        return Ok(false);
    };
    if fence.try_get::<Uuid, _>("lease_token")? != source.lease_token {
        transaction.commit().await?;
        return Ok(false);
    }
    let released = sqlx::query(
        "UPDATE mix_delivery_recipients
            SET lease_token=NULL,lease_until=NULL,next_attempt_at=clock_timestamp(),
                last_error='remote cluster transport did not establish ownership'
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(released == 1, "MIX cluster hand-off lost its recipient row");
    let deleted = sqlx::query(
        "DELETE FROM mix_cluster_delivery_fences
          WHERE delivery_id=$1 AND lease_token=$2 AND node_id=$3 AND request_id=$4",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .bind(node_id)
    .bind(request_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        deleted == 1,
        "MIX cluster hand-off fence changed during release"
    );
    transaction.commit().await?;
    Ok(true)
}

/// Transfer a claimed MIX recipient source to one direct TCP/WebSocket writer
/// before it receives the stanza bytes. The returned rotated token belongs
/// only to that writer. A claiming worker which still holds `source` can no
/// longer retry or acknowledge it, so a queued stale item cannot overtake the
/// recovery path after its caller is cancelled.
pub async fn fence_mix_socket_write(
    pool: &PgPool,
    source: crate::outbound::MixDelivery,
) -> Result<crate::outbound::MixDelivery> {
    let mut transaction = pool.begin().await?;
    let recipient = sqlx::query(
        "SELECT lease_until>clock_timestamp() AS active
           FROM mix_delivery_recipients
          WHERE delivery_id=$1 AND lease_token=$2
          FOR UPDATE",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(recipient) = recipient else {
        anyhow::bail!("MIX lease changed before direct socket fencing");
    };
    anyhow::ensure!(
        recipient.try_get::<bool, _>("active")?,
        "MIX lease expired before direct socket fencing"
    );
    let sm_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM sm_resume_stanzas stanza
               JOIN sm_resume_sessions session ON session.id=stanza.session_id
              WHERE stanza.mix_delivery_id=$1
                AND session.expires_at>clock_timestamp()
         )",
    )
    .bind(source.delivery_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        !sm_owned,
        "MIX delivery is already owned by an active XEP-0198 sequence"
    );
    let bosh_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM mix_bosh_delivery_fences
              WHERE delivery_id=$1 AND expires_at>clock_timestamp()
         )",
    )
    .bind(source.delivery_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        !bosh_owned,
        "MIX delivery is already owned by an active BOSH response"
    );
    consume_mix_cluster_delivery_fence_tx(&mut transaction, source).await?;
    let fenced = crate::outbound::MixDelivery {
        delivery_id: source.delivery_id,
        lease_token: Uuid::new_v4(),
    };
    let updated = sqlx::query(
        "UPDATE mix_delivery_recipients
            SET lease_token=$3,
                lease_until=clock_timestamp()+make_interval(secs=>$4)
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .bind(fenced.lease_token)
    .bind(MIX_SOCKET_WRITE_FENCE_SECONDS)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        updated == 1,
        "MIX lease changed while direct socket fencing was committed"
    );
    transaction.commit().await?;
    Ok(fenced)
}

/// Transfer one exact claimed MIX recipient lease to a BOSH actor before the
/// actor is allowed to retain the stanza in its response FIFO. The original
/// worker token is rotated in the same transaction so a delayed worker cannot
/// retry, dead-letter, or acknowledge a source already owned by BOSH.
pub async fn transfer_mix_delivery_to_bosh(
    pool: &PgPool,
    source: crate::outbound::MixDelivery,
    session_id: Uuid,
    ttl_seconds: u64,
) -> Result<crate::outbound::MixDelivery> {
    let ttl_seconds =
        i64::try_from(ttl_seconds.clamp(1, 300)).context("MIX BOSH hand-off TTL is too large")?;
    let mut transaction = pool.begin().await?;
    let recipient = sqlx::query(
        "SELECT lease_until>clock_timestamp() AS active
           FROM mix_delivery_recipients
          WHERE delivery_id=$1 AND lease_token=$2
          FOR UPDATE",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(recipient) = recipient else {
        anyhow::bail!("MIX lease changed before BOSH ownership transfer");
    };
    anyhow::ensure!(
        recipient.try_get::<bool, _>("active")?,
        "MIX lease expired before BOSH ownership transfer"
    );
    let sm_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM sm_resume_stanzas stanza
               JOIN sm_resume_sessions session ON session.id=stanza.session_id
              WHERE stanza.mix_delivery_id=$1
                AND session.expires_at>clock_timestamp()
         )",
    )
    .bind(source.delivery_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        !sm_owned,
        "MIX delivery is already owned by an active XEP-0198 sequence"
    );
    consume_mix_cluster_delivery_fence_tx(&mut transaction, source).await?;
    let existing = sqlx::query(
        "SELECT session_id,expires_at>clock_timestamp() AS active
           FROM mix_bosh_delivery_fences
          WHERE delivery_id=$1
          FOR UPDATE",
    )
    .bind(source.delivery_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(existing) = existing {
        anyhow::ensure!(
            !existing.try_get::<bool, _>("active")?,
            "MIX delivery is already owned by an active BOSH response"
        );
        sqlx::query("DELETE FROM mix_bosh_delivery_fences WHERE delivery_id=$1")
            .bind(source.delivery_id)
            .execute(&mut *transaction)
            .await?;
    }
    let transferred = crate::outbound::MixDelivery {
        delivery_id: source.delivery_id,
        lease_token: Uuid::new_v4(),
    };
    let updated = sqlx::query(
        "UPDATE mix_delivery_recipients
            SET lease_token=$3,
                lease_until=clock_timestamp()+make_interval(secs=>$4)
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .bind(transferred.lease_token)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        updated == 1,
        "MIX lease changed while BOSH ownership was being transferred"
    );
    let inserted = sqlx::query(
        "INSERT INTO mix_bosh_delivery_fences(
            delivery_id,lease_token,session_id,expires_at
         ) VALUES(
            $1,$2,$3,
            clock_timestamp()+make_interval(secs=>$4)
         )",
    )
    .bind(transferred.delivery_id)
    .bind(transferred.lease_token)
    .bind(session_id)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        inserted == 1,
        "MIX BOSH ownership transfer did not create its fence"
    );
    transaction.commit().await?;
    Ok(transferred)
}

pub async fn renew_mix_delivery_lease(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
) -> Result<bool> {
    let renewed = sqlx::query(
        "UPDATE mix_delivery_recipients
            SET lease_until=clock_timestamp()+make_interval(secs=>$3)
          WHERE delivery_id=$1 AND lease_token=$2 AND lease_until>clock_timestamp()",
    )
    .bind(delivery_id)
    .bind(lease_token)
    .bind(MIX_DELIVERY_LEASE_SECONDS)
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    if !renewed {
        MIX_DELIVERY_LEASE_LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    Ok(renewed)
}

pub async fn dead_letter_mix_delivery(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
    terminal_reason: &str,
    error: &str,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let moved = move_mix_delivery_to_dead_letter_tx(
        &mut transaction,
        delivery_id,
        lease_token,
        terminal_reason,
        error,
    )
    .await?;
    transaction.commit().await?;
    if !moved {
        MIX_DELIVERY_LEASE_LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
    } else {
        MIX_DELIVERY_DEAD_LETTERS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    Ok(moved)
}

pub async fn retry_mix_delivery(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
    route_wake_generation: i64,
    error: &str,
) -> Result<MixDeliveryRetryOutcome> {
    // The worker's claimed attempt count is intentionally *not* an authority:
    // lease recovery or a route wake can race after claim.  Hold the exact
    // recipient row while reading both durable values and while choosing
    // between retry, route-woken release, and terminal deletion.  That makes
    // a wake committed before this lock observable before the terminal branch;
    // a wake that arrives later serializes after this completion and advances
    // the then-current ordered head instead.
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT attempt_count,route_wake_generation
           FROM mix_delivery_recipients
          WHERE delivery_id=$1 AND lease_token=$2
          FOR UPDATE",
    )
    .bind(delivery_id)
    .bind(lease_token)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.commit().await?;
        MIX_DELIVERY_LEASE_LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
        return Ok(MixDeliveryRetryOutcome::LeaseLost);
    };

    let persisted_attempt_count: i32 = row.get("attempt_count");
    let persisted_route_wake_generation: i64 = row.get("route_wake_generation");
    let next_attempt = persisted_attempt_count.saturating_add(1);
    let outcome = if next_attempt >= 20 {
        if persisted_route_wake_generation != route_wake_generation {
            // Do not consume the terminal attempt merely because a routing
            // fact arrived after claim. Keeping the persisted count unchanged
            // grants the verified route exactly one new claimed delivery; a
            // subsequent failure without another wake follows the ordinary
            // terminal branch below.
            let released = sqlx::query(
                "UPDATE mix_delivery_recipients
                    SET next_attempt_at=clock_timestamp(),
                        lease_token=NULL,lease_until=NULL,last_error=left($3,2048)
                  WHERE delivery_id=$1 AND lease_token=$2",
            )
            .bind(delivery_id)
            .bind(lease_token)
            .bind(error)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            anyhow::ensure!(
                released == 1,
                "MIX route-woken retry lost its locked delivery fence"
            );
            MixDeliveryRetryOutcome::RouteWokenAtAttemptLimit
        } else {
            anyhow::ensure!(
                move_mix_delivery_to_dead_letter_tx(
                    &mut transaction,
                    delivery_id,
                    lease_token,
                    "attempt-limit",
                    error,
                )
                .await?,
                "MIX terminal retry lost its locked delivery fence"
            );
            MixDeliveryRetryOutcome::DeadLettered
        }
    } else {
        let delay = 1_i64 << u32::try_from(next_attempt.clamp(0, 10)).unwrap_or(10);
        // A capacity/route wake can commit after this worker claimed the row
        // but before it releases the lease. The row lock above makes this
        // comparison the same durable observation used for terminal routing.
        let released = sqlx::query(
            "UPDATE mix_delivery_recipients
                SET attempt_count=$3,
                    next_attempt_at=CASE
                        WHEN route_wake_generation<>$4 THEN clock_timestamp()
                        ELSE clock_timestamp()+make_interval(secs=>$5)
                    END,
                    lease_token=NULL,lease_until=NULL,last_error=left($6,2048)
              WHERE delivery_id=$1 AND lease_token=$2",
        )
        .bind(delivery_id)
        .bind(lease_token)
        .bind(next_attempt)
        .bind(route_wake_generation)
        .bind(delay)
        .bind(error)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(
            released == 1,
            "MIX non-terminal retry lost its locked delivery fence"
        );
        MixDeliveryRetryOutcome::Retried
    };
    transaction.commit().await?;
    match outcome {
        MixDeliveryRetryOutcome::LeaseLost => unreachable!("handled before the transaction"),
        MixDeliveryRetryOutcome::Retried | MixDeliveryRetryOutcome::RouteWokenAtAttemptLimit => {
            MIX_DELIVERY_RETRIES_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        MixDeliveryRetryOutcome::DeadLettered => {
            MIX_DELIVERY_DEAD_LETTERS_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
    }
    Ok(outcome)
}

pub async fn defer_mix_delivery(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
    route_wake_generation: i64,
    delay_seconds: i64,
) -> Result<bool> {
    // `route_wake_generation` is captured atomically with the lease. A
    // verified resource wake updates the same recipient row, so the UPDATE
    // below serializes with it: if the wake committed first we release for an
    // immediate re-claim; if it waits behind this UPDATE it advances the
    // unleased head to `clock_timestamp()` afterwards. Either order retains
    // the route wake across processes without weakening the fallback delay.
    let updated = sqlx::query(
        "UPDATE mix_delivery_recipients
            SET next_attempt_at=CASE
                    WHEN route_wake_generation<>$3 THEN clock_timestamp()
                    ELSE clock_timestamp()+make_interval(secs=>$4)
                END,
                lease_token=NULL,lease_until=NULL
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(delivery_id)
    .bind(lease_token)
    .bind(route_wake_generation)
    .bind(delay_seconds.clamp(1, 30))
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    if !updated {
        MIX_DELIVERY_LEASE_LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    Ok(updated)
}

/// Make the current ordered delivery head for one recipient eligible now.
///
/// Advance only the persisted head row, preserving per-recipient order.
/// Increment its wake epoch even while leased so the current owner cannot
/// overwrite the wake with a recovery delay. Delivery still requires a fenced claim.
pub async fn wake_mix_delivery_recipient(pool: &PgPool, recipient_jid: &str) -> Result<u64> {
    let updated = sqlx::query(
        "UPDATE mix_delivery_recipients AS recipient
            SET route_wake_generation=route_wake_generation+1,
                next_attempt_at=CASE
                    WHEN recipient.lease_token IS NULL
                        THEN clock_timestamp()
                    ELSE recipient.next_attempt_at
                END
          WHERE recipient.recipient_jid=$1
            AND NOT EXISTS(
                SELECT 1
                 FROM mix_delivery_recipients AS earlier
                 WHERE earlier.recipient_jid=recipient.recipient_jid
                   AND earlier.delivery_sequence < recipient.delivery_sequence
            )",
    )
    .bind(recipient_jid)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(updated)
}

pub async fn mix_delivery_dead_letters(
    pool: &PgPool,
    before: Option<(DateTime<Utc>, Uuid)>,
    limit: i64,
) -> Result<Vec<MixDeliveryDeadLetter>> {
    let rows = sqlx::query(
        "SELECT dead_letter_id,delivery_id,event_id,channel_id,channel_jid,recipient_jid,
                attempt_count,terminal_reason,last_error,failed_at
           FROM mix_delivery_dead_letters
          WHERE ($1::timestamptz IS NULL OR (failed_at,dead_letter_id)<($1,$2))
          ORDER BY failed_at DESC,dead_letter_id DESC LIMIT $3",
    )
    .bind(before.as_ref().map(|cursor| cursor.0))
    .bind(before.as_ref().map(|cursor| cursor.1))
    .bind(limit.clamp(1, 200))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| MixDeliveryDeadLetter {
            dead_letter_id: row.get("dead_letter_id"),
            delivery_id: row.get("delivery_id"),
            event_id: row.get("event_id"),
            channel_id: row.get("channel_id"),
            channel_jid: row.get("channel_jid"),
            recipient_jid: row.get("recipient_jid"),
            attempt_count: row.get("attempt_count"),
            terminal_reason: row.get("terminal_reason"),
            last_error: row.get("last_error"),
            failed_at: row.get("failed_at"),
        })
        .collect())
}

/// Re-admit one terminal projection at the recipient's current queue tail.
///
/// A dead-letter records historical order; it is not a license to recreate a
/// lower sequence after later recipients have already been delivered. The
/// operator action is all-or-nothing with capacity accounting, so a recovery
/// cannot silently bypass the same queue limits as normal traffic.
pub async fn requeue_mix_delivery_dead_letter(pool: &PgPool, dead_letter_id: Uuid) -> Result<bool> {
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    let row = sqlx::query(
        "SELECT * FROM mix_delivery_dead_letters
          WHERE dead_letter_id=$1 FOR UPDATE",
    )
    .bind(dead_letter_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Ok(false);
    };

    let event_id: Uuid = row.get("event_id");
    let delivery_id: Uuid = row.get("delivery_id");
    let channel_id: Uuid = row.get("channel_id");
    let channel_jid: String = row.get("channel_jid");
    let stanza_template: String = row.get("stanza_template");
    let authoritative_stanza_id: Option<Uuid> = row.get("authoritative_stanza_id");
    let archive: bool = row.get("archive");
    let encrypted: bool = row.get("encrypted");
    let recipient_jid: String = row.get("recipient_jid");
    let matches_event = |existing: &sqlx::postgres::PgRow| {
        existing.get::<Uuid, _>("channel_id") == channel_id
            && existing.get::<String, _>("channel_jid") == channel_jid
            && existing.get::<String, _>("stanza_template") == stanza_template
            && existing.get::<Option<Uuid>, _>("authoritative_stanza_id") == authoritative_stanza_id
            && existing.get::<bool, _>("archive") == archive
            && existing.get::<bool, _>("encrypted") == encrypted
    };
    let mut existing = sqlx::query(
        "SELECT channel_id,channel_jid,stanza_template,authoritative_stanza_id,archive,encrypted
           FROM mix_delivery_events WHERE event_id=$1 FOR UPDATE",
    )
    .bind(event_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(existing) = existing.as_ref() {
        anyhow::ensure!(
            matches_event(existing),
            "MIX dead-letter event identity conflicts with queued event"
        );
    }
    // A missing row has no lockable gap. Exactly one concurrent requeue may
    // create the shared event; only that INSERT's RETURNING result owns the
    // template capacity charge. A loser locks and verifies the winning row
    // before adding its independent recipient, preventing double accounting.
    let event_created = if existing.is_some() {
        false
    } else {
        let inserted = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO mix_delivery_events(
                 event_id,channel_id,channel_jid,stanza_template,authoritative_stanza_id,
                 archive,encrypted,created_at,expires_at
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,GREATEST($9,clock_timestamp()+INTERVAL '7 days'))
             ON CONFLICT(event_id) DO NOTHING
             RETURNING event_id",
        )
        .bind(event_id)
        .bind(channel_id)
        .bind(&channel_jid)
        .bind(&stanza_template)
        .bind(authoritative_stanza_id)
        .bind(archive)
        .bind(encrypted)
        .bind(row.get::<DateTime<Utc>, _>("original_created_at"))
        .bind(row.get::<DateTime<Utc>, _>("original_expires_at"))
        .fetch_optional(&mut *transaction)
        .await?;
        if inserted.is_some() {
            true
        } else {
            let winner = sqlx::query(
                "SELECT channel_id,channel_jid,stanza_template,authoritative_stanza_id,archive,encrypted
                   FROM mix_delivery_events WHERE event_id=$1 FOR UPDATE",
            )
            .bind(event_id)
            .fetch_one(&mut *transaction)
            .await?;
            anyhow::ensure!(
                matches_event(&winner),
                "MIX dead-letter event identity conflicts with concurrent requeue"
            );
            existing = Some(winner);
            false
        }
    };
    if existing.is_some() {
        sqlx::query(
            "UPDATE mix_delivery_events
                SET expires_at=GREATEST(expires_at,clock_timestamp()+INTERVAL '7 days')
              WHERE event_id=$1",
        )
        .bind(event_id)
        .execute(&mut *transaction)
        .await?;
    }
    let template_bytes = if event_created {
        i64::try_from(stanza_template.len()).context("MIX dead-letter template overflow")?
    } else {
        0
    };
    let recipient_bytes = i64::try_from(recipient_jid.len())
        .context("MIX dead-letter recipient overflow")?
        .checked_add(MIX_DELIVERY_RECIPIENT_OVERHEAD)
        .context("MIX dead-letter capacity overflow")?;
    let mut capacity_deltas = BTreeMap::new();
    add_mix_delivery_capacity_delta(
        &mut capacity_deltas,
        mix_delivery_capacity_bucket(delivery_id),
        1,
        recipient_bytes,
    )?;
    if template_bytes > 0 {
        add_mix_delivery_capacity_delta(
            &mut capacity_deltas,
            mix_delivery_capacity_bucket(event_id),
            0,
            template_bytes,
        )?;
    }
    // Preserve in-order delivery for the live queue. A historical sequence
    // can be lower than an already-finalized successor; restoring it would
    // both reorder messages and let a head-local route-wake epoch disappear
    // when the old row is acknowledged. Allocate one fresh tail sequence
    // under the existing recipient-sequence authority instead.
    let delivery_sequence: i64 = sqlx::query_scalar(
        "INSERT INTO mix_delivery_recipient_sequences(recipient_jid,next_sequence)
         VALUES($1,2)
         ON CONFLICT(recipient_jid) DO UPDATE
             SET next_sequence=mix_delivery_recipient_sequences.next_sequence+1
         RETURNING next_sequence-1",
    )
    .bind(&recipient_jid)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO mix_delivery_recipients(
             delivery_id,event_id,recipient_participant_id,recipient_jid,
             delivery_sequence,attempt_count,next_attempt_at,created_at
         ) VALUES($1,$2,$3,$4,$5,0,clock_timestamp(),$6)",
    )
    .bind(delivery_id)
    .bind(event_id)
    .bind(row.get::<Uuid, _>("recipient_participant_id"))
    .bind(&recipient_jid)
    .bind(delivery_sequence)
    .bind(row.get::<DateTime<Utc>, _>("original_created_at"))
    .execute(&mut *transaction)
    .await?;
    // Capacity is reserved after the complete recoverable projection exists;
    // a rejection rolls the projection and sequence update back atomically.
    reserve_mix_delivery_capacity_tx(&mut transaction, &delivery_fence, &capacity_deltas).await?;
    sqlx::query("DELETE FROM mix_delivery_dead_letters WHERE dead_letter_id=$1")
        .bind(dead_letter_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateChannelOutcome {
    Created(Uuid),
    Conflict,
    QuotaExceeded,
}

#[derive(Clone, Debug)]
pub enum JoinChannelOutcome {
    Joined {
        participant: MixParticipant,
        preference: MixParticipantPreference,
        subscriptions: Vec<String>,
        newly_joined: bool,
        roster_change: Option<Box<super::RosterChange>>,
    },
    Banned,
    NotAllowed,
    Full,
    MissingNick,
    NickConflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreEventOutcome {
    Stored(Uuid),
    Existing(MixIntentEvidence),
    NotParticipant,
    Conflict,
    TooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixIntentEvidence {
    pub authoritative_id: Uuid,
    pub semantic_key_id: String,
    pub semantic_mac: Vec<u8>,
    pub target_id: Option<Uuid>,
}

#[derive(Clone, Copy, Debug)]
pub struct MixBusinessIdentity<'a> {
    pub client_id: &'a str,
    pub semantic_key_id: &'a str,
    pub semantic_mac: &'a [u8; 32],
}

/// Read an unexpired replay commitment before consulting mutable channel
/// policy. An exact retry must keep returning the original authoritative
/// outcome even if the actor subsequently leaves, permissions change, or the
/// retracted event ages out. A miss is not inserted here: first execution is
/// still admitted only after all current authorization checks succeed.
async fn existing_mix_business_intent_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    actor: &str,
    operation: &str,
    client_id: &str,
) -> Result<Option<MixIntentEvidence>> {
    anyhow::ensure!(
        !client_id.is_empty() && client_id.len() <= 1_024,
        "invalid MIX client replay id"
    );
    let row = sqlx::query(
        "SELECT authoritative_id,semantic_key_id,semantic_mac,target_id
           FROM mix_business_intents
          WHERE channel_id=$1 AND actor_jid=$2 AND client_id=$3 AND operation=$4
            AND expires_at>clock_timestamp()
          FOR SHARE",
    )
    .bind(channel_id)
    .bind(actor)
    .bind(client_id)
    .bind(operation)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.map(|row| MixIntentEvidence {
        authoritative_id: row.get("authoritative_id"),
        semantic_key_id: row.get("semantic_key_id"),
        semantic_mac: row.get("semantic_mac"),
        target_id: row.get("target_id"),
    }))
}

pub async fn lookup_mix_business_intent(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    operation: &str,
    client_id: &str,
) -> Result<Option<MixIntentEvidence>> {
    let actor = canonical_user_bare(actor)?;
    anyhow::ensure!(
        matches!(operation, "message" | "retraction"),
        "invalid MIX replay operation"
    );
    anyhow::ensure!(
        !client_id.is_empty() && client_id.len() <= 1_024,
        "invalid MIX client replay id"
    );
    let row = sqlx::query(
        "SELECT authoritative_id,semantic_key_id,semantic_mac,target_id
           FROM mix_business_intents
          WHERE channel_id=$1 AND actor_jid=$2 AND client_id=$3 AND operation=$4
            AND expires_at>clock_timestamp()",
    )
    .bind(channel_id)
    .bind(actor)
    .bind(client_id)
    .bind(operation)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| MixIntentEvidence {
        authoritative_id: row.get("authoritative_id"),
        semantic_key_id: row.get("semantic_key_id"),
        semantic_mac: row.get("semantic_mac"),
        target_id: row.get("target_id"),
    }))
}

async fn admit_mix_business_intent_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    actor: &str,
    operation: &str,
    identity: MixBusinessIdentity<'_>,
    authoritative_id: Uuid,
    target_id: Option<Uuid>,
) -> Result<Option<MixIntentEvidence>> {
    anyhow::ensure!(
        !identity.client_id.is_empty() && identity.client_id.len() <= 1_024,
        "invalid MIX client replay id"
    );
    anyhow::ensure!(
        identity.semantic_key_id.len() == 16
            && identity
                .semantic_key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
        "invalid MIX semantic key id"
    );
    sqlx::query(
        "DELETE FROM mix_business_intents
          WHERE channel_id=$1 AND actor_jid=$2 AND client_id=$3
            AND operation=$4 AND expires_at<=clock_timestamp()",
    )
    .bind(channel_id)
    .bind(actor)
    .bind(identity.client_id)
    .bind(operation)
    .execute(&mut **transaction)
    .await?;
    let inserted = sqlx::query(
        "INSERT INTO mix_business_intents(channel_id,actor_jid,client_id,operation,semantic_key_id,semantic_mac,authoritative_id,target_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(channel_id,actor_jid,client_id,operation) DO NOTHING",
    )
    .bind(channel_id)
    .bind(actor)
    .bind(identity.client_id)
    .bind(operation)
    .bind(identity.semantic_key_id)
    .bind(identity.semantic_mac.as_slice())
    .bind(authoritative_id)
    .bind(target_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT authoritative_id,semantic_key_id,semantic_mac,target_id FROM mix_business_intents WHERE channel_id=$1 AND actor_jid=$2 AND client_id=$3 AND operation=$4 FOR SHARE",
    )
    .bind(channel_id)
    .bind(actor)
    .bind(identity.client_id)
    .bind(operation)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(Some(MixIntentEvidence {
        authoritative_id: row.get("authoritative_id"),
        semantic_key_id: row.get("semantic_key_id"),
        semantic_mac: row.get("semantic_mac"),
        target_id: row.get("target_id"),
    }))
}

/// Remove a bounded page of replay intents whose commitment is no longer
/// authoritative.  `SKIP LOCKED` keeps cleanup independent from live
/// admissions, while deleting by the complete primary key prevents a row
/// renewed by another transaction from being removed accidentally.
pub async fn prune_expired_mix_business_intents(pool: &PgPool, limit: i64) -> Result<u64> {
    let removed = sqlx::query(
        "WITH expired AS (
             SELECT channel_id,actor_jid,client_id,operation
               FROM mix_business_intents
              WHERE expires_at<=clock_timestamp()
              ORDER BY expires_at,channel_id,actor_jid,client_id,operation
              LIMIT $1 FOR UPDATE SKIP LOCKED
         )
         DELETE FROM mix_business_intents intent
          USING expired
          WHERE intent.channel_id=expired.channel_id
            AND intent.actor_jid=expired.actor_jid
            AND intent.client_id=expired.client_id
            AND intent.operation=expired.operation",
    )
    .bind(limit.clamp(1, 2_048))
    .execute(pool)
    .await?
    .rows_affected();
    Ok(removed)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FederatedMixIqReplay {
    Miss,
    Replay(String),
    Conflict,
}

fn validate_federated_mix_mutation(context: &FederatedMixMutation) -> Result<()> {
    anyhow::ensure!(
        crate::jid::prepare_domainpart(&context.authenticated_domain)?
            == context.authenticated_domain,
        "non-canonical federated MIX authenticated domain"
    );
    anyhow::ensure!(
        crate::jid::CanonicalJid::parse(&context.actor_jid)?.to_string() == context.actor_jid,
        "non-canonical federated MIX actor JID"
    );
    anyhow::ensure!(
        !context.request_id.is_empty() && context.request_id.len() <= 1_024,
        "invalid federated MIX IQ id"
    );
    anyhow::ensure!(
        !context.addressed.is_empty()
            && context.addressed.len() <= 3_071
            && !context.reply_to.is_empty()
            && context.reply_to.len() <= 3_071,
        "invalid federated MIX IQ addresses"
    );
    Ok(())
}

/// Serialize equal authenticated mutation keys before touching authority.
/// If a concurrent/exact replay already finalized while this transaction was
/// waiting, fail before any state change; the protocol then reads and returns
/// the durable result. A changed request digest is handled by the same lookup
/// as a conflict. The advisory key is only a serialization fence, never a
/// security identity or durable commitment.
async fn guard_federated_mix_mutation_tx(
    transaction: &mut Transaction<'_, Postgres>,
    context: Option<&FederatedMixMutation>,
) -> Result<()> {
    let Some(context) = context else {
        return Ok(());
    };
    validate_federated_mix_mutation(context)?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(
             hashtextextended($1 || E'\\n' || $2 || E'\\n' || $3, 0)
         )",
    )
    .bind(&context.authenticated_domain)
    .bind(&context.actor_jid)
    .bind(&context.request_id)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "DELETE FROM mix_federated_iq_results
          WHERE authenticated_domain=$1 AND actor_jid=$2 AND request_id=$3
            AND expires_at<=clock_timestamp()",
    )
    .bind(&context.authenticated_domain)
    .bind(&context.actor_jid)
    .bind(&context.request_id)
    .execute(&mut **transaction)
    .await?;
    let already_finalized: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM mix_federated_iq_results
              WHERE authenticated_domain=$1 AND actor_jid=$2 AND request_id=$3
         )",
    )
    .bind(&context.authenticated_domain)
    .bind(&context.actor_jid)
    .bind(&context.request_id)
    .fetch_one(&mut **transaction)
    .await?;
    anyhow::ensure!(
        !already_finalized,
        "federated MIX mutation was already finalized"
    );
    Ok(())
}

/// Persist the exact successful IQ result and its durable S2S delivery in the
/// same transaction as the authoritative state change. Once this succeeds,
/// a process kill can at worst delay delivery; an exact retry returns the
/// journaled bytes and never executes the business mutation again.
async fn finalize_federated_mix_mutation_tx(
    transaction: &mut Transaction<'_, Postgres>,
    context: Option<&FederatedMixMutation>,
    success: FederatedMixSuccess,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<()> {
    let Some(context) = context else {
        return Ok(());
    };
    let response = payloads.federated_iq_result(context, &success)?;
    anyhow::ensure!(
        !response.is_empty() && response.len() <= 2_097_152,
        "invalid federated MIX IQ result"
    );
    let inserted = sqlx::query(
        "INSERT INTO mix_federated_iq_results(
             authenticated_domain,actor_jid,request_id,request_digest,response
         ) VALUES($1,$2,$3,$4,$5)
         ON CONFLICT(authenticated_domain,actor_jid,request_id) DO NOTHING",
    )
    .bind(&context.authenticated_domain)
    .bind(&context.actor_jid)
    .bind(&context.request_id)
    .bind(context.request_digest.as_slice())
    .bind(&response)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        inserted == 1,
        "federated MIX result fence changed inside one transaction"
    );
    super::enqueue_s2s_outbox_in_transaction(
        transaction,
        &context.authenticated_domain,
        &response,
        None,
        context.policy,
    )
    .await?;
    Ok(())
}

pub async fn federated_mix_iq_replay(
    pool: &PgPool,
    authenticated_domain: &str,
    actor_jid: &str,
    request_id: &str,
    request_digest: &[u8; 32],
) -> Result<FederatedMixIqReplay> {
    let authenticated_domain = crate::jid::prepare_domainpart(authenticated_domain)?;
    let actor_jid = crate::jid::CanonicalJid::parse(actor_jid)?.to_string();
    anyhow::ensure!(
        !request_id.is_empty() && request_id.len() <= 1_024,
        "invalid federated MIX IQ id"
    );
    let row = sqlx::query(
        "SELECT request_digest,response FROM mix_federated_iq_results
          WHERE authenticated_domain=$1 AND actor_jid=$2 AND request_id=$3
            AND expires_at>clock_timestamp()",
    )
    .bind(authenticated_domain)
    .bind(actor_jid)
    .bind(request_id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(FederatedMixIqReplay::Miss);
    };
    if row.get::<Vec<u8>, _>("request_digest").as_slice() == request_digest {
        Ok(FederatedMixIqReplay::Replay(row.get("response")))
    } else {
        Ok(FederatedMixIqReplay::Conflict)
    }
}

/// Persist the exact authenticated mutation result and admit its S2S reply in
/// one transaction. A retry with changed bytes cannot reuse the IQ id; an
/// exact retry re-enqueues the original result rather than recomputing it.
pub async fn admit_federated_mix_iq_result(
    pool: &PgPool,
    authenticated_domain: &str,
    actor_jid: &str,
    request_id: &str,
    request_digest: &[u8; 32],
    response: &str,
    policy: super::S2sOutboxPolicy,
) -> Result<FederatedMixIqReplay> {
    let authenticated_domain = crate::jid::prepare_domainpart(authenticated_domain)?;
    let actor_jid = crate::jid::CanonicalJid::parse(actor_jid)?.to_string();
    anyhow::ensure!(
        !request_id.is_empty() && request_id.len() <= 1_024,
        "invalid federated MIX IQ id"
    );
    anyhow::ensure!(
        !response.is_empty() && response.len() <= 2_097_152,
        "invalid federated MIX IQ result"
    );
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "DELETE FROM mix_federated_iq_results
          WHERE authenticated_domain=$1 AND actor_jid=$2 AND request_id=$3
            AND expires_at<=clock_timestamp()",
    )
    .bind(&authenticated_domain)
    .bind(&actor_jid)
    .bind(request_id)
    .execute(&mut *transaction)
    .await?;
    let inserted = sqlx::query(
        "INSERT INTO mix_federated_iq_results(
             authenticated_domain,actor_jid,request_id,request_digest,response
         ) VALUES($1,$2,$3,$4,$5)
         ON CONFLICT(authenticated_domain,actor_jid,request_id) DO NOTHING",
    )
    .bind(&authenticated_domain)
    .bind(&actor_jid)
    .bind(request_id)
    .bind(request_digest.as_slice())
    .bind(response)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    let exact_response = if inserted == 1 {
        response.to_owned()
    } else {
        let row = sqlx::query(
            "SELECT request_digest,response FROM mix_federated_iq_results
              WHERE authenticated_domain=$1 AND actor_jid=$2 AND request_id=$3 FOR SHARE",
        )
        .bind(&authenticated_domain)
        .bind(&actor_jid)
        .bind(request_id)
        .fetch_one(&mut *transaction)
        .await?;
        if row.get::<Vec<u8>, _>("request_digest").as_slice() != request_digest {
            transaction.rollback().await?;
            return Ok(FederatedMixIqReplay::Conflict);
        }
        row.get("response")
    };
    super::enqueue_s2s_outbox_in_transaction(
        &mut transaction,
        &authenticated_domain,
        &exact_response,
        None,
        policy,
    )
    .await?;
    transaction.commit().await?;
    Ok(FederatedMixIqReplay::Replay(exact_response))
}

pub async fn prune_expired_federated_mix_iq_results(pool: &PgPool, limit: i64) -> Result<u64> {
    let removed = sqlx::query(
        "WITH expired AS (
             SELECT authenticated_domain,actor_jid,request_id
               FROM mix_federated_iq_results
              WHERE expires_at<=clock_timestamp()
              ORDER BY expires_at,authenticated_domain,actor_jid,request_id
              LIMIT $1 FOR UPDATE SKIP LOCKED
         )
         DELETE FROM mix_federated_iq_results result
          USING expired
          WHERE result.authenticated_domain=expired.authenticated_domain
            AND result.actor_jid=expired.actor_jid
            AND result.request_id=expired.request_id",
    )
    .bind(limit.clamp(1, 2_048))
    .execute(pool)
    .await?
    .rows_affected();
    Ok(removed)
}

#[derive(Clone, Debug)]
pub struct StoreMixMessageAdmission {
    pub outcome: StoreEventOutcome,
    /// Audience captured while the channel lock and archive transaction were
    /// still held. Join/leave/subscription changes use the same lock, so a
    /// committed message has one linearizable recipient set.
    pub recipients: Vec<MixParticipant>,
}

/// Exact event and audience committed by one state mutation.  Protocol code
/// must publish this snapshot and must not reconstruct security-sensitive
/// configuration from a later read.
#[derive(Clone, Debug)]
pub struct MixMutationAdmission {
    pub channel: MixChannel,
    pub node: String,
    pub item_id: String,
    pub payload: String,
    pub recipients: Vec<MixParticipant>,
}

#[derive(Clone, Debug)]
pub struct LeaveMixOutcome {
    pub participant: MixParticipant,
    pub presence_items: Vec<MixPresenceItem>,
    pub roster_change: Option<super::RosterChange>,
}

#[derive(Clone, Debug)]
pub struct MixPresenceItem {
    pub item_id: String,
    pub payload: String,
    pub source_full_jid: Option<String>,
}

#[derive(Clone, Debug)]
pub enum PresenceOutcome {
    Published,
    Retracted,
    Unchanged,
    NotSharing,
    NotParticipant,
}

#[derive(Clone, Debug)]
pub struct UpdateSubscriptionsOutcome {
    pub subscriptions: Vec<String>,
    pub participant: MixParticipant,
    pub removed_presence: Vec<MixPresenceItem>,
}

#[derive(Clone, Debug)]
pub struct MixParticipantPreferenceUpdateOutcome {
    pub participant: MixParticipant,
    pub roster_changes: Vec<(Uuid, super::RosterChange)>,
}

#[derive(Clone, Debug, Default)]
pub struct AccessChangeOutcome {
    pub removed_participants: Vec<Uuid>,
    pub removed_local_users: Vec<Uuid>,
    /// Current presence items removed as a consequence of a ban.  The
    /// protocol layer uses these to publish the mandatory unavailable
    /// transition instead of leaving subscribers with a ghost resource.
    pub removed_presence: Vec<(MixParticipant, Vec<MixPresenceItem>)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixAccessList {
    Allowed,
    Banned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixAccessEntryOperation<'a> {
    Publish { reason: Option<&'a str> },
    Retract,
}

/// One authorized mutation of a MIX allow/ban list.
///
/// Keeping the target list and operation explicit prevents callers from
/// constructing ambiguous combinations of `banned`, `present` and `reason`
/// booleans while the repository retains the existing single transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixAccessEntryUpdate<'a> {
    pub channel_id: Uuid,
    pub actor: &'a str,
    pub pattern: &'a str,
    pub list: MixAccessList,
    pub operation: MixAccessEntryOperation<'a>,
}

/// XEP-0403 identifies each current presence item by the encoded participant
/// JID plus the publishing resource, never by the participant's real full
/// JID.  Keeping this constructor beside persistence makes that privacy
/// invariant hard to bypass accidentally.
pub(crate) fn mix_presence_item_id(
    channel: &MixChannel,
    participant_id: Uuid,
    public_resource: &str,
) -> Result<String> {
    let resource = crate::jid::prepare_resourcepart(public_resource)?;
    let encoded = format!(
        "{}#{}@{}/{}",
        participant_id, channel.localpart, channel.service_domain, resource
    );
    let canonical = crate::jid::CanonicalJid::parse(&encoded)?;
    anyhow::ensure!(
        canonical.to_string() == encoded,
        "encoded MIX presence item is not canonical"
    );
    Ok(encoded)
}

fn canonical_user_bare(jid: &str) -> Result<String> {
    let jid = crate::jid::CanonicalJid::parse(jid)?;
    anyhow::ensure!(
        jid.localpart().is_some(),
        "MIX participants require a user bare JID"
    );
    Ok(jid.bare())
}

async fn pam_account_matches_actor_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    actor_jid: &str,
) -> Result<bool> {
    let actor_username = crate::jid::CanonicalJid::parse_bare(actor_jid)?
        .localpart()
        .context("MIX-PAM actor requires a localpart")?
        .to_owned();
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND username=$2 AND NOT is_disabled)",
    )
    .bind(user_id)
    .bind(actor_username)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

fn canonical_service_domain(domain: &str) -> Result<String> {
    crate::jid::prepare_domainpart(domain)
}

fn canonical_channel_localpart(localpart: &str) -> Result<String> {
    let value = crate::jid::prepare_localpart(localpart)?;
    anyhow::ensure!(value.len() <= 1023, "MIX channel localpart is too large");
    Ok(value)
}

/// MIX recommends the RFC 7700 nickname profile of PRECIS OpaqueString. The
/// resourcepart preparation used by RFC 7622 has the same case-preserving
/// OpaqueString behavior and enforces the protocol's 1023-octet bound.
pub(crate) use crate::services::mix::prepare_mix_nick;

fn channel_from_row(row: &sqlx::postgres::PgRow) -> MixChannel {
    let contacts = row
        .get::<serde_json::Value, _>("contacts")
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    MixChannel {
        id: row.get("id"),
        revision: row.get("revision"),
        service_domain: row.get("service_domain"),
        localpart: row.get("localpart"),
        creator_jid: row.get("creator_jid"),
        name: row.get("name"),
        description: row.get("description"),
        contacts,
        access_model: row.get("access_model"),
        jid_visibility: row.get("jid_visibility"),
        nick_required: row.get("nick_required"),
        max_participants: row.get("max_participants"),
        max_events: row.get("max_events"),
        allow_private_messages: row.get("allow_private_messages"),
        allow_participant_invites: row.get("allow_participant_invites"),
        allow_user_message_retraction: row.get("allow_user_message_retraction"),
        administrator_retraction_rights: row.get("administrator_retraction_rights"),
        enforce_registered_nick: row.get("enforce_registered_nick"),
    }
}

fn participant_from_row(row: &sqlx::postgres::PgRow) -> MixParticipant {
    MixParticipant {
        participant_id: row.get("participant_id"),
        jid: row.get("jid"),
        nick: row.get("nick"),
    }
}

pub async fn create_mix_channel(
    pool: &PgPool,
    service_domain: &str,
    requested_localpart: Option<&str>,
    creator_jid: &str,
    max_channels_per_owner: i64,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<(CreateChannelOutcome, String)> {
    let service_domain = canonical_service_domain(service_domain)?;
    let creator_jid = canonical_user_bare(creator_jid)?;
    let discoverable = requested_localpart.is_some();
    let localpart = match requested_localpart {
        Some(value) => canonical_channel_localpart(value)?,
        None => Uuid::new_v4().simple().to_string(),
    };
    let mut transaction = pool.begin().await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&creator_jid)
        .execute(&mut *transaction)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mix_channels WHERE creator_jid = $1")
        .bind(&creator_jid)
        .fetch_one(&mut *transaction)
        .await?;
    if count >= max_channels_per_owner.max(1) {
        transaction.rollback().await?;
        return Ok((CreateChannelOutcome::QuotaExceeded, localpart));
    }
    let id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO mix_channels (id, service_domain, localpart, creator_jid, discoverable) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (service_domain, localpart) DO NOTHING",
    )
    .bind(id)
    .bind(&service_domain)
    .bind(&localpart)
    .bind(&creator_jid)
    .bind(discoverable)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if inserted == 0 {
        transaction.rollback().await?;
        return Ok((CreateChannelOutcome::Conflict, localpart));
    }
    sqlx::query("INSERT INTO mix_channel_roles (channel_id, jid, role) VALUES ($1, $2, 'owner')")
        .bind(id)
        .bind(&creator_jid)
        .execute(&mut *transaction)
        .await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *transaction)
        .await?;
    let channel = channel_from_row(&channel_row);
    let _ = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_INFO,
        &mix_timestamp_item_id(),
        None,
        &payloads.info_payload(&channel),
    )
    .await?;
    let _ = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_CONFIG,
        &mix_timestamp_item_id(),
        None,
        &payloads.config_payload(
            &channel,
            &creator_jid,
            &BTreeSet::from([creator_jid.clone()]),
            &BTreeSet::new(),
        ),
    )
    .await?;
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::Create {
            channel: localpart.clone(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok((CreateChannelOutcome::Created(id), localpart))
}

pub async fn mix_channel(
    pool: &PgPool,
    service_domain: &str,
    localpart: &str,
) -> Result<Option<MixChannel>> {
    let service_domain = canonical_service_domain(service_domain)?;
    let localpart = canonical_channel_localpart(localpart)?;
    let row =
        sqlx::query("SELECT * FROM mix_channels WHERE service_domain = $1 AND localpart = $2")
            .bind(service_domain)
            .bind(localpart)
            .fetch_optional(pool)
            .await?;
    Ok(row.as_ref().map(channel_from_row))
}

#[cfg(test)]
pub async fn mix_channel_by_id(pool: &PgPool, channel_id: Uuid) -> Result<Option<MixChannel>> {
    let row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1")
        .bind(channel_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(channel_from_row))
}

#[derive(Clone, Debug)]
pub struct MixDiscoPage {
    pub channels: Vec<MixChannel>,
    pub total: i64,
    pub first_index: i64,
}

/// Page channels visible and joinable by `requester` in one stable snapshot.
/// `before == Some(None)` is XEP-0059's empty-before request for the final page.
pub async fn discoverable_mix_channel_page(
    pool: &PgPool,
    service_domain: &str,
    requester: &str,
    after: Option<&str>,
    before: Option<Option<&str>>,
    max: i64,
) -> Result<Option<MixDiscoPage>> {
    anyhow::ensure!(
        after.is_none() || before.is_none(),
        "ambiguous MIX RSM page"
    );
    let service_domain = canonical_service_domain(service_domain)?;
    let requester = canonical_user_bare(requester)?;
    let requester_domain = crate::jid::CanonicalJid::parse_bare(&requester)?
        .domainpart()
        .to_owned();
    let after = after.map(canonical_channel_localpart).transpose()?;
    let before = before
        .map(|value| value.map(canonical_channel_localpart).transpose())
        .transpose()?;
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let visible = "c.service_domain = $1 AND c.discoverable AND NOT EXISTS (SELECT 1 FROM mix_banned b WHERE b.channel_id = c.id AND b.jid_pattern IN ($2, $3)) AND (c.access_model = 'open' OR EXISTS (SELECT 1 FROM mix_allowed a WHERE a.channel_id = c.id AND a.jid_pattern IN ($2, $3)) OR EXISTS (SELECT 1 FROM mix_channel_roles r WHERE r.channel_id = c.id AND r.jid = $2))";
    if let Some(cursor) = after
        .as_deref()
        .or(before.as_ref().and_then(|v| v.as_deref()))
    {
        let exists: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM mix_channels c WHERE {visible} AND c.localpart = $4)"
        ))
        .bind(&service_domain)
        .bind(&requester)
        .bind(&requester_domain)
        .bind(cursor)
        .fetch_one(&mut *transaction)
        .await?;
        if !exists {
            transaction.rollback().await?;
            return Ok(None);
        }
    }
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM mix_channels c WHERE {visible}"
    ))
    .bind(&service_domain)
    .bind(&requester)
    .bind(&requester_domain)
    .fetch_one(&mut *transaction)
    .await?;
    let max = max.clamp(0, 100);
    let rows = if let Some(after) = after.as_deref() {
        sqlx::query(&format!(
            "SELECT c.* FROM mix_channels c WHERE {visible} AND c.localpart > $4 ORDER BY c.localpart ASC LIMIT $5"
        ))
        .bind(&service_domain)
        .bind(&requester)
        .bind(&requester_domain)
        .bind(after)
        .bind(max + 1)
        .fetch_all(&mut *transaction)
        .await?
    } else if let Some(before) = before.as_ref() {
        sqlx::query(&format!(
            "SELECT c.* FROM mix_channels c WHERE {visible} AND ($4::text IS NULL OR c.localpart < $4) ORDER BY c.localpart DESC LIMIT $5"
        ))
        .bind(&service_domain)
        .bind(&requester)
        .bind(&requester_domain)
        .bind(before.as_deref())
        .bind(max + 1)
        .fetch_all(&mut *transaction)
        .await?
    } else {
        sqlx::query(&format!(
            "SELECT c.* FROM mix_channels c WHERE {visible} ORDER BY c.localpart ASC LIMIT $4"
        ))
        .bind(&service_domain)
        .bind(&requester)
        .bind(&requester_domain)
        .bind(max + 1)
        .fetch_all(&mut *transaction)
        .await?
    };
    let mut channels = rows.iter().map(channel_from_row).collect::<Vec<_>>();
    if channels.len() > max as usize {
        channels.truncate(max as usize);
    }
    if before.is_some() {
        channels.reverse();
    }
    let first_index = if let Some(first) = channels.first() {
        sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM mix_channels c WHERE {visible} AND c.localpart < $4"
        ))
        .bind(&service_domain)
        .bind(&requester)
        .bind(&requester_domain)
        .bind(&first.localpart)
        .fetch_one(&mut *transaction)
        .await?
    } else {
        0
    };
    transaction.commit().await?;
    Ok(Some(MixDiscoPage {
        channels,
        total,
        first_index,
    }))
}

pub async fn mix_role(pool: &PgPool, channel_id: Uuid, jid: &str) -> Result<Option<String>> {
    let jid = canonical_user_bare(jid)?;
    sqlx::query_scalar("SELECT role FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2")
        .bind(channel_id)
        .bind(jid)
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
}

/// Apply the same joinability/privacy boundary to channel disco#info and
/// disco#items. Ad-hoc channels are visible only to participants and channel
/// administrators; named channels are visible only when the requester is not
/// banned and satisfies the channel access model.
pub async fn mix_channel_discoverable_to(
    pool: &PgPool,
    channel: &MixChannel,
    actor: &str,
) -> Result<bool> {
    let actor = crate::jid::CanonicalJid::parse(actor)?;
    anyhow::ensure!(
        actor.resourcepart().is_none(),
        "MIX disco requester must be a bare JID or authenticated domain"
    );
    let actor_domain = actor.domainpart().to_owned();
    let actor = actor.to_string();
    let row = sqlx::query(
        "SELECT c.discoverable, c.access_model,
            EXISTS(SELECT 1 FROM mix_participants WHERE channel_id = $1 AND jid = $2) AS participant,
            EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2) AS privileged,
            EXISTS(SELECT 1 FROM mix_banned WHERE channel_id = $1 AND jid_pattern IN ($2, $3)) AS banned,
            EXISTS(SELECT 1 FROM mix_allowed WHERE channel_id = $1 AND jid_pattern IN ($2, $3)) AS allowed
         FROM mix_channels c WHERE c.id = $1",
    )
    .bind(channel.id)
    .bind(&actor)
    .bind(actor_domain)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let participant: bool = row.get("participant");
    let privileged: bool = row.get("privileged");
    if row.get::<bool, _>("banned") && !privileged {
        return Ok(false);
    }
    if !row.get::<bool, _>("discoverable") {
        return Ok(participant || privileged);
    }
    Ok(row.get::<String, _>("access_model") == "open"
        || participant
        || privileged
        || row.get::<bool, _>("allowed"))
}

pub async fn destroy_mix_channel(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<bool> {
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id=$1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(false);
    };
    let channel = channel_from_row(&channel_row);
    let channel_jid = channel.jid();
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role = 'owner')",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(false);
    }
    let participants = sqlx::query(
        "SELECT channel_id,participant_id,jid,nick,role,joined_at
           FROM mix_participants WHERE channel_id=$1 ORDER BY participant_id",
    )
    .bind(channel_id)
    .fetch_all(&mut *transaction)
    .await?
    .iter()
    .map(participant_from_row)
    .collect::<Vec<_>>();
    // Keep one terminal channel-state event after the authority row is gone.
    // Every current participant is an explicit recipient, independently of
    // its optional node subscriptions, and the normalized outbox stores the
    // channel address rather than depending on the deleted row.
    let info_item_id: String = sqlx::query_scalar(
        "SELECT item_id FROM mix_events
          WHERE channel_id=$1 AND node=$2
          ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .bind(channel_id)
    .bind(NODE_INFO)
    .fetch_optional(&mut *transaction)
    .await?
    .unwrap_or_else(|| channel_jid.clone());
    enqueue_mix_node_event_tx(
        &mut transaction,
        &delivery_fence,
        MixNodeProjection {
            channel: &channel,
            node: NODE_INFO,
            item_id: &info_item_id,
            payload: None,
            retract: true,
            event_id: Uuid::new_v4(),
            extra_recipients: participants,
        },
        payloads,
    )
    .await?;
    let local_users: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM mix_pam_memberships WHERE channel_jid = $1")
            .bind(&channel_jid)
            .fetch_all(&mut *transaction)
            .await?;
    for user_id in local_users {
        delete_mix_roster_tx(&mut transaction, user_id, &channel_jid).await?;
    }
    sqlx::query("DELETE FROM mix_pam_memberships WHERE channel_jid = $1")
        .bind(&channel_jid)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM mix_channels WHERE id = $1")
        .bind(channel_id)
        .execute(&mut *transaction)
        .await?;
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::Destroy {
            channel: channel.localpart.clone(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
}

pub struct JoinMixRequest<'a> {
    pub actor_jid: &'a str,
    pub nick: Option<&'a str>,
    pub nodes: &'a [String],
    /// Set only for a local MIX-PAM operation. The membership is committed in
    /// the same transaction as the local channel participant.
    pub pam_user_id: Option<Uuid>,
    /// A XEP-0407 invitation is consumed atomically with an allow-list join.
    pub invitation: Option<&'a MixInvitationProof>,
    /// XEP-0404 preferences supplied with the join. Missing preferences use
    /// the specification defaults and are committed with membership.
    pub preference: Option<&'a MixParticipantPreference>,
    /// Whether the XEP-0404 anonymous-profile namespace was used for this
    /// join result. This affects only the exact protocol acknowledgement.
    pub anonymous_profile: bool,
}

#[derive(Clone, Debug)]
pub struct MixInvitationProof {
    pub inviter_jid: String,
    pub invitee_jid: String,
    pub channel_jid: String,
    pub token: String,
}

pub(crate) use crate::services::mix::valid_join_nodes;

async fn prune_mix_events_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    max_events: i32,
) -> Result<()> {
    // `max_events` is the channel message/MAM retention limit.  Current-state
    // nodes are independent authorities: message traffic must never evict the
    // singleton info/config item, participants, avatar or live presence.
    sqlx::query(
        "DELETE FROM mix_events
          WHERE channel_id=$1 AND node=$3
            AND id NOT IN (
                SELECT id FROM mix_events
                 WHERE channel_id=$1 AND node=$3
                 ORDER BY created_at DESC,id DESC LIMIT $2
            )",
    )
    .bind(channel_id)
    .bind(max_events)
    .bind(NODE_MESSAGES)
    .execute(&mut **transaction)
    .await?;
    // Information and configuration are singleton current-state nodes. Their
    // committed notification history lives in the normalized delivery
    // outbox; retaining superseded authority rows here is both misleading
    // and unbounded.
    sqlx::query(
        "DELETE FROM mix_events
          WHERE channel_id=$1 AND node IN ($2,$3)
            AND id NOT IN (
                SELECT DISTINCT ON (node) id FROM mix_events
                 WHERE channel_id=$1 AND node IN ($2,$3)
                 ORDER BY node,created_at DESC,id DESC
            )",
    )
    .bind(channel_id)
    .bind(NODE_INFO)
    .bind(NODE_CONFIG)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn store_mix_event_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel: &MixChannel,
    node: &str,
    item_id: &str,
    publisher: Option<&MixParticipant>,
    payload: &str,
) -> Result<Option<Uuid>> {
    anyhow::ensure!(ALL_NODES.contains(&node), "unknown MIX node");
    anyhow::ensure!(
        !item_id.is_empty() && item_id.len() <= 3071,
        "invalid MIX item id"
    );
    anyhow::ensure!(payload.len() <= 1_048_576, "MIX event payload too large");
    let id = Uuid::new_v4();
    let replace_existing = node != NODE_MESSAGES;
    let affected = sqlx::query(
        "INSERT INTO mix_events (id, channel_id, node, item_id, publisher_id, publisher_jid, payload) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (channel_id, node, item_id) DO UPDATE SET publisher_id = EXCLUDED.publisher_id, publisher_jid = EXCLUDED.publisher_jid, payload = EXCLUDED.payload, created_at = NOW() WHERE $8",
    )
    .bind(id)
    .bind(channel.id)
    .bind(node)
    .bind(item_id)
    .bind(publisher.map(|participant| participant.participant_id))
    .bind(publisher.map(|participant| participant.jid.as_str()))
    .bind(payload)
    .bind(replace_existing)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if affected == 0 {
        return Ok(None);
    }
    prune_mix_events_tx(transaction, channel.id, channel.max_events).await?;
    Ok(Some(id))
}

async fn upsert_mix_roster_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    channel_jid: &str,
    display_name: Option<&str>,
    share_presence: bool,
) -> Result<super::RosterChange> {
    let channel_jid = crate::jid::canonicalize_bare(channel_jid)?;
    sqlx::query(
        "INSERT INTO roster_items (owner_id, contact_jid, display_name, subscription, ask) VALUES ($1, $2, $3, $4, NULL) ON CONFLICT (owner_id, contact_jid) DO UPDATE SET display_name = EXCLUDED.display_name, subscription = EXCLUDED.subscription, ask = NULL, updated_at = NOW()",
    )
    .bind(user_id)
    .bind(&channel_jid)
    .bind(display_name)
    .bind(if share_presence { "to" } else { "none" })
    .execute(&mut **transaction)
    .await?;
    let version: i64 = sqlx::query_scalar("SELECT northstar_user_bump_roster_version($1)")
        .bind(user_id)
        .fetch_one(&mut **transaction)
        .await?;
    super::roster::record_roster_change(transaction, user_id, version, &channel_jid, false).await
}

async fn delete_mix_roster_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    channel_jid: &str,
) -> Result<Option<super::RosterChange>> {
    let channel_jid = crate::jid::canonicalize_bare(channel_jid)?;
    let deleted = sqlx::query("DELETE FROM roster_items WHERE owner_id = $1 AND contact_jid = $2")
        .bind(user_id)
        .bind(&channel_jid)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Ok(None);
    }
    let version: i64 = sqlx::query_scalar("SELECT northstar_user_bump_roster_version($1)")
        .bind(user_id)
        .fetch_one(&mut **transaction)
        .await?;
    Ok(Some(
        super::roster::record_roster_change(transaction, user_id, version, &channel_jid, true)
            .await?,
    ))
}

pub async fn join_mix_channel(
    pool: &PgPool,
    channel_id: Uuid,
    request: JoinMixRequest<'_>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<JoinChannelOutcome> {
    let actor_jid = canonical_user_bare(request.actor_jid)?;
    let nodes = valid_join_nodes(request.nodes)?;
    let nick = request.nick.map(prepare_mix_nick).transpose()?;
    let mut preference = request.preference.cloned().unwrap_or_default();
    validate_mix_participant_preference(&preference)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("mix-actor:{actor_jid}"))
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(channel_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_one(&mut *transaction)
        .await?;
    let channel = channel_from_row(&row);
    if let Some(user_id) = request.pam_user_id {
        anyhow::ensure!(
            pam_account_matches_actor_tx(&mut transaction, user_id, &actor_jid).await?,
            "MIX-PAM account UUID does not belong to authenticated actor"
        );
    }
    if (channel.jid_visibility == "visible" && preference.jid_visibility == "never")
        || (channel.jid_visibility == "hidden" && preference.jid_visibility == "always")
    {
        transaction.rollback().await?;
        return Ok(JoinChannelOutcome::NotAllowed);
    }
    let registered_nick: Option<String> = sqlx::query_scalar(
        "SELECT nick FROM mix_registered_nicks WHERE service_domain = $1 AND jid = $2",
    )
    .bind(&channel.service_domain)
    .bind(&actor_jid)
    .fetch_optional(&mut *transaction)
    .await?;
    if channel.enforce_registered_nick && registered_nick.as_deref() != nick.as_deref() {
        transaction.rollback().await?;
        return Ok(if nick.is_none() {
            JoinChannelOutcome::MissingNick
        } else {
            JoinChannelOutcome::NickConflict
        });
    }
    if channel.nick_required && nick.is_none() {
        transaction.rollback().await?;
        return Ok(JoinChannelOutcome::MissingNick);
    }
    if let Some(nick) = nick.as_deref() {
        let collision: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mix_participants WHERE channel_id = $1 AND nick = $2 AND jid <> $3)",
        )
        .bind(channel_id)
        .bind(nick)
        .bind(&actor_jid)
        .fetch_one(&mut *transaction)
        .await?;
        if collision {
            transaction.rollback().await?;
            return Ok(JoinChannelOutcome::NickConflict);
        }
    }
    let actor_domain = crate::jid::CanonicalJid::parse_bare(&actor_jid)?
        .domainpart()
        .to_owned();
    let banned: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_banned WHERE channel_id = $1 AND jid_pattern IN ($2, $3))",
    )
    .bind(channel_id)
    .bind(&actor_jid)
    .bind(&actor_domain)
    .fetch_one(&mut *transaction)
    .await?;
    if banned {
        transaction.rollback().await?;
        return Ok(JoinChannelOutcome::Banned);
    }
    if channel.access_model == "allowlist" {
        let mut allowed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mix_allowed WHERE channel_id = $1 AND jid_pattern IN ($2, $3)) OR EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2)",
        )
        .bind(channel_id)
        .bind(&actor_jid)
        .bind(&actor_domain)
        .fetch_one(&mut *transaction)
        .await?;
        if !allowed {
            if let Some(invitation) = request.invitation {
                let channel_jid = crate::jid::canonicalize_bare(&invitation.channel_jid)?;
                let inviter_jid = canonical_user_bare(&invitation.inviter_jid)?;
                let invitee_jid = canonical_user_bare(&invitation.invitee_jid)?;
                anyhow::ensure!(
                    channel_jid == channel.jid() && invitee_jid == actor_jid,
                    "MIX invitation identity mismatch"
                );
                let digest = Sha256::digest(invitation.token.as_bytes()).to_vec();
                let consumed = sqlx::query(
                    "UPDATE mix_invitations SET consumed_at = NOW() WHERE channel_id = $1 AND inviter_jid = $2 AND invitee_jid = $3 AND token_hash = $4 AND consumed_at IS NULL AND expires_at > NOW() RETURNING id",
                )
                .bind(channel_id)
                .bind(&inviter_jid)
                .bind(&invitee_jid)
                .bind(digest)
                .fetch_optional(&mut *transaction)
                .await?
                .is_some();
                if consumed {
                    sqlx::query(
                        "INSERT INTO mix_allowed (channel_id, jid_pattern, added_by) VALUES ($1, $2, $3) ON CONFLICT (channel_id, jid_pattern) DO NOTHING",
                    )
                    .bind(channel_id)
                    .bind(&actor_jid)
                    .bind(&inviter_jid)
                    .execute(&mut *transaction)
                    .await?;
                    allowed = true;
                }
            }
        }
        if !allowed {
            transaction.rollback().await?;
            return Ok(JoinChannelOutcome::NotAllowed);
        }
    }

    let existing = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2",
    )
    .bind(channel_id)
    .bind(&actor_jid)
    .fetch_optional(&mut *transaction)
    .await?;
    let newly_joined = existing.is_none();
    let nick_changed = existing
        .as_ref()
        .is_some_and(|row| nick.is_some() && row.get::<Option<String>, _>("nick") != nick);
    let participant = if let Some(row) = existing {
        if nick.is_some() && row.get::<Option<String>, _>("nick") != nick {
            sqlx::query(
                "UPDATE mix_participants SET nick = $3, updated_at = NOW() WHERE channel_id = $1 AND jid = $2",
            )
            .bind(channel_id)
            .bind(&actor_jid)
            .bind(&nick)
            .execute(&mut *transaction)
            .await?;
        }
        let mut participant = participant_from_row(&row);
        if nick.is_some() {
            participant.nick = nick.clone();
        }
        participant
    } else {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM mix_participants WHERE channel_id = $1")
                .bind(channel_id)
                .fetch_one(&mut *transaction)
                .await?;
        if count >= i64::from(channel.max_participants) {
            transaction.rollback().await?;
            return Ok(JoinChannelOutcome::Full);
        }
        let candidate = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO mix_participant_identities (channel_id, jid, participant_id) VALUES ($1, $2, $3) ON CONFLICT (channel_id, jid) DO NOTHING",
        )
        .bind(channel_id)
        .bind(&actor_jid)
        .bind(candidate)
        .execute(&mut *transaction)
        .await?;
        let participant_id: Uuid = sqlx::query_scalar(
            "SELECT participant_id FROM mix_participant_identities WHERE channel_id = $1 AND jid = $2",
        )
        .bind(channel_id)
        .bind(&actor_jid)
        .fetch_one(&mut *transaction)
        .await?;
        let role = sqlx::query_scalar::<_, String>(
            "SELECT role FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2",
        )
        .bind(channel_id)
        .bind(&actor_jid)
        .fetch_optional(&mut *transaction)
        .await?
        .unwrap_or_else(|| "participant".to_owned());
        let role = if role == "administrator" {
            "administrator".to_owned()
        } else if role == "owner" {
            "owner".to_owned()
        } else {
            "participant".to_owned()
        };
        let row = sqlx::query(
            "INSERT INTO mix_participants (channel_id, participant_id, jid, nick, role) VALUES ($1, $2, $3, $4, $5) RETURNING channel_id, participant_id, jid, nick, role, joined_at",
        )
        .bind(channel_id)
        .bind(participant_id)
        .bind(&actor_jid)
        .bind(&nick)
        .bind(role)
        .fetch_one(&mut *transaction)
        .await?;
        let participant = participant_from_row(&row);
        sqlx::query(
            "INSERT INTO mix_participant_preferences (channel_id, participant_id, jid_visibility, private_messages, vcard, share_presence) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(channel_id)
        .bind(participant.participant_id)
        .bind(&preference.jid_visibility)
        .bind(&preference.private_messages)
        .bind(&preference.vcard)
        .bind(preference.share_presence)
        .execute(&mut *transaction)
        .await?;
        participant
    };
    if !newly_joined && request.preference.is_some() {
        sqlx::query(
            "INSERT INTO mix_participant_preferences (channel_id, participant_id, jid_visibility, private_messages, vcard, share_presence) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (channel_id, participant_id) DO UPDATE SET jid_visibility = EXCLUDED.jid_visibility, private_messages = EXCLUDED.private_messages, vcard = EXCLUDED.vcard, share_presence = EXCLUDED.share_presence, updated_at = NOW()",
        )
        .bind(channel_id)
        .bind(participant.participant_id)
        .bind(&preference.jid_visibility)
        .bind(&preference.private_messages)
        .bind(&preference.vcard)
        .bind(preference.share_presence)
        .execute(&mut *transaction)
        .await?;
    } else if !newly_joined {
        let row = sqlx::query(
            "SELECT jid_visibility, private_messages, vcard, share_presence FROM mix_participant_preferences WHERE channel_id = $1 AND participant_id = $2",
        )
        .bind(channel_id)
        .bind(participant.participant_id)
        .fetch_one(&mut *transaction)
        .await?;
        preference = MixParticipantPreference {
            jid_visibility: row.get("jid_visibility"),
            private_messages: row.get("private_messages"),
            vcard: row.get("vcard"),
            share_presence: row.get("share_presence"),
        };
    }
    for node in &nodes {
        sqlx::query(
            "INSERT INTO mix_subscriptions (channel_id, participant_id, node) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(channel_id)
        .bind(participant.participant_id)
        .bind(node)
        .execute(&mut *transaction)
        .await?;
    }
    if newly_joined || nick_changed {
        let payload = payloads.participant_payload(&channel, &participant, &preference);
        let event_id = store_mix_event_tx(
            &mut transaction,
            &channel,
            NODE_PARTICIPANTS,
            &participant.participant_id.to_string(),
            Some(&participant),
            &payload,
        )
        .await?
        .context("MIX participant event unexpectedly conflicted")?;
        enqueue_mix_node_event_tx(
            &mut transaction,
            &delivery_fence,
            MixNodeProjection {
                channel: &channel,
                node: NODE_PARTICIPANTS,
                item_id: &participant.participant_id.to_string(),
                payload: Some(&payload),
                retract: false,
                event_id,
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
    }
    let mut roster_change = None;
    if let Some(user_id) = request.pam_user_id {
        let membership_id = Uuid::new_v4();
        sqlx::query(
        "INSERT INTO mix_pam_memberships (id, user_id, channel_jid, participant_id, nick, state) VALUES ($1, $2, $3, $4, $5, 'joined') ON CONFLICT (user_id, channel_jid) DO UPDATE SET participant_id = EXCLUDED.participant_id, nick = EXCLUDED.nick, state = 'joined', request_id = NULL, client_request_id = NULL, requester_full_jid = NULL, updated_at = NOW()",
        )
        .bind(membership_id)
        .bind(user_id)
        .bind(channel.jid())
        .bind(participant.participant_id.to_string())
        .bind(&participant.nick)
        .execute(&mut *transaction)
        .await?;
        let membership_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM mix_pam_memberships WHERE user_id = $1 AND channel_jid = $2",
        )
        .bind(user_id)
        .bind(channel.jid())
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM mix_pam_subscriptions WHERE membership_id = $1")
            .bind(membership_id)
            .execute(&mut *transaction)
            .await?;
        for node in &nodes {
            sqlx::query("INSERT INTO mix_pam_subscriptions (membership_id, node) VALUES ($1, $2)")
                .bind(membership_id)
                .bind(node)
                .execute(&mut *transaction)
                .await?;
        }
        roster_change = Some(Box::new(
            upsert_mix_roster_tx(
                &mut transaction,
                user_id,
                &channel.jid(),
                channel.name.as_deref(),
                preference.share_presence,
            )
            .await?,
        ));
    }
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::Join {
            participant: participant.clone(),
            subscriptions: nodes.clone(),
            preference: request.preference.map(|_| preference.clone()),
            anonymous_profile: request.anonymous_profile,
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(JoinChannelOutcome::Joined {
        participant,
        preference,
        subscriptions: nodes,
        newly_joined,
        roster_change,
    })
}

pub async fn mix_participant(
    pool: &PgPool,
    channel_id: Uuid,
    jid: &str,
) -> Result<Option<MixParticipant>> {
    let jid = canonical_user_bare(jid)?;
    let row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2",
    )
    .bind(channel_id)
    .bind(jid)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(participant_from_row))
}

pub async fn mix_participant_by_id(
    pool: &PgPool,
    channel_id: Uuid,
    participant_id: Uuid,
) -> Result<Option<MixParticipant>> {
    let row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND participant_id = $2",
    )
    .bind(channel_id)
    .bind(participant_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(participant_from_row))
}

pub async fn mix_presence_source_jid(
    pool: &PgPool,
    channel_id: Uuid,
    item_id: &str,
) -> Result<Option<String>> {
    let item_id = crate::jid::CanonicalJid::parse(item_id)?.to_string();
    sqlx::query_scalar(
        "SELECT source_full_jid FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3 AND source_full_jid IS NOT NULL",
    )
    .bind(channel_id)
    .bind(NODE_PRESENCE)
    .bind(item_id)
    .fetch_optional(pool)
    .await
    .map_err(Into::into)
}

/// Snapshot every current presence item before process recovery. No row is
/// eagerly deleted by domain: in a clustered deployment another node may
/// still own a local-domain resource. The supervised recovery worker refreshes
/// live local sessions, probes remote actors, then atomically expires and
/// publishes unavailable for only rows older than the returned cutoff.
pub async fn prepare_mix_presence_after_restart(
    pool: &PgPool,
    local_domain: &str,
) -> Result<(DateTime<Utc>, Vec<MixPresenceProbeTarget>)> {
    let _local_domain = crate::jid::prepare_domainpart(local_domain)?;
    let mut transaction = pool.begin().await?;
    let cutoff = Utc::now();
    let rows = sqlx::query(
        "SELECT DISTINCT c.localpart || '@' || c.service_domain AS channel_jid,
                         p.jid AS participant_jid
           FROM mix_events e
           JOIN mix_channels c ON c.id=e.channel_id
           JOIN mix_participants p
             ON p.channel_id=e.channel_id AND p.participant_id=e.publisher_id
          WHERE e.node=$1 ORDER BY channel_jid,participant_jid",
    )
    .bind(NODE_PRESENCE)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((
        cutoff,
        rows.into_iter()
            .map(|row| MixPresenceProbeTarget {
                channel_jid: row.get("channel_jid"),
                participant_jid: row.get("participant_jid"),
            })
            .collect(),
    ))
}

pub async fn expire_unrefreshed_mix_presence(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<Vec<ExpiredMixPresence>> {
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    let rows = sqlx::query(
        "WITH stale AS (SELECT e.id FROM mix_events e WHERE e.node = $1 AND e.created_at < $2 ORDER BY e.created_at, e.id LIMIT 128 FOR UPDATE SKIP LOCKED), deleted AS (DELETE FROM mix_events e USING stale WHERE e.id = stale.id RETURNING e.channel_id, e.publisher_id, e.item_id, e.payload, e.source_full_jid) SELECT d.channel_id, d.publisher_id AS participant_id, p.jid, p.nick, d.item_id, d.payload, d.source_full_jid FROM deleted d JOIN mix_participants p ON p.channel_id = d.channel_id AND p.participant_id = d.publisher_id ORDER BY d.channel_id, d.publisher_id, d.item_id",
    )
    .bind(NODE_PRESENCE)
    .bind(cutoff)
    .fetch_all(&mut *transaction)
    .await?;
    let expired = rows
        .into_iter()
        .map(|row| ExpiredMixPresence {
            channel_id: row.get("channel_id"),
            participant: MixParticipant {
                participant_id: row.get("participant_id"),
                jid: row.get("jid"),
                nick: row.get("nick"),
            },
            item_id: row.get("item_id"),
            payload: row.get("payload"),
            source_full_jid: row.get("source_full_jid"),
        })
        .collect::<Vec<_>>();
    for item in &expired {
        let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id=$1 FOR SHARE")
            .bind(item.channel_id)
            .fetch_one(&mut *transaction)
            .await?;
        let channel = channel_from_row(&channel_row);
        let preference_row = sqlx::query(
            "SELECT jid_visibility,private_messages,vcard,share_presence
               FROM mix_participant_preferences
              WHERE channel_id=$1 AND participant_id=$2",
        )
        .bind(item.channel_id)
        .bind(item.participant.participant_id)
        .fetch_one(&mut *transaction)
        .await?;
        let preference = MixParticipantPreference {
            jid_visibility: preference_row.get("jid_visibility"),
            private_messages: preference_row.get("private_messages"),
            vcard: preference_row.get("vcard"),
            share_presence: preference_row.get("share_presence"),
        };
        let presence = MixPresenceItem {
            item_id: item.item_id.clone(),
            payload: item.payload.clone(),
            source_full_jid: item.source_full_jid.clone(),
        };
        enqueue_mix_presence_event_tx(
            &mut transaction,
            &delivery_fence,
            MixPresenceProjection {
                channel: &channel,
                participant: &item.participant,
                preference: &preference,
                item: &presence,
                unavailable: true,
                event_id: Uuid::new_v4(),
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
    }
    transaction.commit().await?;
    Ok(expired)
}

pub async fn update_mix_subscriptions(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    subscribe: &[String],
    unsubscribe: &[String],
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<Option<UpdateSubscriptionsOutcome>> {
    let actor = canonical_user_bare(actor)?;
    let subscribe = valid_join_nodes(subscribe)?;
    let unsubscribe = valid_join_nodes(unsubscribe)?;
    anyhow::ensure!(
        subscribe.iter().all(|node| !unsubscribe.contains(node)),
        "a MIX node cannot be subscribed and unsubscribed together"
    );
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    // Serialize subscription changes with message/retraction admission. Those
    // paths lock the channel before persisting an event and selecting its
    // committed audience. Without the same lock here, an unsubscribe could
    // commit after that audience was read but before the message transaction
    // committed, causing a delivery to a participant who had already left the
    // node by commit time. Keep the global lock order channel -> participant,
    // which also matches join/leave and avoids an inversion deadlock.
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(None);
    };
    let channel = channel_from_row(&channel_row);
    let participant_row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2 FOR UPDATE",
    )
    .bind(channel_id)
    .bind(actor)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(participant_row) = participant_row else {
        transaction.rollback().await?;
        return Ok(None);
    };
    let participant = participant_from_row(&participant_row);
    let participant_id = participant.participant_id;
    let preference_row = sqlx::query(
        "SELECT jid_visibility,private_messages,vcard,share_presence
           FROM mix_participant_preferences
          WHERE channel_id=$1 AND participant_id=$2",
    )
    .bind(channel_id)
    .bind(participant_id)
    .fetch_one(&mut *transaction)
    .await?;
    let preference = MixParticipantPreference {
        jid_visibility: preference_row.get("jid_visibility"),
        private_messages: preference_row.get("private_messages"),
        vcard: preference_row.get("vcard"),
        share_presence: preference_row.get("share_presence"),
    };
    for node in subscribe {
        sqlx::query(
            "INSERT INTO mix_subscriptions (channel_id, participant_id, node) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(channel_id)
        .bind(participant_id)
        .bind(node)
        .execute(&mut *transaction)
        .await?;
    }
    for node in &unsubscribe {
        sqlx::query(
            "DELETE FROM mix_subscriptions WHERE channel_id = $1 AND participant_id = $2 AND node = $3",
        )
        .bind(channel_id)
        .bind(participant_id)
        .bind(node)
        .execute(&mut *transaction)
        .await?;
    }
    let removed_presence = if unsubscribe.iter().any(|node| node == NODE_PRESENCE) {
        sqlx::query(
            "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND publisher_id = $3 RETURNING item_id, payload, source_full_jid",
        )
        .bind(channel_id)
        .bind(NODE_PRESENCE)
        .bind(participant_id)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| MixPresenceItem {
            item_id: row.get("item_id"),
            payload: row.get("payload"),
            source_full_jid: row.get("source_full_jid"),
        })
        .collect()
    } else {
        Vec::new()
    };
    let current: Vec<String> = sqlx::query_scalar(
        "SELECT node FROM mix_subscriptions WHERE channel_id = $1 AND participant_id = $2 ORDER BY node",
    )
    .bind(channel_id)
    .bind(participant_id)
    .fetch_all(&mut *transaction)
    .await?;
    for item in &removed_presence {
        enqueue_mix_presence_event_tx(
            &mut transaction,
            &delivery_fence,
            MixPresenceProjection {
                channel: &channel,
                participant: &participant,
                preference: &preference,
                item,
                unavailable: true,
                event_id: Uuid::new_v4(),
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
    }
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::UpdateSubscriptions {
            subscriptions: current.clone(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(Some(UpdateSubscriptionsOutcome {
        subscriptions: current,
        participant,
        removed_presence,
    }))
}

pub async fn set_mix_nick(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    nick: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<Result<MixParticipant, SetNickError>> {
    let actor = canonical_user_bare(actor)?;
    let nick = prepare_mix_nick(nick)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("mix-actor:{actor}"))
        .execute(&mut *transaction)
        .await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_one(&mut *transaction)
        .await?;
    let channel = channel_from_row(&channel_row);
    let collision: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_participants WHERE channel_id = $1 AND nick = $2 AND jid <> $3)",
    )
    .bind(channel_id)
    .bind(&nick)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if collision {
        transaction.rollback().await?;
        return Ok(Err(SetNickError::Conflict));
    }
    let row = sqlx::query(
        "UPDATE mix_participants SET nick = $3, updated_at = NOW() WHERE channel_id = $1 AND jid = $2 RETURNING channel_id, participant_id, jid, nick, role, joined_at",
    )
    .bind(channel_id)
    .bind(actor)
    .bind(&nick)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Ok(Err(SetNickError::NotParticipant));
    };
    let participant = participant_from_row(&row);
    let preference_row = sqlx::query(
        "SELECT jid_visibility,private_messages,vcard,share_presence
           FROM mix_participant_preferences
          WHERE channel_id=$1 AND participant_id=$2",
    )
    .bind(channel_id)
    .bind(participant.participant_id)
    .fetch_one(&mut *transaction)
    .await?;
    let preference = MixParticipantPreference {
        jid_visibility: preference_row.get("jid_visibility"),
        private_messages: preference_row.get("private_messages"),
        vcard: preference_row.get("vcard"),
        share_presence: preference_row.get("share_presence"),
    };
    let payload = payloads.participant_payload(&channel, &participant, &preference);
    let event_id = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_PARTICIPANTS,
        &participant.participant_id.to_string(),
        Some(&participant),
        &payload,
    )
    .await?
    .context("MIX participant event unexpectedly conflicted")?;
    enqueue_mix_node_event_tx(
        &mut transaction,
        &delivery_fence,
        MixNodeProjection {
            channel: &channel,
            node: NODE_PARTICIPANTS,
            item_id: &participant.participant_id.to_string(),
            payload: Some(&payload),
            retract: false,
            event_id,
            extra_recipients: Vec::new(),
        },
        payloads,
    )
    .await?;
    sqlx::query(
        "UPDATE mix_pam_memberships SET nick = $3, updated_at = NOW() WHERE channel_jid = $1 AND participant_id = $2",
    )
    .bind(channel.jid())
    .bind(participant.participant_id.to_string())
    .bind(&nick)
    .execute(&mut *transaction)
    .await?;
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::SetNick { nick: nick.clone() },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(Ok(participant))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetNickError {
    NotParticipant,
    Conflict,
}

pub async fn leave_mix_channel(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    pam_user_id: Option<Uuid>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<Option<LeaveMixOutcome>> {
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(channel_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_one(&mut *transaction)
        .await?;
    let channel = channel_from_row(&channel_row);
    if let Some(user_id) = pam_user_id {
        anyhow::ensure!(
            pam_account_matches_actor_tx(&mut transaction, user_id, &actor).await?,
            "MIX-PAM account UUID does not belong to authenticated actor"
        );
    }
    let participant_row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2 FOR UPDATE",
    )
    .bind(channel_id)
    .bind(actor)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(participant_row) = participant_row else {
        transaction.rollback().await?;
        return Ok(None);
    };
    let participant = participant_from_row(&participant_row);
    let participant_id = participant.participant_id;
    let preference_row = sqlx::query(
        "SELECT jid_visibility,private_messages,vcard,share_presence
           FROM mix_participant_preferences
          WHERE channel_id=$1 AND participant_id=$2",
    )
    .bind(channel_id)
    .bind(participant_id)
    .fetch_one(&mut *transaction)
    .await?;
    let preference = MixParticipantPreference {
        jid_visibility: preference_row.get("jid_visibility"),
        private_messages: preference_row.get("private_messages"),
        vcard: preference_row.get("vcard"),
        share_presence: preference_row.get("share_presence"),
    };
    let presence_items = sqlx::query(
        "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND publisher_id = $3 RETURNING item_id, payload, source_full_jid",
    )
    .bind(channel_id)
    .bind(NODE_PRESENCE)
    .bind(participant_id)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .map(|row| MixPresenceItem {
        item_id: row.get("item_id"),
        payload: row.get("payload"),
        source_full_jid: row.get("source_full_jid"),
    })
    .collect::<Vec<_>>();
    sqlx::query("DELETE FROM mix_participants WHERE channel_id = $1 AND participant_id = $2")
        .bind(channel_id)
        .bind(participant_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3")
        .bind(channel_id)
        .bind(NODE_PARTICIPANTS)
        .bind(participant_id.to_string())
        .execute(&mut *transaction)
        .await?;
    for item in &presence_items {
        enqueue_mix_presence_event_tx(
            &mut transaction,
            &delivery_fence,
            MixPresenceProjection {
                channel: &channel,
                participant: &participant,
                preference: &preference,
                item,
                unavailable: true,
                event_id: Uuid::new_v4(),
                extra_recipients: vec![participant.clone()],
            },
            payloads,
        )
        .await?;
    }
    enqueue_mix_node_event_tx(
        &mut transaction,
        &delivery_fence,
        MixNodeProjection {
            channel: &channel,
            node: NODE_PARTICIPANTS,
            item_id: &participant_id.to_string(),
            payload: None,
            retract: true,
            event_id: Uuid::new_v4(),
            extra_recipients: vec![participant.clone()],
        },
        payloads,
    )
    .await?;
    let mut roster_change = None;
    if let Some(user_id) = pam_user_id {
        sqlx::query("DELETE FROM mix_pam_memberships WHERE user_id = $1 AND channel_jid = $2")
            .bind(user_id)
            .bind(channel.jid())
            .execute(&mut *transaction)
            .await?;
        roster_change = delete_mix_roster_tx(&mut transaction, user_id, &channel.jid()).await?;
    }
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::Leave,
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(Some(LeaveMixOutcome {
        participant,
        presence_items,
        roster_change,
    }))
}

pub async fn store_mix_presence(
    pool: &PgPool,
    channel_id: Uuid,
    actor_bare: &str,
    actor_full: &str,
    payload: &str,
    unavailable: bool,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<PresenceOutcome> {
    store_mix_presence_with_policy(
        pool,
        channel_id,
        actor_bare,
        actor_full,
        payload,
        unavailable,
        false,
        payloads,
    )
    .await
}

/// Publish a conservative verified-capability presence only when this exact
/// resource has no newer authoritative channel presence. The channel row lock
/// makes the absence check linearizable with explicit client updates.
pub async fn ensure_mix_presence(
    pool: &PgPool,
    channel_id: Uuid,
    actor_bare: &str,
    actor_full: &str,
    payload: &str,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<PresenceOutcome> {
    store_mix_presence_with_policy(
        pool, channel_id, actor_bare, actor_full, payload, false, true, payloads,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the MIX presence transaction keeps identity, payload, availability, and replacement policy explicit"
)]
async fn store_mix_presence_with_policy(
    pool: &PgPool,
    channel_id: Uuid,
    actor_bare: &str,
    actor_full: &str,
    payload: &str,
    unavailable: bool,
    only_if_absent: bool,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<PresenceOutcome> {
    let actor_bare = canonical_user_bare(actor_bare)?;
    let actor_full = crate::jid::canonicalize(actor_full)?;
    anyhow::ensure!(
        crate::jid::canonical_bare_key(&actor_full)? == actor_bare,
        "MIX presence full JID does not belong to participant"
    );
    anyhow::ensure!(payload.len() <= 1_048_576, "MIX presence payload too large");
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_one(&mut *transaction)
        .await?;
    let channel = channel_from_row(&channel_row);
    let participant_row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2",
    )
    .bind(channel_id)
    .bind(&actor_bare)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(participant_row) = participant_row else {
        transaction.rollback().await?;
        return Ok(PresenceOutcome::NotParticipant);
    };
    let participant = participant_from_row(&participant_row);
    let preference_row = sqlx::query(
        "SELECT jid_visibility, private_messages, vcard, share_presence FROM mix_participant_preferences WHERE channel_id = $1 AND participant_id = $2",
    )
    .bind(channel_id)
    .bind(participant.participant_id)
    .fetch_one(&mut *transaction)
    .await?;
    let preference = MixParticipantPreference {
        jid_visibility: preference_row.get("jid_visibility"),
        private_messages: preference_row.get("private_messages"),
        vcard: preference_row.get("vcard"),
        share_presence: preference_row.get("share_presence"),
    };
    if !preference.share_presence {
        transaction.rollback().await?;
        return Ok(PresenceOutcome::NotSharing);
    }
    let existing_item: Option<String> = sqlx::query_scalar(
        "SELECT item_id FROM mix_events WHERE channel_id = $1 AND node = $2 AND source_full_jid = $3",
    )
    .bind(channel_id)
    .bind(NODE_PRESENCE)
    .bind(&actor_full)
    .fetch_optional(&mut *transaction)
    .await?;
    if only_if_absent && existing_item.is_some() {
        transaction.commit().await?;
        return Ok(PresenceOutcome::Unchanged);
    }
    let actor = crate::jid::CanonicalJid::parse(&actor_full)?;
    let public_resource = if participant_jid_visible(&channel, &preference) {
        actor
            .resourcepart()
            .context("MIX presence requires a full JID")?
            .to_owned()
    } else {
        Uuid::new_v4().simple().to_string()
    };
    let item_id = existing_item.unwrap_or(mix_presence_item_id(
        &channel,
        participant.participant_id,
        &public_resource,
    )?);
    if unavailable {
        let deleted = sqlx::query(
            "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND source_full_jid = $3",
        )
        .bind(channel_id)
        .bind(NODE_PRESENCE)
        .bind(&actor_full)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if deleted == 0 {
            transaction.commit().await?;
            Ok(PresenceOutcome::Unchanged)
        } else {
            let item = MixPresenceItem {
                item_id: item_id.clone(),
                payload: payload.to_owned(),
                source_full_jid: Some(actor_full.clone()),
            };
            enqueue_mix_presence_event_tx(
                &mut transaction,
                &delivery_fence,
                MixPresenceProjection {
                    channel: &channel,
                    participant: &participant,
                    preference: &preference,
                    item: &item,
                    unavailable: true,
                    event_id: Uuid::new_v4(),
                    extra_recipients: Vec::new(),
                },
                payloads,
            )
            .await?;
            transaction.commit().await?;
            Ok(PresenceOutcome::Retracted)
        }
    } else {
        let event_id = store_mix_event_tx(
            &mut transaction,
            &channel,
            NODE_PRESENCE,
            &item_id,
            Some(&participant),
            payload,
        )
        .await?
        .context("MIX presence event unexpectedly conflicted")?;
        sqlx::query(
            "UPDATE mix_events SET source_full_jid = $4 WHERE channel_id = $1 AND node = $2 AND item_id = $3",
        )
        .bind(channel_id)
        .bind(NODE_PRESENCE)
        .bind(&item_id)
        .bind(&actor_full)
        .execute(&mut *transaction)
        .await?;
        let item = MixPresenceItem {
            item_id: item_id.clone(),
            payload: payload.to_owned(),
            source_full_jid: Some(actor_full),
        };
        enqueue_mix_presence_event_tx(
            &mut transaction,
            &delivery_fence,
            MixPresenceProjection {
                channel: &channel,
                participant: &participant,
                preference: &preference,
                item: &item,
                unavailable: false,
                event_id,
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
        transaction.commit().await?;
        Ok(PresenceOutcome::Published)
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the channel-locked message transaction keeps every replay, archive, audience, and encryption input explicit"
)]
pub async fn store_mix_message(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    item_id: &str,
    payload: &str,
    identity: Option<MixBusinessIdentity<'_>>,
    delivery_payload: &str,
    visible_jid: Option<&str>,
    encrypted: bool,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<StoreMixMessageAdmission> {
    if payload.len() > 1_048_576 {
        return Ok(StoreMixMessageAdmission {
            outcome: StoreEventOutcome::TooLarge,
            recipients: Vec::new(),
        });
    }
    let authoritative_id = Uuid::parse_str(item_id)?;
    anyhow::ensure!(
        authoritative_id.to_string() == item_id,
        "MIX message item id must be a canonical UUID"
    );
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_one(&mut *transaction)
        .await?;
    let channel = channel_from_row(&channel_row);
    if let Some(identity) = identity {
        if let Some(existing) = existing_mix_business_intent_tx(
            &mut transaction,
            channel_id,
            &actor,
            "message",
            identity.client_id,
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(StoreMixMessageAdmission {
                outcome: StoreEventOutcome::Existing(existing),
                recipients: Vec::new(),
            });
        }
    }
    let participant_row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(participant_row) = participant_row else {
        transaction.rollback().await?;
        return Ok(StoreMixMessageAdmission {
            outcome: StoreEventOutcome::NotParticipant,
            recipients: Vec::new(),
        });
    };
    let participant = participant_from_row(&participant_row);
    if let Some(identity) = identity {
        if let Some(existing) = admit_mix_business_intent_tx(
            &mut transaction,
            channel_id,
            &actor,
            "message",
            identity,
            authoritative_id,
            None,
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(StoreMixMessageAdmission {
                outcome: StoreEventOutcome::Existing(existing),
                recipients: Vec::new(),
            });
        }
    }
    let stored = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_MESSAGES,
        item_id,
        Some(&participant),
        payload,
    )
    .await;
    match stored {
        Ok(Some(_storage_id)) => {
            let recipients =
                mix_subscribers_tx(&mut transaction, channel_id, NODE_MESSAGES).await?;
            let stanza_template = recipients
                .first()
                .map(|recipient| {
                    payloads.message_delivery_stanza(
                        &channel,
                        &participant,
                        recipient,
                        authoritative_id,
                        delivery_payload,
                        visible_jid,
                    )
                })
                .transpose()?
                .unwrap_or_default();
            enqueue_mix_deliveries_tx(
                &mut transaction,
                &delivery_fence,
                MixDeliveryProjection {
                    channel: &channel,
                    event_id: authoritative_id,
                    recipients: &recipients,
                    stanza_template: &stanza_template,
                    authoritative_stanza_id: Some(authoritative_id),
                    archive: true,
                    encrypted,
                },
            )
            .await?;
            transaction.commit().await?;
            Ok(StoreMixMessageAdmission {
                outcome: StoreEventOutcome::Stored(authoritative_id),
                recipients,
            })
        }
        Ok(None) => {
            transaction.rollback().await?;
            Ok(StoreMixMessageAdmission {
                outcome: StoreEventOutcome::Conflict,
                recipients: Vec::new(),
            })
        }
        Err(error) => Err(error),
    }
}

async fn authorize_mix_node_read_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    actor: &str,
    node: &str,
) -> Result<MixReadOutcome<MixChannel>> {
    anyhow::ensure!(ALL_NODES.contains(&node), "unknown MIX node");
    let actor = canonical_user_bare(actor)?;
    let actor_domain = crate::jid::CanonicalJid::parse_bare(&actor)?
        .domainpart()
        .to_owned();
    let row = sqlx::query(
        "SELECT c.*,
                EXISTS(SELECT 1 FROM mix_participants p WHERE p.channel_id=c.id AND p.jid=$2) AS participant,
                EXISTS(SELECT 1 FROM mix_channel_roles r WHERE r.channel_id=c.id AND r.jid=$2) AS privileged,
                EXISTS(SELECT 1 FROM mix_banned b WHERE b.channel_id=c.id AND b.jid_pattern IN ($2,$3)) AS banned,
                EXISTS(SELECT 1 FROM mix_allowed a WHERE a.channel_id=c.id AND a.jid_pattern IN ($2,$3)) AS allowed
           FROM mix_channels c WHERE c.id=$1",
    )
    .bind(channel_id)
    .bind(&actor)
    .bind(actor_domain)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(MixReadOutcome::NotFound);
    };
    let channel = channel_from_row(&row);
    let participant: bool = row.get("participant");
    let privileged: bool = row.get("privileged");
    let banned: bool = row.get("banned");
    let allowed: bool = row.get("allowed");
    let discoverable: bool = row.get("discoverable");
    let authorized = if banned && !privileged {
        false
    } else if matches!(node, NODE_CONFIG | NODE_ALLOWED | NODE_BANNED | NODE_JIDMAP) {
        privileged
    } else if node == NODE_INFO {
        participant || privileged || (discoverable && (channel.access_model == "open" || allowed))
    } else {
        participant || privileged
    };
    if authorized {
        Ok(MixReadOutcome::Found(channel))
    } else {
        Ok(MixReadOutcome::Unauthorized)
    }
}

pub async fn authorized_mix_event_page(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    node: &str,
    before: Option<(DateTime<Utc>, Uuid)>,
    limit: i64,
) -> Result<MixReadOutcome<MixEventPage>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    match authorize_mix_node_read_tx(&mut transaction, channel_id, actor, node).await? {
        MixReadOutcome::Found(_) => {}
        MixReadOutcome::Unauthorized => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::Unauthorized);
        }
        MixReadOutcome::NotFound => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::NotFound);
        }
    }
    let limit = limit.clamp(1, 200);
    let rows = if let Some((created_at, id)) = before {
        sqlx::query(
            "SELECT id,node,item_id,publisher_id,publisher_jid,payload,created_at FROM mix_events WHERE channel_id=$1 AND node=$2 AND (created_at,id)<($3,$4) ORDER BY created_at DESC,id DESC LIMIT $5",
        )
        .bind(channel_id)
        .bind(node)
        .bind(created_at)
        .bind(id)
        .bind(limit + 1)
        .fetch_all(&mut *transaction)
        .await?
    } else {
        sqlx::query(
            "SELECT id,node,item_id,publisher_id,publisher_jid,payload,created_at FROM mix_events WHERE channel_id=$1 AND node=$2 ORDER BY created_at DESC,id DESC LIMIT $3",
        )
        .bind(channel_id)
        .bind(node)
        .bind(limit + 1)
        .fetch_all(&mut *transaction)
        .await?
    };
    let events = rows
        .into_iter()
        .take(limit as usize)
        .map(|row| MixEvent {
            id: row.get("id"),
            item_id: row.get("item_id"),
            payload: row.get("payload"),
            created_at: row.get("created_at"),
        })
        .collect();
    transaction.commit().await?;
    Ok(MixReadOutcome::Found(MixEventPage { events }))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the atomic avatar mutation keeps its authorization, event, renderer, and federation inputs explicit"
)]
pub async fn publish_mix_avatar(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    node: &str,
    item_id: &str,
    payload: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<bool> {
    anyhow::ensure!(
        matches!(node, NODE_AVATAR_DATA | NODE_AVATAR_METADATA),
        "invalid MIX avatar node"
    );
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(false);
    };
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role IN ('owner', 'administrator'))",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(false);
    }
    let channel = channel_from_row(&channel_row);
    if node == NODE_AVATAR_METADATA {
        sqlx::query("DELETE FROM mix_events WHERE channel_id = $1 AND node = $2")
            .bind(channel_id)
            .bind(NODE_AVATAR_METADATA)
            .execute(&mut *transaction)
            .await?;
    }
    let event_id = store_mix_event_tx(&mut transaction, &channel, node, item_id, None, payload)
        .await?
        .context("MIX avatar event unexpectedly conflicted")?;
    if node == NODE_AVATAR_DATA {
        sqlx::query(
            "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND id NOT IN (SELECT id FROM mix_events WHERE channel_id = $1 AND node = $2 ORDER BY created_at DESC, id DESC LIMIT 64)",
        )
        .bind(channel_id)
        .bind(NODE_AVATAR_DATA)
        .execute(&mut *transaction)
        .await?;
    }
    enqueue_mix_node_event_tx(
        &mut transaction,
        &delivery_fence,
        MixNodeProjection {
            channel: &channel,
            node,
            item_id,
            payload: Some(payload),
            retract: false,
            event_id,
            extra_recipients: Vec::new(),
        },
        payloads,
    )
    .await?;
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::PubSubPublish {
            node: node.to_owned(),
            item_id: item_id.to_owned(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn retract_mix_avatar(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    node: &str,
    item_id: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<bool> {
    anyhow::ensure!(
        matches!(node, NODE_AVATAR_DATA | NODE_AVATAR_METADATA),
        "invalid MIX avatar node"
    );
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(false);
    };
    let channel = channel_from_row(&channel_row);
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role IN ('owner', 'administrator'))",
    )
    .bind(channel_id)
    .bind(actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(false);
    }
    let deleted =
        sqlx::query("DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3")
            .bind(channel_id)
            .bind(node)
            .bind(item_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
    if deleted == 1 {
        enqueue_mix_node_event_tx(
            &mut transaction,
            &delivery_fence,
            MixNodeProjection {
                channel: &channel,
                node,
                item_id,
                payload: None,
                retract: true,
                event_id: Uuid::new_v4(),
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
    }
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::PubSubEmpty,
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
}

#[derive(Clone, Debug)]
enum MixMamBlockedPattern {
    Bare(String),
    Domain(String),
}

async fn mix_mam_blocked_patterns(
    transaction: &mut Transaction<'_, Postgres>,
    viewer_id: Option<Uuid>,
) -> Result<Vec<MixMamBlockedPattern>> {
    let Some(viewer_id) = viewer_id else {
        return Ok(Vec::new());
    };
    let patterns = sqlx::query_scalar::<_, String>(
        "SELECT blocked_jid FROM blocked_jids WHERE owner_id=$1 ORDER BY blocked_jid",
    )
    .bind(viewer_id)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(patterns
        .into_iter()
        .filter_map(|value| {
            let jid = crate::jid::CanonicalJid::parse(&value).ok()?;
            if jid.resourcepart().is_some() {
                None
            } else if jid.localpart().is_some() {
                Some(MixMamBlockedPattern::Bare(jid.bare()))
            } else {
                Some(MixMamBlockedPattern::Domain(jid.domainpart().to_owned()))
            }
        })
        .collect())
}

fn push_mix_mam_archive_base(
    query_builder: &mut QueryBuilder<'_, Postgres>,
    channel_id: Uuid,
    blocked_patterns: &[MixMamBlockedPattern],
) {
    query_builder
        .push(" WHERE channel_id = ")
        .push_bind(channel_id)
        .push(" AND node = ")
        .push_bind(NODE_MESSAGES);
    for pattern in blocked_patterns {
        match pattern {
            MixMamBlockedPattern::Bare(value) => {
                query_builder
                    .push(" AND publisher_jid <> ")
                    .push_bind(value.clone());
            }
            MixMamBlockedPattern::Domain(value) => {
                query_builder
                    .push(" AND CASE WHEN position('@' in publisher_jid) > 0 THEN split_part(publisher_jid, '@', 2) ELSE publisher_jid END <> ")
                    .push_bind(value.clone());
            }
        }
    }
}

fn push_mix_mam_scope(
    query_builder: &mut QueryBuilder<'_, Postgres>,
    channel_id: Uuid,
    query: &super::MamArchiveQuery,
    blocked_patterns: &[MixMamBlockedPattern],
    after_point: Option<(DateTime<Utc>, Uuid)>,
    before_point: Option<(DateTime<Utc>, Uuid)>,
) {
    push_mix_mam_archive_base(query_builder, channel_id, blocked_patterns);
    if let Some(with_jid) = &query.with_jid {
        query_builder
            .push(" AND publisher_jid = ")
            .push_bind(with_jid.clone());
    }
    if let Some(start) = query.start {
        query_builder.push(" AND created_at >= ").push_bind(start);
    }
    if let Some(end) = query.end {
        query_builder.push(" AND created_at <= ").push_bind(end);
    }
    if let Some((created_at, id)) = after_point {
        query_builder
            .push(" AND (created_at, id) > (")
            .push_bind(created_at)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    if let Some((created_at, id)) = before_point {
        query_builder
            .push(" AND (created_at, id) < (")
            .push_bind(created_at)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    if !query.ids.is_empty() {
        query_builder
            .push(" AND authoritative_id = ANY(")
            .push_bind(query.ids.clone())
            .push(")");
    }
}

async fn mix_mam_point(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    blocked_patterns: &[MixMamBlockedPattern],
    id: Uuid,
) -> Result<Option<(DateTime<Utc>, Uuid)>> {
    let mut builder = QueryBuilder::<Postgres>::new("SELECT created_at, id FROM mix_events");
    // Cursor existence is evaluated only inside the caller's immutable base
    // visibility. Query filters select results; they must not redefine which
    // otherwise-visible archive item is a valid RSM/form cursor.
    push_mix_mam_archive_base(&mut builder, channel_id, blocked_patterns);
    builder.push(" AND authoritative_id = ").push_bind(id);
    Ok(builder
        .build_query_as()
        .fetch_optional(&mut **transaction)
        .await?)
}

/// Query a MIX channel's mandatory messages archive using one repeatable-read
/// snapshot. Cursor validation, the result count, page rows and first index
/// therefore cannot disagree if retention runs concurrently.
async fn mix_mam_page_for(
    pool: &PgPool,
    channel_id: Uuid,
    viewer_id: Option<Uuid>,
    actor: Option<&str>,
    query: &super::MamArchiveQuery,
) -> Result<MixReadOutcome<MixMamPage>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    if let Some(actor) = actor {
        match authorize_mix_node_read_tx(&mut transaction, channel_id, actor, NODE_MESSAGES).await?
        {
            MixReadOutcome::Found(channel) => {
                if query.with_jid.is_some() && channel.jid_visibility != "visible" {
                    transaction.rollback().await?;
                    return Ok(MixReadOutcome::Unauthorized);
                }
            }
            MixReadOutcome::Unauthorized => {
                transaction.rollback().await?;
                return Ok(MixReadOutcome::Unauthorized);
            }
            MixReadOutcome::NotFound => {
                transaction.rollback().await?;
                return Ok(MixReadOutcome::NotFound);
            }
        }
    }
    let blocked_patterns = mix_mam_blocked_patterns(&mut transaction, viewer_id).await?;

    let requested_ids = query.ids.clone();
    let mut cursor_ids = Vec::new();
    cursor_ids.extend(query.before_id);
    cursor_ids.extend(query.after_id);
    match query.page {
        super::MamRsmPage::Before(id) | super::MamRsmPage::After(id) => cursor_ids.push(id),
        super::MamRsmPage::First | super::MamRsmPage::Last | super::MamRsmPage::Index(_) => {}
    }
    let requested_ids = requested_ids
        .into_iter()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !requested_ids.is_empty() {
        let mut builder = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM mix_events");
        push_mix_mam_scope(
            &mut builder,
            channel_id,
            query,
            &blocked_patterns,
            None,
            None,
        );
        builder
            .push(" AND authoritative_id = ANY(")
            .push_bind(requested_ids.clone())
            .push(")");
        let found: i64 = builder
            .build_query_scalar()
            .fetch_one(&mut *transaction)
            .await?;
        if found != requested_ids.len() as i64 {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::NotFound);
        }
    }
    let cursor_ids = cursor_ids
        .into_iter()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !cursor_ids.is_empty() {
        let mut builder = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM mix_events");
        push_mix_mam_archive_base(&mut builder, channel_id, &blocked_patterns);
        builder
            .push(" AND authoritative_id = ANY(")
            .push_bind(cursor_ids.clone())
            .push(")");
        let found: i64 = builder
            .build_query_scalar()
            .fetch_one(&mut *transaction)
            .await?;
        if found != cursor_ids.len() as i64 {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::NotFound);
        }
    }

    let form_after = match query.after_id {
        Some(id) => Some(
            mix_mam_point(&mut transaction, channel_id, &blocked_patterns, id)
                .await?
                .expect("validated MIX MAM id disappeared from repeatable-read snapshot"),
        ),
        None => None,
    };
    let form_before = match query.before_id {
        Some(id) => Some(
            mix_mam_point(&mut transaction, channel_id, &blocked_patterns, id)
                .await?
                .expect("validated MIX MAM id disappeared from repeatable-read snapshot"),
        ),
        None => None,
    };

    let mut count_builder = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM mix_events");
    push_mix_mam_scope(
        &mut count_builder,
        channel_id,
        query,
        &blocked_patterns,
        form_after,
        form_before,
    );
    let total: i64 = count_builder
        .build_query_scalar()
        .fetch_one(&mut *transaction)
        .await?;

    let resolved_page = match query.page {
        super::MamRsmPage::First => ResolvedMamRsmPage::First,
        super::MamRsmPage::Last => ResolvedMamRsmPage::Last,
        super::MamRsmPage::Index(index) => ResolvedMamRsmPage::Index(index),
        super::MamRsmPage::After(id) => ResolvedMamRsmPage::After(
            mix_mam_point(&mut transaction, channel_id, &blocked_patterns, id)
                .await?
                .expect("validated MIX MAM after cursor disappeared"),
        ),
        super::MamRsmPage::Before(id) => ResolvedMamRsmPage::Before(
            mix_mam_point(&mut transaction, channel_id, &blocked_patterns, id)
                .await?
                .expect("validated MIX MAM before cursor disappeared"),
        ),
    };
    let max = query.max.clamp(0, MAX_MAM_PAGE_SIZE);
    let window = plan_mam_page(form_after, form_before, resolved_page, max);
    let mut page_builder = QueryBuilder::<Postgres>::new(
        "SELECT authoritative_id AS id, item_id, payload, created_at FROM mix_events",
    );
    push_mix_mam_scope(
        &mut page_builder,
        channel_id,
        query,
        &blocked_patterns,
        window.after,
        window.before,
    );
    page_builder.push(if window.descending {
        " ORDER BY created_at DESC, id DESC LIMIT "
    } else {
        " ORDER BY created_at ASC, id ASC LIMIT "
    });
    page_builder.push_bind(window.fetch_limit);
    if let Some(index) = window.offset {
        page_builder.push(" OFFSET ").push_bind(index);
    }
    let rows = page_builder.build().fetch_all(&mut *transaction).await?;
    let (events, complete) = finish_mam_page(
        rows.iter()
            .map(|row| MixEvent {
                id: row.get("id"),
                item_id: row.get("item_id"),
                payload: row.get("payload"),
                created_at: row.get("created_at"),
            })
            .collect(),
        max,
        window.descending,
    );

    let first_index = if let Some(first) = events.first() {
        let mut index_builder = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM mix_events");
        push_mix_mam_scope(
            &mut index_builder,
            channel_id,
            query,
            &blocked_patterns,
            form_after,
            form_before,
        );
        index_builder
            .push(" AND (created_at, id) < (")
            .push_bind(first.created_at)
            .push(", ")
            .push_bind(first.id)
            .push(")");
        index_builder
            .build_query_scalar()
            .fetch_one(&mut *transaction)
            .await?
    } else {
        0
    };
    transaction.commit().await?;
    Ok(MixReadOutcome::Found(MixMamPage {
        events,
        total,
        first_index,
        complete,
    }))
}

#[cfg(test)]
pub async fn mix_mam_page(
    pool: &PgPool,
    channel_id: Uuid,
    query: &super::MamArchiveQuery,
) -> Result<Option<MixMamPage>> {
    Ok(
        match mix_mam_page_for(pool, channel_id, None, None, query).await? {
            MixReadOutcome::Found(page) => Some(page),
            MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => None,
        },
    )
}

#[cfg(test)]
pub async fn mix_mam_page_visible(
    pool: &PgPool,
    channel_id: Uuid,
    viewer_id: Uuid,
    query: &super::MamArchiveQuery,
) -> Result<Option<MixMamPage>> {
    Ok(
        match mix_mam_page_for(pool, channel_id, Some(viewer_id), None, query).await? {
            MixReadOutcome::Found(page) => Some(page),
            MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => None,
        },
    )
}

pub async fn authorized_mix_mam_page(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    viewer_id: Option<Uuid>,
    query: &super::MamArchiveQuery,
) -> Result<MixReadOutcome<MixMamPage>> {
    mix_mam_page_for(pool, channel_id, viewer_id, Some(actor), query).await
}

#[cfg(test)]
pub async fn mix_mam_boundaries(
    pool: &PgPool,
    channel_id: Uuid,
) -> Result<(
    Option<super::ArchiveBoundary>,
    Option<super::ArchiveBoundary>,
)> {
    let first = sqlx::query(
        "SELECT authoritative_id AS id, created_at FROM mix_events
         WHERE channel_id = $1 AND node = $2
         ORDER BY created_at ASC, id ASC LIMIT 1",
    )
    .bind(channel_id)
    .bind(NODE_MESSAGES)
    .fetch_optional(pool)
    .await?;
    let last = sqlx::query(
        "SELECT authoritative_id AS id, created_at FROM mix_events
         WHERE channel_id = $1 AND node = $2
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(channel_id)
    .bind(NODE_MESSAGES)
    .fetch_optional(pool)
    .await?;
    let convert = |row: sqlx::postgres::PgRow| super::ArchiveBoundary {
        id: row.get("id"),
        created_at: row.get("created_at"),
    };
    Ok((first.map(convert), last.map(convert)))
}

pub async fn authorized_mix_mam_boundaries(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    viewer_id: Option<Uuid>,
) -> Result<
    MixReadOutcome<(
        Option<super::ArchiveBoundary>,
        Option<super::ArchiveBoundary>,
    )>,
> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    match authorize_mix_node_read_tx(&mut transaction, channel_id, actor, NODE_MESSAGES).await? {
        MixReadOutcome::Found(_) => {}
        MixReadOutcome::Unauthorized => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::Unauthorized);
        }
        MixReadOutcome::NotFound => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::NotFound);
        }
    }
    let blocked_patterns = mix_mam_blocked_patterns(&mut transaction, viewer_id).await?;
    let mut first_builder =
        QueryBuilder::<Postgres>::new("SELECT authoritative_id AS id,created_at FROM mix_events");
    push_mix_mam_archive_base(&mut first_builder, channel_id, &blocked_patterns);
    first_builder.push(" ORDER BY created_at ASC,id ASC LIMIT 1");
    let first = first_builder
        .build()
        .fetch_optional(&mut *transaction)
        .await?;
    let mut last_builder =
        QueryBuilder::<Postgres>::new("SELECT authoritative_id AS id,created_at FROM mix_events");
    push_mix_mam_archive_base(&mut last_builder, channel_id, &blocked_patterns);
    last_builder.push(" ORDER BY created_at DESC,id DESC LIMIT 1");
    let last = last_builder
        .build()
        .fetch_optional(&mut *transaction)
        .await?;
    let convert = |row: sqlx::postgres::PgRow| super::ArchiveBoundary {
        id: row.get("id"),
        created_at: row.get("created_at"),
    };
    transaction.commit().await?;
    Ok(MixReadOutcome::Found((
        first.map(convert),
        last.map(convert),
    )))
}

async fn mix_subscribers_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    node: &str,
) -> Result<Vec<MixParticipant>> {
    anyhow::ensure!(ALL_NODES.contains(&node), "unknown MIX node");
    let rows = sqlx::query(
        "SELECT p.channel_id, p.participant_id, p.jid, p.nick, p.role, p.joined_at FROM mix_participants p JOIN mix_subscriptions s ON s.channel_id = p.channel_id AND s.participant_id = p.participant_id WHERE p.channel_id = $1 AND s.node = $2 ORDER BY p.participant_id",
    )
    .bind(channel_id)
    .bind(node)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(rows.iter().map(participant_from_row).collect())
}

async fn mix_node_audience_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    node: &str,
) -> Result<Vec<MixParticipant>> {
    anyhow::ensure!(ALL_NODES.contains(&node), "unknown MIX node");
    if matches!(node, NODE_CONFIG | NODE_ALLOWED | NODE_BANNED | NODE_JIDMAP) {
        let rows = sqlx::query(
            "SELECT p.channel_id,p.participant_id,p.jid,p.nick,p.role,p.joined_at
               FROM mix_participants p
               JOIN mix_channel_roles r ON r.channel_id=p.channel_id AND r.jid=p.jid
              WHERE p.channel_id=$1 AND r.role IN ('owner','administrator')
              ORDER BY p.participant_id",
        )
        .bind(channel_id)
        .fetch_all(&mut **transaction)
        .await?;
        return Ok(rows.iter().map(participant_from_row).collect());
    }
    mix_subscribers_tx(transaction, channel_id, node).await
}

fn extend_unique_mix_recipients(
    recipients: &mut Vec<MixParticipant>,
    extras: impl IntoIterator<Item = MixParticipant>,
) {
    let mut seen = recipients
        .iter()
        .map(|participant| participant.jid.clone())
        .collect::<BTreeSet<_>>();
    for participant in extras {
        if seen.insert(participant.jid.clone()) {
            recipients.push(participant);
        }
    }
    recipients.sort_by_key(|participant| participant.participant_id);
}

struct MixPresenceProjection<'a> {
    channel: &'a MixChannel,
    participant: &'a MixParticipant,
    preference: &'a MixParticipantPreference,
    item: &'a MixPresenceItem,
    unavailable: bool,
    event_id: Uuid,
    extra_recipients: Vec<MixParticipant>,
}

async fn enqueue_mix_presence_event_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MixDeliveryAdmissionFence,
    projection: MixPresenceProjection<'_>,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<Vec<MixParticipant>> {
    let MixPresenceProjection {
        channel,
        participant,
        preference,
        item,
        unavailable,
        event_id,
        extra_recipients,
    } = projection;
    let mut recipients = mix_node_audience_tx(transaction, channel.id, NODE_PRESENCE).await?;
    extend_unique_mix_recipients(&mut recipients, extra_recipients);
    let encoded = crate::jid::CanonicalJid::parse(&item.item_id)?;
    let resource = encoded
        .resourcepart()
        .context("stored MIX presence item has no resource")?;
    let actor_full = item
        .source_full_jid
        .clone()
        .unwrap_or_else(|| format!("{}/{}", participant.jid, resource));
    let stanza_template = recipients
        .first()
        .map(|recipient| {
            payloads.presence_delivery_stanza(MixPresenceDelivery {
                channel,
                participant,
                preference,
                recipient,
                item_id: &item.item_id,
                actor_full: &actor_full,
                children: &item.payload,
                unavailable,
            })
        })
        .transpose()?
        .unwrap_or_default();
    enqueue_mix_deliveries_tx(
        transaction,
        fence,
        MixDeliveryProjection {
            channel,
            event_id,
            recipients: &recipients,
            stanza_template: &stanza_template,
            authoritative_stanza_id: None,
            archive: false,
            encrypted: false,
        },
    )
    .await?;
    Ok(recipients)
}

async fn reproject_mix_presence_visibility_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MixDeliveryAdmissionFence,
    old_channel: &MixChannel,
    new_channel: &MixChannel,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<()> {
    if old_channel.jid_visibility == new_channel.jid_visibility {
        return Ok(());
    }
    let rows = sqlx::query(
        "SELECT e.id,e.item_id,e.payload,e.source_full_jid,
                p.participant_id,p.jid,p.nick,
                pref.jid_visibility,pref.private_messages,pref.vcard,pref.share_presence
           FROM mix_events e
           JOIN mix_participants p
             ON p.channel_id=e.channel_id AND p.participant_id=e.publisher_id
           JOIN mix_participant_preferences pref
             ON pref.channel_id=p.channel_id AND pref.participant_id=p.participant_id
          WHERE e.channel_id=$1 AND e.node=$2
          ORDER BY e.created_at,e.id FOR UPDATE OF e,p,pref",
    )
    .bind(new_channel.id)
    .bind(NODE_PRESENCE)
    .fetch_all(&mut **transaction)
    .await?;
    for row in rows {
        let participant = MixParticipant {
            participant_id: row.get("participant_id"),
            jid: row.get("jid"),
            nick: row.get("nick"),
        };
        let preference = MixParticipantPreference {
            jid_visibility: row.get("jid_visibility"),
            private_messages: row.get("private_messages"),
            vcard: row.get("vcard"),
            share_presence: row.get("share_presence"),
        };
        if participant_jid_visible(old_channel, &preference)
            == participant_jid_visible(new_channel, &preference)
        {
            continue;
        }
        let old_item = MixPresenceItem {
            item_id: row.get("item_id"),
            payload: row.get("payload"),
            source_full_jid: row.get("source_full_jid"),
        };
        sqlx::query("DELETE FROM mix_events WHERE id=$1")
            .bind(row.get::<Uuid, _>("id"))
            .execute(&mut **transaction)
            .await?;
        enqueue_mix_presence_event_tx(
            transaction,
            fence,
            MixPresenceProjection {
                channel: old_channel,
                participant: &participant,
                preference: &preference,
                item: &old_item,
                unavailable: true,
                event_id: Uuid::new_v4(),
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
        let Some(source_full_jid) = old_item.source_full_jid.as_deref() else {
            continue;
        };
        let source = crate::jid::CanonicalJid::parse(source_full_jid)?;
        let public_resource = if participant_jid_visible(new_channel, &preference) {
            source
                .resourcepart()
                .context("MIX presence source lost its resource")?
                .to_owned()
        } else {
            Uuid::new_v4().simple().to_string()
        };
        let item_id =
            mix_presence_item_id(new_channel, participant.participant_id, &public_resource)?;
        let event_id = store_mix_event_tx(
            transaction,
            new_channel,
            NODE_PRESENCE,
            &item_id,
            Some(&participant),
            &old_item.payload,
        )
        .await?
        .context("MIX configuration presence event unexpectedly conflicted")?;
        sqlx::query(
            "UPDATE mix_events SET source_full_jid=$4
              WHERE channel_id=$1 AND node=$2 AND item_id=$3",
        )
        .bind(new_channel.id)
        .bind(NODE_PRESENCE)
        .bind(&item_id)
        .bind(source_full_jid)
        .execute(&mut **transaction)
        .await?;
        let new_item = MixPresenceItem {
            item_id,
            payload: old_item.payload,
            source_full_jid: Some(source_full_jid.to_owned()),
        };
        enqueue_mix_presence_event_tx(
            transaction,
            fence,
            MixPresenceProjection {
                channel: new_channel,
                participant: &participant,
                preference: &preference,
                item: &new_item,
                unavailable: false,
                event_id,
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
    }
    Ok(())
}

struct MixNodeProjection<'a> {
    channel: &'a MixChannel,
    node: &'a str,
    item_id: &'a str,
    payload: Option<&'a str>,
    retract: bool,
    event_id: Uuid,
    extra_recipients: Vec<MixParticipant>,
}

async fn enqueue_mix_node_event_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MixDeliveryAdmissionFence,
    projection: MixNodeProjection<'_>,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<Vec<MixParticipant>> {
    let MixNodeProjection {
        channel,
        node,
        item_id,
        payload,
        retract,
        event_id,
        extra_recipients,
    } = projection;
    let mut recipients = mix_node_audience_tx(transaction, channel.id, node).await?;
    extend_unique_mix_recipients(&mut recipients, extra_recipients);
    let stanza_template = recipients
        .first()
        .map(|recipient| {
            payloads.node_event_stanza(channel, recipient, node, item_id, payload, retract)
        })
        .transpose()?
        .unwrap_or_default();
    enqueue_mix_deliveries_tx(
        transaction,
        fence,
        MixDeliveryProjection {
            channel,
            event_id,
            recipients: &recipients,
            stanza_template: &stanza_template,
            authoritative_stanza_id: None,
            archive: false,
            encrypted: false,
        },
    )
    .await?;
    Ok(recipients)
}

pub struct MixInfoUpdate<'a> {
    pub item_id: &'a str,
    pub expected_revision: i64,
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub contacts: &'a [String],
}

pub struct MixConfigUpdate<'a> {
    pub item_id: &'a str,
    pub expected_revision: i64,
    pub access_model: &'a str,
    pub jid_visibility: &'a str,
    pub nick_required: bool,
    pub max_participants: i32,
    pub max_events: i32,
    pub allow_private_messages: bool,
    pub allow_participant_invites: bool,
    pub allow_user_message_retraction: bool,
    pub administrator_retraction_rights: &'a str,
    pub enforce_registered_nick: bool,
}

pub struct MixRoleUpdate<'a> {
    /// `None` preserves the current list; `Some` atomically replaces it.
    pub owners: Option<&'a [String]>,
    pub administrators: Option<&'a [String]>,
}

#[derive(Clone, Debug)]
pub enum MixMutationOutcome {
    Applied(Box<MixMutationAdmission>),
    Conflict,
    Forbidden,
    NotFound,
}

pub(crate) use crate::services::mix::canonical_mix_access_pattern;

pub async fn authorized_mix_access_entries(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    banned: bool,
    limit: i64,
) -> Result<MixReadOutcome<Vec<String>>> {
    let node = if banned { NODE_BANNED } else { NODE_ALLOWED };
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    match authorize_mix_node_read_tx(&mut transaction, channel_id, actor, node).await? {
        MixReadOutcome::Found(_) => {}
        MixReadOutcome::Unauthorized => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::Unauthorized);
        }
        MixReadOutcome::NotFound => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::NotFound);
        }
    }
    let table = if banned { "mix_banned" } else { "mix_allowed" };
    let statement = format!(
        "SELECT jid_pattern FROM {table} WHERE channel_id=$1 ORDER BY jid_pattern LIMIT $2"
    );
    let entries = sqlx::query_scalar(&statement)
        .bind(channel_id)
        .bind(limit.clamp(1, 500))
        .fetch_all(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(MixReadOutcome::Found(entries))
}

pub async fn update_mix_info(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    update: MixInfoUpdate<'_>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<MixMutationOutcome> {
    let actor = canonical_user_bare(actor)?;
    anyhow::ensure!(
        update.name.is_none_or(|value| value.len() <= 512),
        "MIX name too large"
    );
    anyhow::ensure!(
        update.description.is_none_or(|value| value.len() <= 4096),
        "MIX description too large"
    );
    anyhow::ensure!(update.contacts.len() <= 64, "too many MIX contacts");
    let contacts = update
        .contacts
        .iter()
        .map(|jid| canonical_user_bare(jid))
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        contacts.iter().collect::<BTreeSet<_>>().len() == contacts.len(),
        "MIX contacts contain duplicate canonical JIDs"
    );
    let contacts = serde_json::to_value(contacts)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let locked = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(locked) = locked else {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::NotFound);
    };
    if locked.get::<i64, _>("revision") != update.expected_revision {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Conflict);
    }
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role IN ('owner', 'administrator'))",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Forbidden);
    }
    let row = sqlx::query(
        "UPDATE mix_channels SET name=$2,description=$3,contacts=$4,
                revision=revision+1,updated_at=NOW()
          WHERE id=$1 AND revision=$5 RETURNING *",
    )
    .bind(channel_id)
    .bind(update.name)
    .bind(update.description)
    .bind(contacts)
    .bind(update.expected_revision)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Conflict);
    };
    let channel = channel_from_row(&row);
    let payload = payloads.info_payload(&channel);
    let event_id = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_INFO,
        update.item_id,
        None,
        &payload,
    )
    .await?
    .context("MIX information event unexpectedly conflicted")?;
    let recipients = mix_node_audience_tx(&mut transaction, channel_id, NODE_INFO).await?;
    let stanza_template = recipients
        .first()
        .map(|recipient| {
            payloads.node_event_stanza(
                &channel,
                recipient,
                NODE_INFO,
                update.item_id,
                Some(&payload),
                false,
            )
        })
        .transpose()?
        .unwrap_or_default();
    enqueue_mix_deliveries_tx(
        &mut transaction,
        &delivery_fence,
        MixDeliveryProjection {
            channel: &channel,
            event_id,
            recipients: &recipients,
            stanza_template: &stanza_template,
            authoritative_stanza_id: None,
            archive: false,
            encrypted: false,
        },
    )
    .await?;
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::PubSubPublish {
            node: NODE_INFO.to_owned(),
            item_id: update.item_id.to_owned(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(MixMutationOutcome::Applied(Box::new(
        MixMutationAdmission {
            channel,
            node: NODE_INFO.to_owned(),
            item_id: update.item_id.to_owned(),
            payload,
            recipients,
        },
    )))
}

pub async fn update_mix_config(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    update: MixConfigUpdate<'_>,
    roles: MixRoleUpdate<'_>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<MixMutationOutcome> {
    let actor = canonical_user_bare(actor)?;
    anyhow::ensure!(
        matches!(update.access_model, "open" | "allowlist"),
        "invalid access model"
    );
    anyhow::ensure!(
        matches!(update.jid_visibility, "visible" | "maybe" | "hidden"),
        "invalid JID visibility"
    );
    anyhow::ensure!(
        update.jid_visibility == "visible" || update.nick_required,
        "hidden-JID MIX channels require nicknames for presence identity"
    );
    anyhow::ensure!(
        (2..=5000).contains(&update.max_participants),
        "invalid participant limit"
    );
    anyhow::ensure!(
        (100..=100000).contains(&update.max_events),
        "invalid event limit"
    );
    anyhow::ensure!(
        matches!(
            update.administrator_retraction_rights,
            "nobody" | "administrators" | "owners"
        ),
        "invalid MIX retraction rights"
    );
    let requested_owners = roles
        .owners
        .map(|values| {
            let canonical = values
                .iter()
                .map(|jid| canonical_user_bare(jid))
                .collect::<Result<Vec<_>>>()?;
            let unique = canonical.into_iter().collect::<BTreeSet<_>>();
            anyhow::ensure!(
                unique.len() == values.len(),
                "MIX owner list contains duplicate canonical JIDs"
            );
            Ok(unique)
        })
        .transpose()?;
    if let Some(owners) = &requested_owners {
        anyhow::ensure!(
            !owners.is_empty() && owners.len() <= 64,
            "invalid MIX owner list"
        );
    }
    let requested_administrators = roles
        .administrators
        .map(|values| {
            let canonical = values
                .iter()
                .map(|jid| canonical_user_bare(jid))
                .collect::<Result<Vec<_>>>()?;
            let unique = canonical.into_iter().collect::<BTreeSet<_>>();
            anyhow::ensure!(
                unique.len() == values.len(),
                "MIX administrator list contains duplicate canonical JIDs"
            );
            Ok(unique)
        })
        .transpose()?;
    if let Some(administrators) = &requested_administrators {
        anyhow::ensure!(administrators.len() <= 256, "too many MIX administrators");
    }
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let locked = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(locked) = locked else {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::NotFound);
    };
    if locked.get::<i64, _>("revision") != update.expected_revision {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Conflict);
    }
    let old_channel = channel_from_row(&locked);
    let actor_is_owner: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role = 'owner')",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !actor_is_owner {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Forbidden);
    }
    let current_owners = sqlx::query_scalar::<_, String>(
        "SELECT jid FROM mix_channel_roles WHERE channel_id = $1 AND role = 'owner' ORDER BY jid",
    )
    .bind(channel_id)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let current_administrators = sqlx::query_scalar::<_, String>(
        "SELECT jid FROM mix_channel_roles WHERE channel_id = $1 AND role = 'administrator' ORDER BY jid",
    )
    .bind(channel_id)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let owners = requested_owners.as_ref().unwrap_or(&current_owners);
    let administrators = requested_administrators
        .as_ref()
        .unwrap_or(&current_administrators);
    anyhow::ensure!(
        owners.is_disjoint(administrators),
        "a MIX JID cannot have two roles"
    );
    let row = sqlx::query(
        "UPDATE mix_channels SET access_model=$3,jid_visibility=$4,nick_required=$5,
                max_participants=$6,max_events=$7,allow_private_messages=$8,
                allow_participant_invites=$9,allow_user_message_retraction=$10,
                administrator_retraction_rights=$11,enforce_registered_nick=$12,
                revision=revision+1,updated_at=NOW()
          WHERE id=$1 AND revision=$13
            AND EXISTS (SELECT 1 FROM mix_channel_roles
                         WHERE channel_id=$1 AND jid=$2 AND role='owner')
        RETURNING *",
    )
    .bind(channel_id)
    .bind(&actor)
    .bind(update.access_model)
    .bind(update.jid_visibility)
    .bind(update.nick_required)
    .bind(update.max_participants)
    .bind(update.max_events)
    .bind(update.allow_private_messages)
    .bind(update.allow_participant_invites)
    .bind(update.allow_user_message_retraction)
    .bind(update.administrator_retraction_rights)
    .bind(update.enforce_registered_nick)
    .bind(update.expected_revision)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Conflict);
    };
    let channel = channel_from_row(&row);
    if requested_owners.is_some() {
        sqlx::query("DELETE FROM mix_channel_roles WHERE channel_id = $1 AND role = 'owner'")
            .bind(channel_id)
            .execute(&mut *transaction)
            .await?;
        for owner in owners {
            sqlx::query(
                "INSERT INTO mix_channel_roles (channel_id, jid, role) VALUES ($1, $2, 'owner') ON CONFLICT (channel_id, jid) DO UPDATE SET role = 'owner', updated_at = NOW()",
            )
            .bind(channel_id)
            .bind(owner)
            .execute(&mut *transaction)
            .await?;
        }
    }
    if requested_administrators.is_some() {
        sqlx::query(
            "DELETE FROM mix_channel_roles WHERE channel_id = $1 AND role = 'administrator'",
        )
        .bind(channel_id)
        .execute(&mut *transaction)
        .await?;
        for administrator in administrators {
            sqlx::query(
                "INSERT INTO mix_channel_roles (channel_id, jid, role) VALUES ($1, $2, 'administrator') ON CONFLICT (channel_id, jid) DO UPDATE SET role = 'administrator', updated_at = NOW()",
            )
            .bind(channel_id)
            .bind(administrator)
            .execute(&mut *transaction)
            .await?;
        }
    }
    sqlx::query(
        "UPDATE mix_participants p SET role = COALESCE((SELECT r.role FROM mix_channel_roles r WHERE r.channel_id = p.channel_id AND r.jid = p.jid), 'participant'), updated_at = NOW() WHERE p.channel_id = $1",
    )
    .bind(channel_id)
    .execute(&mut *transaction)
    .await?;
    reproject_mix_presence_visibility_tx(
        &mut transaction,
        &delivery_fence,
        &old_channel,
        &channel,
        payloads,
    )
    .await?;
    let payload = payloads.config_payload(&channel, &actor, owners, administrators);
    let event_id = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_CONFIG,
        update.item_id,
        None,
        &payload,
    )
    .await?
    .context("MIX configuration event unexpectedly conflicted")?;
    prune_mix_events_tx(&mut transaction, channel_id, update.max_events).await?;
    let recipients = mix_node_audience_tx(&mut transaction, channel_id, NODE_CONFIG).await?;
    let stanza_template = recipients
        .first()
        .map(|recipient| {
            payloads.node_event_stanza(
                &channel,
                recipient,
                NODE_CONFIG,
                update.item_id,
                Some(&payload),
                false,
            )
        })
        .transpose()?
        .unwrap_or_default();
    enqueue_mix_deliveries_tx(
        &mut transaction,
        &delivery_fence,
        MixDeliveryProjection {
            channel: &channel,
            event_id,
            recipients: &recipients,
            stanza_template: &stanza_template,
            authoritative_stanza_id: None,
            archive: false,
            encrypted: false,
        },
    )
    .await?;
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::PubSubPublish {
            node: NODE_CONFIG.to_owned(),
            item_id: update.item_id.to_owned(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(MixMutationOutcome::Applied(Box::new(
        MixMutationAdmission {
            channel,
            node: NODE_CONFIG.to_owned(),
            item_id: update.item_id.to_owned(),
            payload,
            recipients,
        },
    )))
}

pub async fn set_mix_access_entry(
    pool: &PgPool,
    update: MixAccessEntryUpdate<'_>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<Option<AccessChangeOutcome>> {
    let channel_id = update.channel_id;
    let actor = canonical_user_bare(update.actor)?;
    let pattern = canonical_mix_access_pattern(update.pattern)?;
    let banned = update.list == MixAccessList::Banned;
    let (present, reason) = match update.operation {
        MixAccessEntryOperation::Publish { reason } => (true, reason),
        MixAccessEntryOperation::Retract => (false, None),
    };
    anyhow::ensure!(
        reason.is_none_or(|value| value.len() <= 1024),
        "ban reason too large"
    );
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    // Serialize against owner/administrator replacement before evaluating the
    // role. Checking first allowed a concurrent config transaction to revoke
    // the actor while this transaction waited for the channel lock, then
    // continue with stale authority.
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(None);
    };
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role IN ('owner', 'administrator'))",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(None);
    }
    let mut outcome = AccessChangeOutcome::default();
    let channel = channel_from_row(&channel_row);
    if present {
        let opposite_exists: bool = if banned {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM mix_allowed WHERE channel_id=$1 AND jid_pattern=$2)",
            )
            .bind(channel_id)
            .bind(&pattern)
            .fetch_one(&mut *transaction)
            .await?
        } else {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM mix_banned WHERE channel_id=$1 AND jid_pattern=$2)",
            )
            .bind(channel_id)
            .bind(&pattern)
            .fetch_one(&mut *transaction)
            .await?
        };
        anyhow::ensure!(
            !opposite_exists,
            "a canonical MIX JID pattern cannot be both allowed and banned"
        );
    }
    let node = if banned { NODE_BANNED } else { NODE_ALLOWED };
    let item_id = pattern.clone();
    let access_payload = payloads.access_payload(&pattern);
    let mut access_event_id = None;
    let mut access_retract = false;
    let mut removed_details = Vec::<(
        MixParticipant,
        MixParticipantPreference,
        Vec<MixPresenceItem>,
    )>::new();
    if banned {
        if present {
            sqlx::query(
                "INSERT INTO mix_banned (channel_id, jid_pattern, added_by, reason) VALUES ($1, $2, $3, $4) ON CONFLICT (channel_id, jid_pattern) DO UPDATE SET added_by = EXCLUDED.added_by, reason = EXCLUDED.reason, created_at = NOW()",
            )
            .bind(channel_id)
            .bind(&pattern)
            .bind(&actor)
            .bind(reason)
            .execute(&mut *transaction)
            .await?;
            let domain_pattern = !pattern.contains('@');
            access_event_id = Some(
                store_mix_event_tx(
                    &mut transaction,
                    &channel,
                    node,
                    &item_id,
                    None,
                    &access_payload,
                )
                .await?
                .context("MIX access event unexpectedly conflicted")?,
            );
            let removed = sqlx::query(
                "SELECT p.channel_id,p.participant_id,p.jid,p.nick,p.role,p.joined_at,
                        pref.jid_visibility,pref.private_messages,pref.vcard,pref.share_presence
                   FROM mix_participants p
                   JOIN mix_participant_preferences pref
                     ON pref.channel_id=p.channel_id AND pref.participant_id=p.participant_id
                  WHERE p.channel_id=$1
                    AND (p.jid=$2 OR ($3 AND split_part(p.jid,'@',2)=$2))
                  ORDER BY p.participant_id FOR UPDATE OF p,pref",
            )
            .bind(channel_id)
            .bind(&pattern)
            .bind(domain_pattern)
            .fetch_all(&mut *transaction)
            .await?;
            for row in removed {
                let participant_id: Uuid = row.get("participant_id");
                let participant = participant_from_row(&row);
                let preference = MixParticipantPreference {
                    jid_visibility: row.get("jid_visibility"),
                    private_messages: row.get("private_messages"),
                    vcard: row.get("vcard"),
                    share_presence: row.get("share_presence"),
                };
                sqlx::query(
                    "DELETE FROM mix_participants WHERE channel_id=$1 AND participant_id=$2",
                )
                .bind(channel_id)
                .bind(participant_id)
                .execute(&mut *transaction)
                .await?;
                outcome.removed_participants.push(participant_id);
                let presence_items = sqlx::query(
                    "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND publisher_id = $3 RETURNING item_id, payload, source_full_jid",
                )
                .bind(channel_id)
                .bind(NODE_PRESENCE)
                .bind(participant_id)
                .fetch_all(&mut *transaction)
                .await?
                .into_iter()
                .map(|row| MixPresenceItem {
                    item_id: row.get("item_id"),
                    payload: row.get("payload"),
                    source_full_jid: row.get("source_full_jid"),
                })
                .collect::<Vec<_>>();
                sqlx::query(
                    "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3",
                )
                .bind(channel_id)
                .bind(NODE_PARTICIPANTS)
                .bind(participant_id.to_string())
                .execute(&mut *transaction)
                .await?;
                let local_users: Vec<Uuid> = sqlx::query_scalar(
                    "SELECT user_id FROM mix_pam_memberships WHERE channel_jid = $1 AND participant_id = $2",
                )
                .bind(channel.jid())
                .bind(participant_id.to_string())
                .fetch_all(&mut *transaction)
                .await?;
                for user_id in local_users {
                    delete_mix_roster_tx(&mut transaction, user_id, &channel.jid()).await?;
                    outcome.removed_local_users.push(user_id);
                }
                sqlx::query(
                    "DELETE FROM mix_pam_memberships WHERE channel_jid = (SELECT localpart || '@' || service_domain FROM mix_channels WHERE id = $1) AND participant_id = $2",
                )
                .bind(channel_id)
                .bind(participant_id.to_string())
                .execute(&mut *transaction)
                .await?;
                if !presence_items.is_empty() {
                    outcome
                        .removed_presence
                        .push((participant.clone(), presence_items.clone()));
                }
                removed_details.push((participant, preference, presence_items));
            }
        } else {
            let changed =
                sqlx::query("DELETE FROM mix_banned WHERE channel_id = $1 AND jid_pattern = $2")
                    .bind(channel_id)
                    .bind(&pattern)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected();
            sqlx::query(
                "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3",
            )
            .bind(channel_id)
            .bind(node)
            .bind(&item_id)
            .execute(&mut *transaction)
            .await?;
            if changed == 1 {
                access_event_id = Some(Uuid::new_v4());
                access_retract = true;
            }
        }
    } else if present {
        sqlx::query(
            "INSERT INTO mix_allowed (channel_id, jid_pattern, added_by) VALUES ($1, $2, $3) ON CONFLICT (channel_id, jid_pattern) DO UPDATE SET added_by = EXCLUDED.added_by, created_at = NOW()",
        )
        .bind(channel_id)
        .bind(&pattern)
        .bind(&actor)
        .execute(&mut *transaction)
        .await?;
        access_event_id = Some(
            store_mix_event_tx(
                &mut transaction,
                &channel,
                node,
                &item_id,
                None,
                &access_payload,
            )
            .await?
            .context("MIX access event unexpectedly conflicted")?,
        );
    } else {
        let changed =
            sqlx::query("DELETE FROM mix_allowed WHERE channel_id = $1 AND jid_pattern = $2")
                .bind(channel_id)
                .bind(&pattern)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
        sqlx::query("DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3")
            .bind(channel_id)
            .bind(node)
            .bind(&item_id)
            .execute(&mut *transaction)
            .await?;
        if changed == 1 {
            access_event_id = Some(Uuid::new_v4());
            access_retract = true;
        }
    }
    if let Some(event_id) = access_event_id {
        enqueue_mix_node_event_tx(
            &mut transaction,
            &delivery_fence,
            MixNodeProjection {
                channel: &channel,
                node,
                item_id: &item_id,
                payload: (!access_retract).then_some(access_payload.as_str()),
                retract: access_retract,
                event_id,
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
    }
    for (participant, preference, presence_items) in &removed_details {
        for item in presence_items {
            enqueue_mix_presence_event_tx(
                &mut transaction,
                &delivery_fence,
                MixPresenceProjection {
                    channel: &channel,
                    participant,
                    preference,
                    item,
                    unavailable: true,
                    event_id: Uuid::new_v4(),
                    extra_recipients: vec![participant.clone()],
                },
                payloads,
            )
            .await?;
        }
        enqueue_mix_node_event_tx(
            &mut transaction,
            &delivery_fence,
            MixNodeProjection {
                channel: &channel,
                node: NODE_PARTICIPANTS,
                item_id: &participant.participant_id.to_string(),
                payload: None,
                retract: true,
                event_id: Uuid::new_v4(),
                extra_recipients: vec![participant.clone()],
            },
            payloads,
        )
        .await?;
    }
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::PubSubEmpty,
        payloads,
    )
    .await?;
    transaction.commit().await?;
    outcome.removed_local_users.sort_unstable();
    outcome.removed_local_users.dedup();
    Ok(Some(outcome))
}

#[derive(Clone, Debug)]
pub enum RegisterMixNickOutcome {
    Registered { nick: String },
    Conflict,
}

pub async fn register_mix_nick(
    pool: &PgPool,
    service_domain: &str,
    actor: &str,
    nick: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<RegisterMixNickOutcome> {
    let service_domain = canonical_service_domain(service_domain)?;
    let actor = canonical_user_bare(actor)?;
    let nick = prepare_mix_nick(nick)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    // Registration is an account-wide projection over every participation.
    // Serialize it with join and per-channel nick changes before taking any
    // channel lock, establishing the global actor -> channel lock order.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("mix-actor:{actor}"))
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("mix-nick:{service_domain}:{nick}"))
        .execute(&mut *transaction)
        .await?;
    let conflict: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_registered_nicks WHERE service_domain = $1 AND nick = $2 AND jid <> $3)",
    )
    .bind(&service_domain)
    .bind(&nick)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if conflict {
        transaction.rollback().await?;
        return Ok(RegisterMixNickOutcome::Conflict);
    }
    let channel_ids = sqlx::query_scalar::<_, Uuid>(
        "SELECT c.id
           FROM mix_channels c
          WHERE c.service_domain=$1
            AND EXISTS (
                SELECT 1 FROM mix_participants p
                 WHERE p.channel_id=c.id AND p.jid=$2
            )
          ORDER BY c.id",
    )
    .bind(&service_domain)
    .bind(&actor)
    .fetch_all(&mut *transaction)
    .await?;
    let mut channels = Vec::with_capacity(channel_ids.len());
    for channel_id in channel_ids {
        let row = sqlx::query("SELECT * FROM mix_channels WHERE id=$1 FOR UPDATE")
            .bind(channel_id)
            .fetch_optional(&mut *transaction)
            .await?;
        if let Some(row) = row {
            let channel = channel_from_row(&row);
            let channel_conflict: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM mix_participants
                     WHERE channel_id=$1 AND nick=$2 AND jid<>$3
                )",
            )
            .bind(channel.id)
            .bind(&nick)
            .bind(&actor)
            .fetch_one(&mut *transaction)
            .await?;
            if channel_conflict {
                transaction.rollback().await?;
                return Ok(RegisterMixNickOutcome::Conflict);
            }
            channels.push(channel);
        }
    }
    sqlx::query(
        "INSERT INTO mix_registered_nicks (service_domain, jid, nick) VALUES ($1, $2, $3) ON CONFLICT (service_domain, jid) DO UPDATE SET nick = EXCLUDED.nick, updated_at = NOW()",
    )
    .bind(&service_domain)
    .bind(&actor)
    .bind(&nick)
    .execute(&mut *transaction)
    .await?;
    for channel in channels {
        let Some(row) = sqlx::query(
            "UPDATE mix_participants
                SET nick=$3, updated_at=NOW()
              WHERE channel_id=$1 AND jid=$2
          RETURNING channel_id,participant_id,jid,nick,role,joined_at",
        )
        .bind(channel.id)
        .bind(&actor)
        .bind(&nick)
        .fetch_optional(&mut *transaction)
        .await?
        else {
            // A leave which committed before this channel lock won the serial
            // order; it has no remaining projection to update.
            continue;
        };
        let participant = participant_from_row(&row);
        let preference_row = sqlx::query(
            "SELECT jid_visibility,private_messages,vcard,share_presence
               FROM mix_participant_preferences
              WHERE channel_id=$1 AND participant_id=$2",
        )
        .bind(channel.id)
        .bind(participant.participant_id)
        .fetch_one(&mut *transaction)
        .await?;
        let preference = MixParticipantPreference {
            jid_visibility: preference_row.get("jid_visibility"),
            private_messages: preference_row.get("private_messages"),
            vcard: preference_row.get("vcard"),
            share_presence: preference_row.get("share_presence"),
        };
        sqlx::query(
            "UPDATE mix_pam_memberships
                SET nick=$3, updated_at=NOW()
              WHERE channel_jid=$1 AND participant_id=$2",
        )
        .bind(channel.jid())
        .bind(participant.participant_id.to_string())
        .bind(&nick)
        .execute(&mut *transaction)
        .await?;
        let payload = payloads.participant_payload(&channel, &participant, &preference);
        let event_id = store_mix_event_tx(
            &mut transaction,
            &channel,
            NODE_PARTICIPANTS,
            &participant.participant_id.to_string(),
            Some(&participant),
            &payload,
        )
        .await?
        .context("MIX participant event unexpectedly conflicted")?;
        enqueue_mix_node_event_tx(
            &mut transaction,
            &delivery_fence,
            MixNodeProjection {
                channel: &channel,
                node: NODE_PARTICIPANTS,
                item_id: &participant.participant_id.to_string(),
                payload: Some(&payload),
                retract: false,
                event_id,
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
    }
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::RegisterNick { nick: nick.clone() },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(RegisterMixNickOutcome::Registered { nick })
}

pub async fn mix_participant_preference(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
) -> Result<Option<MixParticipantPreference>> {
    let actor = canonical_user_bare(actor)?;
    let row = sqlx::query(
        "SELECT pref.jid_visibility, pref.private_messages, pref.vcard, pref.share_presence FROM mix_participant_preferences pref JOIN mix_participants p ON p.channel_id = pref.channel_id AND p.participant_id = pref.participant_id WHERE p.channel_id = $1 AND p.jid = $2",
    )
    .bind(channel_id)
    .bind(actor)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| MixParticipantPreference {
        jid_visibility: row.get("jid_visibility"),
        private_messages: row.get("private_messages"),
        vcard: row.get("vcard"),
        share_presence: row.get("share_presence"),
    }))
}

fn validate_mix_participant_preference(preference: &MixParticipantPreference) -> Result<()> {
    anyhow::ensure!(
        matches!(
            preference.jid_visibility.as_str(),
            "default" | "never" | "always" | "prefer not"
        ),
        "invalid MIX JID visibility preference"
    );
    anyhow::ensure!(
        matches!(preference.private_messages.as_str(), "allow" | "block")
            && matches!(preference.vcard.as_str(), "allow" | "block"),
        "invalid MIX participant preference"
    );
    Ok(())
}

pub async fn update_mix_participant_preference(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    preference: &MixParticipantPreference,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<Option<MixParticipantPreferenceUpdateOutcome>> {
    let actor = canonical_user_bare(actor)?;
    validate_mix_participant_preference(preference)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let channel = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?
        .as_ref()
        .map(channel_from_row);
    let Some(channel) = channel else {
        transaction.rollback().await?;
        return Ok(None);
    };
    // An explicit preference incompatible with a mandatory visibility mode
    // cannot be accepted; this prevents a later response from lying about it.
    if (channel.jid_visibility == "visible" && preference.jid_visibility == "never")
        || (channel.jid_visibility == "hidden" && preference.jid_visibility == "always")
    {
        transaction.rollback().await?;
        return Ok(None);
    }
    let participant_row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2 FOR UPDATE",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(participant_row) = participant_row else {
        transaction.rollback().await?;
        return Ok(None);
    };
    let participant = participant_from_row(&participant_row);
    let old_row = sqlx::query(
        "SELECT jid_visibility,private_messages,vcard,share_presence
           FROM mix_participant_preferences
          WHERE channel_id=$1 AND participant_id=$2 FOR UPDATE",
    )
    .bind(channel_id)
    .bind(participant.participant_id)
    .fetch_one(&mut *transaction)
    .await?;
    let old_preference = MixParticipantPreference {
        jid_visibility: old_row.get("jid_visibility"),
        private_messages: old_row.get("private_messages"),
        vcard: old_row.get("vcard"),
        share_presence: old_row.get("share_presence"),
    };
    sqlx::query(
        "INSERT INTO mix_participant_preferences (channel_id, participant_id, jid_visibility, private_messages, vcard, share_presence) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (channel_id, participant_id) DO UPDATE SET jid_visibility = EXCLUDED.jid_visibility, private_messages = EXCLUDED.private_messages, vcard = EXCLUDED.vcard, share_presence = EXCLUDED.share_presence, updated_at = NOW()",
    )
    .bind(channel_id)
    .bind(participant.participant_id)
    .bind(&preference.jid_visibility)
    .bind(&preference.private_messages)
    .bind(&preference.vcard)
    .bind(preference.share_presence)
    .execute(&mut *transaction)
    .await?;
    let old_visible = participant_jid_visible(&channel, &old_preference);
    let new_visible = participant_jid_visible(&channel, preference);
    if old_preference.share_presence != preference.share_presence || old_visible != new_visible {
        let old_presence = sqlx::query(
            "DELETE FROM mix_events
              WHERE channel_id=$1 AND node=$2 AND publisher_id=$3
          RETURNING item_id,payload,source_full_jid",
        )
        .bind(channel_id)
        .bind(NODE_PRESENCE)
        .bind(participant.participant_id)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| MixPresenceItem {
            item_id: row.get("item_id"),
            payload: row.get("payload"),
            source_full_jid: row.get("source_full_jid"),
        })
        .collect::<Vec<_>>();
        for item in old_presence {
            enqueue_mix_presence_event_tx(
                &mut transaction,
                &delivery_fence,
                MixPresenceProjection {
                    channel: &channel,
                    participant: &participant,
                    preference: &old_preference,
                    item: &item,
                    unavailable: true,
                    event_id: Uuid::new_v4(),
                    extra_recipients: Vec::new(),
                },
                payloads,
            )
            .await?;
            if preference.share_presence {
                let Some(source_full_jid) = item.source_full_jid.as_deref() else {
                    // A legacy row without its real publishing resource may
                    // be retracted, but must never be made newly JID-visible.
                    continue;
                };
                let source = crate::jid::CanonicalJid::parse(source_full_jid)?;
                let public_resource = if new_visible {
                    source
                        .resourcepart()
                        .context("MIX presence source lost its resource")?
                        .to_owned()
                } else {
                    Uuid::new_v4().simple().to_string()
                };
                let new_item_id =
                    mix_presence_item_id(&channel, participant.participant_id, &public_resource)?;
                let event_id = store_mix_event_tx(
                    &mut transaction,
                    &channel,
                    NODE_PRESENCE,
                    &new_item_id,
                    Some(&participant),
                    &item.payload,
                )
                .await?
                .context("MIX preference presence event unexpectedly conflicted")?;
                sqlx::query(
                    "UPDATE mix_events SET source_full_jid=$4
                      WHERE channel_id=$1 AND node=$2 AND item_id=$3",
                )
                .bind(channel_id)
                .bind(NODE_PRESENCE)
                .bind(&new_item_id)
                .bind(source_full_jid)
                .execute(&mut *transaction)
                .await?;
                let new_item = MixPresenceItem {
                    item_id: new_item_id,
                    payload: item.payload,
                    source_full_jid: Some(source_full_jid.to_owned()),
                };
                enqueue_mix_presence_event_tx(
                    &mut transaction,
                    &delivery_fence,
                    MixPresenceProjection {
                        channel: &channel,
                        participant: &participant,
                        preference,
                        item: &new_item,
                        unavailable: false,
                        event_id,
                        extra_recipients: Vec::new(),
                    },
                    payloads,
                )
                .await?;
            }
        }
    }
    let rendered = payloads.participant_payload(&channel, &participant, preference);
    let participant_event_id = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_PARTICIPANTS,
        &participant.participant_id.to_string(),
        Some(&participant),
        &rendered,
    )
    .await?
    .context("MIX preference participant event unexpectedly conflicted")?;
    enqueue_mix_node_event_tx(
        &mut transaction,
        &delivery_fence,
        MixNodeProjection {
            channel: &channel,
            node: NODE_PARTICIPANTS,
            item_id: &participant.participant_id.to_string(),
            payload: Some(&rendered),
            retract: false,
            event_id: participant_event_id,
            extra_recipients: Vec::new(),
        },
        payloads,
    )
    .await?;
    let mut roster_changes = Vec::new();
    if old_preference.share_presence != preference.share_presence {
        let local_users = sqlx::query_scalar::<_, Uuid>(
            "SELECT user_id FROM mix_pam_memberships
              WHERE channel_jid=$1 AND participant_id=$2 ORDER BY user_id",
        )
        .bind(channel.jid())
        .bind(participant.participant_id.to_string())
        .fetch_all(&mut *transaction)
        .await?;
        for user_id in local_users {
            let change = upsert_mix_roster_tx(
                &mut transaction,
                user_id,
                &channel.jid(),
                channel.name.as_deref(),
                preference.share_presence,
            )
            .await?;
            roster_changes.push((user_id, change));
        }
    }
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::Preference {
            preference: preference.clone(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(Some(MixParticipantPreferenceUpdateOutcome {
        participant,
        roster_changes,
    }))
}

pub(crate) use crate::services::mix::participant_jid_visible;

#[cfg(test)]
pub async fn mix_jid_map_entries(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    limit: i64,
) -> Result<Option<Vec<(String, String)>>> {
    let actor = canonical_user_bare(actor)?;
    let mut transaction = pool.begin().await?;
    let exists = sqlx::query("SELECT id FROM mix_channels WHERE id = $1 FOR SHARE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    if exists.is_none() {
        transaction.rollback().await?;
        return Ok(None);
    }
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2)",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(None);
    }
    let rows = sqlx::query(
        "SELECT participant_id::text AS participant_id, jid FROM mix_participants WHERE channel_id = $1 ORDER BY participant_id LIMIT $2",
    )
    .bind(channel_id)
    .bind(limit.clamp(1, 500))
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Some(
        rows.into_iter()
            .map(|row| (row.get("participant_id"), row.get("jid")))
            .collect(),
    ))
}

pub async fn authorized_mix_jid_map_entries(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    limit: i64,
) -> Result<MixReadOutcome<Vec<(String, String)>>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    match authorize_mix_node_read_tx(&mut transaction, channel_id, actor, NODE_JIDMAP).await? {
        MixReadOutcome::Found(_) => {}
        MixReadOutcome::Unauthorized => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::Unauthorized);
        }
        MixReadOutcome::NotFound => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::NotFound);
        }
    }
    let rows = sqlx::query(
        "SELECT participant_id::text AS participant_id,jid FROM mix_participants WHERE channel_id=$1 ORDER BY participant_id LIMIT $2",
    )
    .bind(channel_id)
    .bind(limit.clamp(1, 500))
    .fetch_all(&mut *transaction)
    .await?;
    let entries = rows
        .into_iter()
        .map(|row| (row.get("participant_id"), row.get("jid")))
        .collect();
    transaction.commit().await?;
    Ok(MixReadOutcome::Found(entries))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the atomic invitation mutation keeps its principals, token lifetime, renderer, and federation fence explicit"
)]
pub async fn issue_mix_invitation(
    pool: &PgPool,
    channel_id: Uuid,
    inviter: &str,
    invitee: &str,
    token: &str,
    lifetime: chrono::Duration,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<bool> {
    let inviter = canonical_user_bare(inviter)?;
    let invitee = canonical_user_bare(invitee)?;
    anyhow::ensure!(
        (16..=1024).contains(&token.len()),
        "invalid MIX invitation token"
    );
    let token_hash = Sha256::digest(token.as_bytes()).to_vec();
    let mut transaction = pool.begin().await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let channel = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel) = channel else {
        transaction.rollback().await?;
        return Ok(false);
    };
    let channel = channel_from_row(&channel);
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role IN ('owner', 'administrator')) OR (SELECT allow_participant_invites AND EXISTS(SELECT 1 FROM mix_participants WHERE channel_id = $1 AND jid = $2) FROM mix_channels WHERE id = $1)",
    )
    .bind(channel_id)
    .bind(&inviter)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(false);
    }
    sqlx::query("DELETE FROM mix_invitations WHERE expires_at <= NOW() OR consumed_at IS NOT NULL")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO mix_invitations (id, channel_id, inviter_jid, invitee_jid, token_hash, expires_at) VALUES ($1, $2, $3, $4, $5, NOW() + $6::interval)",
    )
    .bind(Uuid::new_v4())
    .bind(channel_id)
    .bind(&inviter)
    .bind(&invitee)
    .bind(token_hash)
    .bind(format!("{} seconds", lifetime.num_seconds().clamp(60, 86400)))
    .execute(&mut *transaction)
    .await?;
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::Invitation {
            inviter: inviter.clone(),
            invitee: invitee.clone(),
            channel: channel.jid(),
            token: token.to_owned(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn mix_private_message_recipient(
    pool: &PgPool,
    channel_id: Uuid,
    sender: &str,
    recipient_id: Uuid,
) -> Result<Option<(MixParticipant, MixParticipant)>> {
    let sender = canonical_user_bare(sender)?;
    // One MVCC statement binds policy, sender membership, recipient membership
    // and recipient preference to the same snapshot. The previous four-step
    // lookup could deliver after a concurrent leave or policy revocation.
    let row = sqlx::query(
        "SELECT sender.participant_id AS sender_id, sender.jid AS sender_jid,
                sender.nick AS sender_nick, recipient.participant_id AS recipient_id,
                recipient.jid AS recipient_jid, recipient.nick AS recipient_nick
         FROM mix_channels channel
         JOIN mix_participants sender
           ON sender.channel_id = channel.id AND sender.jid = $2
         JOIN mix_participants recipient
           ON recipient.channel_id = channel.id AND recipient.participant_id = $3
         JOIN mix_participant_preferences preference
           ON preference.channel_id = recipient.channel_id
          AND preference.participant_id = recipient.participant_id
         WHERE channel.id = $1 AND channel.allow_private_messages
           AND preference.private_messages = 'allow'",
    )
    .bind(channel_id)
    .bind(sender)
    .bind(recipient_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        (
            MixParticipant {
                participant_id: row.get("sender_id"),
                jid: row.get("sender_jid"),
                nick: row.get("sender_nick"),
            },
            MixParticipant {
                participant_id: row.get("recipient_id"),
                jid: row.get("recipient_jid"),
                nick: row.get("recipient_nick"),
            },
        )
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetractMixMessageOutcome {
    Retracted,
    Existing(MixIntentEvidence),
    NotFound,
    Forbidden,
}

#[derive(Clone, Debug)]
pub struct RetractMixMessageAdmission {
    pub outcome: RetractMixMessageOutcome,
    pub recipients: Vec<MixParticipant>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "the channel-locked retraction transaction keeps replay identity and both durable projections explicit"
)]
pub async fn retract_mix_message(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    target_id: Uuid,
    retraction_id: Uuid,
    tombstone_payload: &str,
    retraction_payload: &str,
    identity: Option<MixBusinessIdentity<'_>>,
    visible_jid: Option<&str>,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<RetractMixMessageAdmission> {
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(RetractMixMessageAdmission {
            outcome: RetractMixMessageOutcome::NotFound,
            recipients: Vec::new(),
        });
    };
    let channel = channel_from_row(&channel_row);
    if let Some(identity) = identity {
        if let Some(existing) = existing_mix_business_intent_tx(
            &mut transaction,
            channel_id,
            &actor,
            "retraction",
            identity.client_id,
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(RetractMixMessageAdmission {
                outcome: RetractMixMessageOutcome::Existing(existing),
                recipients: Vec::new(),
            });
        }
    }
    let target = sqlx::query(
        "SELECT publisher_jid FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3 FOR UPDATE",
    )
    .bind(channel_id)
    .bind(NODE_MESSAGES)
    .bind(target_id.to_string())
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(target) = target else {
        transaction.rollback().await?;
        return Ok(RetractMixMessageAdmission {
            outcome: RetractMixMessageOutcome::NotFound,
            recipients: Vec::new(),
        });
    };
    let publisher: Option<String> = target.get("publisher_jid");
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2")
            .bind(channel_id)
            .bind(&actor)
            .fetch_optional(&mut *transaction)
            .await?;
    let own_allowed = channel.allow_user_message_retraction && publisher.as_deref() == Some(&actor);
    let admin_allowed = match channel.administrator_retraction_rights.as_str() {
        "administrators" => role.is_some(),
        "owners" => role.as_deref() == Some("owner"),
        _ => false,
    };
    if !own_allowed && !admin_allowed {
        transaction.rollback().await?;
        return Ok(RetractMixMessageAdmission {
            outcome: RetractMixMessageOutcome::Forbidden,
            recipients: Vec::new(),
        });
    }
    if let Some(identity) = identity {
        if let Some(existing) = admit_mix_business_intent_tx(
            &mut transaction,
            channel_id,
            &actor,
            "retraction",
            identity,
            retraction_id,
            Some(target_id),
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(RetractMixMessageAdmission {
                outcome: RetractMixMessageOutcome::Existing(existing),
                recipients: Vec::new(),
            });
        }
    }
    sqlx::query(
        "UPDATE mix_events SET payload = $4 WHERE channel_id = $1 AND node = $2 AND item_id = $3",
    )
    .bind(channel_id)
    .bind(NODE_MESSAGES)
    .bind(target_id.to_string())
    .bind(tombstone_payload)
    .execute(&mut *transaction)
    .await?;
    let actor_participant = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_optional(&mut *transaction)
    .await?
    .map(|row| participant_from_row(&row));
    let _ = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_MESSAGES,
        &retraction_id.to_string(),
        actor_participant.as_ref(),
        retraction_payload,
    )
    .await?;
    let recipients = mix_subscribers_tx(&mut transaction, channel_id, NODE_MESSAGES).await?;
    let Some(sender) = actor_participant.as_ref() else {
        transaction.rollback().await?;
        return Ok(RetractMixMessageAdmission {
            outcome: RetractMixMessageOutcome::Forbidden,
            recipients: Vec::new(),
        });
    };
    let stanza_template = recipients
        .first()
        .map(|recipient| {
            payloads.retraction_delivery_stanza(
                &channel,
                sender,
                recipient,
                retraction_id,
                target_id,
                visible_jid,
            )
        })
        .transpose()?
        .unwrap_or_default();
    enqueue_mix_deliveries_tx(
        &mut transaction,
        &delivery_fence,
        MixDeliveryProjection {
            channel: &channel,
            event_id: retraction_id,
            recipients: &recipients,
            stanza_template: &stanza_template,
            authoritative_stanza_id: Some(retraction_id),
            archive: true,
            encrypted: false,
        },
    )
    .await?;
    transaction.commit().await?;
    Ok(RetractMixMessageAdmission {
        outcome: RetractMixMessageOutcome::Retracted,
        recipients,
    })
}

pub struct BeginRemotePamJoin<'a> {
    pub user_id: Uuid,
    pub actor_jid: &'a str,
    pub channel_jid: &'a str,
    pub nick: Option<&'a str>,
    pub nodes: &'a [String],
    pub request_id: &'a str,
    pub client_request_id: &'a str,
    pub requester_full_jid: &'a str,
    pub request_digest: &'a [u8; 32],
    pub remote_domain: &'a str,
    pub outbound_stanza: &'a str,
    pub policy: super::S2sOutboxPolicy,
}

pub struct BeginRemotePamLeave<'a> {
    pub user_id: Uuid,
    pub actor_jid: &'a str,
    pub channel_jid: &'a str,
    pub request_id: &'a str,
    pub client_request_id: &'a str,
    pub requester_full_jid: &'a str,
    pub request_digest: &'a [u8; 32],
    pub remote_domain: &'a str,
    pub outbound_stanza: &'a str,
    pub policy: super::S2sOutboxPolicy,
}

#[derive(Clone, Copy)]
pub struct RemotePamJoin<'a> {
    pub participant_id: &'a str,
    pub subscriptions: &'a [String],
    pub nick: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub enum RemotePamCompletionOutcome {
    Applied(RemotePamCompletion),
    Replay(RemotePamCompletion),
    Conflict,
    Missing,
}

const MIX_PAM_RESULT_LEASE_SECONDS: i64 = 90;
const MIX_PAM_RESULT_MAX_ATTEMPTS: i32 = 20;

struct MixPamCapacityReconciliationCommitted(());

async fn reconcile_mix_pam_capacity_committed(
    pool: &PgPool,
) -> Result<MixPamCapacityReconciliationCommitted> {
    let mut transaction = pool.begin().await?;
    // The owner-held capability takes the global counter as its first lock and
    // reclaims the complete hard-bounded eligible set. Commit before opening
    // the producer transaction so a later capacity rejection cannot roll the
    // same cleanup back and depend on worker cadence for forward progress.
    let _: i64 = sqlx::query_scalar("SELECT northstar_mix_pam_capacity_reconcile()")
        .fetch_one(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(MixPamCapacityReconciliationCommitted(()))
}

fn pam_operation_replay(row: &sqlx::postgres::PgRow, digest: &[u8; 32]) -> PamOperationReplay {
    if row.get::<Vec<u8>, _>("request_digest").as_slice() != digest {
        PamOperationReplay::Conflict
    } else if let Some(response) = row.get::<Option<String>, _>("response_xml") {
        PamOperationReplay::Replay(response)
    } else {
        PamOperationReplay::Pending
    }
}

pub async fn lookup_remote_pam_operation(
    pool: &PgPool,
    user_id: Uuid,
    requester_full_jid: &str,
    client_request_id: &str,
    request_digest: &[u8; 32],
) -> Result<PamOperationReplay> {
    let requester = crate::jid::canonical_session_key(requester_full_jid)?;
    anyhow::ensure!(
        !client_request_id.is_empty() && client_request_id.len() <= 1_024,
        "invalid PAM client request id"
    );
    let row = sqlx::query(
        "SELECT request_digest,response_xml FROM mix_pam_operations
          WHERE user_id=$1 AND requester_full_jid=$2 AND client_request_id=$3",
    )
    .bind(user_id)
    .bind(requester)
    .bind(client_request_id)
    .fetch_optional(pool)
    .await?;
    Ok(row
        .as_ref()
        .map(|row| pam_operation_replay(row, request_digest))
        .unwrap_or(PamOperationReplay::Miss))
}

async fn lock_pam_admission_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    channel_jid: &str,
    requester_full_jid: &str,
    client_request_id: &str,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("pam-membership:{user_id}:{channel_jid}"))
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!(
            "pam-client:{user_id}:{requester_full_jid}:{client_request_id}"
        ))
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

/// Lock the authenticated account against deletion, disable or rename, then
/// acquire the durable global PAM capacity authority before any membership,
/// client-id or operation lock. The service's clone-shared FIFO gate is held
/// before this function may check out its transaction, so each process
/// contributes at most one database waiter. Database triggers subsequently
/// lock global -> exact user counter.
async fn remote_pam_account_matches_actor_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    actor_jid: &str,
) -> Result<bool> {
    let actor_username = crate::jid::CanonicalJid::parse_bare(actor_jid)?
        .localpart()
        .context("MIX-PAM actor requires a localpart")?
        .to_owned();
    sqlx::query_scalar("SELECT northstar_mix_pam_account_capacity_lock($1,$2)")
        .bind(user_id)
        .bind(actor_username)
        .fetch_one(&mut **transaction)
        .await
        .map_err(Into::into)
}

fn validate_pam_outbound(
    outbound: &str,
    request_id: &str,
    actor: &str,
    channel: &str,
) -> Result<()> {
    anyhow::ensure!(
        !outbound.is_empty() && outbound.len() <= super::MAX_S2S_STANZA_BYTES,
        "invalid remote PAM stanza size"
    );
    let document = roxmltree::Document::parse(outbound).context("invalid remote PAM stanza")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "iq"
            && root.attribute("type") == Some("set")
            && root.attribute("id") == Some(request_id)
            && root.attribute("from") == Some(actor)
            && root.attribute("to") == Some(channel),
        "remote PAM stanza does not match its durable operation"
    );
    Ok(())
}

async fn existing_pam_operation_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    requester_full_jid: &str,
    client_request_id: &str,
    request_digest: &[u8; 32],
) -> Result<Option<PamOperationReplay>> {
    let row = sqlx::query(
        "SELECT request_digest,response_xml FROM mix_pam_operations
          WHERE user_id=$1 AND requester_full_jid=$2 AND client_request_id=$3
          FOR SHARE",
    )
    .bind(user_id)
    .bind(requester_full_jid)
    .bind(client_request_id)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row
        .as_ref()
        .map(|row| pam_operation_replay(row, request_digest)))
}

#[allow(clippy::too_many_arguments)]
async fn insert_pam_operation_and_outbox_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    channel_jid: &str,
    remote_domain: &str,
    operation: &str,
    remote_request_id: &str,
    client_request_id: &str,
    requester_full_jid: &str,
    request_digest: &[u8; 32],
    outbound_stanza: &str,
    prior_participant_id: Option<&str>,
    prior_nick: Option<&str>,
    prior_subscriptions: &[String],
    policy: super::S2sOutboxPolicy,
) -> Result<()> {
    let expected_username = crate::jid::CanonicalJid::parse(requester_full_jid)?
        .localpart()
        .context("MIX-PAM requester requires a localpart")?
        .to_owned();
    let operation_id = Uuid::new_v4();
    let request_outbox_id = Uuid::new_v4();
    super::enqueue_s2s_outbox_with_id_in_transaction(
        transaction,
        request_outbox_id,
        remote_domain,
        outbound_stanza,
        None,
        policy,
    )
    .await?;
    let deadline_seconds = i64::try_from(policy.ttl_seconds.clamp(30, 86_400))
        .context("remote PAM timeout is too large")?;
    sqlx::query(
        "SELECT northstar_mix_pam_operation_insert(
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
         )",
    )
    .bind(operation_id)
    .bind(user_id)
    .bind(channel_jid)
    .bind(remote_domain)
    .bind(operation)
    .bind(remote_request_id)
    .bind(client_request_id)
    .bind(requester_full_jid)
    .bind(request_digest.as_slice())
    .bind(request_outbox_id)
    .bind(prior_participant_id.is_some())
    .bind(prior_participant_id)
    .bind(prior_nick)
    .bind(prior_subscriptions)
    .bind(deadline_seconds)
    .bind(expected_username)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub async fn begin_remote_pam_join(
    pool: &PgPool,
    request: BeginRemotePamJoin<'_>,
) -> Result<PamOperationReplay> {
    let actor_jid = canonical_user_bare(request.actor_jid)?;
    let channel_jid = crate::jid::canonicalize_bare(request.channel_jid)?;
    let nodes = valid_join_nodes(request.nodes)?;
    let nick = request.nick.map(prepare_mix_nick).transpose()?;
    anyhow::ensure!(
        !request.request_id.is_empty() && request.request_id.len() <= 128,
        "invalid PAM request id"
    );
    anyhow::ensure!(
        !request.client_request_id.is_empty() && request.client_request_id.len() <= 1_024,
        "invalid PAM client request id"
    );
    let requester_full_jid = crate::jid::canonical_session_key(request.requester_full_jid)?;
    let remote_domain = crate::jid::prepare_domainpart(request.remote_domain)?;
    anyhow::ensure!(
        crate::jid::canonical_bare_key(&requester_full_jid)? == actor_jid,
        "MIX-PAM requester resource does not belong to authenticated actor"
    );
    anyhow::ensure!(
        crate::jid::CanonicalJid::parse_bare(&channel_jid)?.domainpart() == remote_domain,
        "MIX-PAM remote domain does not own the channel"
    );
    validate_pam_outbound(
        request.outbound_stanza,
        request.request_id,
        &actor_jid,
        &channel_jid,
    )?;
    let _reconciled = reconcile_mix_pam_capacity_committed(pool).await?;
    let mut transaction = pool.begin().await?;
    anyhow::ensure!(
        remote_pam_account_matches_actor_tx(&mut transaction, request.user_id, &actor_jid).await?,
        "MIX-PAM account UUID does not belong to authenticated actor"
    );
    lock_pam_admission_tx(
        &mut transaction,
        request.user_id,
        &channel_jid,
        &requester_full_jid,
        request.client_request_id,
    )
    .await?;
    if let Some(replay) = existing_pam_operation_tx(
        &mut transaction,
        request.user_id,
        &requester_full_jid,
        request.client_request_id,
        request.request_digest,
    )
    .await?
    {
        transaction.rollback().await?;
        return Ok(replay);
    }
    let previous =
        locked_pam_membership_tx(&mut transaction, request.user_id, &channel_jid).await?;
    if previous
        .as_ref()
        .is_some_and(|membership| membership.state != "joined")
    {
        transaction.rollback().await?;
        // This request has no operation/result journal of its own. Returning
        // `Pending` would make the protocol wait for a result that can only be
        // correlated to the older IQ. Report a miss so the caller emits its
        // bounded resource-constraint response instead.
        return Ok(PamOperationReplay::Miss);
    }
    let prior_participant_id = previous
        .as_ref()
        .and_then(|membership| membership.participant_id.clone());
    anyhow::ensure!(
        previous.is_none() || prior_participant_id.is_some(),
        "joined PAM membership has no stable participant id"
    );
    let prior_nick: Option<String> = if let Some(previous) = previous.as_ref() {
        sqlx::query_scalar("SELECT nick FROM mix_pam_memberships WHERE id=$1")
            .bind(previous.id)
            .fetch_one(&mut *transaction)
            .await?
    } else {
        None
    };
    let prior_subscriptions = previous
        .as_ref()
        .map(|membership| membership.subscriptions.clone())
        .unwrap_or_default();
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mix_pam_memberships (id, user_id, channel_jid, nick, state, request_id, client_request_id, requester_full_jid) VALUES ($1, $2, $3, $4, 'pending_join', $5, $6, $7) ON CONFLICT (user_id, channel_jid) DO UPDATE SET nick = EXCLUDED.nick, state = 'pending_join', request_id = EXCLUDED.request_id, client_request_id = EXCLUDED.client_request_id, requester_full_jid = EXCLUDED.requester_full_jid, updated_at = NOW()",
    )
    .bind(id)
    .bind(request.user_id)
    .bind(&channel_jid)
    .bind(nick.as_deref())
    .bind(request.request_id)
    .bind(request.client_request_id)
    .bind(&requester_full_jid)
    .execute(&mut *transaction)
    .await?;
    let membership_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM mix_pam_memberships WHERE user_id = $1 AND channel_jid = $2",
    )
    .bind(request.user_id)
    .bind(&channel_jid)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM mix_pam_subscriptions WHERE membership_id = $1")
        .bind(membership_id)
        .execute(&mut *transaction)
        .await?;
    for node in nodes {
        sqlx::query("INSERT INTO mix_pam_subscriptions (membership_id, node) VALUES ($1, $2)")
            .bind(membership_id)
            .bind(node)
            .execute(&mut *transaction)
            .await?;
    }
    insert_pam_operation_and_outbox_tx(
        &mut transaction,
        request.user_id,
        &channel_jid,
        &remote_domain,
        "join",
        request.request_id,
        request.client_request_id,
        &requester_full_jid,
        request.request_digest,
        request.outbound_stanza,
        prior_participant_id.as_deref(),
        prior_nick.as_deref(),
        &prior_subscriptions,
        request.policy,
    )
    .await?;
    transaction.commit().await?;
    Ok(PamOperationReplay::Pending)
}

/// Durable PAM correlation and its S2S outbox survive restart. Startup must
/// never guess that an unanswered remote mutation failed and roll back only
/// the local half.
pub async fn recover_remote_pam_after_restart(pool: &PgPool) -> Result<()> {
    let _ = prune_expired_pam_results(pool, 512).await?;
    Ok(())
}

async fn locked_pam_membership_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    channel_jid: &str,
) -> Result<Option<PamMembership>> {
    let row = sqlx::query(
        "SELECT id,user_id,channel_jid,participant_id,state,request_id,
                client_request_id,requester_full_jid
           FROM mix_pam_memberships
          WHERE user_id=$1 AND channel_jid=$2 FOR UPDATE",
    )
    .bind(user_id)
    .bind(channel_jid)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let id: Uuid = row.get("id");
    let subscriptions = sqlx::query_scalar(
        "SELECT node FROM mix_pam_subscriptions WHERE membership_id=$1 ORDER BY node",
    )
    .bind(id)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(Some(PamMembership {
        id,
        user_id: row.get("user_id"),
        channel_jid: row.get("channel_jid"),
        participant_id: row.get("participant_id"),
        state: row.get("state"),
        request_id: row.get("request_id"),
        client_request_id: row.get("client_request_id"),
        requester_full_jid: row.get("requester_full_jid"),
        subscriptions,
    }))
}

fn terminal_pam_completion(
    row: &sqlx::postgres::PgRow,
    response_digest: &[u8; 32],
) -> RemotePamCompletionOutcome {
    let exact = row
        .get::<Option<Vec<u8>>, _>("remote_response_digest")
        .is_some_and(|digest| digest.as_slice() == response_digest);
    if !exact {
        return RemotePamCompletionOutcome::Conflict;
    }
    RemotePamCompletionOutcome::Replay(RemotePamCompletion {
        response_xml: row
            .get::<Option<String>, _>("response_xml")
            .expect("terminal PAM row has a response"),
        membership: None,
        applied: false,
        roster_removed: None,
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn complete_remote_pam_success(
    pool: &PgPool,
    authenticated_domain: &str,
    channel_jid: &str,
    recipient_bare: &str,
    request_id: &str,
    response_digest: &[u8; 32],
    join: Option<RemotePamJoin<'_>>,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<RemotePamCompletionOutcome> {
    let authenticated_domain = crate::jid::prepare_domainpart(authenticated_domain)?;
    let channel_jid = crate::jid::canonicalize_bare(channel_jid)?;
    let recipient_bare = crate::jid::canonicalize_bare(recipient_bare)?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT operation_id,user_id,channel_jid,remote_domain,operation,
                request_outbox_id,
                client_request_id,requester_full_jid,state,
                remote_response_digest,response_xml
           FROM mix_pam_operations WHERE remote_request_id=$1 FOR UPDATE",
    )
    .bind(request_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Ok(RemotePamCompletionOutcome::Missing);
    };
    if row.get::<String, _>("remote_domain") != authenticated_domain
        || row.get::<String, _>("channel_jid") != channel_jid
    {
        transaction.rollback().await?;
        return Ok(RemotePamCompletionOutcome::Conflict);
    }
    let operation_state: String = row.get("state");
    if operation_state == "terminal" {
        let outcome = terminal_pam_completion(&row, response_digest);
        transaction.rollback().await?;
        return Ok(outcome);
    }
    anyhow::ensure!(
        matches!(operation_state.as_str(), "pending" | "reconciliation"),
        "invalid remote PAM operation state"
    );
    let reconciliation_response = (operation_state == "reconciliation")
        .then(|| row.get::<Option<String>, _>("response_xml"))
        .flatten();
    let user_id: Uuid = row.get("user_id");
    let operation: String = row.get("operation");
    let requester: String = row.get("requester_full_jid");
    let actor = crate::jid::canonical_bare_key(&requester)?;
    if actor != recipient_bare {
        transaction.rollback().await?;
        return Ok(RemotePamCompletionOutcome::Conflict);
    }
    let client_request_id: String = row.get("client_request_id");
    let Some(mut membership) =
        locked_pam_membership_tx(&mut transaction, user_id, &channel_jid).await?
    else {
        anyhow::bail!("remote PAM operation lost its membership authority")
    };
    let response = match (operation.as_str(), join) {
        ("join", Some(join)) if membership.state == "pending_join" => {
            anyhow::ensure!(
                valid_stable_participant_id(join.participant_id),
                "invalid remote MIX participant id"
            );
            let subscriptions = valid_join_nodes(join.subscriptions)?;
            anyhow::ensure!(
                subscriptions
                    .iter()
                    .all(|node| membership.subscriptions.contains(node))
                    && (membership.subscriptions.is_empty() || !subscriptions.is_empty()),
                "remote MIX service returned unrequested subscriptions"
            );
            let nick = join.nick.map(prepare_mix_nick).transpose()?;
            sqlx::query(
                "UPDATE mix_pam_memberships
                    SET participant_id=$2,nick=COALESCE($3,nick),state='joined',
                        request_id=NULL,client_request_id=NULL,requester_full_jid=NULL,
                        updated_at=clock_timestamp()
                  WHERE id=$1",
            )
            .bind(membership.id)
            .bind(join.participant_id)
            .bind(nick.as_deref())
            .execute(&mut *transaction)
            .await?;
            sqlx::query("DELETE FROM mix_pam_subscriptions WHERE membership_id=$1")
                .bind(membership.id)
                .execute(&mut *transaction)
                .await?;
            for node in &subscriptions {
                sqlx::query("INSERT INTO mix_pam_subscriptions(membership_id,node) VALUES($1,$2)")
                    .bind(membership.id)
                    .bind(node)
                    .execute(&mut *transaction)
                    .await?;
            }
            membership.participant_id = Some(join.participant_id.to_owned());
            membership.state = "joined".to_owned();
            membership.request_id = None;
            membership.client_request_id = None;
            membership.requester_full_jid = None;
            membership.subscriptions = subscriptions.clone();
            upsert_mix_roster_tx(&mut transaction, user_id, &channel_jid, None, true).await?;
            match reconciliation_response.as_ref() {
                Some(response) => response.clone(),
                None => payloads.pam_join_result(PamJoinResult {
                    client_request_id: &client_request_id,
                    actor_bare: &actor,
                    requester_full_jid: &requester,
                    channel_jid: &channel_jid,
                    participant_id: join.participant_id,
                    subscriptions: &subscriptions,
                    nick: nick.as_deref(),
                })?,
            }
        }
        ("leave", None) if membership.state == "pending_leave" => {
            let response = match reconciliation_response.as_ref() {
                Some(response) => response.clone(),
                None => payloads.pam_leave_result(
                    &client_request_id,
                    &actor,
                    &requester,
                    &channel_jid,
                )?,
            };
            delete_mix_roster_tx(&mut transaction, user_id, &channel_jid).await?;
            sqlx::query("DELETE FROM mix_pam_memberships WHERE id=$1")
                .bind(membership.id)
                .execute(&mut *transaction)
                .await?;
            response
        }
        _ => anyhow::bail!("remote PAM result does not match the pending operation"),
    };
    // An authenticated terminal response proves that this exact request was
    // accepted remotely. Remove any crash-recovered request row in the same
    // transaction so the ordinary S2S worker cannot retransmit it after the
    // business operation has become terminal.
    sqlx::query("DELETE FROM s2s_outbox WHERE id=$1")
        .bind(row.get::<Uuid, _>("request_outbox_id"))
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE mix_pam_operations
            SET state='terminal',remote_response_digest=$2,response_xml=$3,
                next_delivery_at=clock_timestamp(),updated_at=clock_timestamp()
          WHERE operation_id=$1 AND state IN ('pending','reconciliation')",
    )
    .bind(row.get::<Uuid, _>("operation_id"))
    .bind(response_digest.as_slice())
    .bind(&response)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(RemotePamCompletionOutcome::Applied(RemotePamCompletion {
        response_xml: response,
        membership: Some(membership),
        applied: true,
        roster_removed: Some(operation == "leave"),
    }))
}

async fn pam_membership_from_row(
    pool: &PgPool,
    row: sqlx::postgres::PgRow,
) -> Result<PamMembership> {
    let id: Uuid = row.get("id");
    let subscriptions = sqlx::query_scalar(
        "SELECT node FROM mix_pam_subscriptions WHERE membership_id = $1 ORDER BY node",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    Ok(PamMembership {
        id,
        user_id: row.get("user_id"),
        channel_jid: row.get("channel_jid"),
        participant_id: row.get("participant_id"),
        state: row.get("state"),
        request_id: row.get("request_id"),
        client_request_id: row.get("client_request_id"),
        requester_full_jid: row.get("requester_full_jid"),
        subscriptions,
    })
}

pub async fn pam_memberships(pool: &PgPool, user_id: Uuid) -> Result<Vec<PamMembership>> {
    let rows = sqlx::query(
        "SELECT id, user_id, channel_jid, participant_id, state, request_id, client_request_id, requester_full_jid FROM mix_pam_memberships WHERE user_id = $1 ORDER BY channel_jid",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    let mut memberships = Vec::with_capacity(rows.len());
    for row in rows {
        memberships.push(pam_membership_from_row(pool, row).await?);
    }
    Ok(memberships)
}

pub async fn pam_membership(
    pool: &PgPool,
    user_id: Uuid,
    channel_jid: &str,
) -> Result<Option<PamMembership>> {
    let channel_jid = crate::jid::canonicalize_bare(channel_jid)?;
    let row = sqlx::query(
        "SELECT id, user_id, channel_jid, participant_id, state, request_id, client_request_id, requester_full_jid FROM mix_pam_memberships WHERE user_id = $1 AND channel_jid = $2",
    )
    .bind(user_id)
    .bind(channel_jid)
    .fetch_optional(pool)
    .await?;
    match row {
        Some(row) => pam_membership_from_row(pool, row).await.map(Some),
        None => Ok(None),
    }
}

pub async fn local_pam_users_for_channel(pool: &PgPool, channel_jid: &str) -> Result<Vec<Uuid>> {
    let channel_jid = crate::jid::canonicalize_bare(channel_jid)?;
    sqlx::query_scalar(
        "SELECT user_id FROM mix_pam_memberships WHERE channel_jid = $1 ORDER BY user_id",
    )
    .bind(channel_jid)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub async fn begin_remote_pam_leave(
    pool: &PgPool,
    request: BeginRemotePamLeave<'_>,
) -> Result<PamOperationReplay> {
    let actor_jid = canonical_user_bare(request.actor_jid)?;
    let channel_jid = crate::jid::canonicalize_bare(request.channel_jid)?;
    let requester_full_jid = crate::jid::canonical_session_key(request.requester_full_jid)?;
    let remote_domain = crate::jid::prepare_domainpart(request.remote_domain)?;
    anyhow::ensure!(
        crate::jid::canonical_bare_key(&requester_full_jid)? == actor_jid,
        "MIX-PAM requester resource does not belong to authenticated actor"
    );
    anyhow::ensure!(
        !request.request_id.is_empty() && request.request_id.len() <= 128,
        "invalid PAM request id"
    );
    anyhow::ensure!(
        !request.client_request_id.is_empty() && request.client_request_id.len() <= 1_024,
        "invalid PAM client request id"
    );
    anyhow::ensure!(
        crate::jid::CanonicalJid::parse_bare(&channel_jid)?.domainpart() == remote_domain,
        "MIX-PAM remote domain does not own the channel"
    );
    validate_pam_outbound(
        request.outbound_stanza,
        request.request_id,
        &actor_jid,
        &channel_jid,
    )?;
    let _reconciled = reconcile_mix_pam_capacity_committed(pool).await?;
    let mut transaction = pool.begin().await?;
    anyhow::ensure!(
        remote_pam_account_matches_actor_tx(&mut transaction, request.user_id, &actor_jid).await?,
        "MIX-PAM account UUID does not belong to authenticated actor"
    );
    lock_pam_admission_tx(
        &mut transaction,
        request.user_id,
        &channel_jid,
        &requester_full_jid,
        request.client_request_id,
    )
    .await?;
    if let Some(replay) = existing_pam_operation_tx(
        &mut transaction,
        request.user_id,
        &requester_full_jid,
        request.client_request_id,
        request.request_digest,
    )
    .await?
    {
        transaction.rollback().await?;
        return Ok(replay);
    }
    let updated = sqlx::query(
        "UPDATE mix_pam_memberships SET state = 'pending_leave', request_id = $3, client_request_id = $4, requester_full_jid = $5, updated_at = NOW() WHERE user_id = $1 AND channel_jid = $2 AND state = 'joined'",
    )
    .bind(request.user_id)
    .bind(&channel_jid)
    .bind(request.request_id)
    .bind(request.client_request_id)
    .bind(&requester_full_jid)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        == 1;
    if !updated {
        transaction.rollback().await?;
        return Ok(PamOperationReplay::Miss);
    }
    insert_pam_operation_and_outbox_tx(
        &mut transaction,
        request.user_id,
        &channel_jid,
        &remote_domain,
        "leave",
        request.request_id,
        request.client_request_id,
        &requester_full_jid,
        request.request_digest,
        request.outbound_stanza,
        None,
        None,
        &[],
        request.policy,
    )
    .await?;
    transaction.commit().await?;
    Ok(PamOperationReplay::Pending)
}

#[allow(clippy::too_many_arguments)]
pub async fn complete_remote_pam_error(
    pool: &PgPool,
    authenticated_domain: &str,
    channel_jid: &str,
    recipient_bare: &str,
    request_id: &str,
    response_digest: &[u8; 32],
    error_type: &str,
    condition: &str,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<RemotePamCompletionOutcome> {
    let authenticated_domain = crate::jid::prepare_domainpart(authenticated_domain)?;
    let channel_jid = crate::jid::canonicalize_bare(channel_jid)?;
    let recipient_bare = crate::jid::canonicalize_bare(recipient_bare)?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT operation_id,user_id,channel_jid,remote_domain,operation,
                request_outbox_id,prior_joined,prior_participant_id,
                prior_nick,prior_subscriptions,
                client_request_id,requester_full_jid,state,
                remote_response_digest,response_xml
           FROM mix_pam_operations WHERE remote_request_id=$1 FOR UPDATE",
    )
    .bind(request_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Ok(RemotePamCompletionOutcome::Missing);
    };
    if row.get::<String, _>("remote_domain") != authenticated_domain
        || row.get::<String, _>("channel_jid") != channel_jid
    {
        transaction.rollback().await?;
        return Ok(RemotePamCompletionOutcome::Conflict);
    }
    let operation_state: String = row.get("state");
    if operation_state == "terminal" {
        let outcome = terminal_pam_completion(&row, response_digest);
        transaction.rollback().await?;
        return Ok(outcome);
    }
    anyhow::ensure!(
        matches!(operation_state.as_str(), "pending" | "reconciliation"),
        "invalid remote PAM operation state"
    );
    let user_id: Uuid = row.get("user_id");
    let requester: String = row.get("requester_full_jid");
    let actor = crate::jid::canonical_bare_key(&requester)?;
    if actor != recipient_bare {
        transaction.rollback().await?;
        return Ok(RemotePamCompletionOutcome::Conflict);
    }
    let response = match row.get::<Option<String>, _>("response_xml") {
        Some(response) => response,
        None => payloads.pam_error_result(
            row.get::<String, _>("client_request_id").as_str(),
            &actor,
            &requester,
            error_type,
            condition,
        )?,
    };
    let membership = locked_pam_membership_tx(&mut transaction, user_id, &channel_jid).await?;
    let Some(mut membership) = membership else {
        anyhow::bail!("remote PAM error lost its membership authority")
    };
    match (
        row.get::<String, _>("operation").as_str(),
        membership.state.as_str(),
    ) {
        ("join", "pending_join") => {
            if row.get::<bool, _>("prior_joined") {
                let prior_participant_id: String = row.get("prior_participant_id");
                let prior_nick: Option<String> = row.get("prior_nick");
                let prior_subscriptions: Vec<String> = row.get("prior_subscriptions");
                sqlx::query(
                    "UPDATE mix_pam_memberships
                        SET participant_id=$2,nick=$3,state='joined',request_id=NULL,
                            client_request_id=NULL,requester_full_jid=NULL,
                            updated_at=clock_timestamp()
                      WHERE id=$1",
                )
                .bind(membership.id)
                .bind(&prior_participant_id)
                .bind(prior_nick.as_deref())
                .execute(&mut *transaction)
                .await?;
                sqlx::query("DELETE FROM mix_pam_subscriptions WHERE membership_id=$1")
                    .bind(membership.id)
                    .execute(&mut *transaction)
                    .await?;
                for node in &prior_subscriptions {
                    sqlx::query(
                        "INSERT INTO mix_pam_subscriptions(membership_id,node) VALUES($1,$2)",
                    )
                    .bind(membership.id)
                    .bind(node)
                    .execute(&mut *transaction)
                    .await?;
                }
                membership.participant_id = Some(prior_participant_id);
                membership.state = "joined".to_owned();
                membership.request_id = None;
                membership.client_request_id = None;
                membership.requester_full_jid = None;
                membership.subscriptions = prior_subscriptions;
            } else {
                sqlx::query("DELETE FROM mix_pam_memberships WHERE id=$1")
                    .bind(membership.id)
                    .execute(&mut *transaction)
                    .await?;
            }
        }
        ("leave", "pending_leave") => {
            sqlx::query(
                "UPDATE mix_pam_memberships
                    SET state='joined',request_id=NULL,client_request_id=NULL,
                        requester_full_jid=NULL,updated_at=clock_timestamp()
                  WHERE id=$1",
            )
            .bind(membership.id)
            .execute(&mut *transaction)
            .await?;
            membership.state = "joined".to_owned();
            membership.request_id = None;
            membership.client_request_id = None;
            membership.requester_full_jid = None;
        }
        _ => anyhow::bail!("remote PAM error does not match the pending membership"),
    }
    sqlx::query("DELETE FROM s2s_outbox WHERE id=$1")
        .bind(row.get::<Uuid, _>("request_outbox_id"))
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE mix_pam_operations
            SET state='terminal',remote_response_digest=$2,response_xml=$3,
                next_delivery_at=clock_timestamp(),updated_at=clock_timestamp()
          WHERE operation_id=$1 AND state IN ('pending','reconciliation')",
    )
    .bind(row.get::<Uuid, _>("operation_id"))
    .bind(response_digest.as_slice())
    .bind(&response)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(RemotePamCompletionOutcome::Applied(RemotePamCompletion {
        response_xml: response,
        membership: Some(membership),
        applied: true,
        roster_removed: None,
    }))
}

pub async fn reconcile_expired_remote_pam(
    pool: &PgPool,
    limit: i64,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<u64> {
    let mut transaction = pool.begin().await?;
    let rows = sqlx::query(
        "SELECT operation_id,user_id,channel_jid,client_request_id,requester_full_jid
           FROM mix_pam_operations
          WHERE state='pending' AND deadline_at<=clock_timestamp()
          ORDER BY deadline_at,operation_id LIMIT $1 FOR UPDATE SKIP LOCKED",
    )
    .bind(limit.clamp(1, 256))
    .fetch_all(&mut *transaction)
    .await?;
    for row in &rows {
        let requester: String = row.get("requester_full_jid");
        let actor = crate::jid::canonical_bare_key(&requester)?;
        let response = payloads.pam_error_result(
            row.get::<String, _>("client_request_id").as_str(),
            &actor,
            &requester,
            "wait",
            "remote-server-timeout",
        )?;
        // Reconciliation deliberately leaves the membership pending. The
        // server reports uncertainty; it never invents a remote rollback.
        sqlx::query(
            "UPDATE mix_pam_operations
                SET state='reconciliation',response_xml=$2,
                    next_delivery_at=clock_timestamp(),updated_at=clock_timestamp()
              WHERE operation_id=$1 AND state='pending'",
        )
        .bind(row.get::<Uuid, _>("operation_id"))
        .bind(response)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(u64::try_from(rows.len()).unwrap_or(u64::MAX))
}

pub async fn claim_pam_results(pool: &PgPool, limit: i64) -> Result<Vec<ClaimedPamResult>> {
    // Keep the ordered statements in separate autocommit transactions while
    // avoiding a second pool checkout between expiry cleanup and claiming.
    let mut connection = pool.acquire().await?;
    sqlx::query(
        "WITH expired AS (
             SELECT operation_id FROM mix_pam_operations
              WHERE state IN ('terminal','reconciliation') AND response_xml IS NOT NULL
                AND delivered_at IS NULL AND dead_lettered_at IS NULL
                AND expires_at<=clock_timestamp()
                AND (lease_until IS NULL OR lease_until<=clock_timestamp())
              ORDER BY expires_at,operation_id
              LIMIT 256 FOR UPDATE SKIP LOCKED
         )
         UPDATE mix_pam_operations operation
            SET dead_lettered_at=clock_timestamp(),last_error='result retention expired',
                lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp()
           FROM expired WHERE operation.operation_id=expired.operation_id",
    )
    .execute(&mut *connection)
    .await?;
    let rows = sqlx::query(
        "WITH candidates AS (
             SELECT operation_id FROM mix_pam_operations
              WHERE state IN ('terminal','reconciliation')
                AND response_xml IS NOT NULL
                AND delivered_at IS NULL AND dead_lettered_at IS NULL
                AND (state='reconciliation' OR expires_at>clock_timestamp())
                AND next_delivery_at<=clock_timestamp()
                AND (lease_until IS NULL OR lease_until<=clock_timestamp())
                AND NOT EXISTS(
                    SELECT 1 FROM mix_pam_operations earlier
                     WHERE earlier.requester_full_jid=mix_pam_operations.requester_full_jid
                       AND earlier.response_xml IS NOT NULL
                       AND earlier.delivered_at IS NULL
                       AND earlier.dead_lettered_at IS NULL
                       AND (earlier.created_at,earlier.operation_id)
                           < (mix_pam_operations.created_at,mix_pam_operations.operation_id)
                )
              ORDER BY next_delivery_at,created_at,operation_id
              LIMIT $1 FOR UPDATE SKIP LOCKED
         ), claimed AS (
             UPDATE mix_pam_operations operation
                SET lease_token=gen_random_uuid(),
                    lease_until=clock_timestamp()+make_interval(secs=>$2)
               FROM candidates
              WHERE operation.operation_id=candidates.operation_id
             RETURNING operation.*
         )
         SELECT operation_id,user_id,requester_full_jid,response_xml,
                delivery_attempt_count,lease_token FROM claimed
          ORDER BY next_delivery_at,created_at,operation_id",
    )
    .bind(limit.clamp(1, 64))
    .bind(MIX_PAM_RESULT_LEASE_SECONDS)
    .fetch_all(&mut *connection)
    .await?;
    drop(connection);
    Ok(rows
        .into_iter()
        .map(|row| ClaimedPamResult {
            operation_id: row.get("operation_id"),
            user_id: row.get("user_id"),
            requester_full_jid: row.get("requester_full_jid"),
            response_xml: row.get("response_xml"),
            attempt_count: row.get("delivery_attempt_count"),
            lease_token: row.get("lease_token"),
        })
        .collect())
}

pub async fn renew_pam_result_lease(
    pool: &PgPool,
    operation_id: Uuid,
    lease_token: Uuid,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE mix_pam_operations
            SET lease_until=clock_timestamp()+make_interval(secs=>$3),updated_at=clock_timestamp()
          WHERE operation_id=$1 AND lease_token=$2 AND lease_until>clock_timestamp()
            AND delivered_at IS NULL AND dead_lettered_at IS NULL",
    )
    .bind(operation_id)
    .bind(lease_token)
    .bind(MIX_PAM_RESULT_LEASE_SECONDS)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn acknowledge_pam_result(
    pool: &PgPool,
    operation_id: Uuid,
    lease_token: Uuid,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE mix_pam_operations
            SET delivered_at=clock_timestamp(),lease_token=NULL,lease_until=NULL,
                updated_at=clock_timestamp()
          WHERE operation_id=$1 AND lease_token=$2 AND delivered_at IS NULL
            AND dead_lettered_at IS NULL",
    )
    .bind(operation_id)
    .bind(lease_token)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn defer_pam_result(
    pool: &PgPool,
    operation_id: Uuid,
    lease_token: Uuid,
    delay_seconds: i64,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE mix_pam_operations
            SET next_delivery_at=clock_timestamp()+make_interval(secs=>$3),
                lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp()
          WHERE operation_id=$1 AND lease_token=$2 AND delivered_at IS NULL
            AND dead_lettered_at IS NULL",
    )
    .bind(operation_id)
    .bind(lease_token)
    .bind(delay_seconds.clamp(1, 300))
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn retry_pam_result(
    pool: &PgPool,
    operation_id: Uuid,
    lease_token: Uuid,
    attempt_count: i32,
    error: &str,
) -> Result<bool> {
    let next = attempt_count.saturating_add(1);
    if next >= MIX_PAM_RESULT_MAX_ATTEMPTS {
        return Ok(sqlx::query(
            "UPDATE mix_pam_operations
                SET delivery_attempt_count=$3,dead_lettered_at=clock_timestamp(),
                    lease_token=NULL,lease_until=NULL,last_error=left($4,2048),
                    updated_at=clock_timestamp()
              WHERE operation_id=$1 AND lease_token=$2 AND delivered_at IS NULL
                AND dead_lettered_at IS NULL",
        )
        .bind(operation_id)
        .bind(lease_token)
        .bind(next)
        .bind(error)
        .execute(pool)
        .await?
        .rows_affected()
            == 1);
    }
    let delay = 1_i64 << u32::try_from(next.clamp(0, 8)).unwrap_or(8);
    Ok(sqlx::query(
        "UPDATE mix_pam_operations
            SET delivery_attempt_count=$3,
                next_delivery_at=clock_timestamp()+make_interval(secs=>$4),
                lease_token=NULL,lease_until=NULL,last_error=left($5,2048),
                updated_at=clock_timestamp()
          WHERE operation_id=$1 AND lease_token=$2 AND delivered_at IS NULL
            AND dead_lettered_at IS NULL",
    )
    .bind(operation_id)
    .bind(lease_token)
    .bind(next)
    .bind(delay)
    .bind(error)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn prune_expired_pam_results(pool: &PgPool, limit: i64) -> Result<u64> {
    // A reconciliation row is still the only correlation authority for a
    // late authenticated remote result. It may stop automatic client
    // delivery at its retention deadline, but must not be deleted merely
    // because its timeout response was delivered or dead-lettered.
    let mut transaction = pool.begin().await?;
    // The owner-held capability takes the singleton before selecting/deleting
    // any operation. The service gate is held before PgPool checkout, so one
    // process contributes at most one database waiter.
    let removed: i64 = sqlx::query_scalar("SELECT northstar_mix_pam_operation_prune($1)")
        .bind(limit.clamp(1, 2_048))
        .fetch_one(&mut *transaction)
        .await?;
    transaction.commit().await?;
    u64::try_from(removed).context("negative MIX-PAM prune count")
}

#[cfg(test)]
#[path = "mix_pam_durability_tests.rs"]
mod pam_durability_integration_tests;

#[cfg(test)]
#[path = "mix_delivery_capacity_tests.rs"]
mod delivery_capacity_integration_tests;

#[cfg(test)]
#[path = "mix_sequence_retention_tests.rs"]
mod delivery_sequence_retention_integration_tests;

#[cfg(test)]
#[path = "mix_delivery_route_wake_tests.rs"]
mod delivery_route_wake_integration_tests;

#[cfg(test)]
#[path = "mix_nickname_tests.rs"]
mod nickname_tests;

#[cfg(test)]
#[path = "mix_delivery_order_contract_tests.rs"]
mod delivery_order_contract_tests;

#[cfg(test)]
#[path = "mix_mam_tests.rs"]
mod mam_integration_tests;
