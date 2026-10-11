//! MIX delivery capacity: metrics, ledger audits, the producer admission fence and capacity reservation.

use super::*;

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
pub(super) struct MixDeliveryAdmissionFence(pub(super) ());

/// Proof that orphan reclamation and release-journal folding committed before
/// the producer transaction began. This phase must never share the producer's
/// rollback fate: a capacity rejection cannot resurrect the same false-full
/// ledger state for the next attempt.
pub(super) struct MixDeliveryReconciliationCommitted(pub(super) ());

pub(super) async fn acquire_mix_delivery_admission_fence_tx(
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

pub(super) async fn begin_mix_delivery_fenced_transaction(
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

pub(super) async fn reconcile_mix_delivery_capacity_committed(
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

pub(super) async fn begin_mix_delivery_admission(
    pool: &PgPool,
) -> Result<(Transaction<'_, Postgres>, MixDeliveryAdmissionFence)> {
    let _committed = reconcile_mix_delivery_capacity_committed(pool).await?;
    begin_mix_delivery_fenced_transaction(pool).await
}

pub(super) fn mix_delivery_capacity_bucket(id: Uuid) -> i16 {
    i16::from(id.as_bytes()[0] & 63)
}

pub(super) fn add_mix_delivery_capacity_delta(
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
pub(super) async fn drain_mix_delivery_capacity_releases_tx(
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

pub(super) async fn prune_empty_mix_delivery_events_tx(
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

pub(super) async fn prune_empty_mix_delivery_events(pool: &PgPool, limit: i64) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await?;
    prune_empty_mix_delivery_events_tx(&mut transaction, limit).await?;
    transaction.commit().await?;
    Ok(())
}

pub(super) async fn reserve_mix_delivery_capacity_tx(
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
