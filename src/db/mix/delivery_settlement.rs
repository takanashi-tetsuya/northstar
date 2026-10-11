//! MIX delivery settlement: lease renewal, dead-letter, retry, deferral, recipient wakes and dead-letter requeue.

use super::*;

pub async fn renew_mix_delivery_lease(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
) -> Result<bool> {
    renew_mix_delivery_lease_inner(pool, delivery_id, lease_token, None).await
}

pub async fn renew_mix_delivery_lease_observed(
    pool: &PgPool,
    request: &northstar_delivery_core::mix_outbox::RenewalRequest,
) -> Result<bool> {
    let source = request.source();
    renew_mix_delivery_lease_inner(pool, source.delivery_id, source.lease_token, Some(request))
        .await
}

pub(super) async fn renew_mix_delivery_lease_inner(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
    observation: Option<&northstar_delivery_core::mix_outbox::RenewalRequest>,
) -> Result<bool> {
    let entered = observation
        .map(|request| request.enter_statement())
        .transpose()?;
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
    if let Some(request) = observation {
        request.received(
            entered.expect("observed renewal entered its statement"),
            renewed,
        )?;
    }
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
    dead_letter_mix_delivery_inner(pool, delivery_id, lease_token, terminal_reason, error, None)
        .await
}

pub async fn dead_letter_mix_delivery_worker_observed(
    pool: &PgPool,
    request: &northstar_delivery_core::mix_outbox::SettlementRequest,
) -> Result<bool> {
    let northstar_delivery_core::mix_outbox::SettlementCommand::DeadLetter { reason, error } =
        request.command()
    else {
        anyhow::bail!("MIX dead-letter request kind mismatch");
    };
    let source = request.source();
    dead_letter_mix_delivery_inner(
        pool,
        source.delivery_id,
        source.lease_token,
        reason,
        error,
        Some(request),
    )
    .await
}

pub(super) async fn dead_letter_mix_delivery_inner(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
    terminal_reason: &str,
    error: &str,
    observation: Option<&northstar_delivery_core::mix_outbox::SettlementRequest>,
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
    commit_mix_worker_settlement(
        transaction,
        observation,
        northstar_delivery_core::mix_outbox::SettlementResult::DeadLetter(moved),
    )
    .await?;
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
    retry_mix_delivery_inner(
        pool,
        delivery_id,
        lease_token,
        route_wake_generation,
        error,
        None,
    )
    .await
}

pub async fn retry_mix_delivery_worker_observed(
    pool: &PgPool,
    request: &northstar_delivery_core::mix_outbox::SettlementRequest,
) -> Result<MixDeliveryRetryOutcome> {
    let northstar_delivery_core::mix_outbox::SettlementCommand::Retry { error } = request.command()
    else {
        anyhow::bail!("MIX retry request kind mismatch");
    };
    let source = request.source();
    retry_mix_delivery_inner(
        pool,
        source.delivery_id,
        source.lease_token,
        request.route_wake_generation(),
        error,
        Some(request),
    )
    .await
}

pub(super) async fn retry_mix_delivery_inner(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
    route_wake_generation: i64,
    error: &str,
    observation: Option<&northstar_delivery_core::mix_outbox::SettlementRequest>,
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
        commit_mix_worker_settlement(
            transaction,
            observation,
            northstar_delivery_core::mix_outbox::SettlementResult::Retry(
                MixDeliveryRetryOutcome::LeaseLost,
            ),
        )
        .await?;
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
    commit_mix_worker_settlement(
        transaction,
        observation,
        northstar_delivery_core::mix_outbox::SettlementResult::Retry(outcome),
    )
    .await?;
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
    defer_mix_delivery_inner(
        pool,
        delivery_id,
        lease_token,
        route_wake_generation,
        delay_seconds,
        None,
    )
    .await
}

pub async fn defer_mix_delivery_worker_observed(
    pool: &PgPool,
    request: &northstar_delivery_core::mix_outbox::SettlementRequest,
) -> Result<bool> {
    let northstar_delivery_core::mix_outbox::SettlementCommand::Defer { delay_seconds } =
        request.command()
    else {
        anyhow::bail!("MIX defer request kind mismatch");
    };
    let source = request.source();
    defer_mix_delivery_inner(
        pool,
        source.delivery_id,
        source.lease_token,
        request.route_wake_generation(),
        *delay_seconds,
        Some(request),
    )
    .await
}

pub(super) async fn defer_mix_delivery_inner(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
    route_wake_generation: i64,
    delay_seconds: i64,
    observation: Option<&northstar_delivery_core::mix_outbox::SettlementRequest>,
) -> Result<bool> {
    // `route_wake_generation` is captured atomically with the lease. A
    // verified resource wake updates the same recipient row, so the UPDATE
    // below serializes with it: if the wake committed first we release for an
    // immediate re-claim; if it waits behind this UPDATE it advances the
    // unleased head to `clock_timestamp()` afterwards. Either order retains
    // the route wake across processes without weakening the fallback delay.
    let entered = observation
        .map(|request| request.enter_statement())
        .transpose()?;
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
    if let Some(request) = observation {
        request.received(
            entered.expect("observed defer entered its statement"),
            northstar_delivery_core::mix_outbox::SettlementResult::Defer(updated),
        )?;
    }
    if !updated {
        MIX_DELIVERY_LEASE_LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    Ok(updated)
}

pub(super) async fn commit_mix_worker_settlement(
    transaction: Transaction<'_, Postgres>,
    observation: Option<&northstar_delivery_core::mix_outbox::SettlementRequest>,
    result: northstar_delivery_core::mix_outbox::SettlementResult,
) -> Result<()> {
    if let Some(request) = observation {
        northstar_delivery_core::mix_outbox::settlement_commit_observed(
            transaction.commit(),
            request,
            result,
        )
        .await
        .map_err(crate::services::mix::outbox::commit_error)
    } else {
        transaction.commit().await.map_err(Into::into)
    }
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
