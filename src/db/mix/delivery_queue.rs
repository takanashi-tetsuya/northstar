//! MIX delivery queue: enqueue, removal, dead-letter moves, retention, claims and acknowledgements.

use super::*;

pub(super) struct MixDeliveryProjection<'a> {
    pub(super) channel: &'a MixChannel,
    pub(super) event_id: Uuid,
    pub(super) recipients: &'a [MixParticipant],
    pub(super) stanza_template: &'a str,
    pub(super) authoritative_stanza_id: Option<Uuid>,
    pub(super) archive: bool,
    pub(super) encrypted: bool,
}

pub(super) async fn enqueue_mix_deliveries_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MixDeliveryAdmissionFence,
    projection: MixDeliveryProjection<'_>,
) -> Result<()> {
    enqueue_mix_deliveries_tx_with_facts(transaction, fence, projection).await?;
    Ok(())
}

pub(super) async fn enqueue_mix_deliveries_tx_with_facts(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MixDeliveryAdmissionFence,
    projection: MixDeliveryProjection<'_>,
) -> Result<Option<northstar_room_core::mix::DeliveryProjection>> {
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
        return Ok(None);
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
    let delivery_ids = projected_recipients
        .iter()
        .map(|(id, recipient)| (recipient.jid.as_str(), *id))
        .collect::<BTreeMap<_, _>>();
    let recipients = recipients
        .iter()
        .map(|recipient| northstar_room_core::mix::RecipientProjection {
            participant: recipient.clone(),
            delivery_id: delivery_ids[recipient.jid.as_str()],
            sequence: sequences[&recipient.jid],
        })
        .collect();
    Ok(Some(northstar_room_core::mix::DeliveryProjection {
        event_id,
        channel_id: channel.id,
        channel_jid: channel.jid(),
        stanza_template: stanza_template.to_owned(),
        authoritative_stanza_id,
        archive,
        encrypted,
        recipients,
    }))
}

pub(super) async fn remove_mix_delivery_tx(
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

pub(super) async fn move_mix_delivery_to_dead_letter_tx(
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

pub(super) async fn dead_letter_expired_mix_deliveries(pool: &PgPool, limit: i64) -> Result<()> {
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

pub(super) async fn prune_empty_mix_delivery_sequences(pool: &PgPool, limit: i64) -> Result<()> {
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
    match claim_mix_deliveries_inner(pool, limit, max_bytes, None).await? {
        MixClaimReturn::Compatibility(rows) => Ok(rows),
        MixClaimReturn::Observed(_) => {
            anyhow::bail!("MIX compatibility claim returned an observed batch")
        }
    }
}

pub async fn claim_mix_deliveries_observed(
    pool: &PgPool,
    request: &northstar_delivery_core::mix_outbox::ClaimRequest,
) -> Result<northstar_delivery_core::mix_outbox::Rows> {
    let command = request.command();
    match claim_mix_deliveries_inner(pool, command.limit, command.max_bytes, Some(request)).await? {
        MixClaimReturn::Observed(rows) => Ok(rows),
        MixClaimReturn::Compatibility(_) => {
            anyhow::bail!("MIX observed claim returned a compatibility batch")
        }
    }
}

pub(super) enum MixClaimReturn {
    Compatibility(Vec<ClaimedMixDelivery>),
    Observed(northstar_delivery_core::mix_outbox::Rows),
}

pub(super) async fn claim_mix_deliveries_inner(
    pool: &PgPool,
    limit: i64,
    max_bytes: i64,
    observation: Option<&northstar_delivery_core::mix_outbox::ClaimRequest>,
) -> Result<MixClaimReturn> {
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
        return if let Some(request) = observation {
            request.read_empty()?;
            Ok(MixClaimReturn::Observed(Vec::new().into()))
        } else {
            Ok(MixClaimReturn::Compatibility(Vec::new()))
        };
    }
    let entered = observation
        .map(|request| request.enter_statement())
        .transpose()?;
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
    let deliveries: Vec<_> = rows
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
        .collect();
    if let Some(request) = observation {
        let rows: northstar_delivery_core::mix_outbox::Rows = deliveries
            .into_iter()
            .map(|delivery| {
                std::sync::Arc::new(northstar_delivery_core::mix_outbox::Row {
                    source: crate::xmpp::outbound::MixDelivery {
                        delivery_id: delivery.delivery_id,
                        lease_token: delivery.lease_token,
                    },
                    event_id: delivery.event_id,
                    channel_id: delivery.channel_id,
                    channel_jid: delivery.channel_jid,
                    participant_id: delivery.recipient.participant_id,
                    recipient_jid: delivery.recipient.jid,
                    recipient_nick: delivery.recipient.nick,
                    stanza: delivery.stanza,
                    authoritative_stanza_id: delivery.authoritative_stanza_id,
                    archive: delivery.archive,
                    encrypted: delivery.encrypted,
                    attempt_count: delivery.attempt_count,
                    route_wake_generation: delivery.route_wake_generation,
                })
            })
            .collect::<Vec<_>>()
            .into();
        request.received(
            entered.expect("observed claim entered its mutating statement"),
            rows.clone(),
        )?;
        Ok(MixClaimReturn::Observed(rows))
    } else {
        Ok(MixClaimReturn::Compatibility(deliveries))
    }
}

/// Worker settlement is distinct from the native writer's ACK request. Both
/// use the same exact-token deletion helper and preserve the false COMMIT.
pub async fn acknowledge_mix_delivery_worker_observed(
    pool: &PgPool,
    request: &northstar_delivery_core::mix_outbox::SettlementRequest,
) -> Result<bool> {
    let source = request.source();
    let mut transaction = pool.begin().await?;
    let removed = remove_mix_delivery_tx(&mut transaction, source.delivery_id, source.lease_token)
        .await?
        .is_some();
    northstar_delivery_core::mix_outbox::settlement_commit_observed(
        transaction.commit(),
        request,
        northstar_delivery_core::mix_outbox::SettlementResult::Ack(removed),
    )
    .await
    .map_err(crate::services::mix::outbox::commit_error)?;
    if !removed {
        MIX_DELIVERY_LEASE_LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    Ok(removed)
}

pub async fn acknowledge_mix_delivery(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
) -> Result<bool> {
    acknowledge_mix_delivery_observed(pool, delivery_id, lease_token, None).await
}

pub(crate) async fn acknowledge_mix_delivery_observed(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
    observation: Option<&northstar_delivery_core::native_write::AckRequest>,
) -> Result<bool> {
    use northstar_delivery_core::native_write::{commit_observed, AckDisposition};
    if let Some(observation) = observation {
        observation.validate_source(crate::xmpp::outbound::TransportOwnershipSource::Mix(
            crate::xmpp::outbound::MixDelivery {
                delivery_id,
                lease_token,
            },
        ))?;
    }
    let mut transaction = pool.begin().await?;
    let removed = remove_mix_delivery_tx(&mut transaction, delivery_id, lease_token)
        .await?
        .is_some();
    if let Some(observation) = observation {
        commit_observed(
            transaction.commit(),
            observation,
            if removed {
                AckDisposition::Deleted
            } else {
                AckDisposition::NoMatchingMix
            },
        )
        .await?;
    } else {
        transaction.commit().await?;
    }
    if !removed {
        MIX_DELIVERY_LEASE_LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    Ok(removed)
}
