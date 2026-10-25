//! Persists and validates SM snapshots and unacknowledged queues with exact durable source ownership.

use super::*;

/// Remove only the named MUC memberships from one exact live SM owner.  This
/// narrow reconciliation primitive is used after a post-replay local ABA
/// check: filtering the current JSON value in PostgreSQL preserves any newer
/// acknowledgement, outbound queue update, or MUC join committed by the same
/// transport while the post-action task was scheduled.
pub async fn remove_live_sm_muc_memberships(
    pool: &PgPool,
    id: Uuid,
    connection_id: Uuid,
    memberships: &[SmMucMembership],
) -> Result<bool> {
    if memberships.is_empty() {
        return Ok(true);
    }
    anyhow::ensure!(memberships.len() <= 256, "too many SM MUC memberships");
    let mut canonical = Vec::with_capacity(memberships.len());
    let mut rooms = std::collections::BTreeSet::new();
    for membership in memberships {
        let room_jid = northstar_xmpp_types::jid::canonicalize_bare(&membership.room_jid)?;
        let nick = crate::services::xml_util::prepare_muc_nick(&membership.nick)?;
        anyhow::ensure!(
            rooms.insert((room_jid.clone(), nick.clone())),
            "duplicate SM MUC membership"
        );
        canonical.push(SmMucMembership { room_jid, nick });
    }
    let removals = serde_json::to_value(canonical)?;
    Ok(
        sqlx::query_scalar("SELECT northstar_sm_remove_memberships($1,$2,$3)")
            .bind(id)
            .bind(connection_id)
            .bind(removals)
            .fetch_one(pool)
            .await?,
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn checkpoint_sm_session_and_acknowledge_with_ownership_resolution(
    pool: &PgPool,
    id: Uuid,
    connection_id: Uuid,
    snapshot: &SmSessionSnapshot,
    acknowledged: &[outbound::SmUnackedStanza],
    ttl_seconds: u64,
    live_lease_seconds: u64,
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<SmCheckpointOutcome> {
    checkpoint_sm_session_and_acknowledge_observed(
        pool,
        id,
        connection_id,
        snapshot,
        acknowledged,
        ttl_seconds,
        live_lease_seconds,
        max_stanzas,
        max_bytes,
        None,
    )
    .await
}

pub async fn append_suspended_sm_stanza(
    pool: &PgPool,
    id: Uuid,
    volatile_source_id: Uuid,
    stanza: &str,
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<bool> {
    if volatile_source_id.is_nil() || stanza.is_empty() || stanza.len() > 1024 * 1024 {
        return Ok(false);
    }
    let mut transaction = pool.begin().await?;
    let locked: Option<i64> = sqlx::query_scalar("SELECT northstar_sm_lock_suspended($1)")
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(outbound) = locked else {
        transaction.rollback().await?;
        return Ok(false);
    };
    let already_stored: Option<String> = sqlx::query_scalar(
        "SELECT stanza FROM sm_resume_stanzas
          WHERE session_id=$1 AND volatile_source_id=$2",
    )
    .bind(id)
    .bind(volatile_source_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(already_stored) = already_stored {
        let identical = already_stored == stanza;
        transaction.rollback().await?;
        return Ok(identical);
    }
    let (count, bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(byte_count), 0) FROM sm_resume_stanzas WHERE session_id=$1",
    )
    .bind(id)
    .fetch_one(&mut *transaction)
    .await?;
    if count >= i64::try_from(max_stanzas).unwrap_or(i64::MAX)
        || bytes.saturating_add(i64::try_from(stanza.len()).unwrap_or(i64::MAX))
            > i64::try_from(max_bytes).unwrap_or(i64::MAX)
    {
        transaction.rollback().await?;
        return Ok(false);
    }
    let position: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(position), -1) + 1 FROM sm_resume_stanzas WHERE session_id=$1",
    )
    .bind(id)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO sm_resume_stanzas(
             session_id,position,stanza,volatile_source_id
         ) VALUES($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(position)
    .bind(stanza)
    .bind(volatile_source_id)
    .execute(&mut *transaction)
    .await?;
    let outbound = u32::try_from(outbound).context("invalid suspended SM outbound counter")?;
    let advanced: bool = sqlx::query_scalar("SELECT northstar_sm_advance_suspended($1,$2,$3)")
        .bind(id)
        .bind(i64::from(outbound))
        .bind(i64::from(outbound.wrapping_add(1)))
        .fetch_one(&mut *transaction)
        .await?;
    anyhow::ensure!(
        advanced,
        "suspended SM authority changed while appending stanza"
    );
    transaction.commit().await?;
    Ok(true)
}

pub(super) async fn update_snapshot(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    connection_id: Uuid,
    snapshot: &SmSessionSnapshot,
    ttl: i64,
    live_lease: i64,
    suspend: bool,
) -> Result<bool> {
    let (joined_rooms, directed_presence) = canonical_snapshot_identities(snapshot)?;
    Ok(sqlx::query_scalar(
        "SELECT northstar_sm_update_snapshot(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::inet,$14,$15,$16,
            $17,$18,$19,$20)",
    )
    .bind(id)
    .bind(connection_id)
    .bind(i64::from(snapshot.inbound_h))
    .bind(i64::from(snapshot.outbound_h))
    .bind(i64::from(snapshot.acked_h))
    .bind(snapshot.available)
    .bind(snapshot.carbons)
    .bind(snapshot.priority)
    .bind(snapshot.blocklist_requested)
    .bind(snapshot.roster_requested)
    .bind(&snapshot.active_privacy_list)
    .bind(snapshot.privacy_requested)
    .bind(snapshot.peer_ip.to_string())
    .bind(snapshot.user_agent_id)
    .bind(joined_rooms)
    .bind(directed_presence)
    .bind(&snapshot.last_presence)
    .bind(suspend)
    .bind(live_lease)
    .bind(ttl)
    .fetch_one(&mut **transaction)
    .await?)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum SmDurableSourceKey {
    // `offline_messages.id` is globally primary-keyed.  Keying the queue by
    // that value also makes a malformed duplicate which names the same row
    // with a different recipient fail before any acknowledgement can commit.
    C2s(Uuid),
    Mix(Uuid),
}

pub(super) fn durable_source_key(source: outbound::TransportOwnershipSource) -> SmDurableSourceKey {
    match source {
        outbound::TransportOwnershipSource::C2s(delivery) => {
            SmDurableSourceKey::C2s(delivery.message_id)
        }
        outbound::TransportOwnershipSource::Mix(delivery) => {
            SmDurableSourceKey::Mix(delivery.delivery_id)
        }
    }
}

pub(super) fn durable_source_from_columns(
    recipient_id: Option<Uuid>,
    message_id: Option<Uuid>,
    claim_id: Option<Uuid>,
    mix_delivery_id: Option<Uuid>,
    mix_delivery_lease_token: Option<Uuid>,
) -> Result<Option<outbound::TransportOwnershipSource>> {
    match (
        (recipient_id, message_id, claim_id),
        (mix_delivery_id, mix_delivery_lease_token),
    ) {
        ((None, None, None), (None, None)) => Ok(None),
        ((Some(recipient_id), Some(message_id), claim_id), (None, None)) => Ok(Some(
            outbound::TransportOwnershipSource::C2s(outbound::DurableDelivery {
                recipient_id,
                message_id,
                claim_id,
            }),
        )),
        ((None, None, None), (Some(delivery_id), Some(lease_token))) => Ok(Some(
            outbound::TransportOwnershipSource::Mix(outbound::MixDelivery {
                delivery_id,
                lease_token,
            }),
        )),
        _ => anyhow::bail!("invalid mutually-exclusive durable source shape in SM queue"),
    }
}

pub(super) fn source_map(
    entries: &[outbound::SmUnackedStanza],
    context: &str,
) -> Result<HashMap<SmDurableSourceKey, outbound::TransportOwnershipSource>> {
    let mut sources = HashMap::new();
    for entry in entries {
        let Some(source) = entry.source else {
            continue;
        };
        anyhow::ensure!(
            sources.insert(durable_source_key(source), source).is_none(),
            "duplicate durable source in {context}"
        );
    }
    Ok(sources)
}

pub(super) async fn lock_new_c2s_source_for_sm_transfer(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    delivery: outbound::DurableDelivery,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT delivery_claim_id FROM offline_messages
          WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(delivery.recipient_id)
    .bind(delivery.message_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Err(outbound::DurableDeliverySuperseded {
            message_id: delivery.message_id,
        }
        .into());
    };
    let stored_claim: Option<Uuid> = row.try_get("delivery_claim_id")?;
    if stored_claim != delivery.claim_id {
        return Err(outbound::DurableDeliverySuperseded {
            message_id: delivery.message_id,
        }
        .into());
    }
    let bosh_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM bosh_delivery_fences WHERE message_id=$1
         )",
    )
    .bind(delivery.message_id)
    .fetch_one(&mut **transaction)
    .await?;
    if bosh_owned {
        return Err(outbound::DurableDeliverySuperseded {
            message_id: delivery.message_id,
        }
        .into());
    }
    let sm_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM sm_resume_stanzas WHERE delivery_message_id=$1
         )",
    )
    .bind(delivery.message_id)
    .fetch_one(&mut **transaction)
    .await?;
    if sm_owned {
        return Err(outbound::DurableDeliverySuperseded {
            message_id: delivery.message_id,
        }
        .into());
    }
    sqlx::query(
        "UPDATE offline_messages
            SET delivery_claim_id=NULL,delivery_claim_expires_at=NULL
          WHERE recipient_id=$1 AND id=$2",
    )
    .bind(delivery.recipient_id)
    .bind(delivery.message_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(super) async fn lock_mix_bosh_fence_for_sm_transfer(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    delivery_id: Uuid,
) -> Result<()> {
    let fence = sqlx::query(
        "SELECT lease_token,expires_at>clock_timestamp() AS active
           FROM mix_bosh_delivery_fences
          WHERE delivery_id=$1 FOR UPDATE",
    )
    .bind(delivery_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(fence) = fence else {
        return Ok(());
    };
    let active: bool = fence.try_get("active")?;
    anyhow::ensure!(
        !active,
        "MIX delivery is already owned by an active BOSH response"
    );
    let lease_token: Uuid = fence.try_get("lease_token")?;
    let removed = sqlx::query(
        "DELETE FROM mix_bosh_delivery_fences
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(delivery_id)
    .bind(lease_token)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        removed == 1,
        "expired MIX BOSH fence changed during SM ownership transfer"
    );
    Ok(())
}

pub(super) async fn delete_completed_mix_source_from_sm(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    delivery: outbound::MixDelivery,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT lease_token FROM mix_delivery_recipients
          WHERE delivery_id=$1 FOR UPDATE",
    )
    .bind(delivery.delivery_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        anyhow::bail!("SM acknowledged MIX delivery row was not present");
    };
    anyhow::ensure!(
        row.try_get::<Option<Uuid>, _>("lease_token")? == Some(delivery.lease_token),
        "SM acknowledgement lost the exact MIX delivery lease"
    );
    lock_mix_bosh_fence_for_sm_transfer(transaction, delivery.delivery_id).await?;
    let sm_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM sm_resume_stanzas WHERE mix_delivery_id=$1
         )",
    )
    .bind(delivery.delivery_id)
    .fetch_one(&mut **transaction)
    .await?;
    anyhow::ensure!(
        !sm_owned,
        "SM acknowledgement would consume a MIX source owned by another queue"
    );
    let removed = sqlx::query(
        "DELETE FROM mix_delivery_recipients
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(delivery.delivery_id)
    .bind(delivery.lease_token)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        removed == 1,
        "SM acknowledged MIX delivery lease changed before deletion"
    );
    Ok(())
}

/// Atomically acknowledge the exact source set which crossed a non-resumable
/// transport boundary.
///
/// XEP-0198 persistence uses [`replace_queue`] instead: it first transfers a
/// source into its queue and later consumes it together with the matching
/// client acknowledgement.  This function is deliberately for the opposite
/// boundary only, where bytes were written without an SM owner.  Validate
/// every capability before deleting any projection, so a later stale MIX
/// lease cannot partially consume an earlier C2S prefix.
pub async fn acknowledge_transport_sources(
    pool: &PgPool,
    sources: &[outbound::TransportOwnershipSource],
) -> Result<()> {
    acknowledge_transport_sources_observed(pool, sources, None).await
}

pub(super) async fn replace_queue(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    queue: &[outbound::SmUnackedStanza],
    acknowledged: &[outbound::SmUnackedStanza],
) -> Result<SmQueueOwnershipResolution> {
    replace_queue_inner(transaction, id, queue, acknowledged, None).await
}

pub(super) async fn replace_queue_inner(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    queue: &[outbound::SmUnackedStanza],
    acknowledged: &[outbound::SmUnackedStanza],
    mut settled: Option<&mut Vec<outbound::TransportOwnershipSource>>,
) -> Result<SmQueueOwnershipResolution> {
    // First lock the current SM queue.  All later source locks are ordered
    // C2S offline rows, then MIX recipient rows, then their BOSH fence rows.
    // Every queue replacement follows this order, so a mixed snapshot cannot
    // create a C2S/MIX inversion while preserving XEP-0198 FIFO semantics.
    let existing_rows = sqlx::query(
        "SELECT delivery_recipient_id,delivery_message_id,delivery_claim_id,
                mix_delivery_id,mix_delivery_lease_token
           FROM sm_resume_stanzas
          WHERE session_id=$1
            AND (delivery_message_id IS NOT NULL OR mix_delivery_id IS NOT NULL)
          FOR UPDATE",
    )
    .bind(id)
    .fetch_all(&mut **transaction)
    .await?;
    let mut existing = HashMap::new();
    for row in existing_rows {
        let source = durable_source_from_columns(
            row.try_get("delivery_recipient_id")?,
            row.try_get("delivery_message_id")?,
            row.try_get("delivery_claim_id")?,
            row.try_get("mix_delivery_id")?,
            row.try_get("mix_delivery_lease_token")?,
        )?
        .context("persisted SM durable row has no source")?;
        anyhow::ensure!(
            existing
                .insert(durable_source_key(source), source)
                .is_none(),
            "duplicate durable source in persisted SM queue"
        );
    }

    let mut next = source_map(queue, "SM snapshot")?;
    let completed = source_map(acknowledged, "SM acknowledgement")?;
    anyhow::ensure!(
        completed
            .iter()
            .all(|(key, completed)| { existing.get(key).is_some_and(|owned| owned == completed) }),
        "SM acknowledgement does not own the durable source fence"
    );
    anyhow::ensure!(
        next.iter()
            .all(|(key, source)| { existing.get(key).is_none_or(|owned| owned == source) }),
        "SM snapshot changed an existing durable source fence"
    );
    anyhow::ensure!(
        existing
            .keys()
            .all(|key| { next.contains_key(key) || completed.contains_key(key) }),
        "SM snapshot attempted to drop a durable source without client acknowledgement"
    );
    anyhow::ensure!(
        completed.keys().all(|key| !next.contains_key(key)),
        "SM acknowledgement retained the same durable source"
    );

    let mut new_c2s = next
        .values()
        .filter_map(|source| match *source {
            outbound::TransportOwnershipSource::C2s(delivery)
                if !existing.contains_key(&durable_source_key(*source)) =>
            {
                Some(delivery)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    new_c2s.sort_unstable_by_key(|delivery| (delivery.recipient_id, delivery.message_id));
    for delivery in new_c2s {
        lock_new_c2s_source_for_sm_transfer(transaction, delivery).await?;
    }

    let mut new_mix = next
        .values()
        .filter_map(|source| match *source {
            outbound::TransportOwnershipSource::Mix(delivery)
                if !existing.contains_key(&durable_source_key(*source)) =>
            {
                Some(delivery)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    new_mix.sort_unstable_by_key(|delivery| delivery.delivery_id);
    let mut ownership = SmQueueOwnershipResolution::default();
    for previous in new_mix {
        let current = rotate_new_mix_source_for_sm_transfer(transaction, previous).await?;
        let key = durable_source_key(outbound::TransportOwnershipSource::Mix(previous));
        let replaced = next.insert(key, outbound::TransportOwnershipSource::Mix(current));
        anyhow::ensure!(
            replaced == Some(outbound::TransportOwnershipSource::Mix(previous)),
            "MIX source changed while rotating into SM ownership"
        );
        ownership
            .mix_rotations
            .push(SmMixLeaseRotation { previous, current });
    }

    sqlx::query("DELETE FROM sm_resume_stanzas WHERE session_id=$1")
        .bind(id)
        .execute(&mut **transaction)
        .await?;
    for (position, entry) in queue.iter().enumerate() {
        let source = entry
            .source
            .map(|source| {
                next.get(&durable_source_key(source))
                    .copied()
                    .context("SM snapshot source disappeared during replacement")
            })
            .transpose()?;
        let c2s = source.and_then(outbound::TransportOwnershipSource::c2s);
        let mix = source.and_then(outbound::TransportOwnershipSource::mix);
        sqlx::query(
            "INSERT INTO sm_resume_stanzas(
                session_id,position,stanza,delivery_recipient_id,
                delivery_message_id,delivery_claim_id,
                mix_delivery_id,mix_delivery_lease_token
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(id)
        .bind(i32::try_from(position).context("SM queue position overflow")?)
        .bind(&entry.stanza)
        .bind(c2s.map(|delivery| delivery.recipient_id))
        .bind(c2s.map(|delivery| delivery.message_id))
        .bind(c2s.and_then(|delivery| delivery.claim_id))
        .bind(mix.map(|delivery| delivery.delivery_id))
        .bind(mix.map(|delivery| delivery.lease_token))
        .execute(&mut **transaction)
        .await?;
    }
    let mut completed_c2s = completed
        .values()
        .filter_map(|source| source.c2s())
        .collect::<Vec<_>>();
    completed_c2s.sort_unstable_by_key(|delivery| (delivery.recipient_id, delivery.message_id));
    for delivery in completed_c2s {
        let deleted = sqlx::query("DELETE FROM offline_messages WHERE recipient_id=$1 AND id=$2")
            .bind(delivery.recipient_id)
            .bind(delivery.message_id)
            .execute(&mut **transaction)
            .await?
            .rows_affected();
        anyhow::ensure!(
            deleted == 1,
            "SM acknowledged durable delivery row was not present"
        );
        if let Some(settled) = settled.as_deref_mut() {
            settled.push(outbound::TransportOwnershipSource::C2s(delivery));
        }
    }
    let mut completed_mix = completed
        .values()
        .filter_map(|source| source.mix())
        .collect::<Vec<_>>();
    completed_mix.sort_unstable_by_key(|delivery| delivery.delivery_id);
    for delivery in completed_mix {
        delete_completed_mix_source_from_sm(transaction, delivery).await?;
        if let Some(settled) = settled.as_deref_mut() {
            settled.push(outbound::TransportOwnershipSource::Mix(delivery));
        }
    }
    Ok(ownership)
}

pub(super) async fn fetch_queue(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
) -> Result<Vec<outbound::SmUnackedStanza>> {
    sqlx::query(
        "SELECT stanza,delivery_recipient_id,delivery_message_id,delivery_claim_id,
                mix_delivery_id,mix_delivery_lease_token
           FROM sm_resume_stanzas WHERE session_id=$1 ORDER BY position",
    )
    .bind(id)
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        let stanza: String = row.try_get("stanza")?;
        let source = durable_source_from_columns(
            row.try_get("delivery_recipient_id")?,
            row.try_get("delivery_message_id")?,
            row.try_get("delivery_claim_id")?,
            row.try_get("mix_delivery_id")?,
            row.try_get("mix_delivery_lease_token")?,
        )?;
        Ok(outbound::SmUnackedStanza::with_source(stanza, source))
    })
    .collect()
}

pub(super) fn validate_snapshot(
    snapshot: &SmSessionSnapshot,
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<()> {
    if snapshot.joined_rooms.len() > 256 {
        anyhow::bail!("SM MUC membership snapshot is too large");
    }
    if snapshot.joined_rooms.iter().any(|membership| {
        northstar_xmpp_types::jid::CanonicalJid::parse_bare(&membership.room_jid).is_err()
            || crate::services::xml_util::prepare_muc_nick(&membership.nick).is_err()
    }) {
        anyhow::bail!("SM MUC membership snapshot is invalid");
    }
    if snapshot.directed_presence.len() > 1_024
        || snapshot.directed_presence.iter().any(|jid| {
            jid.len() > 3_071 || northstar_xmpp_types::jid::CanonicalJid::parse(jid).is_err()
        })
    {
        anyhow::bail!("SM directed-presence snapshot is invalid or too large");
    }
    if snapshot.last_presence.as_ref().is_some_and(|presence| {
        presence.is_empty()
            || presence.len() > 1_048_576
            || roxmltree::Document::parse(presence).is_err()
    }) {
        anyhow::bail!("SM last-presence snapshot is invalid or too large");
    }
    validate_queue(&snapshot.unacked, max_stanzas, max_bytes)
}

pub(super) fn canonical_snapshot_identities(
    snapshot: &SmSessionSnapshot,
) -> Result<(serde_json::Value, serde_json::Value)> {
    let mut rooms = std::collections::BTreeSet::new();
    let mut joined_rooms = Vec::with_capacity(snapshot.joined_rooms.len());
    for membership in &snapshot.joined_rooms {
        let room_jid = northstar_xmpp_types::jid::canonicalize_bare(&membership.room_jid)?;
        anyhow::ensure!(
            northstar_xmpp_types::jid::CanonicalJid::parse_bare(&room_jid)?
                .localpart()
                .is_some(),
            "SM MUC room must contain a localpart"
        );
        anyhow::ensure!(
            rooms.insert(room_jid.clone()),
            "duplicate canonical SM MUC room"
        );
        joined_rooms.push(SmMucMembership {
            room_jid,
            nick: membership.nick.clone(),
        });
    }
    let mut directed_keys = std::collections::BTreeSet::new();
    let mut directed_presence = Vec::with_capacity(snapshot.directed_presence.len());
    for target in &snapshot.directed_presence {
        let target = northstar_xmpp_types::jid::canonicalize(target)?;
        anyhow::ensure!(
            directed_keys.insert(target.clone()),
            "duplicate canonical SM directed-presence target"
        );
        directed_presence.push(target);
    }
    Ok((
        serde_json::to_value(joined_rooms)?,
        serde_json::to_value(directed_presence)?,
    ))
}

pub(super) fn validate_queue(
    queue: &[outbound::SmUnackedStanza],
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<()> {
    if queue.len() > max_stanzas {
        anyhow::bail!("SM unacknowledged stanza limit exceeded");
    }
    let bytes = queue
        .iter()
        .try_fold(0usize, |total, entry| total.checked_add(entry.stanza.len()))
        .context("SM unacknowledged byte count overflow")?;
    if bytes > max_bytes
        || queue
            .iter()
            .any(|entry| entry.stanza.is_empty() || entry.stanza.len() > 1024 * 1024)
    {
        anyhow::bail!("SM unacknowledged byte limit exceeded");
    }
    Ok(())
}
