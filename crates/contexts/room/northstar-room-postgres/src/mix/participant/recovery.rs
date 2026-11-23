use super::*;
use northstar_room_application::mix_service::{
    RecoveryEpoch, RecoveryEpochAndTargets, RecoveryProbeTarget, RecoveryProgress,
    RECOVERY_PRESENCE_PAGE_CAP,
};
use northstar_room_core::mix::{MixChannelAddress, MixRealJid};

/// Snapshot every current presence item before process recovery. No row is
/// eagerly deleted by domain: in a clustered deployment another node may
/// still own a local-domain resource. The supervised recovery worker refreshes
/// live local sessions, probes remote actors, then atomically expires and
/// publishes unavailable for only rows older than the returned cutoff.
pub(crate) async fn prepare_recovery(pool: &PgPool) -> Result<RecoveryEpochAndTargets> {
    let rows = sqlx::query(
        "WITH epoch AS MATERIALIZED (SELECT clock_timestamp() AS cutoff)
         SELECT epoch.cutoff, targets.channel_jid, targets.participant_jid
           FROM epoch LEFT JOIN (
               SELECT DISTINCT c.localpart || '@' || c.service_domain AS channel_jid,
                               p.jid AS participant_jid
                 FROM mix_events e
                 JOIN mix_channels c ON c.id=e.channel_id
                 JOIN mix_participants p
                   ON p.channel_id=e.channel_id AND p.participant_id=e.publisher_id
                WHERE e.node=$1
           ) targets ON true ORDER BY targets.channel_jid,targets.participant_jid",
    )
    .bind(NODE_PRESENCE)
    .fetch_all(pool)
    .await?;
    let epoch = RecoveryEpoch {
        cutoff: rows
            .first()
            .context("MIX recovery cutoff not returned")?
            .get("cutoff"),
    };
    let mut targets = Vec::new();
    for row in rows {
        let Some(channel) = row.get::<Option<String>, _>("channel_jid") else {
            continue;
        };
        let participant: String = row.get("participant_jid");
        match (
            MixChannelAddress::parse(&channel),
            MixRealJid::parse(&participant),
        ) {
            (Ok(channel), Ok(participant)) => {
                targets.push(RecoveryProbeTarget {
                    channel,
                    participant,
                });
            }
            _ => {
                tracing::warn!(%channel, %participant, "ignored malformed persisted MIX recovery target")
            }
        }
    }
    Ok(RecoveryEpochAndTargets { epoch, targets })
}

pub async fn expire_unrefreshed_mix_presence(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<Vec<ExpiredMixPresence>> {
    let (expired, _) = expire_presence_page(
        pool,
        RecoveryEpoch { cutoff },
        RECOVERY_PRESENCE_PAGE_CAP,
        payloads,
    )
    .await?;
    Ok(expired)
}

pub(crate) async fn expire_recovery_presence_page(
    pool: &PgPool,
    epoch: RecoveryEpoch,
    budget: u32,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<RecoveryProgress> {
    let (_, progress) = expire_presence_page(pool, epoch, budget, payloads).await?;
    Ok(progress)
}

async fn expire_presence_page(
    pool: &PgPool,
    epoch: RecoveryEpoch,
    budget: u32,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<(Vec<ExpiredMixPresence>, RecoveryProgress)> {
    anyhow::ensure!(
        budget > 0,
        "MIX presence recovery requires a positive page budget"
    );
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    let rows = sqlx::query(
        "WITH stale AS (
             SELECT e.id FROM mix_events e WHERE e.node = $1 AND e.created_at < $2
              ORDER BY e.created_at, e.id LIMIT $3 FOR UPDATE SKIP LOCKED
         ), deleted AS (
             DELETE FROM mix_events e USING stale WHERE e.id = stale.id
             RETURNING e.channel_id, e.publisher_id, e.item_id, e.payload, e.source_full_jid
         )
         SELECT d.channel_id, d.publisher_id AS participant_id, p.jid, p.nick,
                d.item_id, d.payload, d.source_full_jid
           FROM deleted d LEFT JOIN mix_participants p
             ON p.channel_id = d.channel_id AND p.participant_id = d.publisher_id
          ORDER BY d.channel_id, d.publisher_id, d.item_id",
    )
    .bind(NODE_PRESENCE)
    .bind(epoch.cutoff)
    .bind(i64::from(budget.min(RECOVERY_PRESENCE_PAGE_CAP)))
    .fetch_all(&mut *transaction)
    .await?;
    let expired_count = rows.len();
    let expired = rows
        .into_iter()
        .filter_map(|row| {
            let jid = row.get::<Option<String>, _>("jid")?;
            Some(ExpiredMixPresence {
                channel_id: row.get("channel_id"),
                participant: MixParticipant {
                    participant_id: row.get("participant_id"),
                    jid,
                    nick: row.get("nick"),
                },
                item_id: row.get("item_id"),
                payload: row.get("payload"),
                source_full_jid: row.get("source_full_jid"),
            })
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
    let has_remaining = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_events WHERE node = $1 AND created_at < $2)",
    )
    .bind(NODE_PRESENCE)
    .bind(epoch.cutoff)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((
        expired,
        RecoveryProgress {
            expired: expired_count,
            has_remaining,
        },
    ))
}
