//! MIX participants: lookup, presence recovery and expiry, subscriptions, nicks and leave.

use super::*;

mod membership;
mod recovery;

pub use self::membership::{leave_mix_channel, set_mix_nick, update_mix_subscriptions};
pub use self::recovery::{expire_unrefreshed_mix_presence, prepare_mix_presence_after_restart};

pub async fn mix_participant<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    channel_id: Uuid,
    jid: &str,
) -> Result<Option<MixParticipant>> {
    let jid = canonical_user_bare(jid)?;
    let row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2",
    )
    .bind(channel_id)
    .bind(jid)
    .fetch_optional(executor)
    .await?;
    Ok(row.as_ref().map(participant_from_row))
}

pub async fn mix_participant_by_id<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    channel_id: Uuid,
    participant_id: Uuid,
) -> Result<Option<MixParticipant>> {
    let row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND participant_id = $2",
    )
    .bind(channel_id)
    .bind(participant_id)
    .fetch_optional(executor)
    .await?;
    Ok(row.as_ref().map(participant_from_row))
}

pub async fn mix_presence_source_jid<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    channel_id: Uuid,
    item_id: &str,
) -> Result<Option<String>> {
    let item_id = northstar_xmpp_types::jid::CanonicalJid::parse(item_id)?.to_string();
    sqlx::query_scalar(
        "SELECT source_full_jid FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3 AND source_full_jid IS NOT NULL",
    )
    .bind(channel_id)
    .bind(NODE_PRESENCE)
    .bind(item_id)
    .fetch_optional(executor)
    .await
    .map_err(Into::into)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetNickError {
    NotParticipant,
    Conflict,
}
