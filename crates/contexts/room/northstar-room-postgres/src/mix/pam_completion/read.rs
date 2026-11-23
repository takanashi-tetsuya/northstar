use super::*;
use northstar_room_application::mix_service::{PamDeliveryAuthority, PamDeliveryQuery};
use northstar_room_core::mix::MixPamState;

pub async fn pam_delivery_view<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    query: PamDeliveryQuery<'_>,
) -> Result<Option<PamDeliveryAuthority>> {
    let recipient = northstar_xmpp_types::jid::CanonicalJid::parse_bare(query.recipient.as_str())?;
    let Some(localpart) = recipient.localpart() else {
        return Ok(None);
    };
    let Ok(username) = northstar_auth_core::normalize_username(localpart) else {
        return Ok(None);
    };
    let row = sqlx::query(
        "SELECT u.id, NOT u.is_disabled AS enabled, m.state,
                ARRAY(SELECT s.node::text FROM mix_pam_subscriptions s
                       WHERE s.membership_id = m.id ORDER BY s.node) AS subscriptions,
                EXISTS(SELECT 1 FROM blocked_jids b WHERE b.owner_id = u.id
                         AND b.blocked_jid IN ($2, $3)) AS blocked
           FROM users u LEFT JOIN mix_pam_memberships m ON m.user_id = u.id AND m.channel_jid = $2
          WHERE u.username = $1",
    )
    .bind(username)
    .bind(query.channel.as_str())
    .bind(query.channel.domain())
    .fetch_optional(executor)
    .await?;
    row.map(|row| {
        let state: Option<String> = row.try_get("state")?;
        Ok(PamDeliveryAuthority {
            account_id: row.try_get("id")?,
            enabled: row.try_get("enabled")?,
            state: state.as_deref().map(MixPamState::parse).transpose()?,
            subscriptions: row.try_get("subscriptions")?,
            blocked: row.try_get("blocked")?,
        })
    })
    .transpose()
}

pub async fn pam_membership_from_row(
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
    match pam_membership_row(pool, user_id, channel_jid).await? {
        Some(row) => pam_membership_from_row(pool, row).await.map(Some),
        None => Ok(None),
    }
}

pub(crate) async fn joined_pam_membership(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    channel_jid: &str,
) -> Result<bool> {
    Ok(pam_membership_row(&mut **transaction, user_id, channel_jid)
        .await?
        .is_some_and(|row| row.get::<&str, _>("state") == "joined"))
}

async fn pam_membership_row<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    user_id: Uuid,
    channel_jid: &str,
) -> Result<Option<sqlx::postgres::PgRow>> {
    let channel_jid = northstar_xmpp_types::jid::canonicalize_bare(channel_jid)?;
    Ok(sqlx::query(
        "SELECT id, user_id, channel_jid, participant_id, state, request_id, client_request_id, requester_full_jid FROM mix_pam_memberships WHERE user_id = $1 AND channel_jid = $2",
    )
    .bind(user_id)
    .bind(channel_jid)
    .fetch_optional(executor)
    .await?)
}

pub async fn local_pam_users_for_channel(pool: &PgPool, channel_jid: &str) -> Result<Vec<Uuid>> {
    let channel_jid = northstar_xmpp_types::jid::canonicalize_bare(channel_jid)?;
    sqlx::query_scalar(
        "SELECT user_id FROM mix_pam_memberships WHERE channel_jid = $1 ORDER BY user_id",
    )
    .bind(channel_jid)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}
