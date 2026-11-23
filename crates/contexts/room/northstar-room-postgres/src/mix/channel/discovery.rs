use super::*;

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
    let requester_domain = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&requester)?
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
        let exists: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT EXISTS(SELECT 1 FROM mix_channels c WHERE {visible} AND c.localpart = $4)"
        )))
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
    let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM mix_channels c WHERE {visible}"
    )))
    .bind(&service_domain)
    .bind(&requester)
    .bind(&requester_domain)
    .fetch_one(&mut *transaction)
    .await?;
    let max = max.clamp(0, 100);
    let rows = if let Some(after) = after.as_deref() {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT c.* FROM mix_channels c WHERE {visible} AND c.localpart > $4 ORDER BY c.localpart ASC LIMIT $5"
        )))
        .bind(&service_domain)
        .bind(&requester)
        .bind(&requester_domain)
        .bind(after)
        .bind(max + 1)
        .fetch_all(&mut *transaction)
        .await?
    } else if let Some(before) = before.as_ref() {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT c.* FROM mix_channels c WHERE {visible} AND ($4::text IS NULL OR c.localpart < $4) ORDER BY c.localpart DESC LIMIT $5"
        )))
        .bind(&service_domain)
        .bind(&requester)
        .bind(&requester_domain)
        .bind(before.as_deref())
        .bind(max + 1)
        .fetch_all(&mut *transaction)
        .await?
    } else {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT c.* FROM mix_channels c WHERE {visible} ORDER BY c.localpart ASC LIMIT $4"
        )))
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
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM mix_channels c WHERE {visible} AND c.localpart < $4"
        )))
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

/// Apply the same joinability/privacy boundary to channel disco#info and
/// disco#items. Ad-hoc channels are visible only to participants and channel
/// administrators; named channels are visible only when the requester is not
/// banned and satisfies the channel access model.
pub async fn mix_channel_discoverable_to(
    pool: &PgPool,
    channel: &MixChannel,
    actor: &str,
) -> Result<bool> {
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse(actor)?;
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
