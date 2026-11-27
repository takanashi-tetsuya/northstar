use super::{PrivacyAction, PrivacyItem, PrivacyList};
use anyhow::Result;
use northstar_roster_application::privacy::commands::{
    ActorOutcome, PrivacyListName, PrivacyOverviewSnapshot,
};
use northstar_roster_core::RosterActor;
use northstar_xep_0016::PrivacyMatcher;
use sqlx::{postgres::PgRow, PgConnection, PgPool, Row};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyOverview {
    pub default: Option<String>,
    pub names: Vec<String>,
}

pub async fn privacy_overview(pool: &PgPool, owner_id: Uuid) -> Result<PrivacyOverview> {
    let rows = overview_rows(pool, owner_id, None, None).await?;
    let default = rows
        .first()
        .and_then(|row| row.try_get::<Option<String>, _>("default_name").ok())
        .flatten();
    let names = rows
        .iter()
        .filter_map(|row| row.get::<Option<String>, _>("name"))
        .collect();
    Ok(PrivacyOverview { default, names })
}

pub async fn privacy_list(
    pool: &PgPool,
    owner_id: Uuid,
    name: &str,
) -> Result<Option<PrivacyList>> {
    let mut connection = pool.acquire().await?;
    privacy_list_on(&mut connection, owner_id, name).await
}

pub(super) async fn privacy_list_on(
    connection: &mut PgConnection,
    owner_id: Uuid,
    name: &str,
) -> Result<Option<PrivacyList>> {
    match read_list(connection, owner_id, name, None).await? {
        ActorOutcome::Current(items) => Ok(items.map(|items| PrivacyList {
            name: name.to_owned(),
            items,
        })),
        ActorOutcome::Stale => Ok(None),
    }
}

pub(super) async fn read_privacy_list(
    pool: &PgPool,
    actor: &RosterActor,
    name: &PrivacyListName,
) -> Result<ActorOutcome<Option<Vec<PrivacyItem>>>> {
    read_list(
        pool,
        actor.account_id,
        name.as_str(),
        Some(actor.auth_generation),
    )
    .await
}

async fn read_list<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    owner_id: Uuid,
    name: &str,
    generation: Option<i64>,
) -> Result<ActorOutcome<Option<Vec<PrivacyItem>>>> {
    let rows = sqlx::query(
        "SELECT list.name AS list_name, item.item_order, item.action, item.match_type, item.match_value, \
                item.filter_message, item.filter_iq, item.filter_presence_in, item.filter_presence_out \
         FROM users owner \
         LEFT JOIN privacy_lists list ON list.owner_id=owner.id AND list.name=$2 \
         LEFT JOIN privacy_list_items item ON item.owner_id=list.owner_id AND item.list_name=list.name \
         WHERE owner.id=$1 AND ($3::bigint IS NULL OR (NOT owner.is_disabled AND owner.auth_generation=$3)) \
         ORDER BY item.item_order",
    )
    .bind(owner_id)
    .bind(name)
    .bind(generation)
    .fetch_all(executor)
    .await?;
    let Some(first) = rows.first() else {
        return Ok(ActorOutcome::Stale);
    };
    if first.try_get::<Option<String>, _>("list_name")?.is_none() {
        return Ok(ActorOutcome::Current(None));
    }
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        if row.try_get::<Option<i64>, _>("item_order")?.is_some() {
            items.push(privacy_item(row)?);
        }
    }
    Ok(ActorOutcome::Current(Some(items)))
}

pub(super) async fn read_privacy_overview(
    pool: &PgPool,
    actor: &RosterActor,
) -> Result<ActorOutcome<PrivacyOverviewSnapshot>> {
    let rows = overview_rows(
        pool,
        actor.account_id,
        Some(actor.auth_generation),
        Some(actor.connection_id),
    )
    .await?;
    let Some(first) = rows.first() else {
        return Ok(ActorOutcome::Stale);
    };
    let mut names = Vec::with_capacity(rows.len());
    for row in &rows {
        names.extend(stored_list_name(row, "name")?);
    }
    Ok(ActorOutcome::Current(PrivacyOverviewSnapshot {
        default: stored_list_name(first, "default_name")?,
        active: stored_list_name(first, "active_name")?,
        names,
    }))
}

async fn overview_rows(
    pool: &PgPool,
    owner_id: Uuid,
    generation: Option<i64>,
    connection_id: Option<Uuid>,
) -> Result<Vec<PgRow>> {
    Ok(sqlx::query(
        "SELECT list.name, defaults.list_name AS default_name, active.list_name AS active_name \
         FROM users owner \
         LEFT JOIN privacy_lists list ON list.owner_id=owner.id \
         LEFT JOIN privacy_default_lists defaults ON defaults.owner_id=owner.id \
         LEFT JOIN privacy_active_sessions active ON active.owner_id=owner.id \
             AND active.connection_id=$3 AND active.expires_at>statement_timestamp() \
         WHERE owner.id=$1 AND ($2::bigint IS NULL OR (NOT owner.is_disabled AND owner.auth_generation=$2)) \
         ORDER BY list.name",
    )
    .bind(owner_id)
    .bind(generation)
    .bind(connection_id)
    .fetch_all(pool)
    .await?)
}

pub(super) fn stored_list_name(row: &PgRow, column: &str) -> Result<Option<PrivacyListName>> {
    row.try_get::<Option<String>, _>(column)?
        .map(|name| {
            PrivacyListName::parse(&name).ok_or_else(|| {
                anyhow::anyhow!("stored privacy-list name is outside the protocol bound")
            })
        })
        .transpose()
}

pub(super) fn privacy_item(row: &PgRow) -> Result<PrivacyItem> {
    let action: String = row.try_get("action")?;
    let match_type: Option<String> = row.try_get("match_type")?;
    let match_value: Option<String> = row.try_get("match_value")?;
    let matcher = match (match_type.as_deref(), match_value) {
        (None, None) => PrivacyMatcher::Everyone,
        (Some("jid"), Some(value)) => PrivacyMatcher::Jid(value),
        (Some("group"), Some(value)) => PrivacyMatcher::Group(value),
        (Some(_), Some(value)) => PrivacyMatcher::Subscription(value),
        _ => anyhow::bail!("stored privacy-list matcher has incomplete fields"),
    };
    let (match_type, match_value) = matcher.matcher_parts();
    Ok(PrivacyItem {
        order: u32::try_from(row.try_get::<i64, _>("item_order")?)
            .map_err(|_| anyhow::anyhow!("stored privacy-list order exceeds xs:unsignedInt"))?,
        action: if action == "allow" {
            PrivacyAction::Allow
        } else {
            PrivacyAction::Deny
        },
        match_type,
        match_value,
        message: row.try_get("filter_message")?,
        iq: row.try_get("filter_iq")?,
        presence_in: row.try_get("filter_presence_in")?,
        presence_out: row.try_get("filter_presence_out")?,
    })
}
