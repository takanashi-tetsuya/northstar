use super::{PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType};
use anyhow::Result;
use sqlx::{postgres::PgRow, PgConnection, PgPool, Row};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyOverview {
    pub default: Option<String>,
    pub names: Vec<String>,
}

pub async fn privacy_overview(pool: &PgPool, owner_id: Uuid) -> Result<PrivacyOverview> {
    let rows = sqlx::query(
        "SELECT l.name, d.list_name AS default_name FROM privacy_lists l \
         LEFT JOIN privacy_default_lists d ON d.owner_id=l.owner_id \
         WHERE l.owner_id=$1 ORDER BY l.name",
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await?;
    let default = rows
        .first()
        .and_then(|row| row.try_get::<Option<String>, _>("default_name").ok())
        .flatten();
    let names = rows.iter().map(|row| row.get("name")).collect();
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
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM privacy_lists WHERE owner_id=$1 AND name=$2)",
    )
    .bind(owner_id)
    .bind(name)
    .fetch_one(&mut *connection)
    .await?;
    if !exists {
        return Ok(None);
    }
    let rows = sqlx::query(
        "SELECT item_order, action, match_type, match_value, filter_message, filter_iq, \
                filter_presence_in, filter_presence_out \
         FROM privacy_list_items WHERE owner_id=$1 AND list_name=$2 ORDER BY item_order",
    )
    .bind(owner_id)
    .bind(name)
    .fetch_all(&mut *connection)
    .await?;
    let items = rows.iter().map(privacy_item).collect::<Result<Vec<_>>>()?;
    Ok(Some(PrivacyList {
        name: name.to_owned(),
        items,
    }))
}

pub(super) fn privacy_item(row: &PgRow) -> Result<PrivacyItem> {
    let action: String = row.get("action");
    let match_type: Option<String> = row.get("match_type");
    Ok(PrivacyItem {
        order: u32::try_from(row.get::<i64, _>("item_order"))
            .map_err(|_| anyhow::anyhow!("stored privacy-list order exceeds xs:unsignedInt"))?,
        action: if action == "allow" {
            PrivacyAction::Allow
        } else {
            PrivacyAction::Deny
        },
        match_type: match_type.as_deref().map(|value| match value {
            "jid" => PrivacyMatchType::Jid,
            "group" => PrivacyMatchType::Group,
            _ => PrivacyMatchType::Subscription,
        }),
        match_value: row.get("match_value"),
        message: row.get("filter_message"),
        iq: row.get("filter_iq"),
        presence_in: row.get("filter_presence_in"),
        presence_out: row.get("filter_presence_out"),
    })
}
