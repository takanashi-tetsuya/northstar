use super::query::{privacy_item, privacy_list_on};
use super::{
    PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType, PrivacyStanzaKind,
    PRIVACY_DECISION_FACTS,
};
use anyhow::Result;
use sqlx::{postgres::PgRow, PgConnection, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

/// Decode one exact policy request's rows in item order.
pub fn privacy_denies_from_facts(
    rows: &[PgRow],
    candidate: &str,
    kind: PrivacyStanzaKind,
) -> Result<bool> {
    let first = rows
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing privacy decision facts"))?;
    if first.try_get::<bool, _>("missing_selection")? {
        return Ok(true);
    }
    let Some(name) = first.try_get::<Option<String>, _>("selected_name")? else {
        return Ok(false);
    };
    let items = if first.try_get::<Option<i64>, _>("item_order")?.is_some() {
        rows.iter().map(privacy_item).collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let subscription: Option<String> = first.try_get("subscription")?;
    let groups = first
        .try_get::<Option<serde_json::Value>, _>("groups")?
        .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
        .unwrap_or_default();
    Ok(privacy_list_denies(
        &PrivacyList { name, items },
        candidate,
        subscription.as_deref(),
        &groups,
        kind,
    ))
}

/// Evaluate a connected resource without extending or repairing its selection lease.
pub async fn session_privacy_denies<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    owner_id: Uuid,
    connection_id: Option<Uuid>,
    expects_active: bool,
    candidate: &str,
    kind: PrivacyStanzaKind,
) -> Result<bool> {
    let candidate = northstar_xmpp_types::jid::CanonicalJid::parse(candidate)?;
    let statement = format!(
        "WITH requested(owner_id, connection_id, expects_active, peer_bare, position) AS
             (VALUES ($1::uuid, $2::uuid, $3::bool, $4::text, 1))
         {PRIVACY_DECISION_FACTS} ORDER BY item_order"
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(statement))
        .bind(owner_id)
        .bind(connection_id)
        .bind(expects_active)
        .bind(candidate.bare())
        .fetch_all(executor)
        .await?;
    privacy_denies_from_facts(&rows, &candidate.to_string(), kind)
}

pub async fn privacy_denies(
    pool: &PgPool,
    owner_id: Uuid,
    active_list: Option<&str>,
    candidate: &str,
    kind: PrivacyStanzaKind,
) -> Result<bool> {
    let mut connection = pool.acquire().await?;
    privacy_denies_on(&mut connection, owner_id, active_list, candidate, kind).await
}

/// Evaluate a session's selected list or the account default in a read snapshot.
pub async fn privacy_denies_in_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    active_list: Option<&str>,
    candidate: &str,
    kind: PrivacyStanzaKind,
) -> Result<bool> {
    privacy_denies_on(transaction, owner_id, active_list, candidate, kind).await
}

async fn privacy_denies_on(
    connection: &mut PgConnection,
    owner_id: Uuid,
    active_list: Option<&str>,
    candidate: &str,
    kind: PrivacyStanzaKind,
) -> Result<bool> {
    let selected = match active_list {
        Some(name) => Some(name.to_owned()),
        None => {
            sqlx::query_scalar::<_, String>(
                "SELECT list_name FROM privacy_default_lists WHERE owner_id=$1",
            )
            .bind(owner_id)
            .fetch_optional(&mut *connection)
            .await?
        }
    };
    let Some(selected) = selected else {
        return Ok(false);
    };
    let Some(list) = privacy_list_on(connection, owner_id, &selected).await? else {
        // A selected list is protected by a FK (or was an already-deleted
        // session-only selection). Missing policy must fail closed.
        return Ok(true);
    };
    let candidate = northstar_xmpp_types::jid::CanonicalJid::parse(candidate)?;
    let bare = candidate.bare();
    let roster = sqlx::query(
        "SELECT subscription, groups FROM roster_items WHERE owner_id=$1 AND contact_jid=$2",
    )
    .bind(owner_id)
    .bind(&bare)
    .fetch_optional(&mut *connection)
    .await?;
    let subscription = roster
        .as_ref()
        .map(|row| row.get::<String, _>("subscription"));
    let groups = roster
        .as_ref()
        .and_then(|row| row.try_get::<serde_json::Value, _>("groups").ok())
        .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
        .unwrap_or_default();
    Ok(privacy_list_denies(
        &list,
        &candidate.to_string(),
        subscription.as_deref(),
        &groups,
        kind,
    ))
}

/// Evaluate the exact connection-scoped XEP-0016 policy inside a wider
/// authorization transaction. The caller must already hold the owner's user
/// row lock. Every supported privacy-list mutation takes a conflicting lock
/// on that row, so the active/default selection, rules, roster context and
/// protected business mutation all belong to one serialization point.
///
/// `connection_id=None` is reserved for inbound federation. A remote server
/// does not own a local C2S connection, so the local recipient's durable
/// default list is the account-wide authority for accepting a subscription
/// transition. Delivery to an individual live resource is still filtered by
/// that resource's active list after commit.
pub async fn privacy_denies_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    connection_id: Option<Uuid>,
    candidate: &str,
    kind: PrivacyStanzaKind,
) -> Result<bool> {
    if connection_id.is_some_and(|connection_id| connection_id.is_nil()) {
        anyhow::bail!("privacy policy requires a non-nil connection identity");
    }
    let active = match connection_id {
        Some(connection_id) => {
            sqlx::query_scalar::<_, String>(
                "SELECT list_name FROM privacy_active_sessions
                  WHERE owner_id=$1 AND connection_id=$2 AND expires_at>NOW()
                  FOR SHARE",
            )
            .bind(owner_id)
            .bind(connection_id)
            .fetch_optional(&mut **transaction)
            .await?
        }
        None => None,
    };
    let selected = match active {
        Some(active) => Some(active),
        None => {
            sqlx::query_scalar::<_, String>(
                "SELECT list_name FROM privacy_default_lists
                  WHERE owner_id=$1
                  FOR SHARE",
            )
            .bind(owner_id)
            .fetch_optional(&mut **transaction)
            .await?
        }
    };
    let Some(selected) = selected else {
        return Ok(false);
    };
    let list_row = sqlx::query(
        "SELECT name FROM privacy_lists
          WHERE owner_id=$1 AND name=$2
          FOR SHARE",
    )
    .bind(owner_id)
    .bind(&selected)
    .fetch_optional(&mut **transaction)
    .await?;
    // Selected lists are FK protected. Treat corrupted/missing authority as
    // deny instead of silently weakening policy.
    if list_row.is_none() {
        return Ok(true);
    }
    let rows = sqlx::query(
        "SELECT item_order,action,match_type,match_value,filter_message,filter_iq,
                filter_presence_in,filter_presence_out
           FROM privacy_list_items
          WHERE owner_id=$1 AND list_name=$2
          ORDER BY item_order
          FOR SHARE",
    )
    .bind(owner_id)
    .bind(&selected)
    .fetch_all(&mut **transaction)
    .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let action: String = row.try_get("action")?;
        let match_type: Option<String> = row.try_get("match_type")?;
        let match_type = match match_type.as_deref() {
            None => None,
            Some("jid") => Some(PrivacyMatchType::Jid),
            Some("group") => Some(PrivacyMatchType::Group),
            Some("subscription") => Some(PrivacyMatchType::Subscription),
            Some(_) => return Ok(true),
        };
        let action = match action.as_str() {
            "allow" => PrivacyAction::Allow,
            "deny" => PrivacyAction::Deny,
            _ => return Ok(true),
        };
        items.push(PrivacyItem {
            order: u32::try_from(row.try_get::<i64, _>("item_order")?)
                .map_err(|_| anyhow::anyhow!("stored privacy-list order exceeds xs:unsignedInt"))?,
            action,
            match_type,
            match_value: row.try_get("match_value")?,
            message: row.try_get("filter_message")?,
            iq: row.try_get("filter_iq")?,
            presence_in: row.try_get("filter_presence_in")?,
            presence_out: row.try_get("filter_presence_out")?,
        });
    }
    let candidate = northstar_xmpp_types::jid::CanonicalJid::parse(candidate)?;
    let roster = sqlx::query(
        "SELECT subscription,groups FROM roster_items
          WHERE owner_id=$1 AND contact_jid=$2
          FOR SHARE",
    )
    .bind(owner_id)
    .bind(candidate.bare())
    .fetch_optional(&mut **transaction)
    .await?;
    let subscription = roster
        .as_ref()
        .map(|row| row.get::<String, _>("subscription"));
    let groups = roster
        .as_ref()
        .and_then(|row| row.try_get::<serde_json::Value, _>("groups").ok())
        .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
        .unwrap_or_default();
    Ok(privacy_list_denies(
        &PrivacyList {
            name: selected,
            items,
        },
        &candidate.to_string(),
        subscription.as_deref(),
        &groups,
        kind,
    ))
}

fn privacy_list_denies(
    list: &PrivacyList,
    candidate: &str,
    subscription: Option<&str>,
    groups: &[String],
    kind: PrivacyStanzaKind,
) -> bool {
    northstar_xep_0016::list_denies(list, candidate, subscription, groups, kind)
}
