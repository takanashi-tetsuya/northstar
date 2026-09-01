use anyhow::Result;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub const MAX_PRIVACY_LISTS: usize = 64;
pub const MAX_PRIVACY_ITEMS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyAction {
    Allow,
    Deny,
}

impl PrivacyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyMatchType {
    Jid,
    Group,
    Subscription,
}

impl PrivacyMatchType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jid => "jid",
            Self::Group => "group",
            Self::Subscription => "subscription",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyItem {
    pub order: u32,
    pub action: PrivacyAction,
    pub match_type: Option<PrivacyMatchType>,
    pub match_value: Option<String>,
    pub message: bool,
    pub iq: bool,
    pub presence_in: bool,
    pub presence_out: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyList {
    pub name: String,
    pub items: Vec<PrivacyItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyOverview {
    pub default: Option<String>,
    pub names: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyStanzaKind {
    Message,
    Iq,
    PresenceIn,
    PresenceOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacePrivacyListOutcome {
    Stored,
    TooManyLists,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemovePrivacyListOutcome {
    Removed,
    Missing,
    Conflict,
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
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM privacy_lists WHERE owner_id=$1 AND name=$2)",
    )
    .bind(owner_id)
    .bind(name)
    .fetch_one(pool)
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
    .fetch_all(pool)
    .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let action: String = row.get("action");
        let match_type: Option<String> = row.get("match_type");
        items.push(PrivacyItem {
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
        });
    }
    Ok(Some(PrivacyList {
        name: name.to_owned(),
        items,
    }))
}

pub async fn replace_privacy_list(
    pool: &PgPool,
    owner_id: Uuid,
    list: &PrivacyList,
) -> Result<ReplacePrivacyListOutcome> {
    anyhow::ensure!(
        !list.name.is_empty() && list.name.len() <= 128,
        "privacy-list name is outside the storage bound"
    );
    anyhow::ensure!(
        !list.items.is_empty() && list.items.len() <= MAX_PRIVACY_ITEMS,
        "privacy-list item count is outside the storage bound"
    );
    let unique_orders = list
        .items
        .iter()
        .map(|item| item.order)
        .collect::<std::collections::HashSet<_>>();
    anyhow::ensure!(
        unique_orders.len() == list.items.len(),
        "privacy-list orders must be unique"
    );
    let mut tx = pool.begin().await?;
    // Serialize list-count enforcement and replacement against account deletion.
    let owner_exists = sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
    if !owner_exists {
        anyhow::bail!("privacy-list owner no longer exists");
    }
    let already_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM privacy_lists WHERE owner_id=$1 AND name=$2)",
    )
    .bind(owner_id)
    .bind(&list.name)
    .fetch_one(&mut *tx)
    .await?;
    if !already_exists {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM privacy_lists WHERE owner_id=$1")
            .bind(owner_id)
            .fetch_one(&mut *tx)
            .await?;
        if count >= MAX_PRIVACY_LISTS as i64 {
            tx.rollback().await?;
            return Ok(ReplacePrivacyListOutcome::TooManyLists);
        }
    }
    sqlx::query(
        "INSERT INTO privacy_lists(owner_id,name) VALUES($1,$2) \
         ON CONFLICT(owner_id,name) DO UPDATE SET updated_at=NOW()",
    )
    .bind(owner_id)
    .bind(&list.name)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM privacy_list_items WHERE owner_id=$1 AND list_name=$2")
        .bind(owner_id)
        .bind(&list.name)
        .execute(&mut *tx)
        .await?;
    for item in &list.items {
        sqlx::query(
            "INSERT INTO privacy_list_items \
             (owner_id,list_name,item_order,action,match_type,match_value,filter_message,filter_iq,filter_presence_in,filter_presence_out) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(owner_id)
        .bind(&list.name)
        .bind(i64::from(item.order))
        .bind(item.action.as_str())
        .bind(item.match_type.map(PrivacyMatchType::as_str))
        .bind(&item.match_value)
        .bind(item.message)
        .bind(item.iq)
        .bind(item.presence_in)
        .bind(item.presence_out)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(ReplacePrivacyListOutcome::Stored)
}

pub async fn remove_privacy_list(
    pool: &PgPool,
    owner_id: Uuid,
    name: &str,
) -> Result<RemovePrivacyListOutcome> {
    let mut tx = pool.begin().await?;
    // A shared user-row lock is sufficient to keep the FK parent alive while
    // the selection changes. Callers such as SM finalization already hold the
    // same authorization lock; avoiding a SHARE -> UPDATE upgrade prevents
    // concurrent resumes for different resources of one account from
    // deadlocking while preserving deletion/change-password serialization.
    let owner = sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE id=$1 FOR SHARE")
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await?;
    if owner.is_none() {
        tx.rollback().await?;
        return Ok(RemovePrivacyListOutcome::Missing);
    }
    sqlx::query("DELETE FROM privacy_active_sessions WHERE owner_id=$1 AND expires_at<=NOW()")
        .bind(owner_id)
        .execute(&mut *tx)
        .await?;
    let conflict: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM privacy_default_lists WHERE owner_id=$1 AND list_name=$2) \
         OR EXISTS(SELECT 1 FROM privacy_active_sessions WHERE owner_id=$1 AND list_name=$2 AND expires_at>NOW()) \
         OR northstar_sm_privacy_list_in_use($1,$2)",
    )
    .bind(owner_id)
    .bind(name)
    .fetch_one(&mut *tx)
    .await?;
    if conflict {
        tx.rollback().await?;
        return Ok(RemovePrivacyListOutcome::Conflict);
    }
    let result = sqlx::query("DELETE FROM privacy_lists WHERE owner_id=$1 AND name=$2")
        .bind(owner_id)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(if result.rows_affected() == 1 {
        RemovePrivacyListOutcome::Removed
    } else {
        RemovePrivacyListOutcome::Missing
    })
}

pub async fn set_default_privacy_list(
    pool: &PgPool,
    owner_id: Uuid,
    name: Option<&str>,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let owner = sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await?;
    if owner.is_none() {
        tx.rollback().await?;
        return Ok(false);
    }
    let exists = if let Some(name) = name {
        privacy_list_exists_in_tx(&mut tx, owner_id, name).await?
    } else {
        true
    };
    if !exists {
        tx.rollback().await?;
        return Ok(false);
    }
    match name {
        Some(name) => {
            sqlx::query(
                "INSERT INTO privacy_default_lists(owner_id,list_name) VALUES($1,$2) \
                 ON CONFLICT(owner_id) DO UPDATE SET list_name=EXCLUDED.list_name",
            )
            .bind(owner_id)
            .bind(name)
            .execute(&mut *tx)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM privacy_default_lists WHERE owner_id=$1")
                .bind(owner_id)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(true)
}

pub async fn set_active_privacy_list(
    pool: &PgPool,
    owner_id: Uuid,
    connection_id: Uuid,
    name: Option<&str>,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let updated =
        set_active_privacy_list_in_transaction(&mut tx, owner_id, connection_id, name).await?;
    if !updated {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

/// Persist a connection's XEP-0016 selection inside a wider session
/// activation transaction. Callers already holding the authentication row
/// lock can therefore commit SM ownership, FAST state and privacy selection as
/// one unit instead of exposing a successfully resumed route before this write.
pub async fn set_active_privacy_list_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    connection_id: Uuid,
    name: Option<&str>,
) -> Result<bool> {
    let owner = sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(owner_id)
        .fetch_optional(&mut **tx)
        .await?;
    if owner.is_none() {
        return Ok(false);
    }
    if let Some(name) = name {
        if !privacy_list_exists_in_tx(tx, owner_id, name).await? {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO privacy_active_sessions(owner_id,connection_id,list_name) VALUES($1,$2,$3) \
             ON CONFLICT(owner_id,connection_id) DO UPDATE \
             SET list_name=EXCLUDED.list_name,updated_at=NOW(),expires_at=NOW()+INTERVAL '24 hours'",
        )
        .bind(owner_id)
        .bind(connection_id)
        .bind(name)
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query("DELETE FROM privacy_active_sessions WHERE owner_id=$1 AND connection_id=$2")
            .bind(owner_id)
            .bind(connection_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(true)
}

pub async fn clear_active_privacy_session(
    pool: &PgPool,
    owner_id: Uuid,
    connection_id: Uuid,
) -> Result<()> {
    sqlx::query("DELETE FROM privacy_active_sessions WHERE owner_id=$1 AND connection_id=$2")
        .bind(owner_id)
        .bind(connection_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn refresh_active_privacy_session(
    pool: &PgPool,
    owner_id: Uuid,
    connection_id: Uuid,
) -> Result<()> {
    sqlx::query(
        "UPDATE privacy_active_sessions SET updated_at=NOW(),expires_at=NOW()+INTERVAL '24 hours' \
         WHERE owner_id=$1 AND connection_id=$2",
    )
    .bind(owner_id)
    .bind(connection_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn privacy_list_exists_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    name: &str,
) -> Result<bool> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM privacy_lists WHERE owner_id=$1 AND name=$2)")
        .bind(owner_id)
        .bind(name)
        .fetch_one(&mut **tx)
        .await
        .map_err(Into::into)
}

pub async fn privacy_denies(
    pool: &PgPool,
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
            .fetch_optional(pool)
            .await?
        }
    };
    let Some(selected) = selected else {
        return Ok(false);
    };
    let Some(list) = privacy_list(pool, owner_id, &selected).await? else {
        // A selected list is protected by a FK (or was an already-deleted
        // session-only selection). Missing policy must fail closed.
        return Ok(true);
    };
    let candidate = crate::jid::CanonicalJid::parse(candidate)?;
    let bare = candidate.bare();
    let roster = sqlx::query(
        "SELECT subscription, groups FROM roster_items WHERE owner_id=$1 AND contact_jid=$2",
    )
    .bind(owner_id)
    .bind(&bare)
    .fetch_optional(pool)
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
        &candidate,
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
pub(crate) async fn privacy_denies_in_transaction(
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
    let candidate = crate::jid::CanonicalJid::parse(candidate)?;
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
        &candidate,
        subscription.as_deref(),
        &groups,
        kind,
    ))
}

fn privacy_list_denies(
    list: &PrivacyList,
    candidate: &crate::jid::CanonicalJid,
    subscription: Option<&str>,
    groups: &[String],
    kind: PrivacyStanzaKind,
) -> bool {
    for item in &list.items {
        let stanza_matches = if !(item.message || item.iq || item.presence_in || item.presence_out)
        {
            true
        } else {
            match kind {
                PrivacyStanzaKind::Message => item.message,
                PrivacyStanzaKind::Iq => item.iq,
                PrivacyStanzaKind::PresenceIn => item.presence_in,
                PrivacyStanzaKind::PresenceOut => item.presence_out,
            }
        };
        if !stanza_matches {
            continue;
        }
        let entity_matches = match (item.match_type, item.match_value.as_deref()) {
            (None, None) => true,
            (Some(PrivacyMatchType::Jid), Some(value)) => {
                super::roster::blocked_jid_matches(value, &candidate.to_string())
            }
            (Some(PrivacyMatchType::Group), Some(value)) => {
                groups.iter().any(|group| group == value)
            }
            (Some(PrivacyMatchType::Subscription), Some(value)) => {
                subscription.unwrap_or("none") == value
            }
            _ => false,
        };
        if entity_matches {
            return item.action == PrivacyAction::Deny;
        }
    }
    false
}

pub async fn privacy_denies_for_sm_session(
    pool: &PgPool,
    session_id: Uuid,
    candidate: &str,
    kind: PrivacyStanzaKind,
) -> Result<Option<bool>> {
    let row = sqlx::query("SELECT * FROM northstar_sm_privacy_state($1)")
        .bind(session_id)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let user_id: Uuid = row.get("user_id");
    let active: Option<String> = row.get("active_privacy_list");
    privacy_denies(pool, user_id, active.as_deref(), candidate, kind)
        .await
        .map(Some)
}

/// Account communication policy with the non-overridable XEP-0191 rule
/// evaluated first.  A privacy-list `allow` can never bypass a block.
#[cfg(test)]
pub async fn communication_denied(
    pool: &PgPool,
    owner_id: Uuid,
    owner_bare_jid: &str,
    active_list: Option<&str>,
    candidate: &str,
    kind: PrivacyStanzaKind,
) -> Result<bool> {
    if super::roster::is_blocked_for_account(pool, owner_id, owner_bare_jid, candidate).await? {
        return Ok(true);
    }
    privacy_denies(pool, owner_id, active_list, candidate, kind).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires a random-schema TEST_DATABASE_URL"]
    async fn postgres_privacy_lists_are_bounded_ordered_cascading_and_enforced() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to a disposable random-schema xmpp_test URL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let owner_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(owner_id)
            .bind(format!("privacy{}", owner_id.simple()))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO roster_items(owner_id,contact_jid,subscription,groups) \
             VALUES($1,'bob@example.test','both','[\"Friends\"]'::jsonb)",
        )
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();

        let list = PrivacyList {
            name: "work".to_owned(),
            items: vec![
                PrivacyItem {
                    order: 10,
                    action: PrivacyAction::Deny,
                    match_type: Some(PrivacyMatchType::Group),
                    match_value: Some("Friends".to_owned()),
                    message: true,
                    iq: false,
                    presence_in: false,
                    presence_out: false,
                },
                PrivacyItem {
                    order: 20,
                    action: PrivacyAction::Deny,
                    match_type: Some(PrivacyMatchType::Subscription),
                    match_value: Some("both".to_owned()),
                    message: false,
                    iq: true,
                    presence_in: false,
                    presence_out: false,
                },
                PrivacyItem {
                    order: 30,
                    action: PrivacyAction::Allow,
                    match_type: None,
                    match_value: None,
                    message: false,
                    iq: false,
                    presence_in: false,
                    presence_out: false,
                },
            ],
        };
        assert_eq!(
            replace_privacy_list(&pool, owner_id, &list).await.unwrap(),
            ReplacePrivacyListOutcome::Stored
        );
        assert!(set_default_privacy_list(&pool, owner_id, Some("work"))
            .await
            .unwrap());
        assert!(privacy_denies(
            &pool,
            owner_id,
            None,
            "bob@example.test/Phone",
            PrivacyStanzaKind::Message,
        )
        .await
        .unwrap());
        assert!(privacy_denies(
            &pool,
            owner_id,
            Some("work"),
            "bob@example.test/Phone",
            PrivacyStanzaKind::Iq,
        )
        .await
        .unwrap());
        assert!(!privacy_denies(
            &pool,
            owner_id,
            Some("work"),
            "carol@example.test/Phone",
            PrivacyStanzaKind::Message,
        )
        .await
        .unwrap());
        assert_eq!(
            remove_privacy_list(&pool, owner_id, "work").await.unwrap(),
            RemovePrivacyListOutcome::Conflict
        );

        let allow = PrivacyList {
            name: "allow".to_owned(),
            items: vec![PrivacyItem {
                order: u32::MAX,
                action: PrivacyAction::Allow,
                match_type: None,
                match_value: None,
                message: false,
                iq: false,
                presence_in: false,
                presence_out: false,
            }],
        };
        replace_privacy_list(&pool, owner_id, &allow).await.unwrap();
        let active_connection = Uuid::new_v4();
        assert!(
            set_active_privacy_list(&pool, owner_id, active_connection, Some("allow"),)
                .await
                .unwrap()
        );
        assert_eq!(
            remove_privacy_list(&pool, owner_id, "allow").await.unwrap(),
            RemovePrivacyListOutcome::Conflict
        );
        clear_active_privacy_session(&pool, owner_id, active_connection)
            .await
            .unwrap();
        let sm_snapshot = crate::db::SmSessionSnapshot {
            inbound_h: 0,
            outbound_h: 0,
            acked_h: 0,
            available: true,
            carbons: false,
            priority: 0,
            blocklist_requested: false,
            roster_requested: false,
            active_privacy_list: Some("allow".to_owned()),
            privacy_requested: true,
            peer_ip: "192.0.2.44".parse().unwrap(),
            user_agent_id: None,
            joined_rooms: vec![],
            directed_presence: vec![],
            last_presence: None,
            unacked: vec![],
        };
        crate::db::create_sm_session(
            &pool,
            &[7_u8; 32],
            owner_id,
            0,
            &format!("privacy{}@example.test/Phone", owner_id.simple()),
            "Phone",
            "example.test",
            Uuid::new_v4(),
            &sm_snapshot,
            300,
            30,
            8,
            100,
        )
        .await
        .unwrap();
        assert_eq!(
            remove_privacy_list(&pool, owner_id, "allow").await.unwrap(),
            RemovePrivacyListOutcome::Conflict
        );
        sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,'bob@example.test')")
            .bind(owner_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(communication_denied(
            &pool,
            owner_id,
            &format!("privacy{}@example.test", owner_id.simple()),
            Some("allow"),
            "bob@example.test/Phone",
            PrivacyStanzaKind::Message,
        )
        .await
        .unwrap());

        // Database constraints independently reject ambiguous evaluation.
        let duplicate = sqlx::query(
            "INSERT INTO privacy_list_items(owner_id,list_name,item_order,action) \
             VALUES($1,'allow',4294967295,'deny')",
        )
        .bind(owner_id)
        .execute(&pool)
        .await;
        assert!(duplicate.is_err());

        set_default_privacy_list(&pool, owner_id, None)
            .await
            .unwrap();
        assert_eq!(
            remove_privacy_list(&pool, owner_id, "work").await.unwrap(),
            RemovePrivacyListOutcome::Removed
        );
        let existing = privacy_overview(&pool, owner_id).await.unwrap().names.len();
        for index in existing..MAX_PRIVACY_LISTS {
            let fill = PrivacyList {
                name: format!("quota-{index:03}"),
                items: allow.items.clone(),
            };
            assert_eq!(
                replace_privacy_list(&pool, owner_id, &fill).await.unwrap(),
                ReplacePrivacyListOutcome::Stored
            );
        }
        let overflow = PrivacyList {
            name: "quota-overflow".to_owned(),
            items: allow.items.clone(),
        };
        assert_eq!(
            replace_privacy_list(&pool, owner_id, &overflow)
                .await
                .unwrap(),
            ReplacePrivacyListOutcome::TooManyLists
        );
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(owner_id)
            .execute(&pool)
            .await
            .unwrap();
        let remaining: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM privacy_lists) + \
                    (SELECT COUNT(*) FROM privacy_list_items) + \
                    (SELECT COUNT(*) FROM privacy_default_lists) + \
                    (SELECT COUNT(*) FROM privacy_active_sessions)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remaining, 0);
    }
}
