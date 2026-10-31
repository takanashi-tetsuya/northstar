use anyhow::Result;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub use northstar_xep_0016::{
    PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType, PrivacyStanzaKind,
    MAX_PRIVACY_ITEMS, MAX_PRIVACY_LISTS,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyOverview {
    pub default: Option<String>,
    pub names: Vec<String>,
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
    // Exclude new selections until the in-use check and deletion commit.
    let owner = sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE id=$1 FOR UPDATE")
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
    // SM finalization already holds this shared authorization lock. Upgrading
    // it would deadlock concurrent resumes for different account resources.
    // List deletion takes the exclusive lock before checking active selections.
    let owner = sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE id=$1 FOR SHARE")
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
    let candidate = northstar_xmpp_types::jid::CanonicalJid::parse(candidate)?;
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

mod application_repository {
    use anyhow::Result;
    use northstar_roster_application::privacy::*;
    use sqlx::PgPool;
    use uuid::Uuid;
    #[derive(Clone)]
    pub struct PostgresPrivacyRepository {
        pool: PgPool,
    }
    impl PostgresPrivacyRepository {
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }
    }
    impl PrivacyRepository for PostgresPrivacyRepository {
        async fn clear_active_session(&self, owner_id: Uuid, connection_id: Uuid) -> Result<()> {
            super::clear_active_privacy_session(&self.pool, owner_id, connection_id).await
        }

        async fn overview(&self, owner_id: Uuid) -> Result<PrivacyOverview> {
            let overview = super::privacy_overview(&self.pool, owner_id).await?;
            Ok(PrivacyOverview {
                default: overview.default,
                names: overview.names,
            })
        }
        async fn list(&self, owner_id: Uuid, name: &str) -> Result<Option<PrivacyList>> {
            super::privacy_list(&self.pool, owner_id, name).await
        }
        async fn select_active(
            &self,
            owner_id: Uuid,
            connection_id: Uuid,
            name: Option<&str>,
        ) -> Result<PrivacySelectionOutcome> {
            Ok(
                if super::set_active_privacy_list(&self.pool, owner_id, connection_id, name).await?
                {
                    PrivacySelectionOutcome::Updated
                } else {
                    PrivacySelectionOutcome::Missing
                },
            )
        }
        async fn select_default(
            &self,
            owner_id: Uuid,
            name: Option<&str>,
        ) -> Result<PrivacySelectionOutcome> {
            Ok(
                if super::set_default_privacy_list(&self.pool, owner_id, name).await? {
                    PrivacySelectionOutcome::Updated
                } else {
                    PrivacySelectionOutcome::Missing
                },
            )
        }
        async fn replace_list(
            &self,
            owner_id: Uuid,
            list: &PrivacyList,
        ) -> Result<PrivacyListMutationOutcome> {
            Ok(
                match super::replace_privacy_list(&self.pool, owner_id, list).await? {
                    super::ReplacePrivacyListOutcome::Stored => PrivacyListMutationOutcome::Stored,
                    super::ReplacePrivacyListOutcome::TooManyLists => {
                        PrivacyListMutationOutcome::QuotaExceeded
                    }
                },
            )
        }
        async fn remove_list(
            &self,
            owner_id: Uuid,
            name: &str,
        ) -> Result<PrivacyListMutationOutcome> {
            Ok(
                match super::remove_privacy_list(&self.pool, owner_id, name).await? {
                    super::RemovePrivacyListOutcome::Removed => PrivacyListMutationOutcome::Removed,
                    super::RemovePrivacyListOutcome::Missing => PrivacyListMutationOutcome::Missing,
                    super::RemovePrivacyListOutcome::Conflict => {
                        PrivacyListMutationOutcome::Conflict
                    }
                },
            )
        }
        async fn denies(
            &self,
            owner_id: Uuid,
            active_privacy_list: Option<&str>,
            candidate: &str,
            kind: PrivacyStanzaKind,
        ) -> Result<bool> {
            super::privacy_denies(&self.pool, owner_id, active_privacy_list, candidate, kind).await
        }
    }
}
pub use application_repository::PostgresPrivacyRepository;
