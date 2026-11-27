use super::{
    PrivacyItem, PrivacyList, PrivacyMatchType, LOCK_OWNER_FOR_UPDATE_SQL, MAX_PRIVACY_ITEMS,
    MAX_PRIVACY_LISTS,
};
use anyhow::Result;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

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

pub async fn replace_privacy_list(
    pool: &PgPool,
    owner_id: Uuid,
    list: &PrivacyList,
) -> Result<ReplacePrivacyListOutcome> {
    anyhow::ensure!(
        !list.name.is_empty() && list.name.len() <= 128,
        "privacy-list name is outside the storage bound"
    );
    validate_replacement(&list.items)?;
    let mut tx = pool.begin().await?;
    // Serialize list-count enforcement and replacement against account deletion.
    let owner_exists = sqlx::query_scalar::<_, Uuid>(LOCK_OWNER_FOR_UPDATE_SQL)
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
    if !owner_exists {
        anyhow::bail!("privacy-list owner no longer exists");
    }
    let outcome = replace_list_in_transaction(&mut tx, owner_id, &list.name, &list.items).await?;
    if outcome == ReplacePrivacyListOutcome::Stored {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(outcome)
}

pub(super) fn validate_replacement(items: &[PrivacyItem]) -> Result<()> {
    anyhow::ensure!(
        !items.is_empty() && items.len() <= MAX_PRIVACY_ITEMS,
        "privacy-list item count is outside the storage bound"
    );
    let unique_orders = items
        .iter()
        .map(|item| item.order)
        .collect::<std::collections::HashSet<_>>();
    anyhow::ensure!(
        unique_orders.len() == items.len(),
        "privacy-list orders must be unique"
    );
    Ok(())
}

pub(super) async fn replace_list_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    name: &str,
    items: &[PrivacyItem],
) -> Result<ReplacePrivacyListOutcome> {
    let already_exists = privacy_list_exists_in_tx(tx, owner_id, name).await?;
    if !already_exists {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM privacy_lists WHERE owner_id=$1")
            .bind(owner_id)
            .fetch_one(&mut **tx)
            .await?;
        if count >= MAX_PRIVACY_LISTS as i64 {
            return Ok(ReplacePrivacyListOutcome::TooManyLists);
        }
    }
    sqlx::query(
        "INSERT INTO privacy_lists(owner_id,name) VALUES($1,$2) \
         ON CONFLICT(owner_id,name) DO UPDATE SET updated_at=NOW()",
    )
    .bind(owner_id)
    .bind(name)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM privacy_list_items WHERE owner_id=$1 AND list_name=$2")
        .bind(owner_id)
        .bind(name)
        .execute(&mut **tx)
        .await?;
    for item in items {
        sqlx::query(
            "INSERT INTO privacy_list_items \
             (owner_id,list_name,item_order,action,match_type,match_value,filter_message,filter_iq,filter_presence_in,filter_presence_out) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(owner_id)
        .bind(name)
        .bind(i64::from(item.order))
        .bind(item.action.as_str())
        .bind(item.match_type.map(PrivacyMatchType::as_str))
        .bind(&item.match_value)
        .bind(item.message)
        .bind(item.iq)
        .bind(item.presence_in)
        .bind(item.presence_out)
        .execute(&mut **tx)
        .await?;
    }
    Ok(ReplacePrivacyListOutcome::Stored)
}

pub async fn remove_privacy_list(
    pool: &PgPool,
    owner_id: Uuid,
    name: &str,
) -> Result<RemovePrivacyListOutcome> {
    let mut tx = pool.begin().await?;
    // Exclude new selections until the in-use check and deletion commit.
    let owner = sqlx::query_scalar::<_, Uuid>(LOCK_OWNER_FOR_UPDATE_SQL)
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await?;
    if owner.is_none() {
        tx.rollback().await?;
        return Ok(RemovePrivacyListOutcome::Missing);
    }
    let outcome = remove_list_in_transaction(&mut tx, owner_id, name).await?;
    if outcome == RemovePrivacyListOutcome::Conflict {
        tx.rollback().await?;
        return Ok(outcome);
    }
    Ok(if commit_list_removal(tx).await? {
        outcome
    } else {
        RemovePrivacyListOutcome::Conflict
    })
}

/// A suspended SM session can still name the list through the deferred
/// resume foreign key, which reports only at commit.
pub(super) async fn commit_list_removal(tx: Transaction<'_, Postgres>) -> Result<bool> {
    match tx.commit().await {
        Ok(()) => Ok(true),
        Err(error)
            if error.as_database_error().is_some_and(|database| {
                database.constraint() == Some("sm_resume_active_privacy_fk")
            }) =>
        {
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) async fn remove_list_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    name: &str,
) -> Result<RemovePrivacyListOutcome> {
    sqlx::query(
        "WITH expired AS MATERIALIZED (
             SELECT connection_id FROM privacy_active_sessions
              WHERE owner_id=$1 AND expires_at<=clock_timestamp()
              ORDER BY connection_id FOR UPDATE
         )
         DELETE FROM privacy_active_sessions AS active USING expired
          WHERE active.owner_id=$1 AND active.connection_id=expired.connection_id
            AND active.expires_at<=clock_timestamp()",
    )
    .bind(owner_id)
    .execute(&mut **tx)
    .await?;
    let conflict: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM privacy_default_lists WHERE owner_id=$1 AND list_name=$2) \
         OR EXISTS(SELECT 1 FROM privacy_active_sessions WHERE owner_id=$1 AND list_name=$2) \
         OR northstar_sm_privacy_list_in_use($1,$2)",
    )
    .bind(owner_id)
    .bind(name)
    .fetch_one(&mut **tx)
    .await?;
    if conflict {
        return Ok(RemovePrivacyListOutcome::Conflict);
    }
    let result = sqlx::query("DELETE FROM privacy_lists WHERE owner_id=$1 AND name=$2")
        .bind(owner_id)
        .bind(name)
        .execute(&mut **tx)
        .await?;
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
    let owner = sqlx::query_scalar::<_, Uuid>(LOCK_OWNER_FOR_UPDATE_SQL)
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await?;
    if owner.is_none() {
        tx.rollback().await?;
        return Ok(false);
    }
    let updated = set_default_in_transaction(&mut tx, owner_id, name).await?;
    if updated {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(updated)
}

pub(super) async fn set_default_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    name: Option<&str>,
) -> Result<bool> {
    let exists = if let Some(name) = name {
        privacy_list_exists_in_tx(tx, owner_id, name).await?
    } else {
        true
    };
    if !exists {
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
            .execute(&mut **tx)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM privacy_default_lists WHERE owner_id=$1")
                .bind(owner_id)
                .execute(&mut **tx)
                .await?;
        }
    }
    Ok(true)
}

pub(super) async fn privacy_list_exists_in_tx(
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
