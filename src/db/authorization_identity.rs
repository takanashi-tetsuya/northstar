//! Exact RFC 7622 migration for durable authorization and routing keys.
//!
//! These tables predate the shared JID parser.  SQL case folding cannot
//! reproduce PRECIS/IDNA and must never touch an opaque resourcepart, so the
//! migration computes every key with `crate::jid`, rejects collisions before
//! writing, and commits the rewrites and completion marker atomically.

use anyhow::{Context, Result};
#[cfg(test)]
use sqlx::PgPool;
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeMap;
use uuid::Uuid;

const MIGRATION: &str = "authorization-keys-rfc7622-ulabel-v2";
const CANONICALIZER_VERSION: i32 = 2;

#[derive(Debug)]
struct ScopedIdentity {
    scope: String,
    row_key: String,
    original: String,
    canonical: String,
}

fn invalid_jid(table: &str, row_key: &str, value: &str, error: anyhow::Error) -> anyhow::Error {
    error.context(format!(
        "authorization JID migration rejected invalid identity in {table} row {row_key}: {value:?}; correct or remove this row and restart"
    ))
}

fn canonical_bare(table: &str, row_key: &str, value: &str) -> Result<String> {
    crate::jid::canonicalize_bare(value).map_err(|error| invalid_jid(table, row_key, value, error))
}

fn canonical_user_bare(table: &str, row_key: &str, value: &str) -> Result<String> {
    let jid = crate::jid::CanonicalJid::parse_bare(value)
        .map_err(|error| invalid_jid(table, row_key, value, error))?;
    anyhow::ensure!(
        jid.localpart().is_some(),
        "authorization JID migration rejected domain-only identity in {table} row {row_key}: {value:?}; a user bare JID is required"
    );
    Ok(jid.to_string())
}

fn canonical_exact(table: &str, row_key: &str, value: &str) -> Result<String> {
    crate::jid::canonicalize(value).map_err(|error| invalid_jid(table, row_key, value, error))
}

fn ensure_no_collisions(table: &str, rows: &[ScopedIdentity]) -> Result<()> {
    let mut owners = BTreeMap::<(&str, &str), (&str, &str)>::new();
    for row in rows {
        let key = (row.scope.as_str(), row.canonical.as_str());
        if let Some((previous_row, previous_value)) =
            owners.insert(key, (row.row_key.as_str(), row.original.as_str()))
        {
            anyhow::bail!(
                "authorization JID migration found a canonical collision in {table}: rows {previous_row} ({previous_value:?}) and {} ({:?}) in scope {:?} both map to {:?}; resolve the duplicate identities explicitly and restart",
                row.row_key,
                row.original,
                row.scope,
                row.canonical
            );
        }
    }
    Ok(())
}

/// Canonicalize authorization and routing identities exactly once.
///
/// The completion marker is in the same transaction as every rewrite.  Any
/// invalid identity, canonical collision, lock timeout, or update error rolls
/// the whole batch back and leaves the marker absent.
#[cfg(test)]
pub async fn canonicalize_authorization_identity_storage(pool: &PgPool) -> Result<()> {
    let mut transaction = pool.begin().await?;
    canonicalize_authorization_identity_storage_in_transaction(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) async fn canonicalize_authorization_identity_storage_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7622))")
        .bind(MIGRATION)
        .execute(&mut **transaction)
        .await?;

    let completed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration=$1 AND canonicalizer_version=$2)",
    )
    .bind(MIGRATION)
    .bind(CANONICALIZER_VERSION)
    .fetch_one(&mut **transaction)
    .await?;
    if completed {
        return Ok(());
    }

    sqlx::query("SET LOCAL lock_timeout = '30s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "LOCK TABLE roster_items, roster_change_log, blocked_jids, federated_presence_pending, mam_preference_jids, muc_external_affiliations, federation_runtime_rules IN ACCESS EXCLUSIVE MODE",
    )
    .execute(&mut **transaction)
    .await
    .context(
        "timed out after 30 seconds waiting to lock authorization JID tables; stop other Northstar nodes using this database, then restart the migration",
    )?;

    let roster = load_uuid_scoped(
        transaction,
        "roster_items.contact_jid",
        "SELECT owner_id AS scope, contact_jid AS value FROM roster_items ORDER BY owner_id,contact_jid",
        canonical_bare,
    )
    .await?;
    ensure_no_collisions("roster_items(owner_id,contact_jid)", &roster)?;

    let roster_log = load_roster_log(transaction).await?;

    let blocked = load_uuid_scoped(
        transaction,
        "blocked_jids.blocked_jid",
        "SELECT owner_id AS scope, blocked_jid AS value FROM blocked_jids ORDER BY owner_id,blocked_jid",
        canonical_exact,
    )
    .await?;
    ensure_no_collisions("blocked_jids(owner_id,blocked_jid)", &blocked)?;

    let pending = load_uuid_scoped(
        transaction,
        "federated_presence_pending.from_jid",
        "SELECT recipient_id AS scope, from_jid AS value FROM federated_presence_pending ORDER BY recipient_id,from_jid",
        canonical_bare,
    )
    .await?;
    ensure_no_collisions(
        "federated_presence_pending(recipient_id,from_jid)",
        &pending,
    )?;

    let mam = load_uuid_scoped(
        transaction,
        "mam_preference_jids.jid",
        "SELECT user_id AS scope, jid AS value FROM mam_preference_jids ORDER BY user_id,jid",
        canonical_exact,
    )
    .await?;
    ensure_no_collisions("mam_preference_jids(user_id,jid)", &mam)?;

    let muc = load_uuid_scoped(
        transaction,
        "muc_external_affiliations.jid",
        "SELECT room_id AS scope, jid AS value FROM muc_external_affiliations ORDER BY room_id,jid",
        canonical_user_bare,
    )
    .await?;
    ensure_no_collisions("muc_external_affiliations(room_id,jid)", &muc)?;

    let federation = load_federation_rules(transaction).await?;
    ensure_no_collisions("federation_runtime_rules(kind,domain)", &federation)?;

    let mut transformed = 0_i64;
    transformed += update_uuid_scoped(
        transaction,
        "roster_items",
        "owner_id",
        "contact_jid",
        &roster,
    )
    .await?;
    transformed += update_roster_log(transaction, &roster_log).await?;
    transformed += update_uuid_scoped(
        transaction,
        "blocked_jids",
        "owner_id",
        "blocked_jid",
        &blocked,
    )
    .await?;
    transformed += update_uuid_scoped(
        transaction,
        "federated_presence_pending",
        "recipient_id",
        "from_jid",
        &pending,
    )
    .await?;
    transformed +=
        update_uuid_scoped(transaction, "mam_preference_jids", "user_id", "jid", &mam).await?;
    transformed += update_uuid_scoped(
        transaction,
        "muc_external_affiliations",
        "room_id",
        "jid",
        &muc,
    )
    .await?;
    transformed += update_federation_rules(transaction, &federation).await?;

    sqlx::query(
        "INSERT INTO jid_identity_migrations(migration,canonicalizer_version,transformed_rows) VALUES($1,$2,$3)",
    )
    .bind(MIGRATION)
    .bind(CANONICALIZER_VERSION)
    .bind(transformed)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

type Canonicalizer = fn(&str, &str, &str) -> Result<String>;

async fn load_uuid_scoped(
    transaction: &mut Transaction<'_, Postgres>,
    table: &str,
    query: &str,
    canonicalizer: Canonicalizer,
) -> Result<Vec<ScopedIdentity>> {
    sqlx::query(query)
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|row| {
            let scope: Uuid = row.get("scope");
            let original: String = row.get("value");
            let row_key = format!("{scope}/{original:?}");
            let canonical = canonicalizer(table, &row_key, &original)?;
            Ok(ScopedIdentity {
                scope: scope.to_string(),
                row_key,
                original,
                canonical,
            })
        })
        .collect()
}

async fn load_roster_log(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<(Uuid, i64, String, String)>> {
    sqlx::query(
        "SELECT owner_id,version,contact_jid FROM roster_change_log ORDER BY owner_id,version",
    )
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        let owner_id: Uuid = row.get("owner_id");
        let version: i64 = row.get("version");
        let original: String = row.get("contact_jid");
        let row_key = format!("{owner_id}/{version}");
        let canonical = canonical_bare("roster_change_log.contact_jid", &row_key, &original)?;
        Ok((owner_id, version, original, canonical))
    })
    .collect()
}

async fn load_federation_rules(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<ScopedIdentity>> {
    sqlx::query("SELECT kind,domain FROM federation_runtime_rules ORDER BY kind,domain")
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|row| {
            let kind: String = row.get("kind");
            let original: String = row.get("domain");
            let row_key = format!("{kind}/{original:?}");
            let canonical =
                canonical_exact("federation_runtime_rules.domain", &row_key, &original)?;
            Ok(ScopedIdentity {
                scope: kind,
                row_key,
                original,
                canonical,
            })
        })
        .collect()
}

async fn update_uuid_scoped(
    transaction: &mut Transaction<'_, Postgres>,
    table: &str,
    scope_column: &str,
    value_column: &str,
    rows: &[ScopedIdentity],
) -> Result<i64> {
    let statement = format!(
        "UPDATE {table} SET {value_column}=$3 WHERE {scope_column}=$1 AND {value_column}=$2 AND {value_column} IS DISTINCT FROM $3"
    );
    let mut transformed = 0_i64;
    for row in rows {
        transformed += sqlx::query(&statement)
            .bind(Uuid::parse_str(&row.scope)?)
            .bind(&row.original)
            .bind(&row.canonical)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
    }
    Ok(transformed)
}

async fn update_roster_log(
    transaction: &mut Transaction<'_, Postgres>,
    rows: &[(Uuid, i64, String, String)],
) -> Result<i64> {
    let mut transformed = 0_i64;
    for (owner_id, version, original, canonical) in rows {
        transformed += sqlx::query(
            "UPDATE roster_change_log SET contact_jid=$3 WHERE owner_id=$1 AND version=$2 AND contact_jid=$4 AND contact_jid IS DISTINCT FROM $3",
        )
        .bind(owner_id)
        .bind(version)
        .bind(canonical)
        .bind(original)
        .execute(&mut **transaction)
        .await?
        .rows_affected() as i64;
    }
    Ok(transformed)
}

async fn update_federation_rules(
    transaction: &mut Transaction<'_, Postgres>,
    rows: &[ScopedIdentity],
) -> Result<i64> {
    let mut transformed = 0_i64;
    for row in rows {
        transformed += sqlx::query(
            "UPDATE federation_runtime_rules SET domain=$3 WHERE kind=$1 AND domain=$2 AND domain IS DISTINCT FROM $3",
        )
        .bind(&row.scope)
        .bind(&row.original)
        .bind(&row.canonical)
        .execute(&mut **transaction)
        .await?
        .rows_affected() as i64;
    }
    Ok(transformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collisions_use_precis_idna_but_resources_remain_opaque() {
        let first = canonical_bare("test", "one", "A\u{30a}LICE@B\u{fc}CHER.Example.").unwrap();
        let second = canonical_bare("test", "two", "\u{e5}lice@b\u{fc}cher.example").unwrap();
        assert_eq!(first, second);

        let phone = canonical_exact("test", "phone", "ALICE@B\u{fc}CHER.Example/Phone").unwrap();
        let lower = canonical_exact("test", "lower", "alice@b\u{fc}cher.example/phone").unwrap();
        assert_eq!(phone, "alice@b\u{fc}cher.example/Phone");
        assert_ne!(phone, lower);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_batch_rewrites_rolls_back_collisions_and_is_idempotent() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        sqlx::query("DELETE FROM jid_identity_migrations WHERE migration=$1")
            .bind(MIGRATION)
            .execute(&pool)
            .await
            .unwrap();

        let owner_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(owner_id)
            .bind(format!("auth-jid-{}", Uuid::new_v4().simple()))
            .execute(&pool)
            .await
            .unwrap();
        let room_id = Uuid::new_v4();
        sqlx::query("INSERT INTO muc_rooms(id,localpart,occupant_id_secret) VALUES($1,$2,$3)")
            .bind(room_id)
            .bind(format!("auth-jid-{}", Uuid::new_v4().simple()))
            .bind(vec![7_u8; 32])
            .execute(&pool)
            .await
            .unwrap();

        let unicode_domain = "b\u{fc}cher.example";
        sqlx::query("INSERT INTO roster_items(owner_id,contact_jid) VALUES($1,$2)")
            .bind(owner_id)
            .bind(format!("ALICE@{unicode_domain}."))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO roster_change_log(owner_id,version,contact_jid,removed) VALUES($1,1,$2,FALSE)")
            .bind(owner_id)
            .bind(format!("ALICE@{unicode_domain}."))
            .execute(&pool)
            .await
            .unwrap();
        for resource in ["Phone", "phone"] {
            let jid = format!("BOB@{unicode_domain}./{resource}");
            sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)")
                .bind(owner_id)
                .bind(&jid)
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO mam_preference_jids(user_id,jid,policy) VALUES($1,$2,'always')",
            )
            .bind(owner_id)
            .bind(jid)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO federated_presence_pending(recipient_id,from_jid) VALUES($1,$2)")
            .bind(owner_id)
            .bind(format!("CAROL@{unicode_domain}."))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO muc_external_affiliations(room_id,jid,affiliation) VALUES($1,$2,'member')",
        )
        .bind(room_id)
        .bind(format!("dave@{unicode_domain}"))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO federation_runtime_rules(kind,domain) VALUES('blacklist',$1)")
            .bind(format!("ERIN@{unicode_domain}./Desktop"))
            .execute(&pool)
            .await
            .unwrap();

        canonicalize_authorization_identity_storage(&pool)
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT contact_jid FROM roster_items WHERE owner_id=$1",
            )
            .bind(owner_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            "alice@bücher.example"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT contact_jid FROM roster_change_log WHERE owner_id=$1 AND version=1",
            )
            .bind(owner_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            "alice@bücher.example"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT blocked_jid FROM blocked_jids WHERE owner_id=$1 ORDER BY blocked_jid",
            )
            .bind(owner_id)
            .fetch_all(&pool)
            .await
            .unwrap(),
            vec!["bob@bücher.example/Phone", "bob@bücher.example/phone"]
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT from_jid FROM federated_presence_pending WHERE recipient_id=$1",
            )
            .bind(owner_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            "carol@bücher.example"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT jid FROM mam_preference_jids WHERE user_id=$1 ORDER BY jid",
            )
            .bind(owner_id)
            .fetch_all(&pool)
            .await
            .unwrap(),
            vec!["bob@bücher.example/Phone", "bob@bücher.example/phone"]
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT jid FROM muc_external_affiliations WHERE room_id=$1",
            )
            .bind(room_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            "dave@bücher.example"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT domain FROM federation_runtime_rules WHERE kind='blacklist'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            "erin@bücher.example/Desktop"
        );

        let marker_before: (i64, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT transformed_rows,completed_at FROM jid_identity_migrations WHERE migration=$1",
        )
        .bind(MIGRATION)
        .fetch_one(&pool)
        .await
        .unwrap();
        canonicalize_authorization_identity_storage(&pool)
            .await
            .unwrap();
        let marker_after: (i64, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT transformed_rows,completed_at FROM jid_identity_migrations WHERE migration=$1",
        )
        .bind(MIGRATION)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(marker_before, marker_after);

        sqlx::query("DELETE FROM jid_identity_migrations WHERE migration=$1")
            .bind(MIGRATION)
            .execute(&pool)
            .await
            .unwrap();
        let collision_owner = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(collision_owner)
            .bind(format!("auth-collision-{}", Uuid::new_v4().simple()))
            .execute(&pool)
            .await
            .unwrap();
        for value in [
            "A\u{30a}LICE@B\u{fc}CHER.Example.",
            "\u{e5}lice@b\u{fc}cher.example",
        ] {
            sqlx::query("INSERT INTO roster_items(owner_id,contact_jid) VALUES($1,$2)")
                .bind(collision_owner)
                .bind(value)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO federation_runtime_rules(kind,domain) VALUES('whitelist',$1)")
            .bind("DIRTY@Example.test/Resource")
            .execute(&pool)
            .await
            .unwrap();

        let error = canonicalize_authorization_identity_storage(&pool)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("canonical collision"), "{error}");
        assert!(error.contains("roster_items"), "{error}");
        assert!(!sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration=$1)",
        )
        .bind(MIGRATION)
        .fetch_one(&pool)
        .await
        .unwrap());
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT domain FROM federation_runtime_rules WHERE kind='whitelist'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            "DIRTY@Example.test/Resource"
        );
    }
}
