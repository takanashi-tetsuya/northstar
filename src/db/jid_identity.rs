//! Exact RFC 7622 identity migration for persisted PubSub and PEP ownership.
//!
//! SQL `LOWER()` is not a JID canonicalizer: it neither applies the
//! UsernameCaseMapped/OpaqueString PRECIS profiles nor IDNA processing, and it
//! would corrupt case-sensitive resourceparts.  This migration therefore runs
//! through `crate::jid` while all affected tables are locked.  Every key-space
//! is checked for canonical collisions before the first row is changed.

use anyhow::{Context, Result};
#[cfg(test)]
use sqlx::PgPool;
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeMap;
use uuid::Uuid;

const MIGRATION: &str = "pubsub-pep-rfc7622-ulabel-v2";
const CANONICALIZER_VERSION: i32 = 2;

#[derive(Debug)]
struct TextIdentity {
    row_key: String,
    original: String,
    canonical: String,
}

fn canonical_bare(table: &str, row_key: &str, value: &str) -> Result<String> {
    crate::jid::canonical_bare_key(value).with_context(|| {
        format!(
            "JID identity migration rejected invalid bare JID in {table} row {row_key}: {value:?}; correct or remove this row and restart"
        )
    })
}

fn canonical_full(table: &str, row_key: &str, value: &str) -> Result<String> {
    crate::jid::canonicalize(value).with_context(|| {
        format!(
            "JID identity migration rejected invalid JID in {table} row {row_key}: {value:?}; correct or remove this row and restart"
        )
    })
}

fn ensure_no_collisions(table: &str, rows: &[TextIdentity]) -> Result<()> {
    let mut owners = BTreeMap::<&str, (&str, &str)>::new();
    for row in rows {
        if let Some((previous_row, previous_value)) = owners.insert(
            row.canonical.as_str(),
            (row.row_key.as_str(), row.original.as_str()),
        ) {
            anyhow::bail!(
                "JID identity migration found a canonical collision in {table}: rows {previous_row} ({previous_value:?}) and {} ({:?}) both map to {:?}; resolve the duplicate identities explicitly and restart",
                row.row_key,
                row.original,
                row.canonical
            );
        }
    }
    Ok(())
}

fn canonical_bare_array(table: &str, row_key: &str, values: Vec<String>) -> Result<Vec<String>> {
    let mut canonical = Vec::with_capacity(values.len());
    let mut seen = BTreeMap::<String, String>::new();
    for original in values {
        let prepared = canonical_bare(table, row_key, &original)?;
        if let Some(previous) = seen.insert(prepared.clone(), original.clone()) {
            anyhow::bail!(
                "JID identity migration found a canonical collision in {table} row {row_key}: array values {previous:?} and {original:?} both map to {prepared:?}; remove one entry and restart"
            );
        }
        canonical.push(prepared);
    }
    Ok(canonical)
}

/// Canonicalize all durable PubSub/PEP identity keys exactly once.
///
/// The marker is written in the same transaction as the rewrites.  If parsing,
/// collision detection, or any update fails, PostgreSQL rolls back every
/// change and leaves the marker absent so the next startup retries safely.
#[cfg(test)]
pub async fn canonicalize_identity_storage(pool: &PgPool) -> Result<()> {
    let mut transaction = pool.begin().await?;
    canonicalize_identity_storage_in_transaction(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) async fn canonicalize_identity_storage_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7622))")
        .bind(MIGRATION)
        .execute(&mut **transaction)
        .await?;

    let completed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration = $1 AND canonicalizer_version = $2)",
    )
    .bind(MIGRATION)
    .bind(CANONICALIZER_VERSION)
    .fetch_one(&mut **transaction)
    .await?;
    if completed {
        return Ok(());
    }

    // A rolling deployment may have an older server process using the same
    // database.  Table locks turn that into a bounded deployment pause instead
    // of a race between identity writes and collision detection.
    sqlx::query("SET LOCAL lock_timeout = '30s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "LOCK TABLE pubsub_nodes, pubsub_items, pubsub_affiliations, pubsub_subscriptions, pubsub_digest_queue, pep_nodes, pep_subscriptions IN ACCESS EXCLUSIVE MODE",
    )
    .execute(&mut **transaction)
    .await
    .context(
        "timed out after 30 seconds waiting to lock PubSub/PEP identity tables; stop other Northstar nodes using this database, then restart the migration",
    )?;

    let affiliation_rows = load_scoped_bare_identities(
        transaction,
        "pubsub_affiliations",
        "SELECT node_id::TEXT AS scope, jid AS value FROM pubsub_affiliations ORDER BY node_id, jid",
    )
    .await?;
    ensure_no_collisions("pubsub_affiliations(node_id,jid)", &affiliation_rows)?;

    let subscription_rows = load_scoped_bare_identities(
        transaction,
        "pubsub_subscriptions",
        "SELECT node_id::TEXT AS scope, jid AS value FROM pubsub_subscriptions ORDER BY node_id, jid",
    )
    .await?;
    ensure_no_collisions("pubsub_subscriptions(node_id,jid)", &subscription_rows)?;

    let pep_subscription_rows = load_pep_subscription_identities(transaction).await?;
    ensure_no_collisions(
        "pep_subscriptions(owner_id,node,subscriber_jid)",
        &pep_subscription_rows,
    )?;

    let node_rows = load_uuid_bare_identities(
        transaction,
        "pubsub_nodes.creator_jid",
        "SELECT id, creator_jid AS value FROM pubsub_nodes ORDER BY id",
    )
    .await?;
    let item_rows = load_uuid_bare_identities(
        transaction,
        "pubsub_items.publisher_jid",
        "SELECT id, publisher_jid AS value FROM pubsub_items ORDER BY id",
    )
    .await?;
    let digest_rows = load_uuid_bare_identities(
        transaction,
        "pubsub_digest_queue.subscriber_jid",
        "SELECT id, subscriber_jid AS value FROM pubsub_digest_queue ORDER BY id",
    )
    .await?;

    let node_whitelists =
        sqlx::query("SELECT id, children_association_whitelist FROM pubsub_nodes ORDER BY id")
            .fetch_all(&mut **transaction)
            .await?
            .into_iter()
            .map(|row| {
                let id: Uuid = row.get("id");
                let values: Vec<String> = row.get("children_association_whitelist");
                canonical_bare_array(
                    "pubsub_nodes.children_association_whitelist",
                    &id.to_string(),
                    values,
                )
                .map(|canonical| (id, canonical))
            })
            .collect::<Result<Vec<_>>>()?;

    let pep_whitelists = sqlx::query(
        "SELECT owner_id, node, access_whitelist FROM pep_nodes ORDER BY owner_id, node",
    )
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        let owner_id: Uuid = row.get("owner_id");
        let node: String = row.get("node");
        let values: Vec<String> = row.get("access_whitelist");
        let row_key = format!("{owner_id}/{node:?}");
        canonical_bare_array("pep_nodes.access_whitelist", &row_key, values)
            .map(|canonical| (owner_id, node, canonical))
    })
    .collect::<Result<Vec<_>>>()?;

    let mut transformed = 0_i64;
    transformed +=
        update_uuid_column(transaction, "pubsub_nodes", "creator_jid", &node_rows).await?;
    transformed +=
        update_uuid_column(transaction, "pubsub_items", "publisher_jid", &item_rows).await?;
    transformed +=
        update_scoped_column(transaction, "pubsub_affiliations", &affiliation_rows).await?;
    transformed +=
        update_scoped_column(transaction, "pubsub_subscriptions", &subscription_rows).await?;
    transformed += update_uuid_column(
        transaction,
        "pubsub_digest_queue",
        "subscriber_jid",
        &digest_rows,
    )
    .await?;
    transformed += update_pep_subscriptions(transaction, &pep_subscription_rows).await?;

    for (id, values) in node_whitelists {
        let result = sqlx::query(
            "UPDATE pubsub_nodes SET children_association_whitelist = $2 WHERE id = $1 AND children_association_whitelist IS DISTINCT FROM $2",
        )
        .bind(id)
        .bind(values)
        .execute(&mut **transaction)
        .await?;
        transformed += result.rows_affected() as i64;
    }
    for (owner_id, node, values) in pep_whitelists {
        let result = sqlx::query(
            "UPDATE pep_nodes SET access_whitelist = $3 WHERE owner_id = $1 AND node = $2 AND access_whitelist IS DISTINCT FROM $3",
        )
        .bind(owner_id)
        .bind(node)
        .bind(values)
        .execute(&mut **transaction)
        .await?;
        transformed += result.rows_affected() as i64;
    }

    sqlx::query(
        "INSERT INTO jid_identity_migrations (migration, canonicalizer_version, transformed_rows) VALUES ($1, $2, $3)",
    )
    .bind(MIGRATION)
    .bind(CANONICALIZER_VERSION)
    .bind(transformed)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn load_uuid_bare_identities(
    transaction: &mut Transaction<'_, Postgres>,
    table: &str,
    query: &str,
) -> Result<Vec<TextIdentity>> {
    sqlx::query(query)
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|row| {
            let id: Uuid = row.get("id");
            let original: String = row.get("value");
            let row_key = id.to_string();
            let canonical = canonical_bare(table, &row_key, &original)?;
            Ok(TextIdentity {
                row_key,
                original,
                canonical,
            })
        })
        .collect()
}

async fn load_scoped_bare_identities(
    transaction: &mut Transaction<'_, Postgres>,
    table: &str,
    query: &str,
) -> Result<Vec<TextIdentity>> {
    sqlx::query(query)
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|row| {
            let scope: String = row.get("scope");
            let original: String = row.get("value");
            let row_key = format!("{scope}/{original:?}");
            let canonical_jid = canonical_bare(table, &row_key, &original)?;
            Ok(TextIdentity {
                row_key: format!("{scope}/{canonical_jid}"),
                original,
                canonical: format!("{scope}\u{0}{canonical_jid}"),
            })
        })
        .collect()
}

async fn load_pep_subscription_identities(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<TextIdentity>> {
    sqlx::query("SELECT owner_id, node, subscriber_jid FROM pep_subscriptions ORDER BY owner_id, node, subscriber_jid")
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|row| {
            let owner_id: Uuid = row.get("owner_id");
            let node: String = row.get("node");
            let original: String = row.get("subscriber_jid");
            let source_key = format!("{owner_id}/{node:?}/{original:?}");
            let canonical_jid = canonical_full("pep_subscriptions.subscriber_jid", &source_key, &original)?;
            Ok(TextIdentity {
                row_key: format!("{owner_id}/{node:?}/{canonical_jid}"),
                original,
                canonical: format!("{owner_id}\u{0}{node}\u{0}{canonical_jid}"),
            })
        })
        .collect()
}

async fn update_uuid_column(
    transaction: &mut Transaction<'_, Postgres>,
    table: &str,
    column: &str,
    rows: &[TextIdentity],
) -> Result<i64> {
    let statement =
        format!("UPDATE {table} SET {column} = $2 WHERE id = $1 AND {column} IS DISTINCT FROM $2");
    let mut transformed = 0_i64;
    for row in rows {
        let id = Uuid::parse_str(&row.row_key)?;
        transformed += sqlx::query(&statement)
            .bind(id)
            .bind(&row.canonical)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
    }
    Ok(transformed)
}

async fn update_scoped_column(
    transaction: &mut Transaction<'_, Postgres>,
    table: &str,
    rows: &[TextIdentity],
) -> Result<i64> {
    let statement = format!(
        "UPDATE {table} SET jid = $3 WHERE node_id = $1 AND jid = $2 AND jid IS DISTINCT FROM $3"
    );
    let mut transformed = 0_i64;
    for row in rows {
        let (scope, canonical) = row
            .canonical
            .split_once('\0')
            .context("scoped canonical JID key is malformed")?;
        transformed += sqlx::query(&statement)
            .bind(Uuid::parse_str(scope)?)
            .bind(&row.original)
            .bind(canonical)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
    }
    Ok(transformed)
}

async fn update_pep_subscriptions(
    transaction: &mut Transaction<'_, Postgres>,
    rows: &[TextIdentity],
) -> Result<i64> {
    let mut transformed = 0_i64;
    for row in rows {
        let mut key = row.canonical.splitn(3, '\0');
        let owner_id = Uuid::parse_str(key.next().context("PEP owner key is missing")?)?;
        let node = key.next().context("PEP node key is missing")?;
        let canonical = key.next().context("PEP subscriber key is missing")?;
        transformed += sqlx::query(
            "UPDATE pep_subscriptions SET subscriber_jid = $4 WHERE owner_id = $1 AND node = $2 AND subscriber_jid = $3 AND subscriber_jid IS DISTINCT FROM $4",
        )
        .bind(owner_id)
        .bind(node)
        .bind(&row.original)
        .bind(canonical)
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
    fn collision_detection_uses_precis_and_idna_canonical_keys() {
        let first = "A\u{30a}LICE@B\u{fc}CHER.Example.";
        let second = "\u{e5}lice@b\u{fc}cher.example";
        let rows = [first, second]
            .into_iter()
            .map(|value| TextIdentity {
                row_key: value.to_owned(),
                original: value.to_owned(),
                canonical: canonical_bare("test", value, value).unwrap(),
            })
            .collect::<Vec<_>>();
        let error = ensure_no_collisions("test", &rows).unwrap_err().to_string();
        assert!(error.contains("canonical collision"));
        assert!(error.contains("bücher.example"));
    }

    #[test]
    fn full_jids_keep_opaque_resource_case_distinct() {
        let phone = canonical_full("test", "phone", "ALICE@B\u{fc}CHER.Example/Phone").unwrap();
        let lower = canonical_full("test", "lower", "alice@b\u{fc}cher.example/phone").unwrap();
        assert_eq!(phone, "alice@b\u{fc}cher.example/Phone");
        assert_ne!(phone, lower);
        assert!(ensure_no_collisions(
            "test",
            &[
                TextIdentity {
                    row_key: "phone".to_owned(),
                    original: phone.clone(),
                    canonical: phone
                },
                TextIdentity {
                    row_key: "lower".to_owned(),
                    original: lower.clone(),
                    canonical: lower
                },
            ]
        )
        .is_ok());
    }

    #[test]
    fn bare_keys_intentionally_discard_but_never_lowercase_resources() {
        assert_eq!(
            canonical_bare("test", "row", "ALICE@Example.test/Phone").unwrap(),
            "alice@example.test"
        );
        assert_eq!(
            canonical_full("test", "row", "ALICE@Example.test/Phone").unwrap(),
            "alice@example.test/Phone"
        );
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_migration_rewrites_exactly_rejects_collisions_and_is_idempotent() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        sqlx::query("DELETE FROM jid_identity_migrations WHERE migration = $1")
            .bind(MIGRATION)
            .execute(&pool)
            .await
            .unwrap();

        let owner_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, 'test-only')")
            .bind(owner_id)
            .bind(format!("jid-migration-{}", Uuid::new_v4().simple()))
            .execute(&pool)
            .await
            .unwrap();

        let node_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO pubsub_nodes (id, node, creator_jid, access_model, publish_model, max_items, children_association_whitelist) VALUES ($1, $2, $3, 'open', 'publishers', 10, $4)",
        )
        .bind(node_id)
        .bind(format!("jid-migration/{}", Uuid::new_v4()))
        .bind("A\u{30a}LICE@B\u{fc}CHER.Example./CreatorResource")
        .bind(vec!["CAROL@B\u{fc}CHER.Example.".to_owned()])
        .execute(&pool)
        .await
        .unwrap();
        let item_id = Uuid::new_v4();
        sqlx::query("INSERT INTO pubsub_items (id, node_id, item_id, publisher_jid, xml_payload) VALUES ($1, $2, 'item', $3, '<item/>')")
            .bind(item_id)
            .bind(node_id)
            .bind("A\u{30a}LICE@B\u{fc}CHER.Example./PublisherResource")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO pubsub_affiliations (node_id, jid, affiliation) VALUES ($1, $2, 'owner')",
        )
        .bind(node_id)
        .bind("A\u{30a}LICE@B\u{fc}CHER.Example./OwnerResource")
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO pubsub_subscriptions (node_id, jid, state, subid) VALUES ($1, $2, 'subscribed', $3)")
            .bind(node_id)
            .bind("DAVE@B\u{fc}CHER.Example./SubscriptionResource")
            .bind(Uuid::new_v4().to_string())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO pubsub_digest_queue (id, subscription_node_id, subscriber_jid, event_xml, deliver_after) VALUES ($1, $2, $3, '<event/>', NOW())")
            .bind(Uuid::new_v4())
            .bind(node_id)
            .bind("DAVE@B\u{fc}CHER.Example./DigestResource")
            .execute(&pool)
            .await
            .unwrap();

        let pep_node = format!("jid-migration:pep:{}", Uuid::new_v4());
        sqlx::query("INSERT INTO pep_nodes (owner_id, node, access_model, max_items, access_whitelist) VALUES ($1, $2, 'whitelist', 10, $3)")
            .bind(owner_id)
            .bind(&pep_node)
            .bind(vec!["ERIN@B\u{fc}CHER.Example.".to_owned()])
            .execute(&pool)
            .await
            .unwrap();
        for resource in ["Phone", "phone"] {
            sqlx::query("INSERT INTO pep_subscriptions (owner_id, node, subscriber_jid, subid) VALUES ($1, $2, $3, $4)")
                .bind(owner_id)
                .bind(&pep_node)
                .bind(format!("FRANK@B\u{fc}CHER.Example./{resource}"))
                .bind(Uuid::new_v4().to_string())
                .execute(&pool)
                .await
                .unwrap();
        }

        canonicalize_identity_storage(&pool).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT creator_jid FROM pubsub_nodes WHERE id = $1")
                .bind(node_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            "\u{e5}lice@b\u{fc}cher.example"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT publisher_jid FROM pubsub_items WHERE id = $1")
                .bind(item_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            "\u{e5}lice@b\u{fc}cher.example"
        );
        assert_eq!(
            sqlx::query_scalar::<_, Vec<String>>(
                "SELECT children_association_whitelist FROM pubsub_nodes WHERE id = $1"
            )
            .bind(node_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            vec!["carol@bücher.example"]
        );
        assert_eq!(
            sqlx::query_scalar::<_, Vec<String>>(
                "SELECT access_whitelist FROM pep_nodes WHERE owner_id = $1 AND node = $2"
            )
            .bind(owner_id)
            .bind(&pep_node)
            .fetch_one(&pool)
            .await
            .unwrap(),
            vec!["erin@bücher.example"]
        );
        let resources = sqlx::query_scalar::<_, String>("SELECT subscriber_jid FROM pep_subscriptions WHERE owner_id = $1 AND node = $2 ORDER BY subscriber_jid")
            .bind(owner_id)
            .bind(&pep_node)
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(
            resources,
            vec!["frank@bücher.example/Phone", "frank@bücher.example/phone"]
        );

        let marker_before: (i64, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT transformed_rows, completed_at FROM jid_identity_migrations WHERE migration = $1",
        )
        .bind(MIGRATION)
        .fetch_one(&pool)
        .await
        .unwrap();
        canonicalize_identity_storage(&pool).await.unwrap();
        let marker_after: (i64, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT transformed_rows, completed_at FROM jid_identity_migrations WHERE migration = $1",
        )
        .bind(MIGRATION)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(marker_before, marker_after);

        sqlx::query("DELETE FROM jid_identity_migrations WHERE migration = $1")
            .bind(MIGRATION)
            .execute(&pool)
            .await
            .unwrap();
        let collision_node = Uuid::new_v4();
        sqlx::query("INSERT INTO pubsub_nodes (id, node, creator_jid, access_model, publish_model, max_items) VALUES ($1, $2, 'BOB@Example.test/StillDirty', 'open', 'publishers', 10)")
            .bind(collision_node)
            .bind(format!("jid-collision/{}", Uuid::new_v4()))
            .execute(&pool)
            .await
            .unwrap();
        for jid in [
            "A\u{30a}LICE@B\u{fc}CHER.Example.",
            "\u{e5}lice@b\u{fc}cher.example",
        ] {
            sqlx::query("INSERT INTO pubsub_affiliations (node_id, jid, affiliation) VALUES ($1, $2, 'member')")
                .bind(collision_node)
                .bind(jid)
                .execute(&pool)
                .await
                .unwrap();
        }
        let error = canonicalize_identity_storage(&pool)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("canonical collision"), "{error}");
        assert!(error.contains("pubsub_affiliations"), "{error}");
        assert!(!sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration = $1)"
        )
        .bind(MIGRATION)
        .fetch_one(&pool)
        .await
        .unwrap());
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT creator_jid FROM pubsub_nodes WHERE id = $1")
                .bind(collision_node)
                .fetch_one(&pool)
                .await
                .unwrap(),
            "BOB@Example.test/StillDirty"
        );
    }
}
