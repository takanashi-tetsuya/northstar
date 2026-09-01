//! Exact RFC 7622 migration for JID-keyed profile PEP items.
//!
//! XEP-0292 contact vCards and XEP-0402 native bookmarks use a bare JID as
//! their PubSub ItemID.  This module rejects invalid identities, canonical
//! collisions, and payload/key mismatches before updating any row.  The
//! primary key and the stored `<item id>` are changed in the same transaction.

use anyhow::{Context, Result};
#[cfg(test)]
use sqlx::PgPool;
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeMap;
use uuid::Uuid;

const MIGRATION: &str = "profile-pep-item-jids-rfc7622-ulabel-v2";
const CANONICALIZER_VERSION: i32 = 2;
const PROFILE_JID_NODES: [&str; 2] = ["urn:xmpp:bookmarks:1", "urn:xmpp:contacts"];

#[derive(Clone, Debug)]
struct ProfileItemIdentity {
    owner_id: Uuid,
    node: String,
    original_id: String,
    canonical_id: String,
    canonical_payload: String,
}

pub(crate) fn canonical_profile_item_id(node: &str, item_id: &str) -> Result<String> {
    if !PROFILE_JID_NODES.contains(&node) {
        return Ok(item_id.to_owned());
    }
    let canonical = crate::jid::CanonicalJid::parse_bare(item_id).map_err(|error| {
        error.context(format!(
            "profile PEP node {node:?} requires a valid bare-JID ItemID; rejected {item_id:?}"
        ))
    })?;
    anyhow::ensure!(
        canonical.localpart().is_some(),
        "profile PEP node {node:?} requires an account bare-JID ItemID; rejected domain-only {item_id:?}"
    );
    Ok(canonical.to_string())
}

#[cfg(test)]
pub async fn canonicalize_profile_identity_storage(pool: &PgPool) -> Result<()> {
    let mut transaction = pool.begin().await?;
    canonicalize_profile_identity_storage_in_transaction(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) async fn canonicalize_profile_identity_storage_in_transaction(
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
    sqlx::query("LOCK TABLE pep_items IN ACCESS EXCLUSIVE MODE")
        .execute(&mut **transaction)
        .await
        .context(
            "timed out after 30 seconds waiting to lock JID-keyed profile PEP items; stop other Northstar nodes using this database, then restart the migration",
        )?;

    let identities = load_identities(transaction).await?;
    ensure_no_collisions(&identities)?;
    let mut transformed = 0_i64;
    for identity in identities
        .iter()
        .filter(|identity| identity.original_id != identity.canonical_id)
    {
        let updated = sqlx::query(
            "UPDATE pep_items SET item_id=$4,payload=$5
             WHERE owner_id=$1 AND node=$2 AND item_id=$3",
        )
        .bind(identity.owner_id)
        .bind(&identity.node)
        .bind(&identity.original_id)
        .bind(&identity.canonical_id)
        .bind(&identity.canonical_payload)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(
            updated == 1,
            "profile JID migration lost locked PEP item ({}, {:?}, {:?})",
            identity.owner_id,
            identity.node,
            identity.original_id
        );
        transformed += 1;
    }

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

async fn load_identities(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<ProfileItemIdentity>> {
    sqlx::query(
        "SELECT owner_id,node,item_id,payload FROM pep_items
         WHERE node=ANY($1) ORDER BY owner_id,node,item_id",
    )
    .bind(PROFILE_JID_NODES)
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        let owner_id: Uuid = row.get("owner_id");
        let node: String = row.get("node");
        let original_id: String = row.get("item_id");
        let original_payload: String = row.get("payload");
        let canonical_id = canonical_profile_item_id(&node, &original_id).with_context(|| {
            format!(
                "profile JID migration rejected pep_items row ({owner_id}, {node:?}, {original_id:?}); correct or remove this row and restart"
            )
        })?;
        let document = roxmltree::Document::parse(&original_payload).with_context(|| {
            format!(
                "profile JID migration found malformed XML in pep_items row ({owner_id}, {node:?}, {original_id:?}); correct or remove this row and restart"
            )
        })?;
        let item = document.root_element();
        anyhow::ensure!(
            item.tag_name().name() == "item"
                && item.tag_name().namespace() == Some("http://jabber.org/protocol/pubsub")
                && item.attribute("id") == Some(original_id.as_str()),
            "profile JID migration found a payload/root ItemID mismatch in pep_items row ({owner_id}, {node:?}, {original_id:?}); correct the stored <item id> or remove this row and restart"
        );
        let canonical_payload = if original_id == canonical_id {
            original_payload.clone()
        } else {
            crate::xmpp::xml_util::set_root_attribute(&original_payload, "id", &canonical_id)
        };
        Ok(ProfileItemIdentity {
            owner_id,
            node,
            original_id,
            canonical_id,
            canonical_payload,
        })
    })
    .collect()
}

fn ensure_no_collisions(rows: &[ProfileItemIdentity]) -> Result<()> {
    let mut identities = BTreeMap::<(Uuid, &str, &str), &str>::new();
    for row in rows {
        let key = (row.owner_id, row.node.as_str(), row.canonical_id.as_str());
        if let Some(previous) = identities.insert(key, row.original_id.as_str()) {
            anyhow::bail!(
                "profile JID migration found a canonical ItemID collision for owner {} node {:?}: {:?} and {:?} both map to {:?}; resolve the duplicate profile items explicitly and restart",
                row.owner_id,
                row.node,
                previous,
                row.original_id,
                row.canonical_id
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    async fn user(pool: &PgPool, prefix: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'profile-test')")
            .bind(id)
            .bind(format!("{prefix}{}", &id.simple().to_string()[..10]))
            .execute(pool)
            .await
            .unwrap();
        id
    }

    async fn node(pool: &PgPool, owner_id: Uuid, name: &str) {
        sqlx::query(
            "INSERT INTO pep_nodes(owner_id,node,access_model,max_items) VALUES($1,$2,'whitelist',100)",
        )
        .bind(owner_id)
        .bind(name)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn item(pool: &PgPool, owner_id: Uuid, node: &str, id: &str, payload_id: &str) {
        let payload = format!(
            "<item xmlns='http://jabber.org/protocol/pubsub' id='{}'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>Test</text></fn></vcard></item>",
            crate::state::attr_escape(payload_id)
        );
        sqlx::query("INSERT INTO pep_items(owner_id,node,item_id,payload) VALUES($1,$2,$3,$4)")
            .bind(owner_id)
            .bind(node)
            .bind(id)
            .bind(payload)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn reset_marker(pool: &PgPool) {
        sqlx::query("DELETE FROM jid_identity_migrations WHERE migration=$1")
            .bind(MIGRATION)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
    async fn postgres_profile_item_ids_fail_closed_and_restart_idempotently() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to a random isolated PostgreSQL schema");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        reset_marker(&pool).await;

        let exact_owner = user(&pool, "profileexact").await;
        for name in PROFILE_JID_NODES {
            node(&pool, exact_owner, name).await;
        }
        item(
            &pool,
            exact_owner,
            "urn:xmpp:contacts",
            "ALICE@BÜCHER.example",
            "ALICE@BÜCHER.example",
        )
        .await;
        item(
            &pool,
            exact_owner,
            "urn:xmpp:bookmarks:1",
            "ROOM@Conference.Example",
            "ROOM@Conference.Example",
        )
        .await;
        canonicalize_profile_identity_storage(&pool).await.unwrap();
        for (node, expected) in [
            ("urn:xmpp:contacts", "alice@bücher.example"),
            ("urn:xmpp:bookmarks:1", "room@conference.example"),
        ] {
            let (id, payload): (String, String) = sqlx::query_as(
                "SELECT item_id,payload FROM pep_items WHERE owner_id=$1 AND node=$2",
            )
            .bind(exact_owner)
            .bind(node)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(id, expected);
            assert!(payload.contains(&format!("id='{expected}'")));
        }
        canonicalize_profile_identity_storage(&pool).await.unwrap();
        let marker: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*),MAX(transformed_rows) FROM jid_identity_migrations WHERE migration=$1",
        )
        .bind(MIGRATION)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(marker, (1, 2));

        reset_marker(&pool).await;
        let collision_owner = user(&pool, "profilecollision").await;
        node(&pool, collision_owner, "urn:xmpp:contacts").await;
        item(
            &pool,
            collision_owner,
            "urn:xmpp:contacts",
            "BOB@BÜCHER.example",
            "BOB@BÜCHER.example",
        )
        .await;
        item(
            &pool,
            collision_owner,
            "urn:xmpp:contacts",
            "bob@bücher.example",
            "bob@bücher.example",
        )
        .await;
        let safe_owner = user(&pool, "profilesafe").await;
        node(&pool, safe_owner, "urn:xmpp:contacts").await;
        item(
            &pool,
            safe_owner,
            "urn:xmpp:contacts",
            "CAROL@Example.test",
            "CAROL@Example.test",
        )
        .await;
        let collision = canonicalize_profile_identity_storage(&pool)
            .await
            .unwrap_err()
            .to_string();
        assert!(collision.contains("canonical ItemID collision"));
        let safe_after: String = sqlx::query_scalar(
            "SELECT item_id FROM pep_items WHERE owner_id=$1 AND node='urn:xmpp:contacts'",
        )
        .bind(safe_owner)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(safe_after, "CAROL@Example.test");
        let marker: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration=$1)",
        )
        .bind(MIGRATION)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!marker);

        sqlx::query("DELETE FROM pep_items WHERE owner_id=$1")
            .bind(collision_owner)
            .execute(&pool)
            .await
            .unwrap();
        item(
            &pool,
            collision_owner,
            "urn:xmpp:contacts",
            "dave@example.test/Phone",
            "dave@example.test/Phone",
        )
        .await;
        let resource = format!(
            "{:#}",
            canonicalize_profile_identity_storage(&pool)
                .await
                .unwrap_err()
        );
        assert!(resource.contains("valid bare-JID ItemID"));
        let safe_after: String = sqlx::query_scalar(
            "SELECT item_id FROM pep_items WHERE owner_id=$1 AND node='urn:xmpp:contacts'",
        )
        .bind(safe_owner)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(safe_after, "CAROL@Example.test");

        sqlx::query("DELETE FROM pep_items WHERE owner_id=$1")
            .bind(collision_owner)
            .execute(&pool)
            .await
            .unwrap();
        item(
            &pool,
            collision_owner,
            "urn:xmpp:contacts",
            "dave@example.test",
            "eve@example.test",
        )
        .await;
        let mismatch = canonicalize_profile_identity_storage(&pool)
            .await
            .unwrap_err()
            .to_string();
        assert!(mismatch.contains("payload/root ItemID mismatch"));
        let marker: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration=$1)",
        )
        .bind(MIGRATION)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!marker);

        sqlx::query("DELETE FROM pep_items WHERE owner_id=$1")
            .bind(collision_owner)
            .execute(&pool)
            .await
            .unwrap();
        canonicalize_profile_identity_storage(&pool).await.unwrap();
        let canonical_safe: String = sqlx::query_scalar(
            "SELECT item_id FROM pep_items WHERE owner_id=$1 AND node='urn:xmpp:contacts'",
        )
        .bind(safe_owner)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(canonical_safe, "carol@example.test");
        canonicalize_profile_identity_storage(&pool).await.unwrap();
        pool.close().await;
    }
}
