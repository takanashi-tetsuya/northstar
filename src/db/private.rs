use anyhow::Result;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateXmlWriteOutcome {
    Stored,
    QuotaExceeded,
}

pub struct PrivateXmlEntry<'a> {
    pub element_name: &'a str,
    pub element_ns: &'a str,
    pub xml_data: &'a str,
}

pub async fn get_private_xml(
    pool: &PgPool,
    user_id: Uuid,
    element_name: &str,
    element_ns: &str,
) -> Result<Option<String>> {
    let result = sqlx::query_scalar::<_, String>(
        "SELECT xml_data FROM private_xml WHERE user_id = $1 AND element_name = $2 AND element_ns = $3",
    )
    .bind(user_id)
    .bind(element_name)
    .bind(element_ns)
    .fetch_optional(pool)
    .await?;

    Ok(result)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyBookmarkSnapshot {
    pub private_xml: Option<String>,
    pub modern_node_exists: bool,
    pub modern_items: Vec<(String, String)>,
}

/// Read the legacy private-storage document and its XEP-0402 projection from
/// one repeatable-read snapshot.  Reading these relations independently can
/// otherwise produce a document assembled from two different bookmark
/// revisions while a compatibility write commits.
pub async fn legacy_bookmark_snapshot(
    pool: &PgPool,
    user_id: Uuid,
    private_namespace: &str,
    modern_node: &str,
    item_limit: i64,
) -> Result<LegacyBookmarkSnapshot> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let private_xml = sqlx::query_scalar::<_, String>(
        "SELECT xml_data FROM private_xml
          WHERE user_id=$1 AND element_name='storage' AND element_ns=$2",
    )
    .bind(user_id)
    .bind(private_namespace)
    .fetch_optional(&mut *transaction)
    .await?;
    let modern_node_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pep_nodes WHERE owner_id=$1 AND node=$2)")
            .bind(user_id)
            .bind(modern_node)
            .fetch_one(&mut *transaction)
            .await?;
    let modern_items = sqlx::query(
        "SELECT item_id,payload FROM pep_items
          WHERE owner_id=$1 AND node=$2 ORDER BY item_id LIMIT $3",
    )
    .bind(user_id)
    .bind(modern_node)
    .bind(item_limit.clamp(1, super::PEP_MAX_ITEMS as i64))
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .map(|row| (row.get("item_id"), row.get("payload")))
    .collect();
    transaction.commit().await?;
    Ok(LegacyBookmarkSnapshot {
        private_xml,
        modern_node_exists,
        modern_items,
    })
}

pub(crate) async fn lock_private_xml_owner(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<()> {
    // Locking the owning account serializes quota calculations across every
    // namespace. Row locks on existing private_xml entries alone are
    // insufficient when two first writes race into an empty account.
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .fetch_one(&mut **transaction)
        .await?;
    Ok(())
}

/// Atomically replace one or more XEP-0049 values without allowing concurrent
/// writers to exceed the per-account storage budget.
pub async fn set_private_xml_batch(
    pool: &PgPool,
    user_id: Uuid,
    entries: &[PrivateXmlEntry<'_>],
    max_account_bytes: i64,
) -> Result<PrivateXmlWriteOutcome> {
    let mut transaction = pool.begin().await?;
    lock_private_xml_owner(&mut transaction, user_id).await?;
    let outcome =
        set_private_xml_batch_in_transaction(&mut transaction, user_id, entries, max_account_bytes)
            .await?;
    if outcome == PrivateXmlWriteOutcome::Stored {
        transaction.commit().await?;
    } else {
        transaction.rollback().await?;
    }
    Ok(outcome)
}

pub(crate) async fn set_private_xml_batch_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    entries: &[PrivateXmlEntry<'_>],
    max_account_bytes: i64,
) -> Result<PrivateXmlWriteOutcome> {
    let existing_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(octet_length(xml_data)), 0)::BIGINT FROM private_xml WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await?;
    let replaced_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(octet_length(xml_data)), 0)::BIGINT
           FROM private_xml
          WHERE user_id = $1
            AND (element_name, element_ns) IN (SELECT * FROM UNNEST($2::TEXT[], $3::TEXT[]))",
    )
    .bind(user_id)
    .bind(
        entries
            .iter()
            .map(|entry| entry.element_name)
            .collect::<Vec<_>>(),
    )
    .bind(
        entries
            .iter()
            .map(|entry| entry.element_ns)
            .collect::<Vec<_>>(),
    )
    .fetch_one(&mut **transaction)
    .await?;
    let new_bytes = entries.iter().try_fold(0_i64, |total, entry| {
        i64::try_from(entry.xml_data.len())
            .ok()
            .and_then(|bytes| total.checked_add(bytes))
    });
    let Some(projected_bytes) = new_bytes.and_then(|bytes| {
        existing_bytes
            .checked_sub(replaced_bytes)
            .and_then(|remaining| remaining.checked_add(bytes))
    }) else {
        return Ok(PrivateXmlWriteOutcome::QuotaExceeded);
    };
    if projected_bytes > max_account_bytes {
        return Ok(PrivateXmlWriteOutcome::QuotaExceeded);
    }

    for entry in entries {
        sqlx::query(
            "INSERT INTO private_xml (user_id, element_name, element_ns, xml_data)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, element_name, element_ns)
             DO UPDATE SET xml_data = EXCLUDED.xml_data",
        )
        .bind(user_id)
        .bind(entry.element_name)
        .bind(entry.element_ns)
        .bind(entry.xml_data)
        .execute(&mut **transaction)
        .await?;
    }

    Ok(PrivateXmlWriteOutcome::Stored)
}

/// Atomically makes a legacy XEP-0048/XEP-0049 bookmark document and its
/// XEP-0402 item projection visible.  This is the compatibility commit point:
/// a quota or node-policy failure leaves both representations unchanged.
#[cfg(test)]
pub async fn replace_bookmarks_and_private_xml(
    pool: &PgPool,
    user_id: Uuid,
    write: BookmarkCompatibilityWrite<'_>,
) -> Result<std::result::Result<BookmarkCompatibilityCommit, BookmarkCompatibilityFailure>> {
    replace_bookmarks_and_private_xml_with_outbox(pool, user_id, write, &[]).await
}

#[cfg(test)]
pub async fn replace_bookmarks_and_private_xml_with_outbox(
    pool: &PgPool,
    user_id: Uuid,
    write: BookmarkCompatibilityWrite<'_>,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<std::result::Result<BookmarkCompatibilityCommit, BookmarkCompatibilityFailure>> {
    replace_bookmarks_and_private_xml_inner(pool, user_id, write, outbox, true).await
}

#[cfg(test)]
async fn replace_bookmarks_and_private_xml_inner(
    pool: &PgPool,
    user_id: Uuid,
    write: BookmarkCompatibilityWrite<'_>,
    outbox: &[super::PubSubOutboxInsert],
    preserve_extensions: bool,
) -> Result<std::result::Result<BookmarkCompatibilityCommit, BookmarkCompatibilityFailure>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
        .bind(user_id.to_string())
        .execute(&mut *transaction)
        .await?;
    lock_private_xml_owner(&mut transaction, user_id).await?;
    let previous_items = sqlx::query(
        "SELECT item_id,payload FROM pep_items WHERE owner_id=$1 AND node=$2 ORDER BY item_id FOR UPDATE",
    )
    .bind(user_id)
    .bind(write.bookmark_node)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .map(|row| (row.get("item_id"), row.get("payload")))
    .collect::<Vec<(String, String)>>();
    if write
        .expected_previous_items
        .is_some_and(|expected| expected != previous_items)
    {
        transaction.rollback().await?;
        return Ok(Err(BookmarkCompatibilityFailure::ConcurrentChange));
    }
    if preserve_extensions {
        preserve_bookmark_extensions(write.bookmark_items, &previous_items);
    }
    let borrowed = write
        .bookmark_items
        .iter()
        .map(|(item_id, payload)| (item_id.as_str(), payload.as_str()))
        .collect::<Vec<_>>();
    let pep_outcome = super::pep::replace_pep_items_in_transaction(
        &mut transaction,
        user_id,
        write.bookmark_node,
        write.bookmark_config,
        &borrowed,
        write.pep_quotas,
    )
    .await?;
    if pep_outcome != super::PepPublishOutcome::Published {
        transaction.rollback().await?;
        return Ok(Err(BookmarkCompatibilityFailure::Pep));
    }
    let private_outcome = set_private_xml_batch_in_transaction(
        &mut transaction,
        user_id,
        &[write.private_entry],
        write.max_private_bytes,
    )
    .await?;
    if private_outcome != PrivateXmlWriteOutcome::Stored {
        transaction.rollback().await?;
        return Ok(Err(BookmarkCompatibilityFailure::PrivateQuota));
    }
    super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
    transaction.commit().await?;
    Ok(Ok(BookmarkCompatibilityCommit { previous_items }))
}

#[cfg(test)]
pub struct BookmarkCompatibilityWrite<'a> {
    pub private_entry: PrivateXmlEntry<'a>,
    pub max_private_bytes: i64,
    pub bookmark_node: &'a str,
    pub bookmark_config: &'a super::PepNodeConfig,
    pub bookmark_items: &'a mut [(String, String)],
    pub pep_quotas: super::PepQuotas,
    /// Optional optimistic snapshot captured while building the exact event
    /// bytes. The account advisory lock re-checks it before any write, so a
    /// concurrent compatibility update cannot commit a stale notification.
    pub expected_previous_items: Option<&'a [(String, String)]>,
}

pub(crate) fn preserve_bookmark_extensions(
    items: &mut [(String, String)],
    previous: &[(String, String)],
) {
    let previous = previous
        .iter()
        .map(|(item_id, payload)| (item_id.as_str(), payload.as_str()))
        .collect::<std::collections::HashMap<_, _>>();
    for (item_id, item_xml) in items {
        let Some(previous_xml) = previous.get(item_id.as_str()) else {
            continue;
        };
        let Ok(document) = roxmltree::Document::parse(previous_xml) else {
            continue;
        };
        let Some(extensions) = document.descendants().find(|node| {
            node.is_element()
                && node.tag_name().name() == "extensions"
                && node.tag_name().namespace() == Some("urn:xmpp:bookmarks:1")
        }) else {
            continue;
        };
        if let Some(end) = item_xml.rfind("</conference>") {
            item_xml.insert_str(end, &previous_xml[extensions.range()]);
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarkCompatibilityCommit {
    pub previous_items: Vec<(String, String)>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BookmarkCompatibilityFailure {
    Pep,
    PrivateQuota,
    ConcurrentChange,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn private_xml_batch_and_account_quota_are_atomic() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("xmpp_test_private_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {connection_schema}");
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, 'test')")
            .bind(user_id)
            .bind(format!("private-{}", &user_id.simple().to_string()[..12]))
            .execute(&pool)
            .await
            .unwrap();

        let first = PrivateXmlEntry {
            element_name: "one",
            element_ns: "urn:example:private",
            xml_data: "<one xmlns='urn:example:private'>1234</one>",
        };
        let second = PrivateXmlEntry {
            element_name: "two",
            element_ns: "urn:example:private",
            xml_data: "<two xmlns='urn:example:private'>5678</two>",
        };
        let exact = i64::try_from(first.xml_data.len() + second.xml_data.len()).unwrap();
        assert_eq!(
            set_private_xml_batch(&pool, user_id, &[first, second], exact)
                .await
                .unwrap(),
            PrivateXmlWriteOutcome::Stored
        );
        let too_large = PrivateXmlEntry {
            element_name: "three",
            element_ns: "urn:example:private",
            xml_data: "<three xmlns='urn:example:private'>overflow</three>",
        };
        assert_eq!(
            set_private_xml_batch(&pool, user_id, &[too_large], exact)
                .await
                .unwrap(),
            PrivateXmlWriteOutcome::QuotaExceeded
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM private_xml WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 2);

        sqlx::query("DELETE FROM private_xml WHERE user_id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        let contender_bytes = i64::try_from("<a xmlns='urn:race'>same</a>".len()).unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = Vec::new();
        for (name, xml) in [
            ("a", "<a xmlns='urn:race'>same</a>"),
            ("b", "<b xmlns='urn:race'>same</b>"),
        ] {
            let pool = pool.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                set_private_xml_batch(
                    &pool,
                    user_id,
                    &[PrivateXmlEntry {
                        element_name: name,
                        element_ns: "urn:race",
                        xml_data: xml,
                    }],
                    contender_bytes,
                )
                .await
                .unwrap()
            }));
        }
        barrier.wait().await;
        let outcomes = futures::future::join_all(tasks)
            .await
            .into_iter()
            .map(|result| result.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == PrivateXmlWriteOutcome::Stored)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == PrivateXmlWriteOutcome::QuotaExceeded)
                .count(),
            1
        );

        sqlx::query("DELETE FROM private_xml WHERE user_id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        let bookmark_config = db::default_pep_node_config("urn:xmpp:bookmarks:1");
        let old_private =
            "<storage xmlns='storage:bookmarks'><conference jid='old@conference.test'/></storage>";
        let old_item = "<item id='old@conference.test'><conference xmlns='urn:xmpp:bookmarks:1'><extensions><state xmlns='urn:example:state' minimized='true'/></extensions></conference></item>";
        let quotas = db::PepQuotas {
            max_nodes: 10,
            max_storage_bytes: 1_000_000,
        };
        let mut old_items = vec![("old@conference.test".to_owned(), old_item.to_owned())];
        assert!(replace_bookmarks_and_private_xml(
            &pool,
            user_id,
            BookmarkCompatibilityWrite {
                private_entry: PrivateXmlEntry {
                    element_name: "storage",
                    element_ns: "storage:bookmarks",
                    xml_data: old_private,
                },
                max_private_bytes: 1024,
                bookmark_node: "urn:xmpp:bookmarks:1",
                bookmark_config: &bookmark_config,
                bookmark_items: &mut old_items,
                pep_quotas: quotas,
                expected_previous_items: None,
            },
        )
        .await
        .unwrap()
        .is_ok());
        let mut duplicate_items = vec![(
            "old@conference.test".to_owned(),
            "<item id='old@conference.test'><conference xmlns='urn:xmpp:bookmarks:1'></conference></item>".to_owned(),
        )];
        let commit = replace_bookmarks_and_private_xml(
            &pool,
            user_id,
            BookmarkCompatibilityWrite {
                private_entry: PrivateXmlEntry {
                    element_name: "storage",
                    element_ns: "storage:bookmarks",
                    xml_data: old_private,
                },
                max_private_bytes: 1024,
                bookmark_node: "urn:xmpp:bookmarks:1",
                bookmark_config: &bookmark_config,
                bookmark_items: &mut duplicate_items,
                pep_quotas: quotas,
                expected_previous_items: None,
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert!(duplicate_items[0].1.contains("urn:example:state"));
        assert_eq!(commit.previous_items, duplicate_items);
        let new_private =
            "<storage xmlns='storage:bookmarks'><conference jid='new@conference.test'/></storage>";
        let new_item =
            "<item id='new@conference.test'><conference xmlns='urn:xmpp:bookmarks:1'/></item>";
        let mut new_items = vec![("new@conference.test".to_owned(), new_item.to_owned())];
        assert_eq!(
            replace_bookmarks_and_private_xml(
                &pool,
                user_id,
                BookmarkCompatibilityWrite {
                    private_entry: PrivateXmlEntry {
                        element_name: "storage",
                        element_ns: "storage:bookmarks",
                        xml_data: new_private,
                    },
                    max_private_bytes: 1,
                    bookmark_node: "urn:xmpp:bookmarks:1",
                    bookmark_config: &bookmark_config,
                    bookmark_items: &mut new_items,
                    pep_quotas: quotas,
                    expected_previous_items: None,
                },
            )
            .await
            .unwrap(),
            Err(BookmarkCompatibilityFailure::PrivateQuota)
        );
        assert_eq!(
            get_private_xml(&pool, user_id, "storage", "storage:bookmarks")
                .await
                .unwrap()
                .as_deref(),
            Some(old_private)
        );
        let items = db::pep_items(&pool, user_id, "urn:xmpp:bookmarks:1", None, 10)
            .await
            .unwrap();
        assert_eq!(
            items,
            vec![("old@conference.test".to_owned(), old_item.to_owned())]
        );

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
