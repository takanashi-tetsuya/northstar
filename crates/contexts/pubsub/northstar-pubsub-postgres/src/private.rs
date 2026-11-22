use anyhow::Result;
use northstar_pubsub_core::PubSubAccount;
use sqlx::{PgConnection, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateXmlWriteOutcome {
    Stored,
    QuotaExceeded,
    StaleAuthority,
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
    let mut connection = pool.acquire().await?;
    let rows = private_xml_rows(&mut connection, user_id, element_ns, &[element_name]).await?;
    Ok(rows.into_iter().next().map(|(_, xml)| xml))
}

async fn private_xml_rows(
    connection: &mut PgConnection,
    user_id: Uuid,
    namespace: &str,
    element_names: &[&str],
) -> Result<Vec<(String, String)>> {
    Ok(sqlx::query_as(
        "SELECT element_name, xml_data FROM private_xml
          WHERE user_id = $1 AND element_ns = $2 AND element_name = ANY($3::TEXT[])",
    )
    .bind(user_id)
    .bind(namespace)
    .bind(element_names)
    .fetch_all(connection)
    .await?)
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
    let mut transaction = begin_private_xml_snapshot(pool).await?;
    let snapshot = legacy_bookmark_snapshot_in_transaction(
        &mut transaction,
        user_id,
        private_namespace,
        modern_node,
        item_limit,
    )
    .await?;
    transaction.commit().await?;
    Ok(snapshot)
}

async fn begin_private_xml_snapshot(pool: &PgPool) -> Result<Transaction<'_, Postgres>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

async fn legacy_bookmark_snapshot_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    private_namespace: &str,
    modern_node: &str,
    item_limit: i64,
) -> Result<LegacyBookmarkSnapshot> {
    let private_xml = sqlx::query_scalar::<_, String>(
        "SELECT xml_data FROM private_xml
          WHERE user_id=$1 AND element_name='storage' AND element_ns=$2",
    )
    .bind(user_id)
    .bind(private_namespace)
    .fetch_optional(&mut **transaction)
    .await?;
    let modern_node_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pep_nodes WHERE owner_id=$1 AND node=$2)")
            .bind(user_id)
            .bind(modern_node)
            .fetch_one(&mut **transaction)
            .await?;
    let modern_items = sqlx::query(
        "SELECT item_id,payload FROM pep_items
          WHERE owner_id=$1 AND node=$2 ORDER BY item_id LIMIT $3",
    )
    .bind(user_id)
    .bind(modern_node)
    .bind(item_limit.clamp(1, super::PEP_MAX_ITEMS as i64))
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| (row.get("item_id"), row.get("payload")))
    .collect();
    Ok(LegacyBookmarkSnapshot {
        private_xml,
        modern_node_exists,
        modern_items,
    })
}

pub async fn lock_private_xml_owner(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<()> {
    // Locking the owning account serializes quota calculations across every
    // namespace. Row locks on existing private_xml entries alone are
    // insufficient when two first writes race into an empty account.
    // The runtime role has no UPDATE on users, so the exclusive account lock
    // goes through the reviewed row-lock capability.
    sqlx::query("SELECT id FROM northstar_lock_user_rows_update(ARRAY[$1::uuid])")
        .bind(user_id)
        .fetch_one(&mut **transaction)
        .await?;
    Ok(())
}

/// Atomically replace one or more XEP-0049 values without allowing concurrent
/// writers to exceed the per-account storage budget.
pub async fn set_private_xml_batch(
    pool: &PgPool,
    owner: &PubSubAccount,
    entries: &[PrivateXmlEntry<'_>],
    max_account_bytes: i64,
) -> Result<PrivateXmlWriteOutcome> {
    let mut transaction = pool.begin().await?;
    // Keep the account-wide quota lock and verify the captured session under it.
    let locked_owner = sqlx::query_scalar::<_, Uuid>(
        "SELECT locked.id FROM northstar_lock_user_rows_update(ARRAY[$1::uuid]) locked
          WHERE locked.username = $2 AND locked.auth_generation = $3 AND NOT locked.is_disabled",
    )
    .bind(owner.id)
    .bind(&owner.username)
    .bind(owner.auth_generation)
    .fetch_optional(&mut *transaction)
    .await?;
    if locked_owner.is_none() {
        transaction.rollback().await?;
        return Ok(PrivateXmlWriteOutcome::StaleAuthority);
    }
    let outcome = set_private_xml_batch_in_transaction(
        &mut transaction,
        owner.id,
        entries,
        max_account_bytes,
    )
    .await?;
    if outcome == PrivateXmlWriteOutcome::Stored {
        transaction.commit().await?;
    } else {
        transaction.rollback().await?;
    }
    Ok(outcome)
}

pub async fn set_private_xml_batch_in_transaction(
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
#[cfg(any(test, feature = "test-support"))]
pub async fn replace_bookmarks_and_private_xml(
    pool: &PgPool,
    user_id: Uuid,
    write: BookmarkCompatibilityWrite<'_>,
) -> Result<std::result::Result<BookmarkCompatibilityCommit, BookmarkCompatibilityFailure>> {
    replace_bookmarks_and_private_xml_with_outbox(pool, user_id, write, &[]).await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn replace_bookmarks_and_private_xml_with_outbox(
    pool: &PgPool,
    user_id: Uuid,
    write: BookmarkCompatibilityWrite<'_>,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<std::result::Result<BookmarkCompatibilityCommit, BookmarkCompatibilityFailure>> {
    replace_bookmarks_and_private_xml_inner(pool, user_id, write, outbox, true).await
}

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
use northstar_pubsub_application::private_storage::preserve_bookmark_extensions;

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarkCompatibilityCommit {
    pub previous_items: Vec<(String, String)>,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BookmarkCompatibilityFailure {
    Pep,
    PrivateQuota,
    ConcurrentChange,
}

mod application_repository {
    use super::{
        begin_private_xml_snapshot, legacy_bookmark_snapshot_in_transaction, private_xml_rows,
    };
    use anyhow::Result;
    use northstar_pubsub_application::private_storage::{
        LegacyBookmarkSnapshot, PrivateStorageRepository, PrivateXmlEntry, PrivateXmlReadEntry,
        PrivateXmlWriteOutcome, BOOKMARKS2, LEGACY_BOOKMARKS,
    };
    use northstar_pubsub_core::PubSubAccount;
    use sqlx::PgPool;
    use std::collections::HashMap;
    use uuid::Uuid;

    #[derive(Clone)]
    pub struct PostgresPrivateStorageRepository {
        pool: PgPool,
    }
    impl PostgresPrivateStorageRepository {
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }
    }
    impl PrivateStorageRepository for PostgresPrivateStorageRepository {
        async fn read_batch(
            &self,
            owner_id: Uuid,
            namespace: &str,
            element_names: &[&str],
        ) -> Result<Vec<PrivateXmlReadEntry>> {
            let mut transaction = begin_private_xml_snapshot(&self.pool).await?;
            let is_legacy = |name: &str| namespace == LEGACY_BOOKMARKS && name == "storage";
            let ordinary_names = element_names
                .iter()
                .copied()
                .filter(|&name| !is_legacy(name))
                .collect::<Vec<_>>();
            let mut ordinary = HashMap::new();
            if !ordinary_names.is_empty() {
                ordinary.extend(
                    private_xml_rows(&mut transaction, owner_id, namespace, &ordinary_names)
                        .await?,
                );
            }
            let legacy = if ordinary_names.len() != element_names.len() {
                Some(to_application_snapshot(
                    legacy_bookmark_snapshot_in_transaction(
                        &mut transaction,
                        owner_id,
                        LEGACY_BOOKMARKS,
                        BOOKMARKS2,
                        i64::from(crate::PEP_MAX_ITEMS),
                    )
                    .await?,
                ))
            } else {
                None
            };
            transaction.commit().await?;

            Ok(element_names
                .iter()
                .map(|&name| {
                    if let Some(snapshot) = legacy.as_ref().filter(|_| is_legacy(name)) {
                        PrivateXmlReadEntry::LegacyBookmarks(snapshot.clone())
                    } else {
                        ordinary
                            .get(name)
                            .cloned()
                            .map_or(PrivateXmlReadEntry::Absent, PrivateXmlReadEntry::Stored)
                    }
                })
                .collect())
        }

        async fn legacy_bookmark_snapshot(&self, owner_id: Uuid) -> Result<LegacyBookmarkSnapshot> {
            let snapshot = crate::legacy_bookmark_snapshot(
                &self.pool,
                owner_id,
                LEGACY_BOOKMARKS,
                BOOKMARKS2,
                i64::from(crate::PEP_MAX_ITEMS),
            )
            .await?;
            Ok(to_application_snapshot(snapshot))
        }

        async fn set_batch(
            &self,
            owner: &PubSubAccount,
            entries: &[PrivateXmlEntry<'_>],
            max_bytes: i64,
        ) -> Result<PrivateXmlWriteOutcome> {
            let entries = entries
                .iter()
                .map(|entry| crate::PrivateXmlEntry {
                    element_name: entry.element_name,
                    element_ns: entry.element_ns,
                    xml_data: entry.xml_data,
                })
                .collect::<Vec<_>>();
            Ok(
                match crate::set_private_xml_batch(&self.pool, owner, &entries, max_bytes).await? {
                    crate::PrivateXmlWriteOutcome::Stored => PrivateXmlWriteOutcome::Stored,
                    crate::PrivateXmlWriteOutcome::QuotaExceeded => {
                        PrivateXmlWriteOutcome::QuotaExceeded
                    }
                    crate::PrivateXmlWriteOutcome::StaleAuthority => {
                        PrivateXmlWriteOutcome::StaleAuthority
                    }
                },
            )
        }
    }

    fn to_application_snapshot(snapshot: super::LegacyBookmarkSnapshot) -> LegacyBookmarkSnapshot {
        LegacyBookmarkSnapshot {
            private_xml: snapshot.private_xml,
            modern_node_exists: snapshot.modern_node_exists,
            modern_items: snapshot.modern_items,
        }
    }
}
pub use application_repository::PostgresPrivateStorageRepository;

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_pubsub_application::private_storage::{
        LegacyBookmarkSnapshot as ApplicationBookmarkSnapshot, PrivateStorageRepository,
        PrivateStorageService, PrivateXmlEntry as ApplicationXmlEntry, PrivateXmlReadEntry,
        PrivateXmlWriteOutcome as ApplicationWriteOutcome, BOOKMARKS2, LEGACY_BOOKMARKS,
    };
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::time::Duration;

    struct PrivateXmlDatabase {
        options: PgConnectOptions,
        admin: PgPool,
        pool: PgPool,
        schema: String,
        owner: PubSubAccount,
    }

    impl PrivateXmlDatabase {
        async fn new() -> Self {
            let url = std::env::var("TEST_DATABASE_URL")
                .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
            let options = url.parse::<PgConnectOptions>().unwrap();
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect_with(options.clone())
                .await
                .unwrap();
            let schema = format!("xmpp_test_private_{}", Uuid::new_v4().simple());
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
                .execute(&admin)
                .await
                .unwrap();
            let pool = PgPoolOptions::new()
                .max_connections(8)
                .connect_with(options.clone().options([("search_path", schema.as_str())]))
                .await
                .unwrap();
            northstar_postgres::MIGRATOR.run(&pool).await.unwrap();
            let user_id = Uuid::new_v4();
            let username = format!("private-{}", &user_id.simple().to_string()[..12]);
            let auth_generation = sqlx::query_scalar(
                "INSERT INTO users (id, username, password_hash) VALUES ($1, $2, 'test')
                 RETURNING auth_generation",
            )
            .bind(user_id)
            .bind(&username)
            .fetch_one(&pool)
            .await
            .unwrap();
            Self {
                options,
                admin,
                pool,
                schema,
                owner: PubSubAccount {
                    id: user_id,
                    username,
                    auth_generation,
                },
            }
        }

        async fn named_pool(&self, purpose: &str, read_only: bool) -> (String, PgPool) {
            let application_name = format!("private-{}-{purpose}", self.owner.id.simple());
            let settings = [
                ("search_path", self.schema.as_str()),
                (
                    "default_transaction_read_only",
                    if read_only { "on" } else { "off" },
                ),
            ];
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect_with(
                    self.options
                        .clone()
                        .application_name(&application_name)
                        .options(settings),
                )
                .await
                .unwrap();
            (application_name, pool)
        }

        async fn cleanup(self) {
            sqlx::query("DELETE FROM users WHERE id=$1")
                .bind(self.owner.id)
                .execute(&self.pool)
                .await
                .unwrap();
            self.pool.close().await;
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "DROP SCHEMA {} CASCADE",
                self.schema
            )))
            .execute(&self.admin)
            .await
            .unwrap();
            self.admin.close().await;
        }
    }

    async fn wait_for_named_session_lock(pool: &PgPool, application_name: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                      WHERE datname = current_database() AND application_name = $1
                        AND wait_event_type = 'Lock')",
                )
                .bind(application_name)
                .fetch_one(pool)
                .await
                .unwrap();
                if waiting {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("session {application_name} never reached its lock wait"));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn private_xml_batch_and_account_quota_are_atomic() {
        let db = PrivateXmlDatabase::new().await;
        let pool = &db.pool;
        let owner = &db.owner;
        let user_id = owner.id;

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
            set_private_xml_batch(pool, owner, &[first, second], exact)
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
            set_private_xml_batch(pool, owner, &[too_large], exact)
                .await
                .unwrap(),
            PrivateXmlWriteOutcome::QuotaExceeded
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM private_xml WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(count, 2);

        sqlx::query("DELETE FROM private_xml WHERE user_id=$1")
            .bind(user_id)
            .execute(pool)
            .await
            .unwrap();
        let contender_bytes = i64::try_from("<a xmlns='urn:race'>same</a>".len()).unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = Vec::new();
        for (name, xml) in [
            ("a", "<a xmlns='urn:race'>same</a>"),
            ("b", "<b xmlns='urn:race'>same</b>"),
        ] {
            let pool = db.pool.clone();
            let owner = db.owner.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                set_private_xml_batch(
                    &pool,
                    &owner,
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
            .execute(pool)
            .await
            .unwrap();
        let bookmark_config = crate::default_pep_node_config("urn:xmpp:bookmarks:1");
        let old_private =
            "<storage xmlns='storage:bookmarks'><conference jid='old@conference.test'/></storage>";
        let old_item = "<item id='old@conference.test'><conference xmlns='urn:xmpp:bookmarks:1'><extensions><state xmlns='urn:example:state' minimized='true'/></extensions></conference></item>";
        let quotas = crate::PepQuotas {
            max_nodes: 10,
            max_storage_bytes: 1_000_000,
        };
        let mut old_items = vec![("old@conference.test".to_owned(), old_item.to_owned())];
        assert!(replace_bookmarks_and_private_xml(
            pool,
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
            pool,
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
                pool,
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
            get_private_xml(pool, user_id, "storage", "storage:bookmarks")
                .await
                .unwrap()
                .as_deref(),
            Some(old_private)
        );
        let items = crate::pep_items(pool, user_id, "urn:xmpp:bookmarks:1", None, 10)
            .await
            .unwrap();
        assert_eq!(
            items,
            vec![("old@conference.test".to_owned(), old_item.to_owned())]
        );

        db.cleanup().await;
    }

    const PRIVATE_NAMESPACE: &str = "urn:example:private";
    const PRIVATE_QUOTA: i64 = 1024;

    fn entry<'a>(name: &'a str, namespace: &'a str, xml: &'a str) -> PrivateXmlEntry<'a> {
        PrivateXmlEntry {
            element_name: name,
            element_ns: namespace,
            xml_data: xml,
        }
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn private_xml_read_batch_sees_one_revision_during_set() {
        let db = PrivateXmlDatabase::new().await;
        let old = [
            entry(
                "one",
                PRIVATE_NAMESPACE,
                "<one xmlns='urn:example:private'>old</one>",
            ),
            entry(
                "two",
                PRIVATE_NAMESPACE,
                "<two xmlns='urn:example:private'>old</two>",
            ),
        ];
        let new = [
            entry(
                "one",
                PRIVATE_NAMESPACE,
                "<one xmlns='urn:example:private'>new</one>",
            ),
            entry(
                "two",
                PRIVATE_NAMESPACE,
                "<two xmlns='urn:example:private'>new</two>",
            ),
        ];
        assert_eq!(
            set_private_xml_batch(&db.pool, &db.owner, &old, PRIVATE_QUOTA)
                .await
                .unwrap(),
            PrivateXmlWriteOutcome::Stored,
        );

        // Shadow the real table only on the reader. Pause after reading "one"
        // so a split read would start its "two" query after the writer commits.
        sqlx::query("CREATE TABLE private_read_pause (id INTEGER)")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE FUNCTION pause_private_read(row_xml TEXT) RETURNS TEXT LANGUAGE plpgsql VOLATILE AS $$
             BEGIN
                 PERFORM 1 FROM private_read_pause;
                 RETURN row_xml;
             END;
             $$",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        let (application_name, reader) = db.named_pool("ordinary", false).await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE TEMP VIEW private_xml AS
             SELECT user_id, element_name, element_ns,
                    CASE WHEN element_name = 'one' THEN {schema}.pause_private_read(xml_data)
                         ELSE xml_data END AS xml_data
               FROM {schema}.private_xml",
            schema = db.schema,
        )))
        .execute(&reader)
        .await
        .unwrap();
        let mut blocker = db.pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE private_read_pause IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await
            .unwrap();
        let owner_id = db.owner.id;
        let repository = PostgresPrivateStorageRepository::new(reader.clone());
        let task = tokio::spawn(async move {
            repository
                .read_batch(owner_id, PRIVATE_NAMESPACE, &["one", "two"])
                .await
                .unwrap()
        });
        wait_for_named_session_lock(&db.pool, &application_name).await;
        assert_eq!(
            set_private_xml_batch(&db.pool, &db.owner, &new, PRIVATE_QUOTA)
                .await
                .unwrap(),
            PrivateXmlWriteOutcome::Stored,
        );
        blocker.commit().await.unwrap();

        let old_entries = old.map(|entry| PrivateXmlReadEntry::Stored(entry.xml_data.to_owned()));
        assert_eq!(task.await.unwrap().as_slice(), &old_entries);
        let new_entries = new.map(|entry| PrivateXmlReadEntry::Stored(entry.xml_data.to_owned()));
        assert_eq!(
            PostgresPrivateStorageRepository::new(reader.clone())
                .read_batch(owner_id, PRIVATE_NAMESPACE, &["one", "two"])
                .await
                .unwrap()
                .as_slice(),
            &new_entries,
        );
        reader.close().await;
        db.cleanup().await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn private_xml_read_batch_shares_the_legacy_bookmark_revision() {
        let db = PrivateXmlDatabase::new().await;
        let owner_id = db.owner.id;
        let old_prefs = "<prefs xmlns='storage:bookmarks'>old</prefs>";
        let old_storage =
            "<storage xmlns='storage:bookmarks'><url url='https://old.test'/></storage>";
        let room = "room@conference.test";
        let old_item = "<item id='room@conference.test'><conference xmlns='urn:xmpp:bookmarks:1' name='old'/></item>";
        let new_item = "<item id='room@conference.test'><conference xmlns='urn:xmpp:bookmarks:1' name='new'/></item>";
        let mut items = vec![(room.to_owned(), old_item.to_owned())];
        assert!(replace_bookmarks_and_private_xml(
            &db.pool,
            owner_id,
            BookmarkCompatibilityWrite {
                private_entry: entry("storage", LEGACY_BOOKMARKS, old_storage),
                max_private_bytes: PRIVATE_QUOTA,
                bookmark_node: BOOKMARKS2,
                bookmark_config: &crate::default_pep_node_config(BOOKMARKS2),
                bookmark_items: &mut items,
                pep_quotas: crate::PepQuotas {
                    max_nodes: 10,
                    max_storage_bytes: 1_000_000,
                },
                expected_previous_items: None,
            },
        )
        .await
        .unwrap()
        .is_ok());
        assert_eq!(
            set_private_xml_batch(
                &db.pool,
                &db.owner,
                &[entry("prefs", LEGACY_BOOKMARKS, old_prefs)],
                PRIVATE_QUOTA,
            )
            .await
            .unwrap(),
            PrivateXmlWriteOutcome::Stored,
        );

        let (application_name, reader) = db.named_pool("legacy", false).await;
        let mut blocker = db.pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE pep_items IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await
            .unwrap();
        let repository = PostgresPrivateStorageRepository::new(reader.clone());
        let task = tokio::spawn(async move {
            repository
                .read_batch(owner_id, LEGACY_BOOKMARKS, &["storage", "prefs", "storage"])
                .await
                .unwrap()
        });
        wait_for_named_session_lock(&db.pool, &application_name).await;
        // Commit both bookmark representations under the table lock. Change
        // the ordinary sibling in the same transaction to expose split reads.
        let updated = sqlx::query(
            "UPDATE pep_items SET payload = $1 WHERE owner_id = $2 AND node = $3 AND item_id = $4",
        )
        .bind(new_item)
        .bind(owner_id)
        .bind(BOOKMARKS2)
        .bind(room)
        .execute(&mut *blocker)
        .await
        .unwrap();
        assert_eq!(updated.rows_affected(), 1);
        let new_storage =
            "<storage xmlns='storage:bookmarks'><url url='https://new.test'/></storage>";
        let new_prefs = "<prefs xmlns='storage:bookmarks'>new</prefs>";
        assert_eq!(
            set_private_xml_batch_in_transaction(
                &mut blocker,
                owner_id,
                &[
                    entry("storage", LEGACY_BOOKMARKS, new_storage),
                    entry("prefs", LEGACY_BOOKMARKS, new_prefs),
                ],
                PRIVATE_QUOTA,
            )
            .await
            .unwrap(),
            PrivateXmlWriteOutcome::Stored,
        );
        blocker.commit().await.unwrap();

        let legacy = PrivateXmlReadEntry::LegacyBookmarks(ApplicationBookmarkSnapshot {
            private_xml: Some(old_storage.to_owned()),
            modern_node_exists: true,
            modern_items: vec![(room.to_owned(), old_item.to_owned())],
        });
        assert_eq!(
            task.await.unwrap(),
            vec![
                legacy.clone(),
                PrivateXmlReadEntry::Stored(old_prefs.to_owned()),
                legacy,
            ],
        );
        reader.close().await;
        db.cleanup().await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn private_xml_set_rejects_authority_lost_while_waiting_for_the_account_lock() {
        let db = PrivateXmlDatabase::new().await;
        let mut owner = db.owner.clone();
        let (application_name, writer) = db.named_pool("set", false).await;
        let service = PrivateStorageService::new(
            PostgresPrivateStorageRepository::new(writer.clone()),
            100,
            8_000_000,
        );
        for revoke in [
            "UPDATE users SET auth_generation = auth_generation + 1 WHERE id = $1 RETURNING auth_generation",
            "UPDATE users SET is_disabled = TRUE WHERE id = $1 RETURNING auth_generation",
        ] {
            let mut blocker = db.pool.begin().await.unwrap();
            lock_private_xml_owner(&mut blocker, owner.id).await.unwrap();
            let captured_owner = owner.clone();
            let service = service.clone();
            let task = tokio::spawn(async move {
                service
                    .set_batch(
                        &captured_owner,
                        &[ApplicationXmlEntry {
                            element_name: "prefs",
                            element_ns: PRIVATE_NAMESPACE,
                            xml_data: "<prefs xmlns='urn:example:private'/>",
                        }],
                    )
                    .await
                    .unwrap()
            });
            wait_for_named_session_lock(&db.pool, &application_name).await;
            owner.auth_generation = sqlx::query_scalar(revoke)
                .bind(owner.id)
                .fetch_one(&mut *blocker)
                .await
                .unwrap();
            blocker.commit().await.unwrap();

            assert_eq!(task.await.unwrap(), ApplicationWriteOutcome::StaleAuthority);
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM private_xml WHERE user_id = $1")
                .bind(owner.id)
                .fetch_one(&db.pool)
                .await
                .unwrap();
            assert_eq!(count, 0);
        }
        writer.close().await;
        db.cleanup().await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn private_xml_read_batch_succeeds_on_a_read_only_connection() {
        let db = PrivateXmlDatabase::new().await;
        let prefs = "<prefs xmlns='storage:bookmarks'/>";
        let storage = "<storage xmlns='storage:bookmarks'/>";
        assert_eq!(
            set_private_xml_batch(
                &db.pool,
                &db.owner,
                &[
                    entry("prefs", LEGACY_BOOKMARKS, prefs),
                    entry("storage", LEGACY_BOOKMARKS, storage),
                ],
                PRIVATE_QUOTA,
            )
            .await
            .unwrap(),
            PrivateXmlWriteOutcome::Stored,
        );
        let (_, reader) = db.named_pool("readonly", true).await;
        let read_only: String = sqlx::query_scalar("SHOW default_transaction_read_only")
            .fetch_one(&reader)
            .await
            .unwrap();
        assert_eq!(read_only, "on");
        let entries = PostgresPrivateStorageRepository::new(reader.clone())
            .read_batch(
                db.owner.id,
                LEGACY_BOOKMARKS,
                &["prefs", "storage", "absent", "prefs"],
            )
            .await
            .unwrap();
        assert_eq!(
            entries,
            vec![
                PrivateXmlReadEntry::Stored(prefs.to_owned()),
                PrivateXmlReadEntry::LegacyBookmarks(ApplicationBookmarkSnapshot {
                    private_xml: Some(storage.to_owned()),
                    modern_node_exists: false,
                    modern_items: Vec::new(),
                }),
                PrivateXmlReadEntry::Absent,
                PrivateXmlReadEntry::Stored(prefs.to_owned()),
            ],
        );
        reader.close().await;
        db.cleanup().await;
    }
}
