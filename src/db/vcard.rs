use anyhow::Result;
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Builds the durable XEP-0084 notification projection from the exact
/// explicit-subscription snapshot taken while the PEP node is locked.
///
/// XML belongs to the application/protocol boundary, while this repository
/// owns the transaction. A synchronous callback keeps those responsibilities
/// separated without yielding or opening another database connection inside
/// the critical section.
#[cfg(test)]
pub trait ConvertedAvatarOutboxFactory: Send + Sync {
    fn build(&self, subscriber_jids: &[String]) -> Result<Vec<super::PubSubOutboxInsert>>;
}

#[cfg(test)]
impl<F> ConvertedAvatarOutboxFactory for F
where
    F: Fn(&[String]) -> Result<Vec<super::PubSubOutboxInsert>> + Send + Sync,
{
    fn build(&self, subscriber_jids: &[String]) -> Result<Vec<super::PubSubOutboxInsert>> {
        self(subscriber_jids)
    }
}

pub struct VCardRecord {
    pub payload_vcard_temp: Option<String>,
    pub avatar_hash: Option<String>,
}

pub async fn get_vcard(pool: &PgPool, user_id: Uuid) -> Result<VCardRecord> {
    let row = sqlx::query("SELECT payload, avatar_hash FROM vcards WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    if let Some(row) = row {
        Ok(VCardRecord {
            payload_vcard_temp: row.try_get("payload")?,
            avatar_hash: row.try_get("avatar_hash")?,
        })
    } else {
        Ok(VCardRecord {
            payload_vcard_temp: None,
            avatar_hash: None,
        })
    }
}

/// Commits a legacy vCard write and the server-generated XEP-0084 data and
/// metadata items as one account-scoped transaction.  The metadata item is
/// the public avatar switch; no observer can therefore see it without the
/// matching vCard fallback or after a rejected quota/precondition check.
#[cfg(test)]
pub async fn set_vcard_with_converted_avatar(
    pool: &PgPool,
    user_id: Uuid,
    payload: &str,
    avatar_hash: Option<&str>,
    data_item: Option<(&str, &str)>,
    metadata_item: (&str, &str),
    quotas: super::PepQuotas,
) -> Result<super::PepPublishOutcome> {
    let empty_outbox = |_subscribers: &[String]| Ok(Vec::new());
    set_vcard_with_converted_avatar_and_outbox(
        pool,
        user_id,
        payload,
        avatar_hash,
        data_item,
        metadata_item,
        quotas,
        &empty_outbox,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub async fn set_vcard_with_converted_avatar_and_outbox(
    pool: &PgPool,
    user_id: Uuid,
    payload: &str,
    avatar_hash: Option<&str>,
    data_item: Option<(&str, &str)>,
    metadata_item: (&str, &str),
    quotas: super::PepQuotas,
    outbox_factory: &dyn ConvertedAvatarOutboxFactory,
) -> Result<super::PepPublishOutcome> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
        .bind(user_id.to_string())
        .execute(&mut *transaction)
        .await?;
    // PEP subscription mutations use this node-scoped lock. Snapshotting the
    // audience only after it is held gives subscribe/unsubscribe and the
    // avatar publication one unambiguous serial order.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 5))")
        .bind(format!("{user_id}:urn:xmpp:avatar:metadata"))
        .execute(&mut *transaction)
        .await?;
    if !avatar_node_compatible(&mut transaction, user_id, "urn:xmpp:avatar:data", false).await?
        || !avatar_node_compatible(&mut transaction, user_id, "urn:xmpp:avatar:metadata", true)
            .await?
    {
        transaction.rollback().await?;
        return Ok(super::PepPublishOutcome::PreconditionFailed);
    }
    let subscriber_jids = sqlx::query_scalar::<_, String>(
        "SELECT subscriber_jid FROM pep_subscriptions
          WHERE owner_id=$1 AND node='urn:xmpp:avatar:metadata'
            AND state='subscribed'
          ORDER BY subscriber_jid",
    )
    .bind(user_id)
    .fetch_all(&mut *transaction)
    .await?;
    let outbox = match outbox_factory.build(&subscriber_jids) {
        Ok(outbox) => outbox,
        Err(error) => {
            transaction.rollback().await?;
            return Err(error);
        }
    };
    if let Some(data_item) = data_item {
        let data_config = super::default_pep_node_config("urn:xmpp:avatar:data");
        let outcome = super::pep::publish_pep_items_in_transaction(
            &mut transaction,
            user_id,
            "urn:xmpp:avatar:data",
            &data_config,
            false,
            &[data_item],
            quotas,
        )
        .await?;
        if outcome != super::PepPublishOutcome::Published {
            transaction.rollback().await?;
            return Ok(outcome);
        }
    }
    let metadata_config = super::default_pep_node_config("urn:xmpp:avatar:metadata");
    let outcome = super::pep::publish_pep_items_in_transaction(
        &mut transaction,
        user_id,
        "urn:xmpp:avatar:metadata",
        &metadata_config,
        false,
        &[metadata_item],
        quotas,
    )
    .await?;
    if outcome != super::PepPublishOutcome::Published {
        transaction.rollback().await?;
        return Ok(outcome);
    }
    upsert_vcard_in_transaction(&mut transaction, user_id, payload, avatar_hash).await?;
    super::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
    transaction.commit().await?;
    Ok(super::PepPublishOutcome::Published)
}

/// Commits an owner publication to the avatar metadata node together with the
/// XEP-0398 vCard projection.  The already-published data item is deliberately
/// not rewritten; its hash and byte length are validated by the protocol
/// layer immediately before entering this transaction.
#[cfg(test)]
pub struct AvatarMetadataWrite<'a> {
    pub requested: &'a super::PepNodeConfig,
    pub enforce_preconditions: bool,
    pub items: &'a [(&'a str, &'a str)],
    pub required_data: Option<(&'a str, &'a str)>,
    pub quotas: super::PepQuotas,
    pub vcard_payload: &'a str,
    pub avatar_hash: Option<&'a str>,
}

#[cfg(test)]
pub async fn publish_avatar_metadata_with_vcard(
    pool: &PgPool,
    user_id: Uuid,
    write: AvatarMetadataWrite<'_>,
) -> Result<(super::PepPublishOutcome, bool)> {
    publish_avatar_metadata_with_vcard_and_outbox(pool, user_id, write, &[]).await
}

#[cfg(test)]
pub async fn publish_avatar_metadata_with_vcard_and_outbox(
    pool: &PgPool,
    user_id: Uuid,
    write: AvatarMetadataWrite<'_>,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<(super::PepPublishOutcome, bool)> {
    let AvatarMetadataWrite {
        requested,
        enforce_preconditions,
        items,
        required_data,
        quotas,
        vcard_payload,
        avatar_hash,
    } = write;
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
        .bind(user_id.to_string())
        .execute(&mut *transaction)
        .await?;
    if !avatar_node_compatible(&mut transaction, user_id, "urn:xmpp:avatar:data", false).await?
        || !avatar_node_compatible(&mut transaction, user_id, "urn:xmpp:avatar:metadata", true)
            .await?
    {
        transaction.rollback().await?;
        return Ok((super::PepPublishOutcome::PreconditionFailed, false));
    }
    if let Some((item_id, expected_payload)) = required_data {
        let unchanged: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pep_items WHERE owner_id=$1 AND node='urn:xmpp:avatar:data' AND item_id=$2 AND payload=$3)",
        )
        .bind(user_id)
        .bind(item_id)
        .bind(expected_payload)
        .fetch_one(&mut *transaction)
        .await?;
        if !unchanged {
            transaction.rollback().await?;
            return Ok((super::PepPublishOutcome::PreconditionFailed, false));
        }
    }
    let item_ids = items
        .iter()
        .map(|(item_id, _)| *item_id)
        .collect::<Vec<_>>();
    let previous = sqlx::query(
        "SELECT item_id,payload FROM pep_items WHERE owner_id=$1 AND node='urn:xmpp:avatar:metadata' AND item_id=ANY($2) FOR UPDATE",
    )
    .bind(user_id)
    .bind(&item_ids)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .map(|row| (row.get::<String, _>("item_id"), row.get::<String, _>("payload")))
    .collect::<std::collections::HashMap<_, _>>();
    let changed = previous.len() != items.len()
        || items
            .iter()
            .any(|(item_id, payload)| previous.get(*item_id).map(String::as_str) != Some(*payload));
    let outcome = super::pep::publish_pep_items_in_transaction(
        &mut transaction,
        user_id,
        "urn:xmpp:avatar:metadata",
        requested,
        enforce_preconditions,
        items,
        quotas,
    )
    .await?;
    if outcome != super::PepPublishOutcome::Published {
        transaction.rollback().await?;
        return Ok((outcome, false));
    }
    upsert_vcard_in_transaction(&mut transaction, user_id, vcard_payload, avatar_hash).await?;
    if changed {
        super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
    }
    transaction.commit().await?;
    Ok((super::PepPublishOutcome::Published, changed))
}

#[cfg(test)]
async fn avatar_node_compatible(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    node: &str,
    require_single_item: bool,
) -> Result<bool> {
    let row = sqlx::query(
        "SELECT access_model,persist_items,max_items FROM pep_nodes WHERE owner_id=$1 AND node=$2 FOR UPDATE",
    )
    .bind(user_id)
    .bind(node)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.is_none_or(|row| {
        row.get::<String, _>("access_model") == "open"
            && row.get::<bool, _>("persist_items")
            && (!require_single_item || row.get::<i32, _>("max_items") == 1)
    }))
}

#[cfg(test)]
async fn upsert_vcard_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    payload: &str,
    avatar_hash: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO vcards (user_id, payload, avatar_hash) VALUES ($1, $2, $3) ON CONFLICT (user_id) DO UPDATE SET payload = EXCLUDED.payload, avatar_hash = EXCLUDED.avatar_hash, updated_at = NOW()",
    )
    .bind(user_id)
    .bind(payload)
    .bind(avatar_hash)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;

    fn register_isolated_schema_for_harness(schema: &str, owner_token: &str) {
        let log_path = std::env::var_os("XMPP_TEST_CREATED_SCHEMA_LOG").expect(
            "run this ignored database test through scripts/pubsub-db-wsl.sh so its schema can be recovered after interruption",
        );
        let mut log = OpenOptions::new()
            .append(true)
            .open(log_path)
            .expect("open the harness-owned schema recovery log");
        let record = format!("{schema} {owner_token}\n");
        log.write_all(record.as_bytes())
            .expect("record the isolated vCard test schema");
        log.sync_all()
            .expect("durably flush the isolated vCard test schema record");
    }

    async fn create_harness_owned_schema(admin: &sqlx::PgPool, schema: &str) {
        let owner_token = Uuid::new_v4().simple().to_string();
        register_isolated_schema_for_harness(schema, &owner_token);
        let mut transaction = admin.begin().await.unwrap();
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query(&format!(
            "CREATE TABLE {schema}.northstar_test_schema_guard \
             (singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton), token TEXT NOT NULL)"
        ))
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO {schema}.northstar_test_schema_guard(token) VALUES($1)"
        ))
        .bind(owner_token)
        .execute(&mut *transaction)
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn avatar_conversion_is_atomic_across_pep_and_vcard() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("xmpp_test_vcard_{}", Uuid::new_v4().simple());
        create_harness_owned_schema(&admin, &schema).await;
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(6)
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
        crate::db::migrate(&pool).await.unwrap();
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(user_id)
            .bind(format!("vcard-{}", &user_id.simple().to_string()[..12]))
            .execute(&pool)
            .await
            .unwrap();
        let quotas = super::super::PepQuotas {
            max_nodes: 10,
            max_storage_bytes: 1_000_000,
        };
        let first_hash = "1111111111111111111111111111111111111111";
        let second_hash = "2222222222222222222222222222222222222222";
        let first_data = format!(
            "<item id='{first_hash}'><data xmlns='urn:xmpp:avatar:data'>Zmlyc3Q=</data></item>"
        );
        let first_metadata = format!(
            "<item id='{first_hash}'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='5' id='{first_hash}' type='image/png'/></metadata></item>"
        );
        assert_eq!(
            set_vcard_with_converted_avatar(
                &pool,
                user_id,
                "<vCard xmlns='vcard-temp'><FN>First</FN></vCard>",
                Some(first_hash),
                Some((first_hash, &first_data)),
                (first_hash, &first_metadata),
                quotas,
            )
            .await
            .unwrap(),
            super::super::PepPublishOutcome::Published
        );

        let second_data = format!(
            "<item id='{second_hash}'><data xmlns='urn:xmpp:avatar:data'>c2Vjb25k</data></item>"
        );
        let second_metadata = format!(
            "<item id='{second_hash}'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='6' id='{second_hash}' type='image/png'/></metadata></item>"
        );
        assert_eq!(
            set_vcard_with_converted_avatar(
                &pool,
                user_id,
                "<vCard xmlns='vcard-temp'><FN>Second</FN></vCard>",
                Some(second_hash),
                Some((second_hash, &second_data)),
                (second_hash, &second_metadata),
                super::super::PepQuotas {
                    max_nodes: 10,
                    max_storage_bytes: 1,
                },
            )
            .await
            .unwrap(),
            super::super::PepPublishOutcome::QuotaExceeded
        );
        let record = get_vcard(&pool, user_id).await.unwrap();
        assert_eq!(record.avatar_hash.as_deref(), Some(first_hash));
        assert!(record
            .payload_vcard_temp
            .as_deref()
            .is_some_and(|payload| payload.contains("First")));
        assert!(super::super::pep_items(
            &pool,
            user_id,
            "urn:xmpp:avatar:data",
            Some(second_hash),
            1,
        )
        .await
        .unwrap()
        .is_empty());
        assert_eq!(
            super::super::pep_items(&pool, user_id, "urn:xmpp:avatar:metadata", None, 10,)
                .await
                .unwrap(),
            vec![(first_hash.to_owned(), first_metadata.clone())]
        );

        let requested = super::super::default_pep_node_config("urn:xmpp:avatar:metadata");
        let repeated_items = [(first_hash, first_metadata.as_str())];
        assert_eq!(
            publish_avatar_metadata_with_vcard(
                &pool,
                user_id,
                AvatarMetadataWrite {
                    requested: &requested,
                    enforce_preconditions: false,
                    items: &repeated_items,
                    required_data: Some((first_hash, &first_data)),
                    quotas,
                    vcard_payload: "<vCard xmlns='vcard-temp'><FN>First</FN></vCard>",
                    avatar_hash: Some(first_hash),
                },
            )
            .await
            .unwrap(),
            (super::super::PepPublishOutcome::Published, false)
        );
        let changed_items = [(second_hash, second_metadata.as_str())];
        assert_eq!(
            publish_avatar_metadata_with_vcard(
                &pool,
                user_id,
                AvatarMetadataWrite {
                    requested: &requested,
                    enforce_preconditions: false,
                    items: &changed_items,
                    required_data: Some((first_hash, "stale-payload")),
                    quotas,
                    vcard_payload: "<vCard xmlns='vcard-temp'><FN>Second</FN></vCard>",
                    avatar_hash: Some(second_hash),
                },
            )
            .await
            .unwrap(),
            (super::super::PepPublishOutcome::PreconditionFailed, false)
        );
        assert_eq!(
            get_vcard(&pool, user_id)
                .await
                .unwrap()
                .avatar_hash
                .as_deref(),
            Some(first_hash)
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn converted_avatar_uses_the_exact_locked_pep_subscription_snapshot() {
        use std::sync::{Arc, Condvar, Mutex};
        use std::time::Duration;

        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("xmpp_test_vcard_audience_{}", Uuid::new_v4().simple());
        create_harness_owned_schema(&admin, &schema).await;
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(6)
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
        crate::db::migrate(&pool).await.unwrap();

        let user_id = Uuid::new_v4();
        let username = format!("vcard-race-{}", &user_id.simple().to_string()[..12]);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(user_id)
            .bind(&username)
            .execute(&pool)
            .await
            .unwrap();
        // An explicit PEP subscription is a child of the metadata node.  Set
        // up that parent through the same default configuration that the
        // avatar conversion validates, rather than relying on the conversion
        // below to create it after this subscription fixture is inserted.
        let metadata_config = super::super::default_pep_node_config("urn:xmpp:avatar:metadata");
        assert_eq!(
            super::super::create_pep_node(
                &pool,
                user_id,
                "urn:xmpp:avatar:metadata",
                &metadata_config,
                10,
            )
            .await
            .unwrap(),
            super::super::PepCreateOutcome::Created
        );
        let subscriber = format!("avatar-{}@remote.test/phone", Uuid::new_v4().simple());
        let subscription = super::super::subscribe_pep_node(
            &pool,
            user_id,
            "urn:xmpp:avatar:metadata",
            &subscriber,
            10,
        )
        .await
        .unwrap()
        .expect("explicit PEP subscription must be created");

        let avatar_hash = "3333333333333333333333333333333333333333";
        let data_item = format!(
            "<item id='{avatar_hash}'><data xmlns='urn:xmpp:avatar:data'>cmFjZQ==</data></item>"
        );
        let metadata_item = format!(
            "<item id='{avatar_hash}'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='4' id='{avatar_hash}' type='image/png'/></metadata></item>"
        );
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let factory_gate = Arc::clone(&gate);
        let (snapshot_tx, mut snapshot_rx) = tokio::sync::mpsc::unbounded_channel();
        let owner_bare_jid = format!("{username}@example.test");
        let factory = move |subscriber_jids: &[String]| {
            snapshot_tx
                .send(subscriber_jids.to_vec())
                .map_err(|_| anyhow::anyhow!("avatar audience observer closed"))?;
            let (released, wake) = &*factory_gate;
            let mut released = released.lock().expect("avatar gate poisoned");
            while !*released {
                released = wake.wait(released).expect("avatar gate poisoned");
            }
            let event_id = Uuid::new_v4();
            let created_at = chrono::Utc::now();
            subscriber_jids
                .iter()
                .map(|jid| {
                    super::super::PubSubOutboxInsert::new_pep_stanza(
                        event_id,
                        user_id,
                        &owner_bare_jid,
                        None,
                        jid.clone(),
                        None,
                        super::super::PepOutboxEventKind::Publish,
                        super::super::PepOutboxAuthorizationMode::LiveNodeAccess,
                        format!("<message xmlns='jabber:client' to='{jid}'><event xmlns='urn:test:avatar-race'/></message>"),
                        "urn:xmpp:avatar:metadata",
                        "example.test",
                        created_at,
                    )
                })
                .collect::<Result<Vec<_>>>()
        };
        let avatar_pool = pool.clone();
        let avatar_task = tokio::spawn(async move {
            set_vcard_with_converted_avatar_and_outbox(
                &avatar_pool,
                user_id,
                "<vCard xmlns='vcard-temp'><FN>Race</FN></vCard>",
                Some(avatar_hash),
                Some((avatar_hash, &data_item)),
                (avatar_hash, &metadata_item),
                super::super::PepQuotas {
                    max_nodes: 10,
                    max_storage_bytes: 1_000_000,
                },
                &factory,
            )
            .await
        });

        let first_snapshot = tokio::time::timeout(Duration::from_secs(3), snapshot_rx.recv())
            .await
            .expect("avatar publication never reached its locked audience snapshot")
            .expect("avatar audience observer closed unexpectedly");
        assert_eq!(first_snapshot, vec![subscriber.clone()]);

        let unsubscribe_pool = pool.clone();
        let unsubscribe_jid = subscriber.clone();
        let unsubscribe_subid = subscription.subid.clone();
        let mut unsubscribe_task = tokio::spawn(async move {
            super::super::unsubscribe_pep_node(
                &unsubscribe_pool,
                user_id,
                "urn:xmpp:avatar:metadata",
                &unsubscribe_jid,
                Some(&unsubscribe_subid),
            )
            .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut unsubscribe_task)
                .await
                .is_err(),
            "unsubscribe bypassed the metadata-node audience lock"
        );

        {
            let (released, wake) = &*gate;
            *released.lock().expect("avatar gate poisoned") = true;
            wake.notify_all();
        }
        assert_eq!(
            avatar_task.await.unwrap().unwrap(),
            super::super::PepPublishOutcome::Published
        );
        assert_eq!(
            unsubscribe_task.await.unwrap().unwrap().as_deref(),
            Some(subscription.subid.as_str())
        );
        let durable_recipients = sqlx::query_scalar::<_, String>(
            "SELECT recipient_jid FROM pubsub_event_outbox
              WHERE source_kind='pep' AND source_node='urn:xmpp:avatar:metadata'
              ORDER BY recipient_jid",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(durable_recipients, vec![subscriber.clone()]);

        let (second_snapshot_tx, mut second_snapshot_rx) = tokio::sync::mpsc::unbounded_channel();
        let second_factory = move |subscriber_jids: &[String]| {
            second_snapshot_tx
                .send(subscriber_jids.to_vec())
                .map_err(|_| anyhow::anyhow!("second avatar audience observer closed"))?;
            Ok(Vec::new())
        };
        assert_eq!(
            set_vcard_with_converted_avatar_and_outbox(
                &pool,
                user_id,
                "<vCard xmlns='vcard-temp'><FN>Race Again</FN></vCard>",
                Some(avatar_hash),
                None,
                (avatar_hash, &format!(
                    "<item id='{avatar_hash}'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='4' id='{avatar_hash}' type='image/png'/></metadata></item>"
                )),
                super::super::PepQuotas {
                    max_nodes: 10,
                    max_storage_bytes: 1_000_000,
                },
                &second_factory,
            )
            .await
            .unwrap(),
            super::super::PepPublishOutcome::Published
        );
        assert_eq!(
            second_snapshot_rx.recv().await.unwrap(),
            Vec::<String>::new()
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
