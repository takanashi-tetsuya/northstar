//! Bookmarks outbox tests that render from the locked item diff.

use super::*;

struct LockedBookmarksOutbox;

impl PepOutboxFactory for LockedBookmarksOutbox {
    fn build(&self, _: &PepAudienceSnapshot) -> Result<Vec<(String, String)>> {
        anyhow::bail!("Bookmarks2 outbox did not receive the locked item diff")
    }

    fn build_published(
        &self,
        audience: &PepAudienceSnapshot,
        changed_items: &[(&str, &str)],
    ) -> Result<Vec<(String, String)>> {
        let Some(event) = crate::xmpp::protocol::pep::bookmarks2_items_event(changed_items)? else {
            return Ok(Vec::new());
        };
        let owner = &audience.owner_bare_jid;
        Ok(vec![(
            owner.clone(),
            format!("<message xmlns='jabber:client' from='{owner}' to='{owner}'>{event}</message>"),
        )])
    }
}

struct LockedBookmarkReplacementOutbox;

impl PepOutboxFactory for LockedBookmarkReplacementOutbox {
    fn build(&self, _: &PepAudienceSnapshot) -> Result<Vec<(String, String)>> {
        anyhow::bail!("legacy bookmark outbox did not receive the locked replacement")
    }

    fn build_replaced(
        &self,
        audience: &PepAudienceSnapshot,
        current_items: &[(&str, &str)],
        previous_items: &[(&str, &str)],
    ) -> Result<Vec<(String, String)>> {
        let plan =
            northstar_pubsub_application::plan_pep_bookmark_event(current_items, previous_items);
        if plan.is_empty() {
            return Ok(Vec::new());
        }
        let mut items =
            crate::xmpp::xml_builder::XmlElement::new("items").attr("node", "urn:xmpp:bookmarks:1");
        for (_, payload) in &plan.changed_items {
            items.push_validated_fragment(payload)?;
        }
        for item_id in &plan.retracted_item_ids {
            items.push_child(
                crate::xmpp::xml_builder::XmlElement::new("retract").attr("id", item_id),
            );
        }
        let owner = &audience.owner_bare_jid;
        let message = crate::xmpp::xml_builder::XmlElement::namespaced("message", "jabber:client")
            .attr("from", owner)
            .attr("to", owner)
            .child(
                crate::xmpp::xml_builder::XmlElement::namespaced(
                    "event",
                    "http://jabber.org/protocol/pubsub#event",
                )
                .child(items),
            )
            .finish();
        Ok(vec![(owner.clone(), message)])
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn bookmarks2_outbox_uses_locked_item_diff_after_lock_wait() {
    const NODE: &str = "urn:xmpp:bookmarks:1";
    let (url, pool) = integration_pool(8).await;
    let owner_id = Uuid::new_v4();
    let username = format!("bookmarkowner{}", &owner_id.simple().to_string()[..10]);
    let auth_generation: i64 = sqlx::query_scalar(
        "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test') RETURNING auth_generation",
    )
    .bind(owner_id)
    .bind(&username)
    .fetch_one(&pool)
    .await
    .unwrap();
    let config = db::default_pep_node_config(NODE);
    assert_eq!(
        db::create_pep_node(&pool, owner_id, NODE, &config, 10)
            .await
            .unwrap(),
        db::PepCreateOutcome::Created
    );
    let first_id = "one@conference.example.test";
    let second_id = "two@conference.example.test";
    let unchanged =
        format!("<item id='{first_id}'><conference xmlns='{NODE}' name='unchanged'/></item>");
    let committed =
        format!("<item id='{second_id}'><conference xmlns='{NODE}' name='committed'/></item>");
    let intervening =
        format!("<item id='{second_id}'><conference xmlns='{NODE}' name='intervening'/></item>");
    for (item_id, payload) in [(first_id, &unchanged), (second_id, &committed)] {
        sqlx::query("INSERT INTO pep_items(owner_id,node,item_id,payload) VALUES($1,$2,$3,$4)")
            .bind(owner_id)
            .bind(NODE)
            .bind(item_id)
            .bind(payload)
            .execute(&pool)
            .await
            .unwrap();
    }
    let stale_read = db::pep_items(&pool, owner_id, NODE, None, 10)
        .await
        .unwrap();
    assert!(stale_read
        .iter()
        .any(|(id, payload)| id == second_id && payload == &committed));

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("UPDATE pep_items SET payload=$4 WHERE owner_id=$1 AND node=$2 AND item_id=$3")
        .bind(owner_id)
        .bind(NODE)
        .bind(second_id)
        .bind(&intervening)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let application = format!("ps-bookmarks-{}", &owner_id.simple().to_string()[..8]);
    let publish_pool = named_single_connection_pool(&url, &application).await;
    let publish_service = PubSubService::new(publish_pool.clone(), "example.test");
    let requested_config = crate::services::pubsub::PepNodeConfig::from(config);
    let publish = tokio::spawn({
        let username = username.clone();
        let unchanged = unchanged.clone();
        let committed = committed.clone();
        let requested_config = requested_config.clone();
        async move {
            let items = [
                (first_id, unchanged.as_str()),
                (second_id, committed.as_str()),
            ];
            publish_service
                .publish_pep_items(
                    northstar_pubsub_application::PepPublishItemsCommand::new(
                        crate::services::pubsub::PepPublishWrite {
                            user_id: owner_id,
                            username: &username,
                            auth_generation,
                            connection_id: Uuid::new_v4(),
                            node: NODE,
                            requested: &requested_config,
                            enforce_preconditions: false,
                            items: &items,
                            quotas: crate::services::pubsub::PepQuotas {
                                max_nodes: 10,
                                max_storage_bytes: 1_000_000,
                            },
                        },
                        true,
                    ),
                    &LockedBookmarksOutbox,
                )
                .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    blocker.commit().await.unwrap();
    let result = publish.await.unwrap().unwrap();
    assert_eq!(
        result.outcome,
        northstar_pubsub_application::PepPublishItemsOutcome::Published
    );
    assert!(result.content_changed);
    let owner_jid = format!("{username}@example.test");
    let payload: String = sqlx::query_scalar(
        "SELECT payload_xml FROM pubsub_event_outbox
          WHERE source_node=$1 AND recipient_jid=$2 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(NODE)
    .bind(&owner_jid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(payload.contains(second_id));
    assert!(payload.contains("committed"));
    assert!(!payload.contains(first_id));
    assert!(!payload.contains("intervening"));
    let outbox_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1")
            .bind(NODE)
            .fetch_one(&pool)
            .await
            .unwrap();

    let items = [
        (first_id, unchanged.as_str()),
        (second_id, committed.as_str()),
    ];
    let replay = PubSubService::new(pool.clone(), "example.test")
        .publish_pep_items(
            northstar_pubsub_application::PepPublishItemsCommand::new(
                crate::services::pubsub::PepPublishWrite {
                    user_id: owner_id,
                    username: &username,
                    auth_generation,
                    connection_id: Uuid::new_v4(),
                    node: NODE,
                    requested: &requested_config,
                    enforce_preconditions: false,
                    items: &items,
                    quotas: crate::services::pubsub::PepQuotas {
                        max_nodes: 10,
                        max_storage_bytes: 1_000_000,
                    },
                },
                true,
            ),
            &LockedBookmarksOutbox,
        )
        .await
        .unwrap();
    assert!(!replay.content_changed);
    let after_replay: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1")
            .bind(NODE)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(after_replay, outbox_count);

    publish_pool.close().await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn legacy_bookmark_commit_conflict_is_atomic_and_success_uses_locked_diff() {
    const NODE: &str = "urn:xmpp:bookmarks:1";
    let (url, pool) = integration_pool(8).await;
    let owner_id = Uuid::new_v4();
    let username = format!("legacybookmark{}", &owner_id.simple().to_string()[..10]);
    let auth_generation: i64 = sqlx::query_scalar(
        "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test') RETURNING auth_generation",
    )
    .bind(owner_id)
    .bind(&username)
    .fetch_one(&pool)
    .await
    .unwrap();
    let owner = crate::services::pubsub::PubSubAccount {
        id: owner_id,
        username: username.clone(),
        auth_generation,
    };
    let config = db::default_pep_node_config(NODE);
    assert_eq!(
        db::create_pep_node(&pool, owner_id, NODE, &config, 10)
            .await
            .unwrap(),
        db::PepCreateOutcome::Created
    );
    let unchanged_id = "unchanged@conference.example.test";
    let changed_id = "changed@conference.example.test";
    let removed_id = "removed@conference.example.test";
    let unchanged =
        format!("<item id='{unchanged_id}'><conference xmlns='{NODE}' name='same'/></item>");
    let old_changed =
        format!("<item id='{changed_id}'><conference xmlns='{NODE}' name='old'/></item>");
    let intervening =
        format!("<item id='{changed_id}'><conference xmlns='{NODE}' name='intervening'/></item>");
    let new_changed =
        format!("<item id='{changed_id}'><conference xmlns='{NODE}' name='new'/></item>");
    let removed =
        format!("<item id='{removed_id}'><conference xmlns='{NODE}' name='remove'/></item>");
    for (id, payload) in [
        (unchanged_id, &unchanged),
        (changed_id, &old_changed),
        (removed_id, &removed),
    ] {
        sqlx::query("INSERT INTO pep_items(owner_id,node,item_id,payload) VALUES($1,$2,$3,$4)")
            .bind(owner_id)
            .bind(NODE)
            .bind(id)
            .bind(payload)
            .execute(&pool)
            .await
            .unwrap();
    }
    let old_private = "<storage xmlns='storage:bookmarks'><conference jid='old@conference.example.test'/></storage>";
    let new_private = "<storage xmlns='storage:bookmarks'><conference jid='new@conference.example.test'/></storage>";
    sqlx::query("INSERT INTO private_xml(user_id,element_name,element_ns,xml_data) VALUES($1,'storage','storage:bookmarks',$2)")
        .bind(owner_id)
        .bind(old_private)
        .execute(&pool)
        .await
        .unwrap();
    let stale = sqlx::query_as::<_, (String, String)>(
        "SELECT item_id,payload FROM pep_items WHERE owner_id=$1 AND node=$2 ORDER BY item_id",
    )
    .bind(owner_id)
    .bind(NODE)
    .fetch_all(&pool)
    .await
    .unwrap();

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("UPDATE pep_items SET payload=$4 WHERE owner_id=$1 AND node=$2 AND item_id=$3")
        .bind(owner_id)
        .bind(NODE)
        .bind(changed_id)
        .bind(&intervening)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let application = format!(
        "ps-legacy-bookmarks-{}",
        &owner_id.simple().to_string()[..8]
    );
    let retry_pool = named_single_connection_pool(&url, &application).await;
    let conflict = tokio::spawn({
        let owner = owner.clone();
        let retry_pool = retry_pool.clone();
        let unchanged = unchanged.clone();
        let new_changed = new_changed.clone();
        async move {
            let service = PubSubService::new(retry_pool, "example.test");
            let mut items = [
                (unchanged_id.to_owned(), unchanged),
                (changed_id.to_owned(), new_changed),
            ];
            service
                .commit_legacy_bookmarks(
                    northstar_pubsub_application::PepCommitLegacyBookmarksCommand {
                        owner: &owner,
                        connection_id: Uuid::new_v4(),
                        private_xml: new_private,
                        items: &mut items,
                        expected_previous_items: &stale,
                        max_private_bytes: 1_000_000,
                        quotas: crate::services::pubsub::PepQuotas {
                            max_nodes: 10,
                            max_storage_bytes: 1_000_000,
                        },
                    },
                    &LockedBookmarkReplacementOutbox,
                )
                .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    blocker.commit().await.unwrap();
    assert_eq!(
        conflict.await.unwrap().unwrap().outcome,
        crate::services::pubsub::PepBookmarkMutationOutcome::ConcurrentChange
    );
    let after_conflict = sqlx::query_as::<_, (String, String)>(
        "SELECT item_id,payload FROM pep_items WHERE owner_id=$1 AND node=$2 ORDER BY item_id",
    )
    .bind(owner_id)
    .bind(NODE)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(after_conflict.len(), 3);
    assert!(after_conflict.contains(&(unchanged_id.to_owned(), unchanged.clone())));
    assert!(after_conflict.contains(&(changed_id.to_owned(), intervening.clone())));
    assert!(after_conflict.contains(&(removed_id.to_owned(), removed)));
    assert_eq!(
        db::private::get_private_xml(&pool, owner_id, "storage", "storage:bookmarks")
            .await
            .unwrap()
            .as_deref(),
        Some(old_private)
    );
    let owner_jid = format!("{username}@example.test");
    let outbox_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1 AND recipient_jid=$2",
    )
    .bind(NODE)
    .bind(&owner_jid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outbox_count, 0);

    let mut items = [
        (unchanged_id.to_owned(), unchanged),
        (changed_id.to_owned(), new_changed),
    ];
    let result = PubSubService::new(pool.clone(), "example.test")
        .commit_legacy_bookmarks(
            northstar_pubsub_application::PepCommitLegacyBookmarksCommand {
                owner: &owner,
                connection_id: Uuid::new_v4(),
                private_xml: new_private,
                items: &mut items,
                expected_previous_items: &after_conflict,
                max_private_bytes: 1_000_000,
                quotas: crate::services::pubsub::PepQuotas {
                    max_nodes: 10,
                    max_storage_bytes: 1_000_000,
                },
            },
            &LockedBookmarkReplacementOutbox,
        )
        .await
        .unwrap();
    assert_eq!(
        result.outcome,
        crate::services::pubsub::PepBookmarkMutationOutcome::Stored
    );
    assert_eq!(
        db::private::get_private_xml(&pool, owner_id, "storage", "storage:bookmarks")
            .await
            .unwrap()
            .as_deref(),
        Some(new_private)
    );
    let stored_items = sqlx::query_as::<_, (String, String)>(
        "SELECT item_id,payload FROM pep_items WHERE owner_id=$1 AND node=$2 ORDER BY item_id",
    )
    .bind(owner_id)
    .bind(NODE)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(stored_items.len(), 2);
    assert!(stored_items.contains(&(unchanged_id.to_owned(), items[0].1.clone())));
    assert!(stored_items.contains(&(changed_id.to_owned(), items[1].1.clone())));
    let payload: String = sqlx::query_scalar(
        "SELECT payload_xml FROM pubsub_event_outbox
         WHERE source_node=$1 AND recipient_jid=$2 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(NODE)
    .bind(&owner_jid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(payload.contains("name='new'"));
    assert!(payload.contains("<retract"));
    assert!(payload.contains(removed_id));
    assert!(!payload.contains(unchanged_id));
    assert!(!payload.contains("intervening"));
    retry_pool.close().await;
    pool.close().await;
}
