use super::*;
use crate::db;
use crate::db::pubsub_repository::{
    db_outbox, pep_outbox_authorization_lock_plan, PepOutboxAuthorizationLockPlan,
};
use chrono::{TimeZone, Utc};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

struct QueryOnlyItems;

impl PubSubItemQueryRepository for QueryOnlyItems {
    async fn leaf_disco_snapshot(
        &self,
        _node: &str,
        _requester: &str,
    ) -> Result<Option<PubSubLeafDiscoSnapshot>> {
        Ok(None)
    }

    async fn collection_disco_snapshot(
        &self,
        _node: &str,
        _requester: &str,
    ) -> Result<Option<PubSubCollectionDiscoSnapshot>> {
        Ok(None)
    }

    async fn get_items(
        &self,
        _node_id: Uuid,
        _item_ids: &[String],
        _limit: i64,
    ) -> Result<Vec<PubSubItem>> {
        Ok(Vec::new())
    }

    async fn collection_visible_items(
        &self,
        _collection_id: Uuid,
        _requester: &str,
        _global_item_limit: i64,
        _xml_byte_limit: i64,
    ) -> Result<Vec<CollectionVisibleItem>> {
        Ok(Vec::new())
    }

    async fn can_publish(&self, _node: &PubSubNode, _requester: &str) -> Result<bool> {
        Ok(false)
    }
}

#[tokio::test]
async fn item_queries_do_not_require_mutation_repository_capability() {
    let service = PubSubService::new_with_durable_outbox_database_admission(
        QueryOnlyItems,
        2,
        crate::services::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(2),
    );
    assert!(service
        .get_items(Uuid::new_v4(), &[], 10)
        .await
        .unwrap()
        .is_empty());
}

struct QueryOnlyPepItems;

impl PepItemQueryRepository for QueryOnlyPepItems {
    async fn pep_items(
        &self,
        _owner_id: Uuid,
        _node: &str,
        _item_id: Option<&str>,
        _limit: i64,
    ) -> Result<Vec<(String, String)>> {
        Ok(Vec::new())
    }

    async fn pep_items_by_ids(
        &self,
        _owner_id: Uuid,
        _node: &str,
        _item_ids: &[&str],
        _limit: i64,
    ) -> Result<Vec<(String, String)>> {
        Ok(Vec::new())
    }

    async fn pep_items_with_timestamp(
        &self,
        _owner_id: Uuid,
        _node: &str,
        _limit: i64,
    ) -> Result<Vec<PepItem>> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn pep_item_queries_do_not_require_mutation_repository_capability() {
    let service = PubSubService::new_with_durable_outbox_database_admission(
        QueryOnlyPepItems,
        2,
        crate::services::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(2),
    );
    assert!(service
        .pep_items(Uuid::new_v4(), "urn:xmpp:avatar:data", None, 10)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn injected_durable_outbox_admission_stays_separate_from_foreground_mutations() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy("postgres://unused:unused@localhost/unused")
        .expect("a lazy test pool does not connect");
    let durable =
        crate::services::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(2);
    let service = PubSubService::new_with_durable_outbox_database_admission(
        db::pubsub_repository::PostgresPubSubRepository::new(pool, "example.test"),
        2,
        durable.clone(),
    );

    assert!(service
        .durable_outbox_database_admission
        .shares_with(&durable));
    assert_eq!(
        service.mutation_admission.available_transaction_permits(),
        1,
        "the foreground mutation budget remains independently available"
    );
}

#[test]
fn atom_event_body_limit_never_splits_a_utf8_character() {
    let summary = format!("{}ƞ", "a".repeat(1_023));
    let event =
        format!("<entry xmlns='http://www.w3.org/2005/Atom'><summary>{summary}</summary></entry>");
    let body = northstar_xep_0060::extract_atom_event_body(&event)
        .unwrap()
        .unwrap();
    assert_eq!(body.len(), 1_023);
    assert_eq!(body, "a".repeat(1_023));
}

#[test]
fn live_pep_authorization_locks_audience_before_block_policy() {
    assert_eq!(
        pep_outbox_authorization_lock_plan(PepOutboxAuthorizationMode::LiveNodeAccess),
        PepOutboxAuthorizationLockPlan::AudienceThenBlockPolicy
    );
    assert_eq!(
        pep_outbox_authorization_lock_plan(PepOutboxAuthorizationMode::CausalAudience),
        PepOutboxAuthorizationLockPlan::BlockPolicyOnly
    );
}

#[test]
fn publish_validation_reports_the_specific_payload_failure() {
    let items = vec![(
        "one".to_owned(),
        "<item id='one'><payload xmlns='urn:test:wrong'>value</payload></item>".to_owned(),
    )];
    let mut config = PubSubNodeConfig {
        payload_type: Some("urn:test:expected".to_owned()),
        ..PubSubNodeConfig::default()
    };

    assert_eq!(
        publish_validation_outcome(&config, &items),
        Some(PubSubPublishOutcome::InvalidPayload),
    );

    config.payload_type = None;
    config.max_payload_size = 1;
    assert_eq!(
        publish_validation_outcome(&config, &items),
        Some(PubSubPublishOutcome::PayloadTooBig),
    );

    config.max_payload_size = 1_048_576;
    let missing_payload = vec![("two".to_owned(), "<item id='two'/>".to_owned())];
    assert_eq!(
        publish_validation_outcome(&config, &missing_payload),
        Some(PubSubPublishOutcome::PayloadRequired),
    );
}

#[test]
fn existing_node_publish_hides_payload_policy_before_authorization() {
    let items = vec![(
        "wrong-namespace".to_owned(),
        "<item id='wrong-namespace'><payload xmlns='urn:test:wrong'/></item>".to_owned(),
    )];
    let node_config = PubSubNodeConfig {
        payload_type: Some("urn:test:expected".to_owned()),
        ..PubSubNodeConfig::default()
    };
    let stale_options = PubSubNodeConfig {
        max_items: node_config.max_items + 1,
        ..node_config.clone()
    };

    // The same request has both policy-sensitive failures, but a caller
    // without publish authorization must learn neither one.
    assert_eq!(
        existing_node_publish_admission_outcome(false, &node_config, Some(&stale_options), &items,),
        Some(PubSubPublishOutcome::Forbidden),
    );
    assert_eq!(
        existing_node_publish_admission_outcome(true, &node_config, Some(&stale_options), &items,),
        Some(PubSubPublishOutcome::PreconditionNotMet),
    );
    assert_eq!(
        existing_node_publish_admission_outcome(true, &node_config, None, &items,),
        Some(PubSubPublishOutcome::InvalidPayload),
    );
}

fn renderer_node(id: Uuid, name: &str, node_type: &str) -> db::PubSubNode {
    db::PubSubNode {
        id,
        node: name.to_owned(),
        creator_jid: "owner@example.test".to_owned(),
        access_model: "open".to_owned(),
        publish_model: "publishers".to_owned(),
        max_items: 100,
        title: None,
        description: None,
        deliver_payloads: true,
        notify_delete: true,
        notify_retract: true,
        persist_items: true,
        send_last_published_item: "on_sub_and_presence".to_owned(),
        node_type: node_type.to_owned(),
        deliver_notifications: true,
        notify_config: true,
        notify_sub: true,
        language: None,
        payload_type: None,
        max_payload_size: 1_048_576,
        children_max: 1_000,
        children_association_policy: "owner".to_owned(),
        children_association_whitelist: Vec::new(),
        created_at: Utc.with_ymd_and_hms(2030, 4, 5, 6, 7, 8).unwrap(),
    }
}

fn renderer_subscription(node: &str, jid: &str) -> db::PubSubSubscription {
    db::PubSubSubscription {
        node: node.to_owned(),
        jid: jid.to_owned(),
        state: "subscribed".to_owned(),
        subid: "sub<&\"1".to_owned(),
        deliver: true,
        digest: false,
        digest_frequency: 86_400_000,
        expire: None,
        include_body: false,
        show_values: vec!["online".to_owned()],
        subscription_type: "items".to_owned(),
        subscription_depth: Some(1),
    }
}

#[tokio::test]
async fn mutation_admission_waits_before_database_capacity_and_fails_bounded() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_lazy("postgres://unused:unused@localhost/unused")
        .unwrap();
    let admission = PubSubMutationAdmission::new(pool.options().get_max_connections() as usize);
    // One of four configured database connections remains outside the
    // PubSub mutation budget for unrelated authentication/routing work.
    assert_eq!(admission.available_transaction_permits(), 3);

    let first = admission
        .acquire_with_timeout(&["alice@example.test"], false, Duration::from_millis(50))
        .await
        .unwrap();
    let rejected_before = pubsub_mutation_admission_rejections_total();
    let error = admission
        .acquire_with_timeout(&["alice@example.test"], false, Duration::from_millis(20))
        .await
        .unwrap_err();
    assert!(error
        .downcast_ref::<northstar_pubsub_application::PubSubMutationBusy>()
        .is_some());
    assert!(pubsub_mutation_admission_rejections_total() > rejected_before);
    drop(first);

    admission
        .acquire_with_timeout(&["alice@example.test"], false, Duration::from_millis(50))
        .await
        .unwrap();
}

#[tokio::test]
async fn collection_graph_admission_serializes_distinct_owners_without_pool_waiters() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect_lazy("postgres://unused:unused@localhost/unused")
        .unwrap();
    let admission = PubSubMutationAdmission::new(pool.options().get_max_connections() as usize);
    let first = admission
        .acquire_with_timeout(&["alice@example.test"], true, Duration::from_millis(50))
        .await
        .unwrap();
    let error = admission
        .acquire_with_timeout(&["bob@example.test"], true, Duration::from_millis(20))
        .await
        .unwrap_err();
    assert!(error
        .downcast_ref::<northstar_pubsub_application::PubSubMutationBusy>()
        .is_some());
    drop(first);
    admission
        .acquire_with_timeout(&["bob@example.test"], true, Duration::from_millis(50))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn same_owner_advisory_contention_does_not_exhaust_the_shared_pool() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let owner_id = Uuid::new_v4();
    let username = format!("poolguard{}", &owner_id.simple().to_string()[..10]);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
        .bind(owner_id)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
        .bind(owner_id.to_string())
        .execute(&mut *blocker)
        .await
        .unwrap();
    let service = Arc::new(PubSubService::new(pool.clone(), "example.test"));
    let mut requests = Vec::new();
    for index in 0..16 {
        let service = Arc::clone(&service);
        requests.push(tokio::spawn(async move {
            let node = format!("urn:test:pool-admission:{owner_id}:{index}");
            let config = default_pep_node_config(&node);
            service.create_pep_node(owner_id, &node, &config, 100).await
        }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let unrelated = tokio::time::timeout(
        Duration::from_millis(500),
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&pool),
    )
    .await
    .expect("same-owner PubSub waiters consumed the whole shared pool")
    .unwrap();
    assert_eq!(unrelated, 1);

    blocker.rollback().await.unwrap();
    for request in requests {
        match request.await.unwrap() {
            Ok(PepCreateOutcome::Created | PepCreateOutcome::Conflict) => {}
            Err(error) if is_pubsub_mutation_busy(&error) => {}
            result => panic!("unexpected bounded PubSub admission result: {result:?}"),
        }
    }
}

#[tokio::test]
async fn generic_transaction_renderer_preserves_collection_and_last_item_snapshots() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@localhost/unused")
        .unwrap();
    let service = PubSubService::new(pool, "example.test");
    let child = renderer_node(Uuid::from_u128(10), "child<&", "leaf");
    let parent = renderer_node(Uuid::from_u128(11), "parent<&", "collection");
    let subscription = renderer_subscription(&parent.node, "alice@example.test/phone");
    let audience = [db::PubSubNotificationDelivery {
        subscription_node_id: parent.id,
        subscription: subscription.clone(),
        collection: Some(parent.node.clone()),
    }];
    let created_at = Utc.with_ymd_and_hms(2031, 1, 2, 3, 4, 5).unwrap();
    let create = db::PubSubMutationOutboxRenderer::render_create(
        &service,
        &child,
        &audience,
        Uuid::from_u128(12),
        created_at,
    )
    .unwrap();
    assert_eq!(create.len(), 1);
    let create_payload = format!("<root>{}</root>", create[0].payload_xml);
    let create_document = roxmltree::Document::parse(&create_payload).unwrap();
    let create_event = create_document
        .descendants()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "create"
                && node.tag_name().namespace() == Some(NS_PUBSUB_EVENT)
        })
        .expect("create event");
    assert_eq!(create_event.attribute("node"), Some("child<&"));
    let headers = create_document
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "header"
                && node.tag_name().namespace() == Some("http://jabber.org/protocol/shim")
        })
        .map(|node| (node.attribute("name"), node.text()))
        .collect::<Vec<_>>();
    assert!(headers.contains(&(Some("Collection"), Some("parent<&"))));
    assert!(headers.contains(&(Some("SubID"), Some("sub<&\"1"))));

    let mut pending = renderer_subscription(&child.node, "bob@example.test/tablet");
    pending.state = "pending".to_owned();
    let item = db::PubSubItem {
        item_id: "item<&".to_owned(),
        publisher_jid: "owner@example.test".to_owned(),
        xml_payload: "<item id='item&amp;&lt;'><value xmlns='urn:test'>safe</value></item>"
            .to_owned(),
        created_at,
    };
    let rendered = db::PubSubMutationOutboxRenderer::render_subscription_transition(
        &service,
        &child,
        &pending,
        &["owner@example.test".to_owned()],
        &["owner@example.test".to_owned()],
        Some(&item),
        Uuid::from_u128(13),
        created_at,
    )
    .unwrap();
    assert_eq!(rendered.len(), 3);
    let authorization = rendered
        .iter()
        .find(|row| {
            let payload = format!("<root>{}</root>", row.payload_xml);
            roxmltree::Document::parse(&payload).is_ok_and(|document| {
                document.descendants().any(|node| {
                    node.is_element()
                        && node.tag_name().name() == "value"
                        && node.text() == Some(SUBSCRIBE_AUTH_FORM)
                })
            })
        })
        .expect("subscription authorization form");
    let authorization_payload = format!("<root>{}</root>", authorization.payload_xml);
    let authorization_document = roxmltree::Document::parse(&authorization_payload).unwrap();
    assert!(authorization_document.descendants().any(|node| {
        node.is_element()
            && node.tag_name().name() == "field"
            && node.attribute("var") == Some("pubsub#subscriber_jid")
            && node
                .children()
                .any(|child| child.is_element() && child.text() == Some(pending.jid.as_str()))
    }));

    let last_item = rendered
        .iter()
        .find(|row| {
            if row.recipient_jid != pending.jid {
                return false;
            }
            let payload = format!("<root>{}</root>", row.payload_xml);
            roxmltree::Document::parse(&payload).is_ok_and(|document| {
                let has_delay = document.descendants().any(|node| {
                    node.is_element()
                        && node.tag_name().name() == "delay"
                        && node.tag_name().namespace() == Some("urn:xmpp:delay")
                });
                let has_item_snapshot = document.descendants().any(|node| {
                    node.is_element()
                        && node.tag_name().name() == "items"
                        && node.attribute("node") == Some("child<&")
                        && node.descendants().any(|item| {
                            item.is_element()
                                && item.tag_name().name() == "item"
                                && item.attribute("id") == Some("item&<")
                        })
                });
                has_delay && has_item_snapshot
            })
        })
        .expect("last-item snapshot");
    let last_item_payload = format!("<root>{}</root>", last_item.payload_xml);
    let last_item_document = roxmltree::Document::parse(&last_item_payload).unwrap();
    assert!(last_item_document.descendants().any(|node| {
        node.is_element()
            && node.tag_name().name() == "value"
            && node.tag_name().namespace() == Some("urn:test")
            && node.text() == Some("safe")
    }));
}

fn snapshot_deliveries(audience: &PepAudienceSnapshot) -> Result<Vec<(String, String)>> {
    Ok(audience
        .roster_jids
        .iter()
        .chain(audience.explicit_jids.iter())
        .map(|jid| {
            (
                jid.clone(),
                format!("<message xmlns='jabber:client' to='{jid}'/>"),
            )
        })
        .collect())
}

#[test]
fn subscription_mapping_round_trips_authoritative_delivery_options() {
    let expiry = Utc.with_ymd_and_hms(2030, 4, 5, 6, 7, 8).unwrap();
    let service = PubSubSubscription {
        node: "urn:example:node".to_owned(),
        jid: "alice@example.test/phone".to_owned(),
        state: "subscribed".to_owned(),
        subid: "sub-1".to_owned(),
        deliver: false,
        digest: true,
        digest_frequency: 12_345,
        expire: Some(expiry),
        include_body: true,
        show_values: vec!["chat".to_owned(), "online".to_owned()],
        subscription_type: "nodes".to_owned(),
        subscription_depth: Some(7),
    };

    let repository = db::PubSubSubscription::from(&service);
    let round_trip = PubSubSubscription::from(repository);

    assert_eq!(round_trip.node, service.node);
    assert_eq!(round_trip.jid, service.jid);
    assert_eq!(round_trip.state, service.state);
    assert_eq!(round_trip.subid, service.subid);
    assert_eq!(
        subscription_options(&round_trip),
        subscription_options(&service)
    );
}

#[test]
fn outbox_request_mapping_preserves_recipient_order_and_kind() {
    let event_id = Uuid::from_u128(1);
    let now = Utc.with_ymd_and_hms(2030, 4, 5, 6, 7, 8).unwrap();
    let first = db::PubSubOutboxInsert::new(
        event_id,
        "node:one",
        db::PubSubOutboxSource::PubSub,
        db::PubSubOutboxDeliveryKind::PubSubDirect,
        "alice@example.test/phone",
        "<message xmlns='jabber:client'/>",
        None,
        None,
        "urn:example:node",
        None,
        now,
    )
    .unwrap();
    let sender_id = Uuid::from_u128(2);
    let second = PubSubOutboxInsert::new_pep_stanza(
        event_id,
        sender_id,
        "alice@example.test",
        None,
        "bob@remote.test/laptop",
        None,
        PepOutboxEventKind::Publish,
        PepOutboxAuthorizationMode::CausalAudience,
        "<message xmlns='jabber:client'/>",
        "urn:example:pep",
        "example.test",
        now,
    )
    .unwrap();

    let repository = db_outbox(&[first, second]);

    assert_eq!(repository.len(), 2);
    assert_eq!(repository[0].recipient_jid, "alice@example.test/phone");
    assert_eq!(
        repository[0].delivery_kind,
        db::PubSubOutboxDeliveryKind::PubSubDirect
    );
    assert_eq!(repository[1].recipient_jid, "bob@remote.test/laptop");
    assert_eq!(
        repository[1].delivery_kind,
        db::PubSubOutboxDeliveryKind::PepStanza
    );
    assert_eq!(repository[0].event_id, repository[1].event_id);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn paused_pep_delivery_rechecks_block_privacy_disable_and_sensitive_acl() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(6)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let sender_id = Uuid::new_v4();
    let recipient_id = Uuid::new_v4();
    let sender_username = format!("pep-auth-s-{}", &suffix[..10]);
    let recipient_username = format!("pep-auth-r-{}", &suffix[..10]);
    for (id, username) in [
        (sender_id, sender_username.as_str()),
        (recipient_id, recipient_username.as_str()),
    ] {
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(id)
            .bind(username)
            .execute(&pool)
            .await
            .unwrap();
    }
    let sender_bare = format!("{sender_username}@example.test");
    let recipient_bare = format!("{recipient_username}@example.test");
    let recipient_full = format!("{recipient_bare}/phone");
    let node = format!("urn:xmpp:omemo:2:devices:{suffix}");
    let mut config = db::default_pep_node_config(&node);
    config.access_model = "open".to_owned();
    config.deliver_notifications = true;
    assert_eq!(
        db::create_pep_node(&pool, sender_id, &node, &config, 20)
            .await
            .unwrap(),
        db::PepCreateOutcome::Created
    );
    let insert = db::PubSubOutboxInsert::new_pep_stanza(
        Uuid::new_v4(),
        sender_id,
        &sender_bare,
        None,
        &recipient_full,
        Some(recipient_id),
        db::PepOutboxEventKind::Publish,
        db::PepOutboxAuthorizationMode::CausalAudience,
        "<message id='paused-pep'/>",
        &node,
        "example.test",
        Utc::now(),
    )
    .unwrap();
    let delivery_id = insert.delivery_id;
    let ordering_key = insert.ordering_key.clone();
    let mut transaction = pool.begin().await.unwrap();
    db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &[insert])
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    let service = PubSubService::new(pool.clone(), "example.test");
    let item = service
        .claim_pubsub_outbox(100)
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.delivery_id == delivery_id)
        .unwrap();
    assert_eq!(
        service.authorize_pep_outbox_delivery(&item).await.unwrap(),
        PepOutboxAuthorizationOutcome::Deliver
    );

    db::block_jids(&pool, sender_id, std::slice::from_ref(&recipient_bare))
        .await
        .unwrap();
    assert_eq!(
        service.authorize_pep_outbox_delivery(&item).await.unwrap(),
        PepOutboxAuthorizationOutcome::Drop(PepOutboxDropReason::Blocked)
    );
    db::unblock_jids(
        &pool,
        sender_id,
        Some(std::slice::from_ref(&recipient_bare)),
    )
    .await
    .unwrap();

    let privacy = db::PrivacyList {
        name: "deny-pep".to_owned(),
        items: vec![db::PrivacyItem {
            order: 1,
            action: db::PrivacyAction::Deny,
            match_type: None,
            match_value: None,
            message: true,
            iq: false,
            presence_in: false,
            presence_out: false,
        }],
    };
    db::replace_privacy_list(&pool, sender_id, &privacy)
        .await
        .unwrap();
    assert!(
        db::set_default_privacy_list(&pool, sender_id, Some(&privacy.name))
            .await
            .unwrap()
    );
    assert_eq!(
        service.authorize_pep_outbox_delivery(&item).await.unwrap(),
        PepOutboxAuthorizationOutcome::Drop(PepOutboxDropReason::PrivacyDenied)
    );
    assert!(db::set_default_privacy_list(&pool, sender_id, None)
        .await
        .unwrap());

    sqlx::query("UPDATE users SET is_disabled=TRUE WHERE id=$1")
        .bind(recipient_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        service.authorize_pep_outbox_delivery(&item).await.unwrap(),
        PepOutboxAuthorizationOutcome::Drop(PepOutboxDropReason::RecipientUnavailable)
    );
    sqlx::query("UPDATE users SET is_disabled=FALSE WHERE id=$1")
        .bind(recipient_id)
        .execute(&pool)
        .await
        .unwrap();

    config.access_model = "whitelist".to_owned();
    config.access_whitelist.clear();
    assert!(db::update_pep_node_config(&pool, sender_id, &node, &config)
        .await
        .unwrap());
    assert_eq!(
        service.authorize_pep_outbox_delivery(&item).await.unwrap(),
        PepOutboxAuthorizationOutcome::Drop(PepOutboxDropReason::NodeAccessRevoked)
    );

    service
        .acknowledge_pubsub_outbox(item.delivery_id, item.lease_token)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=ANY($1)")
        .bind([sender_id, recipient_id])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM pubsub_event_streams WHERE ordering_key=$1")
        .bind(ordering_key)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn pep_publish_audience_is_linearizable_with_every_revocation_input() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(12)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let owner_id = Uuid::new_v4();
    let username = format!("owner{}", &owner_id.simple().to_string()[..10]);
    let auth_generation = sqlx::query_scalar::<_, i64>(
        "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')
         RETURNING auth_generation",
    )
    .bind(owner_id)
    .bind(&username)
    .fetch_one(&pool)
    .await
    .unwrap();
    let node = format!("urn:test:pep:audience:{}", Uuid::new_v4().simple());
    let mut config = db::default_pep_node_config(&node);
    config.access_model = "open".to_owned();
    assert_eq!(
        db::create_pep_node(&pool, owner_id, &node, &config, 10)
            .await
            .unwrap(),
        db::PepCreateOutcome::Created
    );
    let unsubscribed = format!("unsubscribe{}@remote.test/phone", Uuid::new_v4().simple());
    let blocked = format!("blocked{}@remote.test/tablet", Uuid::new_v4().simple());
    let roster = format!("roster{}@remote.test", Uuid::new_v4().simple());
    let unsubscribed_record = db::subscribe_pep_node(&pool, owner_id, &node, &unsubscribed, 100)
        .await
        .unwrap()
        .unwrap();
    db::subscribe_pep_node(&pool, owner_id, &node, &blocked, 100)
        .await
        .unwrap()
        .unwrap();
    db::update_subscription(&pool, owner_id, &roster, "from", None)
        .await
        .unwrap();

    let service = Arc::new(PubSubService::new(pool.clone(), "example.test"));
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let factory_gate = Arc::clone(&gate);
    let (snapshot_tx, mut snapshot_rx) = tokio::sync::mpsc::unbounded_channel();
    let publish_service = Arc::clone(&service);
    let publish_username = username.clone();
    let publish_node = node.clone();
    let publish_config = PepNodeConfig::from(config.clone());
    let publish = tokio::spawn(async move {
        let payload = "<item id='one'><value xmlns='urn:test'>one</value></item>";
        let items = [("one", payload)];
        publish_service
            .publish_pep_items(
                PepPublishItemsCommand::new(
                    PepPublishWrite {
                        user_id: owner_id,
                        username: &publish_username,
                        auth_generation,
                        connection_id: Uuid::new_v4(),
                        node: &publish_node,
                        requested: &publish_config,
                        enforce_preconditions: false,
                        items: &items,
                        quotas: PepQuotas {
                            max_nodes: 10,
                            max_storage_bytes: 1_000_000,
                        },
                    },
                    false,
                ),
                &move |audience: &PepAudienceSnapshot| {
                    snapshot_tx
                        .send((audience.roster_jids.clone(), audience.explicit_jids.clone()))
                        .map_err(|_| anyhow::anyhow!("PEP snapshot observer closed"))?;
                    let (released, wake) = &*factory_gate;
                    let mut released = released.lock().expect("PEP gate poisoned");
                    while !*released {
                        released = wake.wait(released).expect("PEP gate poisoned");
                    }
                    snapshot_deliveries(audience)
                },
            )
            .await
    });
    let (first_roster, mut first_explicit) =
        tokio::time::timeout(Duration::from_secs(3), snapshot_rx.recv())
            .await
            .expect("publication never reached its audience snapshot")
            .expect("PEP snapshot observer closed");
    first_explicit.sort_unstable();
    let mut expected_explicit = vec![blocked.clone(), unsubscribed.clone()];
    expected_explicit.sort_unstable();
    assert_eq!(first_roster, vec![roster.clone()]);
    assert_eq!(first_explicit, expected_explicit);

    let unsubscribe_pool = pool.clone();
    let unsubscribe_node = node.clone();
    let unsubscribe_jid = unsubscribed.clone();
    let mut unsubscribe = tokio::spawn(async move {
        db::unsubscribe_pep_node(
            &unsubscribe_pool,
            owner_id,
            &unsubscribe_node,
            &unsubscribe_jid,
            Some(&unsubscribed_record.subid),
        )
        .await
    });
    let block_pool = pool.clone();
    let blocked_jid = blocked.clone();
    let mut block =
        tokio::spawn(async move { db::block_jids(&block_pool, owner_id, &[blocked_jid]).await });
    let roster_pool = pool.clone();
    let roster_jid = roster.clone();
    let mut roster_removal =
        tokio::spawn(async move { db::delete_roster(&roster_pool, owner_id, &roster_jid).await });
    let config_pool = pool.clone();
    let config_node = node.clone();
    let mut restricted_config = config.clone();
    restricted_config.access_model = "whitelist".to_owned();
    restricted_config.access_whitelist.clear();
    let mut access_change = tokio::spawn(async move {
        db::update_pep_node_config(&config_pool, owner_id, &config_node, &restricted_config).await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut unsubscribe)
            .await
            .is_err(),
        "unsubscribe bypassed the PEP publication audience lock"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut block)
            .await
            .is_err(),
        "block bypassed the PEP publication audience lock"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut roster_removal)
            .await
            .is_err(),
        "roster removal bypassed the PEP publication audience lock"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut access_change)
            .await
            .is_err(),
        "access-model change bypassed the PEP publication audience lock"
    );
    {
        let (released, wake) = &*gate;
        *released.lock().expect("PEP gate poisoned") = true;
        wake.notify_all();
    }
    let publish_result = publish.await.unwrap().unwrap();
    assert_eq!(publish_result.outcome, PepPublishItemsOutcome::Published);
    assert!(publish_result.content_changed);
    unsubscribe.await.unwrap().unwrap().unwrap();
    assert!(matches!(
        block.await.unwrap().unwrap(),
        db::BlockJidsUpdate::Changed(_)
    ));
    roster_removal.await.unwrap().unwrap().unwrap();
    assert!(access_change.await.unwrap().unwrap());

    let second_payload = "<item id='one'><value xmlns='urn:test'>two</value></item>";
    let second_items = [("one", second_payload)];
    let (second_tx, mut second_rx) = tokio::sync::mpsc::unbounded_channel();
    let second_config = PepNodeConfig::from(config);
    let result = service
        .publish_pep_items(
            PepPublishItemsCommand::new(
                PepPublishWrite {
                    user_id: owner_id,
                    username: &username,
                    auth_generation,
                    connection_id: Uuid::new_v4(),
                    node: &node,
                    requested: &second_config,
                    enforce_preconditions: false,
                    items: &second_items,
                    quotas: PepQuotas {
                        max_nodes: 10,
                        max_storage_bytes: 1_000_000,
                    },
                },
                false,
            ),
            &|audience: &PepAudienceSnapshot| {
                second_tx
                    .send((audience.roster_jids.clone(), audience.explicit_jids.clone()))
                    .map_err(|_| anyhow::anyhow!("second PEP observer closed"))?;
                snapshot_deliveries(audience)
            },
        )
        .await
        .unwrap();
    assert_eq!(result.outcome, PepPublishItemsOutcome::Published);
    assert!(result.content_changed);
    assert_eq!(second_rx.recv().await.unwrap(), (Vec::new(), Vec::new()));
    let mut expected_recipients = vec![blocked, roster, unsubscribed];
    expected_recipients.sort_unstable();
    assert_eq!(
        sqlx::query_scalar::<_, Vec<String>>(
            "SELECT COALESCE(ARRAY_AGG(recipient_jid ORDER BY recipient_jid),ARRAY[]::TEXT[])
               FROM pubsub_event_outbox WHERE source_node=$1",
        )
        .bind(&node)
        .fetch_one(&pool)
        .await
        .unwrap(),
        expected_recipients,
        "revocation-first publication must not append a stale audience"
    );
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn pep_subscription_admission_is_linearizable_and_principal_scoped() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let owner_id = Uuid::new_v4();
    let owner_username = format!("owner{}", &owner_id.simple().to_string()[..10]);
    let owner_generation = sqlx::query_scalar::<_, i64>(
        "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')
         RETURNING auth_generation",
    )
    .bind(owner_id)
    .bind(&owner_username)
    .fetch_one(&pool)
    .await
    .unwrap();
    let owner = PubSubAccount {
        id: owner_id,
        username: owner_username.clone(),
        auth_generation: owner_generation,
    };
    let service = Arc::new(PubSubService::new(pool.clone(), "example.test"));
    let subscriber = format!("remote{}@remote.test/phone", Uuid::new_v4().simple());
    let subscriber_bare = crate::jid::canonical_bare_key(&subscriber).unwrap();

    // Subscription-first: every revocation input must wait until the
    // subscription and its outbox projection commit from one snapshot.
    let node = format!("urn:test:pep:subscribe-race:{}", Uuid::new_v4().simple());
    let mut config = db::default_pep_node_config(&node);
    config.access_model = "roster".to_owned();
    config.roster_groups_allowed = vec!["friends".to_owned()];
    assert_eq!(
        db::create_pep_node(&pool, owner_id, &node, &config, 20)
            .await
            .unwrap(),
        db::PepCreateOutcome::Created
    );
    db::upsert_roster(
        &pool,
        owner_id,
        &subscriber_bare,
        None,
        &["friends".to_owned()],
    )
    .await
    .unwrap();
    db::update_subscription(&pool, owner_id, &subscriber_bare, "from", None)
        .await
        .unwrap();

    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let subscribe_service = Arc::clone(&service);
    let subscribe_owner = owner.clone();
    let subscribe_node = node.clone();
    let subscribe_jid = subscriber.clone();
    let subscribe_gate = Arc::clone(&gate);
    let subscribe = tokio::spawn(async move {
        let subid = Uuid::new_v4().to_string();
        subscribe_service
            .subscribe_pep_node(
                northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                    owner: &subscribe_owner,
                    actor: PepSubscriptionActor {
                        jid: &subscribe_jid,
                        local_account: None,
                    },
                    node: &subscribe_node,
                    subscriber_jid: &subscribe_jid,
                    max_subscriptions: 100,
                    requested_subid: &subid,
                }),
                &move |_: &PepSubscribeSnapshot| {
                    entered_tx
                        .send(())
                        .map_err(|_| anyhow::anyhow!("subscription observer closed"))?;
                    let (released, wake) = &*subscribe_gate;
                    let mut released = released.lock().expect("subscription gate poisoned");
                    while !*released {
                        released = wake.wait(released).expect("subscription gate poisoned");
                    }
                    Ok(Vec::new())
                },
            )
            .await
    });
    entered_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("subscription never reached its locked snapshot");

    let block_pool = pool.clone();
    let block_jid = subscriber_bare.clone();
    let mut block =
        tokio::spawn(async move { db::block_jids(&block_pool, owner_id, &[block_jid]).await });
    let roster_pool = pool.clone();
    let roster_jid = subscriber_bare.clone();
    let mut roster_revoke = tokio::spawn(async move {
        db::upsert_roster_authorized(
            &roster_pool,
            owner_id,
            owner_generation,
            &roster_jid,
            None,
            &[],
        )
        .await
    });
    let config_pool = pool.clone();
    let config_node = node.clone();
    let mut restricted = config.clone();
    restricted.access_model = "whitelist".to_owned();
    restricted.access_whitelist.clear();
    let mut access_revoke = tokio::spawn(async move {
        db::update_pep_node_config(&config_pool, owner_id, &config_node, &restricted).await
    });
    let delete_pool = pool.clone();
    let delete_node = node.clone();
    let mut node_delete =
        tokio::spawn(
            async move { db::delete_pep_node(&delete_pool, owner_id, &delete_node).await },
        );
    for (name, blocked) in [
        (
            "block",
            tokio::time::timeout(Duration::from_millis(200), &mut block)
                .await
                .is_err(),
        ),
        (
            "roster",
            tokio::time::timeout(Duration::from_millis(200), &mut roster_revoke)
                .await
                .is_err(),
        ),
        (
            "access-model",
            tokio::time::timeout(Duration::from_millis(200), &mut access_revoke)
                .await
                .is_err(),
        ),
        (
            "node-delete",
            tokio::time::timeout(Duration::from_millis(200), &mut node_delete)
                .await
                .is_err(),
        ),
    ] {
        assert!(blocked, "{name} revocation bypassed subscription locks");
    }
    {
        let (released, wake) = &*gate;
        *released.lock().expect("subscription gate poisoned") = true;
        wake.notify_all();
    }
    assert!(matches!(
        subscribe.await.unwrap().unwrap().outcome,
        PepSubscribeOutcome::Subscribed(_)
    ));
    assert!(matches!(
        block.await.unwrap().unwrap(),
        db::BlockJidsUpdate::Changed(_)
    ));
    roster_revoke.await.unwrap().unwrap().unwrap();
    let _ = access_revoke.await.unwrap().unwrap();
    let _ = node_delete.await.unwrap().unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pep_subscriptions WHERE owner_id=$1 AND node=$2",
        )
        .bind(owner_id)
        .bind(&node)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    // Revocation-first snapshots deterministically deny admission.
    let blocked_node = format!("urn:test:pep:blocked:{}", Uuid::new_v4().simple());
    let mut open = db::default_pep_node_config(&blocked_node);
    open.access_model = "open".to_owned();
    assert_eq!(
        db::create_pep_node(&pool, owner_id, &blocked_node, &open, 20)
            .await
            .unwrap(),
        db::PepCreateOutcome::Created
    );
    let denied_subid = Uuid::new_v4().to_string();
    assert!(matches!(
        service
            .subscribe_pep_node(
                northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                    owner: &owner,
                    actor: PepSubscriptionActor {
                        jid: &subscriber,
                        local_account: None,
                    },
                    node: &blocked_node,
                    subscriber_jid: &subscriber,
                    max_subscriptions: 100,
                    requested_subid: &denied_subid,
                }),
                &|_: &PepSubscribeSnapshot| Ok(Vec::new()),
            )
            .await
            .unwrap()
            .outcome,
        PepSubscribeOutcome::NotAuthorized(_)
    ));
    db::unblock_jids(
        &pool,
        owner_id,
        Some(std::slice::from_ref(&subscriber_bare)),
    )
    .await
    .unwrap();

    let mut whitelist_only = open.clone();
    whitelist_only.access_model = "whitelist".to_owned();
    whitelist_only.access_whitelist.clear();
    assert!(
        db::update_pep_node_config(&pool, owner_id, &blocked_node, &whitelist_only,)
            .await
            .unwrap()
    );
    let access_denied_subid = Uuid::new_v4().to_string();
    assert!(matches!(
        service
            .subscribe_pep_node(
                northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                    owner: &owner,
                    actor: PepSubscriptionActor {
                        jid: &subscriber,
                        local_account: None,
                    },
                    node: &blocked_node,
                    subscriber_jid: &subscriber,
                    max_subscriptions: 100,
                    requested_subid: &access_denied_subid,
                }),
                &|_: &PepSubscribeSnapshot| Ok(Vec::new()),
            )
            .await
            .unwrap()
            .outcome,
        PepSubscribeOutcome::NotAuthorized(_)
    ));

    let roster_node = format!("urn:test:pep:roster-deny:{}", Uuid::new_v4().simple());
    let mut roster_config = db::default_pep_node_config(&roster_node);
    roster_config.access_model = "roster".to_owned();
    roster_config.roster_groups_allowed = vec!["friends".to_owned()];
    assert_eq!(
        db::create_pep_node(&pool, owner_id, &roster_node, &roster_config, 20)
            .await
            .unwrap(),
        db::PepCreateOutcome::Created
    );
    let roster_denied_subid = Uuid::new_v4().to_string();
    assert!(matches!(
        service
            .subscribe_pep_node(
                northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                    owner: &owner,
                    actor: PepSubscriptionActor {
                        jid: &subscriber,
                        local_account: None,
                    },
                    node: &roster_node,
                    subscriber_jid: &subscriber,
                    max_subscriptions: 100,
                    requested_subid: &roster_denied_subid,
                }),
                &|_: &PepSubscribeSnapshot| Ok(Vec::new()),
            )
            .await
            .unwrap()
            .outcome,
        PepSubscribeOutcome::NotAuthorized(_)
    ));

    db::update_subscription(&pool, owner_id, &subscriber_bare, "none", None)
        .await
        .unwrap();
    let presence_node = format!("urn:test:pep:presence-deny:{}", Uuid::new_v4().simple());
    let mut presence_config = db::default_pep_node_config(&presence_node);
    presence_config.access_model = "presence".to_owned();
    assert_eq!(
        db::create_pep_node(&pool, owner_id, &presence_node, &presence_config, 20)
            .await
            .unwrap(),
        db::PepCreateOutcome::Created
    );
    let presence_denied_subid = Uuid::new_v4().to_string();
    assert!(matches!(
        service
            .subscribe_pep_node(
                northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                    owner: &owner,
                    actor: PepSubscriptionActor {
                        jid: &subscriber,
                        local_account: None,
                    },
                    node: &presence_node,
                    subscriber_jid: &subscriber,
                    max_subscriptions: 100,
                    requested_subid: &presence_denied_subid,
                }),
                &|_: &PepSubscribeSnapshot| Ok(Vec::new()),
            )
            .await
            .unwrap()
            .outcome,
        PepSubscribeOutcome::NotAuthorized(_)
    ));

    let deleted_node = format!("urn:test:pep:deleted:{}", Uuid::new_v4().simple());
    assert_eq!(
        db::create_pep_node(
            &pool,
            owner_id,
            &deleted_node,
            &db::default_pep_node_config(&deleted_node),
            20,
        )
        .await
        .unwrap(),
        db::PepCreateOutcome::Created
    );
    assert!(db::delete_pep_node(&pool, owner_id, &deleted_node)
        .await
        .unwrap());
    let deleted_subid = Uuid::new_v4().to_string();
    assert_eq!(
        service
            .subscribe_pep_node(
                northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                    owner: &owner,
                    actor: PepSubscriptionActor {
                        jid: &subscriber,
                        local_account: None,
                    },
                    node: &deleted_node,
                    subscriber_jid: &subscriber,
                    max_subscriptions: 100,
                    requested_subid: &deleted_subid,
                }),
                &|_: &PepSubscribeSnapshot| Ok(Vec::new()),
            )
            .await
            .unwrap()
            .outcome,
        PepSubscribeOutcome::NotFound
    );

    // Concurrent duplicate requests converge on one row, one subid and
    // one send-last rendering. A sibling resource cannot remove it.
    let duplicate_node = format!("urn:test:pep:duplicate:{}", Uuid::new_v4().simple());
    let mut duplicate_config = db::default_pep_node_config(&duplicate_node);
    duplicate_config.access_model = "open".to_owned();
    assert_eq!(
        db::create_pep_node(&pool, owner_id, &duplicate_node, &duplicate_config, 20,)
            .await
            .unwrap(),
        db::PepCreateOutcome::Created
    );
    let render_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let first_service = Arc::clone(&service);
    let first_owner = owner.clone();
    let first_node = duplicate_node.clone();
    let first_jid = subscriber.clone();
    let first_count = Arc::clone(&render_count);
    let first = tokio::spawn(async move {
        let subid = Uuid::new_v4().to_string();
        first_service
            .subscribe_pep_node(
                northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                    owner: &first_owner,
                    actor: PepSubscriptionActor {
                        jid: &first_jid,
                        local_account: None,
                    },
                    node: &first_node,
                    subscriber_jid: &first_jid,
                    max_subscriptions: 100,
                    requested_subid: &subid,
                }),
                &move |_: &PepSubscribeSnapshot| {
                    first_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(Vec::new())
                },
            )
            .await
    });
    let second_service = Arc::clone(&service);
    let second_owner = owner.clone();
    let second_node = duplicate_node.clone();
    let second_jid = subscriber.clone();
    let second_count = Arc::clone(&render_count);
    let second = tokio::spawn(async move {
        let subid = Uuid::new_v4().to_string();
        second_service
            .subscribe_pep_node(
                northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                    owner: &second_owner,
                    actor: PepSubscriptionActor {
                        jid: &second_jid,
                        local_account: None,
                    },
                    node: &second_node,
                    subscriber_jid: &second_jid,
                    max_subscriptions: 100,
                    requested_subid: &subid,
                }),
                &move |_: &PepSubscribeSnapshot| {
                    second_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(Vec::new())
                },
            )
            .await
    });
    let first = first.await.unwrap().unwrap();
    let second = second.await.unwrap().unwrap();
    let (PepSubscribeOutcome::Subscribed(first), PepSubscribeOutcome::Subscribed(second)) =
        (first.outcome, second.outcome)
    else {
        panic!("duplicate subscriptions were not accepted idempotently");
    };
    assert_eq!(first.subid, second.subid);
    assert_eq!(render_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pep_subscriptions
              WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3",
        )
        .bind(owner_id)
        .bind(&duplicate_node)
        .bind(&subscriber)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    let sibling = subscriber.replace("/phone", "/tablet");
    assert_eq!(
        service
            .unsubscribe_pep_node(northstar_pubsub_application::PepUnsubscribeCommand::from(
                PepUnsubscribeWrite {
                    owner: &owner,
                    actor: PepSubscriptionActor {
                        jid: &sibling,
                        local_account: None,
                    },
                    node: &duplicate_node,
                    subscriber_jid: &subscriber,
                    subid: Some(&first.subid),
                },
            ))
            .await
            .unwrap()
            .outcome,
        PepUnsubscribeOutcome::Forbidden
    );
    assert_eq!(
        service
            .unsubscribe_pep_node(northstar_pubsub_application::PepUnsubscribeCommand::from(
                PepUnsubscribeWrite {
                    owner: &owner,
                    actor: PepSubscriptionActor {
                        jid: &subscriber,
                        local_account: None,
                    },
                    node: &duplicate_node,
                    subscriber_jid: &subscriber,
                    subid: Some(&first.subid),
                },
            ))
            .await
            .unwrap()
            .outcome,
        PepUnsubscribeOutcome::Unsubscribed(Some(first.subid.clone()))
    );
    assert_eq!(
        service
            .unsubscribe_pep_node(northstar_pubsub_application::PepUnsubscribeCommand::from(
                PepUnsubscribeWrite {
                    owner: &owner,
                    actor: PepSubscriptionActor {
                        jid: &subscriber,
                        local_account: None,
                    },
                    node: &duplicate_node,
                    subscriber_jid: &subscriber,
                    subid: Some(&first.subid),
                },
            ))
            .await
            .unwrap()
            .outcome,
        PepUnsubscribeOutcome::Unsubscribed(None)
    );

    // A hosted subscriber's own block policy is the reciprocal half of
    // the admission decision and is locked with the target owner's policy.
    let local_id = Uuid::new_v4();
    let local_username = format!("local{}", &local_id.simple().to_string()[..10]);
    let local_generation = sqlx::query_scalar::<_, i64>(
        "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')
         RETURNING auth_generation",
    )
    .bind(local_id)
    .bind(&local_username)
    .fetch_one(&pool)
    .await
    .unwrap();
    let local = PubSubAccount {
        id: local_id,
        username: local_username.clone(),
        auth_generation: local_generation,
    };
    let local_jid = format!("{local_username}@example.test/phone");
    let owner_bare = format!("{owner_username}@example.test");
    assert!(matches!(
        db::block_jids(&pool, local_id, &[owner_bare])
            .await
            .unwrap(),
        db::BlockJidsUpdate::Changed(_)
    ));
    let reciprocal_subid = Uuid::new_v4().to_string();
    assert!(matches!(
        service
            .subscribe_pep_node(
                northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                    owner: &owner,
                    actor: PepSubscriptionActor {
                        jid: &local_jid,
                        local_account: Some(&local),
                    },
                    node: &duplicate_node,
                    subscriber_jid: &local_jid,
                    max_subscriptions: 100,
                    requested_subid: &reciprocal_subid,
                }),
                &|_: &PepSubscribeSnapshot| Ok(Vec::new()),
            )
            .await
            .unwrap()
            .outcome,
        PepSubscribeOutcome::NotAuthorized(_)
    ));

    sqlx::query("DELETE FROM users WHERE id=ANY($1)")
        .bind(vec![owner_id, local_id])
        .execute(&pool)
        .await
        .unwrap();
}

fn subscription_options(subscription: &PubSubSubscription) -> PubSubSubscriptionOptions {
    PubSubSubscriptionOptions {
        deliver: subscription.deliver,
        digest: subscription.digest,
        digest_frequency: subscription.digest_frequency,
        expire: subscription.expire,
        include_body: subscription.include_body,
        show_values: subscription.show_values.clone(),
        subscription_type: subscription.subscription_type.clone(),
        subscription_depth: subscription.subscription_depth,
    }
}
