use super::*;
use crate::{PubSubCollectionDiscoSnapshot, PubSubLeafDiscoSnapshot};
use chrono::{TimeZone, Utc};
use std::sync::{Arc, Mutex};
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
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(2),
    );
    assert!(service
        .get_items(Uuid::new_v4(), &[], 10)
        .await
        .unwrap()
        .is_empty());
}

struct RetrievalFacts {
    affiliation: Option<String>,
    subscribed: bool,
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl PubSubAffiliationQueryRepository for RetrievalFacts {
    async fn retrieval_authorization_facts(
        &self,
        _node_id: Uuid,
        _jid: &str,
    ) -> Result<(Option<String>, bool)> {
        self.calls.lock().unwrap().push("facts");
        Ok((self.affiliation.clone(), self.subscribed))
    }

    async fn get_node_affiliation(&self, _node_id: Uuid, _jid: &str) -> Result<Option<String>> {
        panic!("retrieval should use the combined facts query")
    }

    async fn affiliations_for_jid(
        &self,
        _jid: &str,
        _node: Option<&str>,
    ) -> Result<Vec<PubSubAffiliation>> {
        panic!("retrieval should not enumerate affiliations")
    }
}

#[tokio::test]
async fn retrieval_query_preserves_outcast_precedence_over_open_and_subscription() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let service = PubSubService::new_with_durable_outbox_database_admission(
        RetrievalFacts {
            affiliation: Some("outcast".to_owned()),
            subscribed: true,
            calls: Arc::clone(&calls),
        },
        2,
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(2),
    );
    let node = renderer_node(Uuid::new_v4(), "news", "leaf");
    assert!(!service
        .can_retrieve_node(&node, "reader@example.test/mobile")
        .await
        .unwrap());
    assert_eq!(*calls.lock().unwrap(), ["facts"]);
}

#[tokio::test]
async fn retrieval_query_preserves_affiliation_error_before_access_model_error() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let service = PubSubService::new_with_durable_outbox_database_admission(
        RetrievalFacts {
            affiliation: Some("invalid-affiliation".to_owned()),
            subscribed: true,
            calls: Arc::clone(&calls),
        },
        2,
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(2),
    );
    let mut node = renderer_node(Uuid::new_v4(), "news", "leaf");
    node.access_model = "invalid-access-model".to_owned();
    let error = service
        .can_retrieve_node(&node, "reader@example.test")
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("invalid stored PubSub affiliation"));
    assert_eq!(*calls.lock().unwrap(), ["facts"]);
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
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(2),
    );
    assert!(service
        .pep_items(Uuid::new_v4(), "urn:xmpp:avatar:data", None, 10)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn injected_durable_outbox_admission_stays_separate_from_foreground_mutations() {
    let durable =
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(2);
    let service = PubSubService::new_with_durable_outbox_database_admission(
        QueryOnlyItems,
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

fn renderer_node(id: Uuid, name: &str, node_type: &str) -> PubSubNode {
    PubSubNode {
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

#[tokio::test]
async fn mutation_admission_waits_before_database_capacity_and_fails_bounded() {
    let admission = PubSubMutationAdmission::new(4);
    // One of four configured database connections remains outside the
    // PubSub mutation budget for unrelated authentication/routing work.
    assert_eq!(admission.available_transaction_permits(), 3);

    let first = admission
        .acquire_with_timeout(&["alice@example.test"], false, Duration::from_millis(50))
        .await
        .unwrap();
    let rejected_before =
        northstar_telemetry::admission_gauges::pubsub_mutation_admission_rejections_total();
    let error = admission
        .acquire_with_timeout(&["alice@example.test"], false, Duration::from_millis(20))
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<crate::PubSubMutationBusy>().is_some());
    assert!(
        northstar_telemetry::admission_gauges::pubsub_mutation_admission_rejections_total()
            > rejected_before
    );
    drop(first);

    admission
        .acquire_with_timeout(&["alice@example.test"], false, Duration::from_millis(50))
        .await
        .unwrap();
}

#[tokio::test]
async fn collection_graph_admission_serializes_distinct_owners_without_pool_waiters() {
    let admission = PubSubMutationAdmission::new(8);
    let first = admission
        .acquire_with_timeout(&["alice@example.test"], true, Duration::from_millis(50))
        .await
        .unwrap();
    let error = admission
        .acquire_with_timeout(&["bob@example.test"], true, Duration::from_millis(20))
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<crate::PubSubMutationBusy>().is_some());
    drop(first);
    admission
        .acquire_with_timeout(&["bob@example.test"], true, Duration::from_millis(50))
        .await
        .unwrap();
}
