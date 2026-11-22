use super::*;
use crate::{PubSubOwnerRead, PubSubOwnerReadKind};
use northstar_pubsub_core::{
    FixedPubSubClock, PubSubNode, PubSubNodeMetadata, PubSubSubscribeWrite, PubSubSubscription,
    PubSubTimeSources, PubSubUnsubscribeWrite, RequestedSubId, SequentialPubSubIds,
    SetSubscriptionsOutcome, SubscriptionOptionsPatch,
};
use northstar_time::DateTime;
use std::sync::Arc;
use uuid::Uuid;

const REQUESTER: &str = "reader@example.test";
const SUBSCRIBER: &str = "reader@example.test/desktop";
const NODE: &str = "news";

struct SubscriptionRepository {
    node: PubSubNode,
    subscribe_outcome: PubSubSubscribeOutcome,
}

impl PubSubNodeQueryRepository for SubscriptionRepository {
    async fn get_node(&self, name: &str) -> Result<Option<PubSubNode>> {
        assert_eq!(name, NODE);
        Ok(Some(self.node.clone()))
    }

    async fn node_redirect(&self, _node: &str) -> Result<Option<String>> {
        panic!("unexpected redirect lookup");
    }

    async fn collection_parents(&self, _child_id: Uuid) -> Result<Vec<PubSubNode>> {
        panic!("unexpected parent lookup");
    }

    async fn collection_children(&self, _collection_id: Uuid) -> Result<Vec<PubSubNode>> {
        panic!("unexpected child lookup");
    }

    async fn is_owner(&self, _node_id: Uuid, _requester: &str) -> Result<bool> {
        panic!("unexpected owner lookup");
    }

    async fn node_metadata(&self, _node_id: Uuid) -> Result<PubSubNodeMetadata> {
        panic!("unexpected metadata lookup");
    }

    async fn owner_read(
        &self,
        _node: &str,
        _requester: &str,
        _kind: PubSubOwnerReadKind,
    ) -> Result<PubSubOwnerRead> {
        panic!("unexpected owner read");
    }
}

impl PubSubSubscriptionMutationRepository for SubscriptionRepository {
    fn local_domain(&self) -> &str {
        "example.test"
    }

    async fn update_subscription_options_checked(
        &self,
        node_id: PubSubNodeId,
        requester: &PubSubBareJid,
        subscriber: &PubSubAddress,
        expected_subid: &str,
        patch: &SubscriptionOptionsPatch,
    ) -> Result<SubscriptionOptionsOutcome> {
        assert_eq!(node_id.get(), self.node.id);
        assert_eq!(requester.to_string(), REQUESTER);
        assert_eq!(subscriber.to_string(), SUBSCRIBER);
        assert_eq!(expected_subid, "original");
        assert_eq!(
            patch,
            &SubscriptionOptionsPatch {
                deliver: Some(false),
                ..SubscriptionOptionsPatch::default()
            }
        );
        Ok(SubscriptionOptionsOutcome::InvalidSubid)
    }

    #[allow(clippy::too_many_arguments)]
    async fn subscribe_checked(
        &self,
        node_id: PubSubNodeId,
        requester: &PubSubBareJid,
        subscriber: &PubSubAddress,
        max_subscriptions: i64,
        patch: Option<&SubscriptionOptionsPatch>,
        planned_subid: &str,
        _time: &PubSubTimeSources,
    ) -> Result<PubSubSubscribeOutcome> {
        assert_eq!(node_id.get(), self.node.id);
        assert_eq!(requester.to_string(), REQUESTER);
        assert_eq!(subscriber.to_string(), SUBSCRIBER);
        assert_eq!(max_subscriptions, 100);
        assert!(patch.is_none());
        assert_eq!(planned_subid, Uuid::from_u128(1).to_string());
        Ok(self.subscribe_outcome.clone())
    }

    async fn unsubscribe_checked(
        &self,
        node_id: PubSubNodeId,
        requester: &PubSubBareJid,
        subscriber: &PubSubAddress,
        requested_subid: RequestedSubId<'_>,
        _time: &PubSubTimeSources,
    ) -> Result<PubSubUnsubscribeOutcome> {
        assert_eq!(node_id.get(), self.node.id);
        assert_eq!(requester.to_string(), REQUESTER);
        assert_eq!(subscriber.to_string(), SUBSCRIBER);
        Ok(match requested_subid {
            RequestedSubId(None) => PubSubUnsubscribeOutcome::Unsubscribed {
                subid: Some("replacement".to_owned()),
            },
            RequestedSubId(Some("original")) => PubSubUnsubscribeOutcome::InvalidSubid,
            other => panic!("unexpected requested SubID {other:?}"),
        })
    }

    async fn set_subscriptions(
        &self,
        _node_id: Uuid,
        _requester: &str,
        _changes: &[(String, String, Option<String>)],
    ) -> Result<SetSubscriptionsOutcome> {
        panic!("unexpected owner subscription write");
    }

    async fn resolve_pending_subscription(
        &self,
        _node_id: Uuid,
        _requester: &str,
        _subscriber_jid: &str,
        _expected_subid: &str,
        _allow: bool,
    ) -> Result<SubscriptionAuthorizationOutcome> {
        panic!("unexpected owner authorization");
    }
}

fn service(outcome: PubSubSubscribeOutcome) -> PubSubService<SubscriptionRepository> {
    PubSubService::new_with_durable_outbox_database_admission(
        SubscriptionRepository {
            subscribe_outcome: outcome,
            node: PubSubNode {
                id: Uuid::from_u128(2),
                node: NODE.to_owned(),
                creator_jid: "owner@example.test".to_owned(),
                access_model: "whitelist".to_owned(),
                publish_model: "publishers".to_owned(),
                max_items: 100,
                title: None,
                description: None,
                deliver_payloads: true,
                notify_delete: true,
                notify_retract: true,
                persist_items: true,
                send_last_published_item: "on_sub_and_presence".to_owned(),
                node_type: "leaf".to_owned(),
                deliver_notifications: true,
                notify_config: true,
                notify_sub: true,
                language: None,
                payload_type: None,
                max_payload_size: 1_048_576,
                children_max: 1_000,
                children_association_policy: "owner".to_owned(),
                children_association_whitelist: Vec::new(),
                created_at: DateTime::UNIX_EPOCH,
            },
        },
        2,
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(2),
    )
    .with_time_sources(PubSubTimeSources::new(
        Arc::new(FixedPubSubClock(DateTime::UNIX_EPOCH)),
        Arc::new(SequentialPubSubIds::default()),
    ))
}

#[tokio::test]
async fn subscribe_reports_the_repository_decision_and_injects_the_planned_subid() {
    let existing = PubSubSubscription {
        node: NODE.to_owned(),
        jid: SUBSCRIBER.to_owned(),
        state: "subscribed".to_owned(),
        subid: "current".to_owned(),
        deliver: true,
        digest: false,
        digest_frequency: 86_400_000,
        expire: None,
        include_body: false,
        show_values: Vec::new(),
        subscription_type: "items".to_owned(),
        subscription_depth: Some(1),
    };
    for expected in [
        PubSubSubscribeOutcome::Subscribed(existing.clone()),
        PubSubSubscribeOutcome::ExistingActive(existing),
        PubSubSubscribeOutcome::PendingSubscription,
        PubSubSubscribeOutcome::ClosedNode,
        PubSubSubscribeOutcome::Forbidden,
        PubSubSubscribeOutcome::LimitExceeded,
        PubSubSubscribeOutcome::InvalidOptions,
        PubSubSubscribeOutcome::PreconditionFailed,
        PubSubSubscribeOutcome::NotFound,
    ] {
        let result = service(expected.clone())
            .execute_pubsub_subscribe(PubSubSubscribeCommand::from(PubSubSubscribeWrite {
                requester: REQUESTER,
                subscriber_jid: SUBSCRIBER,
                node: NODE,
                options: None,
                max_subscriptions: 100,
            }))
            .await
            .unwrap();
        assert_eq!(result.outcome, expected);
    }
}

#[tokio::test]
async fn unsubscribe_forwards_the_optional_echo_and_reports_the_removed_subid() {
    let service = service(PubSubSubscribeOutcome::PendingSubscription);
    for (echo, expected) in [
        (
            None,
            PubSubUnsubscribeOutcome::Unsubscribed {
                subid: Some("replacement".to_owned()),
            },
        ),
        (Some("original"), PubSubUnsubscribeOutcome::InvalidSubid),
    ] {
        let result = service
            .execute_pubsub_unsubscribe(PubSubUnsubscribeCommand::from(PubSubUnsubscribeWrite {
                requester: REQUESTER,
                subscriber_jid: SUBSCRIBER,
                node: NODE,
                requested_subid: RequestedSubId(echo),
            }))
            .await
            .unwrap();
        assert_eq!(result.outcome, expected);
    }
}

#[tokio::test]
async fn options_set_forwards_the_sparse_patch_and_expected_subid() {
    let service = service(PubSubSubscribeOutcome::PendingSubscription);
    let result = service
        .execute_pubsub_update_subscription_options(PubSubUpdateSubscriptionOptionsCommand {
            node_id: PubSubNodeId::new(Uuid::from_u128(2)),
            requester: REQUESTER,
            subscriber_jid: SUBSCRIBER,
            expected_subid: "original",
            patch: &SubscriptionOptionsPatch {
                deliver: Some(false),
                ..SubscriptionOptionsPatch::default()
            },
        })
        .await
        .unwrap();
    assert_eq!(result.outcome, SubscriptionOptionsOutcome::InvalidSubid);
}
