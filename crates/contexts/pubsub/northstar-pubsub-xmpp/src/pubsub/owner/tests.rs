use super::*;
use northstar_pubsub_core::{
    AutoCreatePublishOutcome, PubSubAddress, PubSubNodeId, PubSubSubscribeOutcome,
    PubSubTimeSources, PubSubUnsubscribeOutcome, PublishItemsOutcome, RequestedSubId,
    RetractItemsOutcome, SubscriptionAuthorizationOutcome, SubscriptionOptionsPatch,
};
use northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission;
use northstar_time::DateTime;
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

const NODE: &str = "news";
const REQUESTER: &str = "alice@example.test";

struct OwnerRepository<'a> {
    preflight: Option<PubSubOwnerPreflight>,
    preflight_calls: &'a AtomicUsize,
    configure_calls: &'a AtomicUsize,
}

macro_rules! unexpected_calls {
    ($(fn $name:ident($($arg:ident: $type:ty),*) -> $output:ty;)*) => {
        $(async fn $name(&self, $($arg: $type),*) -> Result<$output> {
            panic!("unexpected call to {}", stringify!($name));
        })*
    };
}

impl PubSubOwnerPreflightRepository for OwnerRepository<'_> {
    async fn owner_preflight(
        &self,
        node: &PubSubNodeName,
        requester: &PubSubBareJid,
        include_graph: bool,
    ) -> Result<Option<PubSubOwnerPreflight>> {
        assert_eq!(node.as_str(), NODE);
        assert_eq!(requester.to_string(), REQUESTER);
        assert!(include_graph);
        self.preflight_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.preflight.clone())
    }
}

impl PubSubNodeQueryRepository for OwnerRepository<'_> {
    unexpected_calls! {
        fn get_node(_node: &str) -> Option<PubSubNode>;
        fn node_redirect(_node: &str) -> Option<String>;
        fn collection_parents(_node_id: Uuid) -> Vec<PubSubNode>;
        fn collection_children(_node_id: Uuid) -> Vec<PubSubNode>;
        fn is_owner(_node_id: Uuid, _requester: &str) -> bool;
        fn node_metadata(_node_id: Uuid) -> PubSubNodeMetadata;
        fn owner_read(_node: &str, _requester: &str, _kind: PubSubOwnerReadKind) -> PubSubOwnerRead;
    }
}

impl PubSubNodeMutationRepository for OwnerRepository<'_> {
    async fn update_node_config_and_graph_with_outbox(
        &self,
        node: &PubSubNode,
        requester: &str,
        expected: &PubSubNodeConfig,
        config: &PubSubNodeConfig,
    ) -> Result<PubSubConfigOutcome> {
        assert_eq!(node.id, self.preflight.as_ref().unwrap().node.id);
        assert_eq!(requester, REQUESTER);
        let original = PubSubNodeConfig {
            collections: vec!["parent-z".to_owned()],
            children: vec!["child-a".to_owned(), "child-b".to_owned()],
            ..node.config()
        };
        assert_eq!(expected, &original);
        assert_eq!(
            config,
            &PubSubNodeConfig {
                title: Some("New title".to_owned()),
                ..original
            }
        );
        self.configure_calls.fetch_add(1, Ordering::Relaxed);
        Ok(PubSubConfigOutcome::Updated)
    }

    unexpected_calls! {
        fn create_node(_node: &str, _creator: &str, _config: &PubSubNodeConfig, _limit: i64)
            -> CreateNodeOutcome;
        fn delete_node_as_owner_with_redirect_and_outbox(_node_id: Uuid, _requester: &str, _redirect: Option<&str>)
            -> OwnerMutationOutcome;
        fn associate_collection_child(_collection: &PubSubNode, _child: &PubSubNode, _requester: &str)
            -> CollectionUpdateOutcome;
        fn dissociate_collection_child(_collection: &PubSubNode, _child: &PubSubNode, _requester: &str)
            -> CollectionUpdateOutcome;
    }
}

impl PubSubItemMutationRepository for OwnerRepository<'_> {
    unexpected_calls! {
        fn publish_items(_node: &PubSubNode, _publisher: &str, _items: &[(String, String)], _options: Option<&PubSubNodeConfig>, _limit: i64)
            -> PublishItemsOutcome;
        fn create_node_and_publish_items(_node: &str, _publisher: &str, _config: &PubSubNodeConfig, _max_nodes: i64, _items: &[(String, String)], _limit: i64)
            -> AutoCreatePublishOutcome;
        fn purge_node_as_owner_with_outbox(_node_id: Uuid, _requester: &str)
            -> OwnerMutationOutcome;
        fn retract_items(_node_id: Uuid, _item_ids: &[String], _publisher: &str, _notify: bool)
            -> RetractItemsOutcome;
    }
}

impl PubSubSubscriptionMutationRepository for OwnerRepository<'_> {
    fn local_domain(&self) -> &str {
        panic!("unexpected call to local_domain")
    }

    unexpected_calls! {
        fn update_subscription_options_checked(_node_id: PubSubNodeId, _requester: &PubSubBareJid, _subscriber: &PubSubAddress, _subid: &str, _patch: &SubscriptionOptionsPatch)
            -> SubscriptionOptionsOutcome;
        fn subscribe_checked(_node_id: PubSubNodeId, _requester: &PubSubBareJid, _subscriber: &PubSubAddress, _max: i64, _patch: Option<&SubscriptionOptionsPatch>, _subid: &str, _time: &PubSubTimeSources)
            -> PubSubSubscribeOutcome;
        fn unsubscribe_checked(_node_id: PubSubNodeId, _requester: &PubSubBareJid, _subscriber: &PubSubAddress, _subid: RequestedSubId<'_>, _time: &PubSubTimeSources)
            -> PubSubUnsubscribeOutcome;
        fn set_subscriptions(_node_id: Uuid, _requester: &str, _changes: &[(String, String, Option<String>)])
            -> SetSubscriptionsOutcome;
        fn resolve_pending_subscription(_node_id: Uuid, _requester: &str, _subscriber: &str, _subid: &str, _allow: bool)
            -> SubscriptionAuthorizationOutcome;
    }
}

impl PubSubAffiliationMutationRepository for OwnerRepository<'_> {
    unexpected_calls! {
        fn set_affiliations(_node_id: Uuid, _requester: &str, _changes: &[(String, String)])
            -> SetAffiliationsOutcome;
    }
}

fn preflight(is_owner: bool) -> PubSubOwnerPreflight {
    PubSubOwnerPreflight {
        node: PubSubNode {
            id: Uuid::new_v4(),
            node: NODE.to_owned(),
            creator_jid: REQUESTER.to_owned(),
            access_model: "open".to_owned(),
            publish_model: "publishers".to_owned(),
            max_items: 100,
            title: None,
            description: None,
            deliver_payloads: false,
            notify_delete: true,
            notify_retract: true,
            persist_items: false,
            send_last_published_item: "never".to_owned(),
            node_type: "collection".to_owned(),
            deliver_notifications: true,
            notify_config: true,
            notify_sub: true,
            language: None,
            payload_type: None,
            max_payload_size: 1_048_576,
            children_max: 1000,
            children_association_policy: "owner".to_owned(),
            children_association_whitelist: Vec::new(),
            created_at: DateTime::UNIX_EPOCH,
        },
        is_owner,
        parents: vec!["parent-z".to_owned()],
        children: vec!["child-a".to_owned(), "child-b".to_owned()],
    }
}

#[tokio::test]
async fn configure_set_uses_one_preflight_for_missing_denied_and_owner_replies() {
    let xml = format!(
        "<configure xmlns='{NS_PUBSUB_OWNER}' node='{NODE}'>
          <x xmlns='{NS_DATA}' type='submit'>
            <field var='FORM_TYPE' type='hidden'><value>{NODE_CONFIG_FORM}</value></field>
            <field var='pubsub#title'><value>New title</value></field>
          </x>
        </configure>"
    );
    let document = roxmltree::Document::parse(&xml).unwrap();
    let requester = PubSubBareJid::parse(REQUESTER).unwrap();
    let name = PubSubNodeName::parse(NODE).unwrap();
    for (preflight, expected_condition, expected_updates) in [
        (None, Some("item-not-found"), 0),
        (Some(preflight(false)), Some("forbidden"), 0),
        (Some(preflight(true)), None, 1),
    ] {
        let preflight_calls = AtomicUsize::new(0);
        let configure_calls = AtomicUsize::new(0);
        let service = PubSubService::new_with_durable_outbox_database_admission(
            OwnerRepository {
                preflight,
                preflight_calls: &preflight_calls,
                configure_calls: &configure_calls,
            },
            2,
            DurableOutboxDatabaseAdmission::for_primary_pool(2),
        );
        let reply = handle_owner_set_operation(
            &service,
            &requester,
            &name,
            document.root_element(),
            async {
                assert_eq!(expected_condition, Some("item-not-found"));
                Ok(missing_node_reply_from_redirect(None))
            },
        )
        .await
        .unwrap();
        assert_eq!(error_condition(&reply), expected_condition);
        assert_eq!(preflight_calls.load(Ordering::Relaxed), 1);
        assert_eq!(configure_calls.load(Ordering::Relaxed), expected_updates);
        if expected_updates == 1 {
            assert!(matches!(reply, PubSubReply::Result(xml) if xml.is_empty()));
        }
    }
}
