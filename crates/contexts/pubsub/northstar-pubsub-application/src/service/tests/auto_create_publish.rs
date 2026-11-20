use super::*;
use northstar_pubsub_core::PubSubPublishWrite;

const NODE: &str = "news";
const PUBLISHER: &str = "publisher@example.test/mobile";

struct PublishRepository {
    auto_create: AutoCreatePublishOutcome,
    reloaded: Option<PubSubNode>,
    authorized: bool,
    calls: Mutex<Vec<&'static str>>,
}

impl PublishRepository {
    fn new(auto_create: AutoCreatePublishOutcome) -> Self {
        Self {
            auto_create,
            reloaded: None,
            authorized: false,
            calls: Mutex::new(Vec::new()),
        }
    }
}

macro_rules! unexpected_calls {
    ($(fn $name:ident($($arg:ident: $type:ty),*) -> $output:ty;)*) => {
        $(async fn $name(&self, $($arg: $type),*) -> Result<$output> {
            panic!("unexpected call to {}", stringify!($name));
        })*
    };
}

impl PubSubNodeQueryRepository for PublishRepository {
    async fn get_node(&self, node: &str) -> Result<Option<PubSubNode>> {
        assert_eq!(node, NODE);
        let mut calls = self.calls.lock().unwrap();
        let initial_lookup = calls.is_empty();
        calls.push("get_node");
        if initial_lookup {
            Ok(None)
        } else {
            Ok(self.reloaded.clone())
        }
    }

    unexpected_calls! {
        fn node_redirect(_node: &str) -> Option<String>;
        fn collection_parents(_child_id: Uuid) -> Vec<PubSubNode>;
        fn collection_children(_collection_id: Uuid) -> Vec<PubSubNode>;
        fn is_owner(_node_id: Uuid, _requester: &str) -> bool;
        fn node_metadata(_node_id: Uuid) -> PubSubNodeMetadata;
        fn owner_read(_node: &str, _requester: &str, _kind: PubSubOwnerReadKind) -> PubSubOwnerRead;
    }
}

impl PubSubNodeMutationRepository for PublishRepository {
    unexpected_calls! {
        fn create_node(_node: &str, _creator: &str, _config: &PubSubNodeConfig, _limit: i64)
            -> CreateNodeOutcome;
        fn delete_node_as_owner_with_redirect_and_outbox(_node_id: Uuid, _requester: &str, _redirect: Option<&str>)
            -> OwnerMutationOutcome;
        fn update_node_config_and_graph_with_outbox(_node: &PubSubNode, _requester: &str, _expected: &PubSubNodeConfig, _config: &PubSubNodeConfig)
            -> PubSubConfigOutcome;
        fn associate_collection_child(_collection: &PubSubNode, _child: &PubSubNode, _requester: &str)
            -> northstar_pubsub_core::CollectionUpdateOutcome;
        fn dissociate_collection_child(_collection: &PubSubNode, _child: &PubSubNode, _requester: &str)
            -> northstar_pubsub_core::CollectionUpdateOutcome;
    }
}

impl PubSubItemQueryRepository for PublishRepository {
    async fn can_publish(&self, node: &PubSubNode, requester: &str) -> Result<bool> {
        assert_eq!(node.id, self.reloaded.as_ref().unwrap().id);
        assert_eq!(requester, PUBLISHER);
        self.calls.lock().unwrap().push("can_publish");
        Ok(self.authorized)
    }

    unexpected_calls! {
        fn leaf_disco_snapshot(_node: &str, _requester: &str) -> Option<PubSubLeafDiscoSnapshot>;
        fn collection_disco_snapshot(_node: &str, _requester: &str) -> Option<PubSubCollectionDiscoSnapshot>;
        fn get_items(_node_id: Uuid, _item_ids: &[String], _limit: i64) -> Vec<PubSubItem>;
    }
}

impl PubSubItemMutationRepository for PublishRepository {
    async fn create_node_and_publish_items(
        &self,
        node: &str,
        publisher_jid: &str,
        config: &PubSubNodeConfig,
        max_nodes_per_owner: i64,
        items: &[(String, String)],
        max_storage_bytes_per_owner: i64,
    ) -> Result<AutoCreatePublishOutcome> {
        assert_eq!(node, NODE);
        assert_eq!(publisher_jid, PUBLISHER);
        assert_eq!(config, &PubSubNodeConfig::default());
        assert_eq!(max_nodes_per_owner, 20);
        assert_eq!(items, publish_items().as_slice());
        assert_eq!(max_storage_bytes_per_owner, 1_000);
        self.calls
            .lock()
            .unwrap()
            .push("create_node_and_publish_items");
        Ok(self.auto_create)
    }

    async fn publish_items(
        &self,
        node: &PubSubNode,
        publisher_jid: &str,
        items: &[(String, String)],
        max_storage_bytes_per_owner: i64,
    ) -> Result<PublishItemsOutcome> {
        assert_eq!(node.id, self.reloaded.as_ref().unwrap().id);
        assert_eq!(publisher_jid, PUBLISHER);
        assert_eq!(items, publish_items().as_slice());
        assert_eq!(max_storage_bytes_per_owner, 1_000);
        self.calls.lock().unwrap().push("publish_items");
        Ok(PublishItemsOutcome::Published)
    }

    unexpected_calls! {
        fn purge_node_as_owner_with_outbox(_node_id: Uuid, _requester: &str) -> OwnerMutationOutcome;
        fn retract_items(_node_id: Uuid, _item_ids: &[String], _publisher: &str, _notify: bool) -> RetractItemsOutcome;
    }
}

impl PubSubSubscriptionQueryRepository for PublishRepository {
    unexpected_calls! {
        fn is_subscribed(_node_id: Uuid, _jid: &str) -> bool;
        fn subscriptions_for_jid(_jid: &str, _node: Option<&str>) -> Vec<PubSubSubscription>;
        fn subscriptions_addressing_jid_page(_jid: &str, _after: Option<(&str, &str)>, _limit: i64)
            -> Vec<PubSubSubscription>;
        fn get_subscription(_node_id: Uuid, _jid: &str) -> Option<PubSubSubscription>;
    }
}

impl PubSubSubscriptionMutationRepository for PublishRepository {
    fn local_domain(&self) -> &str {
        panic!("unexpected call to local_domain");
    }

    unexpected_calls! {
        fn update_subscription_options_checked(_node_id: Uuid, _requester: &str, _subscriber: &str, _subid: Option<&str>, _options: &PubSubSubscriptionOptions)
            -> SubscriptionOptionsOutcome;
        fn set_subscription_limited_with_options(_node_id: Uuid, _requester: &str, _jid: &str, _state: &str, _node_type: &str, _access_model: &str, _max: i64, _options: Option<&PubSubSubscriptionOptions>, _subid: &str)
            -> SubscribeOutcome;
        fn unsubscribe_checked(_node_id: Uuid, _requester: &str, _subscriber: &str, _subid: &str)
            -> UnsubscribeOutcome;
        fn set_subscriptions(_node_id: Uuid, _requester: &str, _changes: &[(String, String, Option<String>)])
            -> SetSubscriptionsOutcome;
        fn resolve_pending_subscription(_node_id: Uuid, _requester: &str, _subscriber: &str, _subid: &str, _allow: bool)
            -> SubscriptionAuthorizationOutcome;
    }
}

impl PubSubAffiliationQueryRepository for PublishRepository {
    unexpected_calls! {
        fn retrieval_authorization_facts(_node_id: Uuid, _jid: &str) -> (Option<String>, bool);
        fn get_node_affiliation(_node_id: Uuid, _jid: &str) -> Option<String>;
        fn affiliations_for_jid(_jid: &str, _node: Option<&str>) -> Vec<PubSubAffiliation>;
    }
}

impl PubSubAffiliationMutationRepository for PublishRepository {
    unexpected_calls! {
        fn set_affiliations(_node_id: Uuid, _requester: &str, _changes: &[(String, String)])
            -> SetAffiliationsOutcome;
    }
}

fn publish_items() -> [(String, String); 2] {
    [
        (
            "b".to_owned(),
            "<item id='b'><b xmlns='urn:test'/></item>".to_owned(),
        ),
        (
            "a".to_owned(),
            "<item id='a'><a xmlns='urn:test'/></item>".to_owned(),
        ),
    ]
}

fn published() -> PubSubPublishOutcome {
    PubSubPublishOutcome::Published {
        item_ids: vec!["b".to_owned(), "a".to_owned()],
    }
}

async fn publish(repository: PublishRepository) -> (PubSubPublishOutcome, Vec<&'static str>) {
    let service = PubSubService::new_with_durable_outbox_database_admission(
        repository,
        2,
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(2),
    );
    let result = service
        .execute_pubsub_publish(PubSubPublishCommand::from(PubSubPublishWrite {
            node: NODE,
            publisher_jid: PUBLISHER,
            items: &publish_items(),
            publish_options: Some(&PubSubNodeConfig::default()),
            max_nodes_per_owner: 20,
            max_storage_bytes_per_owner: 1_000,
        }))
        .await
        .unwrap();
    (
        result.outcome,
        service.repository.calls.into_inner().unwrap(),
    )
}

#[tokio::test]
async fn missing_node_publish_maps_combined_outcomes_without_split_mutations() {
    use AutoCreatePublishOutcome::{Create, Publish, Published};

    let cases = [
        (Published, published()),
        (
            Create(CreateNodeOutcome::QuotaExceeded),
            PubSubPublishOutcome::QuotaExceeded,
        ),
        (
            Create(CreateNodeOutcome::InvalidOptions),
            PubSubPublishOutcome::Conflict,
        ),
        (
            Create(CreateNodeOutcome::Forbidden),
            PubSubPublishOutcome::Conflict,
        ),
        (
            Create(CreateNodeOutcome::CollectionLimitExceeded),
            PubSubPublishOutcome::Conflict,
        ),
        (
            Create(CreateNodeOutcome::Cycle),
            PubSubPublishOutcome::Conflict,
        ),
        (
            Publish(PublishItemsOutcome::Conflict),
            PubSubPublishOutcome::Conflict,
        ),
        (
            Publish(PublishItemsOutcome::QuotaExceeded),
            PubSubPublishOutcome::QuotaExceeded,
        ),
        (
            Publish(PublishItemsOutcome::Forbidden),
            PubSubPublishOutcome::Forbidden,
        ),
        (
            Publish(PublishItemsOutcome::PreconditionFailed),
            PubSubPublishOutcome::PreconditionNotMet,
        ),
    ];
    for (combined, expected) in cases {
        let (outcome, calls) = publish(PublishRepository::new(combined)).await;
        assert_eq!(outcome, expected, "{combined:?}");
        assert_eq!(
            calls,
            ["get_node", "create_node_and_publish_items"],
            "{combined:?}"
        );
    }
}

#[tokio::test]
async fn auto_create_node_exists_checks_authorization_before_racing_node_policy() {
    let mut racing_node = renderer_node(Uuid::new_v4(), NODE, "leaf");
    racing_node.payload_type = Some("urn:private:expected".to_owned());
    let mut repository = PublishRepository::new(AutoCreatePublishOutcome::NodeExists);
    repository.reloaded = Some(racing_node);

    let (outcome, calls) = publish(repository).await;
    assert_eq!(outcome, PubSubPublishOutcome::Forbidden);
    assert_eq!(
        calls,
        [
            "get_node",
            "create_node_and_publish_items",
            "get_node",
            "can_publish"
        ]
    );
}

#[tokio::test]
async fn auto_create_create_conflict_reloads_and_publishes_if_authorized() {
    let mut repository = PublishRepository::new(AutoCreatePublishOutcome::Create(
        CreateNodeOutcome::Conflict,
    ));
    repository.reloaded = Some(renderer_node(Uuid::new_v4(), NODE, "leaf"));
    repository.authorized = true;

    let (outcome, calls) = publish(repository).await;
    assert_eq!(outcome, published());
    assert_eq!(
        calls,
        [
            "get_node",
            "create_node_and_publish_items",
            "get_node",
            "can_publish",
            "publish_items",
        ]
    );
}

#[tokio::test]
async fn auto_create_racing_node_disappearance_returns_missing_node() {
    for combined in [
        AutoCreatePublishOutcome::NodeExists,
        AutoCreatePublishOutcome::Create(CreateNodeOutcome::Conflict),
    ] {
        let (outcome, calls) = publish(PublishRepository::new(combined)).await;
        assert_eq!(outcome, PubSubPublishOutcome::MissingNode);
        assert_eq!(
            calls,
            ["get_node", "create_node_and_publish_items", "get_node"]
        );
    }
}
