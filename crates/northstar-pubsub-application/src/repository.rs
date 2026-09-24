//! Complete PubSub and PEP repository operations. Mutations include their
//! authorization snapshot and durable audience; no transaction escapes a port.
use crate::{
    PepPublishItemsCommand, PepPublishItemsResult, PepSubscribeCommand, PepSubscribeResult,
    PepUnsubscribeCommand, PepUnsubscribeResult,
};
use anyhow::Result;
use northstar_pubsub_core::*;
use uuid::Uuid;
pub trait PubSubNodeQueryRepository: Send + Sync {
    fn get_node(
        &self,
        node: &str,
    ) -> impl std::future::Future<Output = Result<Option<PubSubNode>>> + Send;
    fn node_redirect(
        &self,
        node: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn collection_parents(
        &self,
        child_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<PubSubNode>>> + Send;
    fn collection_children(
        &self,
        collection_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<PubSubNode>>> + Send;
    fn is_owner(
        &self,
        node_id: Uuid,
        requester: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}

pub trait PubSubNodeMutationRepository: Send + Sync {
    fn delete_node_as_owner_with_redirect_and_outbox(
        &self,
        node_id: Uuid,
        requester: &str,
        redirect: Option<&str>,
    ) -> impl std::future::Future<Output = Result<OwnerMutationOutcome>> + Send;

    fn update_node_config_and_graph_with_outbox(
        &self,
        node: &PubSubNode,
        requester: &str,
        expected: &PubSubNodeConfig,
        config: &PubSubNodeConfig,
    ) -> impl std::future::Future<Output = Result<PubSubConfigOutcome>> + Send;

    fn create_node(
        &self,
        node: &str,
        creator_jid: &str,
        config: &PubSubNodeConfig,
        max_nodes_per_owner: i64,
    ) -> impl std::future::Future<Output = Result<CreateNodeOutcome>> + Send;
    fn associate_collection_child(
        &self,
        collection: &PubSubNode,
        child: &PubSubNode,
        requester: &str,
    ) -> impl std::future::Future<Output = Result<CollectionUpdateOutcome>> + Send;
    fn dissociate_collection_child(
        &self,
        collection: &PubSubNode,
        child: &PubSubNode,
        requester: &str,
    ) -> impl std::future::Future<Output = Result<CollectionUpdateOutcome>> + Send;
}
/// Read-only root discovery. Count, cursor admission and rows come from one
/// authorized database statement rather than independent snapshots.
pub trait PubSubRootDiscoveryQueryRepository: Send + Sync {
    fn root_disco_page(
        &self,
        requester: &str,
        cursor: Option<&str>,
        backwards: bool,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<PubSubRootDiscoPage>> + Send;
}
pub trait PubSubItemRepository: Send + Sync {
    fn purge_node_as_owner_with_outbox(
        &self,
        node_id: Uuid,
        requester: &str,
    ) -> impl std::future::Future<Output = Result<OwnerMutationOutcome>> + Send;

    fn get_items(
        &self,
        node_id: Uuid,
        item_ids: &[String],
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<PubSubItem>>> + Send;
    fn item_ids_for_disco(
        &self,
        node_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;
    fn collection_visible_items(
        &self,
        collection_id: Uuid,
        requester: &str,
        global_item_limit: i64,
        xml_byte_limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<CollectionVisibleItem>>> + Send;
    fn can_publish(
        &self,
        node: &PubSubNode,
        requester: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn publish_items(
        &self,
        node: &PubSubNode,
        publisher_jid: &str,
        items: &[(String, String)],
        max_storage_bytes_per_owner: i64,
    ) -> impl std::future::Future<Output = Result<PublishItemsOutcome>> + Send;
    fn retract_items(
        &self,
        node_id: Uuid,
        item_ids: &[String],
        publisher_jid: &str,
        force_notification: bool,
    ) -> impl std::future::Future<Output = Result<RetractItemsOutcome>> + Send;
}
pub trait PubSubSubscriptionRepository: Send + Sync {
    fn is_subscribed(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn subscriptions_for_jid(
        &self,
        jid: &str,
        node: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Vec<PubSubSubscription>>> + Send;
    fn subscriptions_addressing_jid_page(
        &self,
        jid: &str,
        after: Option<(&str, &str)>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<PubSubSubscription>>> + Send;
    fn node_subscriptions(
        &self,
        node_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<PubSubSubscription>>> + Send;
    fn get_subscription(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<PubSubSubscription>>> + Send;
    fn active_subscriber_count(
        &self,
        node_id: Uuid,
    ) -> impl std::future::Future<Output = Result<i64>> + Send;
    fn update_subscription_options_checked(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: Option<&str>,
        options: &PubSubSubscriptionOptions,
    ) -> impl std::future::Future<Output = Result<SubscriptionOptionsOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn set_subscription_limited_with_options(
        &self,
        node_id: Uuid,
        requester: &str,
        jid: &str,
        state: &str,
        expected_node_type: &str,
        expected_access_model: &str,
        max_subscriptions: i64,
        options: Option<&PubSubSubscriptionOptions>,
        requested_subid: &str,
    ) -> impl std::future::Future<Output = Result<SubscribeOutcome>> + Send;
    fn unsubscribe_checked(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: &str,
    ) -> impl std::future::Future<Output = Result<UnsubscribeOutcome>> + Send;
    fn set_subscriptions(
        &self,
        node_id: Uuid,
        requester: &str,
        changes: &[(String, String, Option<String>)],
    ) -> impl std::future::Future<Output = Result<SetSubscriptionsOutcome>> + Send;
    fn resolve_pending_subscription(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: &str,
        allow: bool,
    ) -> impl std::future::Future<Output = Result<SubscriptionAuthorizationOutcome>> + Send;
}
pub trait PubSubAffiliationRepository: Send + Sync {
    fn get_node_affiliation(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn affiliations_for_jid(
        &self,
        jid: &str,
        node: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Vec<PubSubAffiliation>>> + Send;
    fn node_affiliations(
        &self,
        node_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<PubSubAffiliation>>> + Send;
    fn get_owner_jids(
        &self,
        node_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;
    fn get_publisher_jids(
        &self,
        node_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;
    fn set_affiliations(
        &self,
        node_id: Uuid,
        requester: &str,
        changes: &[(String, String)],
    ) -> impl std::future::Future<Output = Result<SetAffiliationsOutcome>> + Send;
}
pub trait PubSubOutboxRepository: Send + Sync {
    fn cleanup_idle_pubsub_event_streams(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;

    fn cleanup_pubsub_dead_letters(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;

    fn outbox_get_subscription(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<PubSubSubscription>>> + Send;

    fn local_account_blocks_pubsub(
        &self,
        username: &str,
        service: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn presence_delivery_denied(
        &self,
        recipient_id: Uuid,
        active_privacy_list: Option<&str>,
        connection_id: Uuid,
        service: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn authorize_pep_outbox_delivery(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
    ) -> impl std::future::Future<Output = Result<PepOutboxAuthorizationOutcome>> + Send;
    fn claim_pubsub_outbox(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<ClaimedPubSubOutboxDelivery>>> + Send;
    fn acknowledge_pubsub_outbox(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn renew_pubsub_outbox_lease(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn retry_pubsub_outbox(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
        error: &str,
    ) -> impl std::future::Future<Output = Result<PubSubOutboxFailureDisposition>> + Send;
    fn dead_letter_pubsub_outbox(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        reason: &str,
        error: &str,
    ) -> impl std::future::Future<Output = Result<PubSubOutboxFailureDisposition>> + Send;
    fn expire_pubsub_outbox(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
    fn pubsub_outbox_snapshot(
        &self,
    ) -> impl std::future::Future<Output = Result<PubSubOutboxSnapshot>> + Send;
    fn enqueue_pubsub_digest_snapshot(
        &self,
        source_delivery_id: Uuid,
        node_id: Uuid,
        subscriber_jid: &str,
        event_xml: &str,
        frequency_ms: i32,
        show_values: &[String],
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn enqueue_pubsub_digest(
        &self,
        node_id: Uuid,
        subscriber_jid: &str,
        event_xml: &str,
        frequency_ms: i32,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn claim_due_pubsub_digests(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<DuePubSubDigest>>> + Send;
    fn release_pubsub_digests(
        &self,
        ids: &[Uuid],
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn acknowledge_pubsub_digests(
        &self,
        ids: &[Uuid],
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}
pub trait PepNodeRepository: Send + Sync {
    fn roster_item(
        &self,
        owner_id: Uuid,
        jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<PubSubRosterEntry>>> + Send;

    fn pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
    ) -> impl std::future::Future<Output = Result<Option<PepNodeConfig>>> + Send;
    fn pep_nodes(
        &self,
        owner_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;
    fn find_enabled_user(
        &self,
        username: &str,
    ) -> impl std::future::Future<Output = Result<Option<PubSubAccount>>> + Send;
    fn roster(
        &self,
        owner_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<PubSubRosterEntry>>> + Send;
    fn is_blocked(
        &self,
        owner_id: Uuid,
        candidate: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn roster_group_allowed(
        &self,
        owner_id: Uuid,
        jid: &str,
        groups: &[String],
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn create_pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
        config: &PepNodeConfig,
        max_nodes: i64,
    ) -> impl std::future::Future<Output = Result<PepCreateOutcome>> + Send;
    fn update_pep_node_config(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        expected: &PepNodeConfig,
        config: &PepNodeConfig,
        factory: &dyn PepOutboxFactory,
    ) -> impl std::future::Future<Output = Result<PepOwnerMutationOutcome>> + Send;
    fn purge_pep_node(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        factory: &dyn PepOutboxFactory,
    ) -> impl std::future::Future<Output = Result<PepOwnerMutationOutcome>> + Send;
    fn delete_pep_node(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        factory: &dyn PepOutboxFactory,
    ) -> impl std::future::Future<Output = Result<PepOwnerMutationOutcome>> + Send;
}
pub trait PepItemRepository: Send + Sync {
    fn pep_items(
        &self,
        owner_id: Uuid,
        node: &str,
        item_id: Option<&str>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<(String, String)>>> + Send;
    fn pep_items_by_ids(
        &self,
        owner_id: Uuid,
        node: &str,
        item_ids: &[&str],
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<(String, String)>>> + Send;
    fn pep_items_with_timestamp(
        &self,
        owner_id: Uuid,
        node: &str,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<PepItem>>> + Send;

    fn retract_pep_items(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        item_ids: &[&str],
        notify: bool,
        factory: &dyn PepOutboxFactory,
    ) -> impl std::future::Future<Output = Result<PepOwnerMutationOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn commit_legacy_bookmarks(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        private_xml: &str,
        items: &mut [(String, String)],
        expected_previous_items: &[(String, String)],
        max_private_bytes: i64,
        quotas: PepQuotas,
        factory: &dyn PepOutboxFactory,
    ) -> impl std::future::Future<Output = Result<PepBookmarkMutationOutcome>> + Send;
    fn publish_pep_items(
        &self,
        command: PepPublishItemsCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> impl std::future::Future<Output = Result<PepPublishItemsResult>> + Send;
}
pub trait PepSubscriptionRepository: Send + Sync {
    fn pep_subscribers(
        &self,
        owner_id: Uuid,
        node: &str,
    ) -> impl std::future::Future<Output = Result<Vec<PepSubscription>>> + Send;
    fn pep_subscriptions_for_available_resource(
        &self,
        subscriber_jid: &str,
    ) -> impl std::future::Future<Output = Result<Vec<PepPresenceSubscription>>> + Send;
    fn pep_owner_usernames_for_presence_subscriber(
        &self,
        subscriber_bare: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;
    fn subscribe_pep_node(
        &self,
        command: PepSubscribeCommand<'_>,
        factory: &dyn PepSubscribeOutboxFactory,
    ) -> impl std::future::Future<Output = Result<PepSubscribeResult>> + Send;
    fn unsubscribe_pep_node(
        &self,
        command: PepUnsubscribeCommand<'_>,
    ) -> impl std::future::Future<Output = Result<PepUnsubscribeResult>> + Send;
    fn unsubscribe_pep_nodes_batch(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        changes: &[(String, Option<String>)],
        factory: &dyn PepDirectOutboxFactory,
    ) -> impl std::future::Future<Output = Result<PepOwnerMutationOutcome>> + Send;
}
pub trait PepAffiliationRepository: Send + Sync {
    fn update_pep_affiliations(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        expected: &PepNodeConfig,
        changes: &[(String, String)],
        factory: &dyn PepDirectOutboxFactory,
    ) -> impl std::future::Future<Output = Result<PepOwnerMutationOutcome>> + Send;
}
pub trait PubSubRepository:
    PubSubNodeMutationRepository
    + PubSubNodeQueryRepository
    + PubSubRootDiscoveryQueryRepository
    + PubSubItemRepository
    + PubSubSubscriptionRepository
    + PubSubAffiliationRepository
    + PubSubOutboxRepository
    + PepNodeRepository
    + PepItemRepository
    + PepSubscriptionRepository
    + PepAffiliationRepository
{
}
impl<T> PubSubRepository for T where
    T: PubSubNodeMutationRepository
        + PubSubNodeQueryRepository
        + PubSubRootDiscoveryQueryRepository
        + PubSubItemRepository
        + PubSubSubscriptionRepository
        + PubSubAffiliationRepository
        + PubSubOutboxRepository
        + PepNodeRepository
        + PepItemRepository
        + PepSubscriptionRepository
        + PepAffiliationRepository
{
}
