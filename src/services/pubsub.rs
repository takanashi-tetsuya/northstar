//! Application-service boundary for XEP-0060 PubSub and PEP.
//!
//! The protocol layer owns XML parsing and stanza error mapping. This service
//! owns the PostgreSQL capability and the durable mutation/outbox workflow, so
//! protocol handlers cannot accidentally compose transactions with unrelated
//! repositories or bypass the durable audience snapshot.

use crate::db;
use crate::services::profile::{
    ProfileOutboxFactory, ProfilePepWrite, ProfilePublishResult, ProfileService,
};
use crate::xmpp::xml_builder::XmlElement;
use anyhow::{Context, Result};
pub(crate) use northstar_pubsub_application::{
    is_pubsub_mutation_busy as is_pubsub_mutation_busy_core,
    pubsub_mutation_admission_active as pubsub_mutation_admission_active_core,
    pubsub_mutation_admission_rejections_total as pubsub_mutation_admission_rejections_total_core,
    pubsub_mutation_admission_waiters as pubsub_mutation_admission_waiters_core,
    validate_pep_configure_node_command, validate_pep_delete_node_command,
    validate_pep_publish_command, validate_pep_purge_node_command,
    validate_pep_retract_command, validate_pep_set_affiliations_command,
    validate_pep_subscribe_command, validate_pep_unsubscribe_command,
    validate_pubsub_configure_node_command, validate_pubsub_create_node_command,
    validate_pubsub_delete_node_command, validate_pubsub_publish_command,
    validate_pubsub_purge_node_command, validate_pubsub_retract_command,
    validate_pubsub_set_affiliations_command, validate_pubsub_set_subscriptions_command,
    validate_pubsub_subscribe_command, validate_pubsub_unsubscribe_command,
    PepConfigureNodeCommand, PepConfigureNodeResult, PepDeleteNodeCommand,
    PepDeleteNodeResult, PepPublishItemsCommand, PepPublishItemsOutcome,
    PepPublishItemsResult, PepPurgeNodeCommand, PepPurgeNodeResult, PepRetractCommand,
    PepRetractResult, PepSetAffiliationsCommand, PepSetAffiliationsResult,
    PepSubscribeCommand, PepSubscribeResult, PepUnsubscribeCommand, PepUnsubscribeResult,
    PubSubConfigureNodeCommand, PubSubConfigureNodeResult, PubSubCreateNodeCommand,
    PubSubCreateNodeResult, PubSubDeleteNodeCommand, PubSubDeleteNodeResult,
    PubSubMutationPermit as ApplicationPubSubMutationPermit, PubSubPublishCommand,
    PubSubPublishResult, PubSubPurgeNodeCommand, PubSubPurgeNodeResult,
    PubSubRetractCommand, PubSubRetractResult, PubSubSetAffiliationsCommand,
    PubSubSetAffiliationsResult, PubSubSetSubscriptionsCommand,
    PubSubSetSubscriptionsResult, PubSubSubscribeCommand, PubSubSubscribeResult,
    PubSubUnsubscribeCommand, PubSubUnsubscribeResult,
};
pub(crate) use northstar_pubsub_core::{
    CollectionUpdateOutcome, CollectionVisibleItem, CreateNodeOutcome, OwnerMutationOutcome,
    PepAudienceSnapshot, PepBookmarkMutationOutcome, PepConfigureNodeWrite, PepCreateOutcome,
    PepDeleteNodeWrite, PepDirectStateSnapshot, PepDirectStateTransition, PepItem, PepNodeConfig,
    PepOwnerMutationOutcome, PepPresenceSubscription, PepProfileWrite, PepPublishOutcome,
    PepPublishWrite, PepPurgeNodeWrite, PepQuotas, PepRetractWrite, PepSetAffiliationsWrite,
    PepSubscribeOutcome, PepSubscribeSnapshot, PepSubscribeWrite, PepSubscription,
    PepSubscriptionActor, PepUnsubscribeOutcome, PepUnsubscribeWrite, PublishItemsOutcome,
    PubSubAccount, PubSubAffiliation, PubSubConfigOutcome, PubSubConfigureNodeWrite,
    PubSubCreateNodeWrite, PubSubDeleteNodeWrite, PubSubDiscoNode, PubSubItem, PubSubNode,
    PubSubNodeConfig, PubSubPublishOutcome, PubSubPublishWrite, PubSubPurgeNodeWrite,
    PubSubRetractOutcome, PubSubRetractWrite, PubSubSetAffiliationsWrite,
    PubSubSetSubscriptionsWrite, PubSubSubscribeOutcome, PubSubSubscribeWrite, PubSubSubscription,
    PubSubSubscriptionOptions, PubSubUnsubscribeOutcome, PubSubUnsubscribeWrite,
    RetractItemsOutcome, SetAffiliationsOutcome, SetSubscriptionsOutcome, SubscribeOutcome,
    SubscriptionAuthorizationOutcome, SubscriptionOptionsOutcome, UnsubscribeOutcome,
};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) type PubSubMutationAdmission = northstar_pubsub_application::PubSubMutationAdmission;
pub(crate) type PubSubMutationPermit = ApplicationPubSubMutationPermit;

pub(crate) fn pubsub_mutation_admission_rejections_total() -> u64 {
    pubsub_mutation_admission_rejections_total_core()
}

pub(crate) fn pubsub_mutation_admission_waiters() -> u64 {
    pubsub_mutation_admission_waiters_core()
}

pub(crate) fn pubsub_mutation_admission_active() -> u64 {
    pubsub_mutation_admission_active_core()
}

/// True only for retryable PubSub capacity/lock pressure.  Authentication,
/// policy and data-integrity errors must keep their existing stanza mapping.
pub(crate) fn is_pubsub_mutation_busy(error: &anyhow::Error) -> bool {
    if is_pubsub_mutation_busy_core(error) {
        return true;
    }
    error.chain().any(|cause| {
        if cause
            .downcast_ref::<db::pubsub::PubSubMutationBusy>()
            .is_some()
        {
            return true;
        }
        cause
            .downcast_ref::<sqlx::Error>()
            .is_some_and(|error| match error {
                sqlx::Error::PoolTimedOut => true,
                sqlx::Error::Database(error) => error
                    .code()
                    .is_some_and(|code| matches!(code.as_ref(), "55P03" | "57014")),
                _ => false,
            })
    })
}

#[derive(Clone)]
pub(crate) struct PubSubService {
    pool: PgPool,
    domain: String,
    service_jid: String,
    mutation_admission: Arc<PubSubMutationAdmission>,
}

/// Pure renderer invoked while the authoritative subscription transaction is
/// open. It receives only values read under the policy locks and cannot add a
/// recipient other than the newly subscribed JID.
pub(crate) trait PepSubscribeOutboxFactory: Send + Sync {
    fn build(&self, snapshot: &PepSubscribeSnapshot) -> Result<Vec<PubSubOutboxInsert>>;
}

impl<F> PepSubscribeOutboxFactory for F
where
    F: Fn(&PepSubscribeSnapshot) -> Result<Vec<PubSubOutboxInsert>> + Send + Sync,
{
    fn build(&self, snapshot: &PepSubscribeSnapshot) -> Result<Vec<PubSubOutboxInsert>> {
        self(snapshot)
    }
}

/// Synchronous payload factory used under the publication transaction. It may
/// consult in-memory caps/resources, but cannot perform I/O or introduce a
/// principal absent from `PepAudienceSnapshot`.
pub(crate) trait PepOutboxFactory: Send + Sync {
    fn build(&self, audience: &PepAudienceSnapshot) -> Result<Vec<(String, String)>>;
}

pub(crate) trait PepDirectOutboxFactory: Send + Sync {
    fn build(&self, snapshot: &PepDirectStateSnapshot) -> Result<Vec<(String, String)>>;
}

impl<F> PepDirectOutboxFactory for F
where
    F: Fn(&PepDirectStateSnapshot) -> Result<Vec<(String, String)>> + Send + Sync,
{
    fn build(&self, snapshot: &PepDirectStateSnapshot) -> Result<Vec<(String, String)>> {
        self(snapshot)
    }
}

impl<F> PepOutboxFactory for F
where
    F: Fn(&PepAudienceSnapshot) -> Result<Vec<(String, String)>> + Send + Sync,
{
    fn build(&self, audience: &PepAudienceSnapshot) -> Result<Vec<(String, String)>> {
        self(audience)
    }
}

struct PepRosterAudienceEntry {
    subscription: String,
    groups: Vec<String>,
}

async fn lock_pep_audience(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    node: &str,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 5))")
        .bind(format!("{owner_id}:{node}"))
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn lock_pep_block_policy(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 0))")
        .bind(owner_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

struct LockedPepSubscriptionPrincipal {
    subscriber_jid: String,
    subscriber_bare: String,
    owner_bare: String,
    local_subscriber_id: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PubSubOutboxSource {
    PubSub,
    Pep,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PubSubOutboxDeliveryKind {
    PubSubChildren,
    PubSubDigest,
    PubSubDirect,
    PepStanza,
}

pub(crate) type PepOutboxEventKind = db::PepOutboxEventKind;
pub(crate) type PepOutboxAuthorizationMode = db::PepOutboxAuthorizationMode;
pub(crate) type PepOutboxSubject = db::PepOutboxSubject;

#[derive(Clone, Debug)]
pub(crate) struct PubSubOutboxInsert {
    inner: db::PubSubOutboxInsert,
}

impl PubSubOutboxInsert {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_pep_stanza(
        event_id: Uuid,
        sender_account_id: Uuid,
        sender_bare_jid: &str,
        sender_connection_id: Option<Uuid>,
        recipient_jid: impl Into<String>,
        recipient_account_id: Option<Uuid>,
        event_kind: PepOutboxEventKind,
        authorization_mode: PepOutboxAuthorizationMode,
        payload_xml: impl Into<String>,
        node: &str,
        local_domain: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self> {
        Ok(Self {
            inner: db::PubSubOutboxInsert::new_pep_stanza(
                event_id,
                sender_account_id,
                sender_bare_jid,
                sender_connection_id,
                recipient_jid,
                recipient_account_id,
                event_kind,
                authorization_mode,
                payload_xml,
                node,
                local_domain,
                now,
            )?,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ClaimedPubSubOutboxDelivery {
    inner: db::ClaimedPubSubOutboxDelivery,
    pub(crate) delivery_id: Uuid,
    pub(crate) event_id: Uuid,
    pub(crate) ordering_key: String,
    pub(crate) event_sequence: i64,
    pub(crate) source: PubSubOutboxSource,
    pub(crate) source_node: String,
    pub(crate) delivery_kind: PubSubOutboxDeliveryKind,
    pub(crate) recipient_jid: String,
    pub(crate) target_domain: String,
    pub(crate) payload_xml: String,
    pub(crate) show_values: Option<Vec<String>>,
    pub(crate) subscription_node_id: Option<Uuid>,
    pub(crate) digest_frequency_ms: Option<i32>,
    pub(crate) attempt_count: i32,
    pub(crate) lease_token: Uuid,
    pub(crate) expires_at: chrono::DateTime<chrono::Utc>,
    pub(crate) security_sensitive: bool,
    pub(crate) pep_subject: Option<PepOutboxSubject>,
    pub(crate) legacy_unverifiable: bool,
}

impl ClaimedPubSubOutboxDelivery {
    pub(crate) fn payload_binding_valid(&self) -> bool {
        self.inner.payload_binding_valid()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PepOutboxDropReason {
    UnverifiableIdentity,
    SenderUnavailable,
    RecipientUnavailable,
    Blocked,
    PrivacyDenied,
    NodeAccessRevoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PepOutboxAuthorizationOutcome {
    Deliver,
    Drop(PepOutboxDropReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PubSubOutboxFailureDisposition {
    Retry,
    DeadLettered,
    LeaseLost,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PubSubOutboxSnapshot {
    pub(crate) pending_rows: i64,
    pub(crate) pending_bytes: i64,
    pub(crate) leased_rows: i64,
    pub(crate) due_rows: i64,
    pub(crate) dead_letter_rows: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct DuePubSubDigest {
    pub(crate) ids: Vec<Uuid>,
    pub(crate) subscription_node_id: Uuid,
    pub(crate) subscriber_jid: String,
    pub(crate) event_xml: Vec<String>,
    pub(crate) show_values: Option<Vec<String>>,
}

impl From<db::CreateNodeOutcome> for CreateNodeOutcome {
    fn from(value: db::CreateNodeOutcome) -> Self {
        match value {
            db::CreateNodeOutcome::Created(_) => Self::Created,
            db::CreateNodeOutcome::Conflict => Self::Conflict,
            db::CreateNodeOutcome::QuotaExceeded => Self::QuotaExceeded,
            db::CreateNodeOutcome::InvalidOptions => Self::InvalidOptions,
            db::CreateNodeOutcome::Forbidden => Self::Forbidden,
            db::CreateNodeOutcome::CollectionLimitExceeded => Self::CollectionLimitExceeded,
            db::CreateNodeOutcome::Cycle => Self::Cycle,
        }
    }
}

impl From<db::PublishItemsOutcome> for PublishItemsOutcome {
    fn from(value: db::PublishItemsOutcome) -> Self {
        match value {
            db::PublishItemsOutcome::Published => Self::Published,
            db::PublishItemsOutcome::Conflict => Self::Conflict,
            db::PublishItemsOutcome::QuotaExceeded => Self::QuotaExceeded,
            db::PublishItemsOutcome::Forbidden => Self::Forbidden,
            db::PublishItemsOutcome::PreconditionFailed => Self::PreconditionFailed,
        }
    }
}

impl From<db::RetractItemsOutcome> for RetractItemsOutcome {
    fn from(value: db::RetractItemsOutcome) -> Self {
        match value {
            db::RetractItemsOutcome::Retracted => Self::Retracted,
            db::RetractItemsOutcome::NotFound => Self::NotFound,
            db::RetractItemsOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<db::CollectionUpdateOutcome> for CollectionUpdateOutcome {
    fn from(value: db::CollectionUpdateOutcome) -> Self {
        match value {
            db::CollectionUpdateOutcome::Updated => Self::Updated,
            db::CollectionUpdateOutcome::NotFound => Self::NotFound,
            db::CollectionUpdateOutcome::NotAssociated => Self::NotAssociated,
            db::CollectionUpdateOutcome::NotCollection => Self::NotCollection,
            db::CollectionUpdateOutcome::Forbidden => Self::Forbidden,
            db::CollectionUpdateOutcome::LimitExceeded => Self::LimitExceeded,
            db::CollectionUpdateOutcome::DepthExceeded => Self::DepthExceeded,
            db::CollectionUpdateOutcome::Cycle => Self::Cycle,
        }
    }
}

impl From<db::PubSubConfigOutcome> for PubSubConfigOutcome {
    fn from(value: db::PubSubConfigOutcome) -> Self {
        match value {
            db::PubSubConfigOutcome::Updated => Self::Updated,
            db::PubSubConfigOutcome::Conflict => Self::Conflict,
            db::PubSubConfigOutcome::NotFound => Self::NotFound,
            db::PubSubConfigOutcome::InvalidOptions => Self::InvalidOptions,
            db::PubSubConfigOutcome::Forbidden => Self::Forbidden,
            db::PubSubConfigOutcome::LimitExceeded => Self::LimitExceeded,
            db::PubSubConfigOutcome::Cycle => Self::Cycle,
        }
    }
}

impl From<db::SetSubscriptionsOutcome> for SetSubscriptionsOutcome {
    fn from(value: db::SetSubscriptionsOutcome) -> Self {
        match value {
            db::SetSubscriptionsOutcome::Updated(transitions) => Self::Updated(transitions),
            db::SetSubscriptionsOutcome::LimitExceeded => Self::LimitExceeded,
            db::SetSubscriptionsOutcome::InvalidSubid => Self::InvalidSubid,
            db::SetSubscriptionsOutcome::NotFound => Self::NotFound,
            db::SetSubscriptionsOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<db::SetAffiliationsOutcome> for SetAffiliationsOutcome {
    fn from(value: db::SetAffiliationsOutcome) -> Self {
        match value {
            db::SetAffiliationsOutcome::Updated {
                revoked_subscriptions,
                approved_subscriptions,
            } => Self::Updated {
                revoked_subscriptions,
                approved_subscriptions,
            },
            db::SetAffiliationsOutcome::LastOwner => Self::LastOwner,
            db::SetAffiliationsOutcome::NotFound => Self::NotFound,
            db::SetAffiliationsOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<db::OwnerMutationOutcome> for OwnerMutationOutcome {
    fn from(value: db::OwnerMutationOutcome) -> Self {
        match value {
            db::OwnerMutationOutcome::Applied => Self::Applied,
            db::OwnerMutationOutcome::NotFound => Self::NotFound,
            db::OwnerMutationOutcome::Forbidden => Self::Forbidden,
            db::OwnerMutationOutcome::Invalid => Self::Invalid,
        }
    }
}

impl From<db::SubscribeOutcome> for SubscribeOutcome {
    fn from(value: db::SubscribeOutcome) -> Self {
        match value {
            db::SubscribeOutcome::Subscribed(subscription) => Self::Subscribed(subscription.into()),
            db::SubscribeOutcome::LimitExceeded => Self::LimitExceeded,
            db::SubscribeOutcome::NotFound => Self::NotFound,
            db::SubscribeOutcome::Forbidden => Self::Forbidden,
            db::SubscribeOutcome::ClosedNode => Self::ClosedNode,
            db::SubscribeOutcome::PreconditionFailed => Self::PreconditionFailed,
        }
    }
}

impl From<db::UnsubscribeOutcome> for UnsubscribeOutcome {
    fn from(value: db::UnsubscribeOutcome) -> Self {
        match value {
            db::UnsubscribeOutcome::Unsubscribed => Self::Unsubscribed,
            db::UnsubscribeOutcome::NotFound => Self::NotFound,
            db::UnsubscribeOutcome::InvalidSubid => Self::InvalidSubid,
            db::UnsubscribeOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<db::SubscriptionOptionsOutcome> for SubscriptionOptionsOutcome {
    fn from(value: db::SubscriptionOptionsOutcome) -> Self {
        match value {
            db::SubscriptionOptionsOutcome::Updated => Self::Updated,
            db::SubscriptionOptionsOutcome::NotFound => Self::NotFound,
            db::SubscriptionOptionsOutcome::InvalidSubid => Self::InvalidSubid,
            db::SubscriptionOptionsOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<db::PepNodeConfig> for PepNodeConfig {
    fn from(value: db::PepNodeConfig) -> Self {
        Self {
            access_model: value.access_model,
            max_items: value.max_items,
            persist_items: value.persist_items,
            send_last_published_item: value.send_last_published_item,
            deliver_notifications: value.deliver_notifications,
            roster_groups_allowed: value.roster_groups_allowed,
            access_whitelist: value.access_whitelist,
        }
    }
}

impl From<&PepNodeConfig> for db::PepNodeConfig {
    fn from(value: &PepNodeConfig) -> Self {
        Self {
            access_model: value.access_model.clone(),
            max_items: value.max_items,
            persist_items: value.persist_items,
            send_last_published_item: value.send_last_published_item.clone(),
            deliver_notifications: value.deliver_notifications,
            roster_groups_allowed: value.roster_groups_allowed.clone(),
            access_whitelist: value.access_whitelist.clone(),
        }
    }
}

impl From<PepQuotas> for db::PepQuotas {
    fn from(value: PepQuotas) -> Self {
        Self {
            max_nodes: value.max_nodes,
            max_storage_bytes: value.max_storage_bytes,
        }
    }
}

impl From<db::PepCreateOutcome> for PepCreateOutcome {
    fn from(value: db::PepCreateOutcome) -> Self {
        match value {
            db::PepCreateOutcome::Created => Self::Created,
            db::PepCreateOutcome::Conflict => Self::Conflict,
            db::PepCreateOutcome::QuotaExceeded => Self::QuotaExceeded,
        }
    }
}

impl From<db::PepPublishOutcome> for PepPublishOutcome {
    fn from(value: db::PepPublishOutcome) -> Self {
        match value {
            db::PepPublishOutcome::Published => Self::Published,
            db::PepPublishOutcome::PreconditionFailed => Self::PreconditionFailed,
            db::PepPublishOutcome::MaxItemsExceeded => Self::MaxItemsExceeded,
            db::PepPublishOutcome::QuotaExceeded => Self::QuotaExceeded,
        }
    }
}

impl From<db::PepSubscription> for PepSubscription {
    fn from(value: db::PepSubscription) -> Self {
        Self {
            jid: value.jid,
            subid: value.subid,
        }
    }
}

impl From<db::PepPresenceSubscription> for PepPresenceSubscription {
    fn from(value: db::PepPresenceSubscription) -> Self {
        Self {
            owner_id: value.owner_id,
            owner_username: value.owner_username,
            node: value.node,
        }
    }
}

impl From<db::PepItem> for PepItem {
    fn from(value: db::PepItem) -> Self {
        Self {
            item_id: value.item_id,
            payload: value.payload,
            updated_at: value.updated_at,
        }
    }
}

impl From<db::PubSubNode> for PubSubNode {
    fn from(value: db::PubSubNode) -> Self {
        Self {
            id: value.id,
            node: value.node,
            creator_jid: value.creator_jid,
            access_model: value.access_model,
            publish_model: value.publish_model,
            max_items: value.max_items,
            title: value.title,
            description: value.description,
            deliver_payloads: value.deliver_payloads,
            notify_delete: value.notify_delete,
            notify_retract: value.notify_retract,
            persist_items: value.persist_items,
            send_last_published_item: value.send_last_published_item,
            node_type: value.node_type,
            deliver_notifications: value.deliver_notifications,
            notify_config: value.notify_config,
            notify_sub: value.notify_sub,
            language: value.language,
            payload_type: value.payload_type,
            max_payload_size: value.max_payload_size,
            children_max: value.children_max,
            children_association_policy: value.children_association_policy,
            children_association_whitelist: value.children_association_whitelist,
            created_at: value.created_at,
        }
    }
}

impl From<&PubSubNode> for db::PubSubNode {
    fn from(value: &PubSubNode) -> Self {
        Self {
            id: value.id,
            node: value.node.clone(),
            creator_jid: value.creator_jid.clone(),
            access_model: value.access_model.clone(),
            publish_model: value.publish_model.clone(),
            max_items: value.max_items,
            title: value.title.clone(),
            description: value.description.clone(),
            deliver_payloads: value.deliver_payloads,
            notify_delete: value.notify_delete,
            notify_retract: value.notify_retract,
            persist_items: value.persist_items,
            send_last_published_item: value.send_last_published_item.clone(),
            node_type: value.node_type.clone(),
            deliver_notifications: value.deliver_notifications,
            notify_config: value.notify_config,
            notify_sub: value.notify_sub,
            language: value.language.clone(),
            payload_type: value.payload_type.clone(),
            max_payload_size: value.max_payload_size,
            children_max: value.children_max,
            children_association_policy: value.children_association_policy.clone(),
            children_association_whitelist: value.children_association_whitelist.clone(),
            created_at: value.created_at,
        }
    }
}

impl From<db::PubSubNodeConfig> for PubSubNodeConfig {
    fn from(value: db::PubSubNodeConfig) -> Self {
        Self {
            access_model: value.access_model,
            publish_model: value.publish_model,
            max_items: value.max_items,
            title: value.title,
            description: value.description,
            deliver_payloads: value.deliver_payloads,
            notify_delete: value.notify_delete,
            notify_retract: value.notify_retract,
            persist_items: value.persist_items,
            send_last_published_item: value.send_last_published_item,
            node_type: value.node_type,
            deliver_notifications: value.deliver_notifications,
            notify_config: value.notify_config,
            notify_sub: value.notify_sub,
            language: value.language,
            payload_type: value.payload_type,
            max_payload_size: value.max_payload_size,
            children_max: value.children_max,
            children_association_policy: value.children_association_policy,
            children_association_whitelist: value.children_association_whitelist,
            collections: value.collections,
            children: value.children,
        }
    }
}

impl From<&PubSubNodeConfig> for db::PubSubNodeConfig {
    fn from(value: &PubSubNodeConfig) -> Self {
        Self {
            access_model: value.access_model.clone(),
            publish_model: value.publish_model.clone(),
            max_items: value.max_items,
            title: value.title.clone(),
            description: value.description.clone(),
            deliver_payloads: value.deliver_payloads,
            notify_delete: value.notify_delete,
            notify_retract: value.notify_retract,
            persist_items: value.persist_items,
            send_last_published_item: value.send_last_published_item.clone(),
            node_type: value.node_type.clone(),
            deliver_notifications: value.deliver_notifications,
            notify_config: value.notify_config,
            notify_sub: value.notify_sub,
            language: value.language.clone(),
            payload_type: value.payload_type.clone(),
            max_payload_size: value.max_payload_size,
            children_max: value.children_max,
            children_association_policy: value.children_association_policy.clone(),
            children_association_whitelist: value.children_association_whitelist.clone(),
            collections: value.collections.clone(),
            children: value.children.clone(),
        }
    }
}

impl From<db::PubSubItem> for PubSubItem {
    fn from(value: db::PubSubItem) -> Self {
        Self {
            item_id: value.item_id,
            xml_payload: value.xml_payload,
            created_at: value.created_at,
        }
    }
}

impl From<db::CollectionVisibleItem> for CollectionVisibleItem {
    fn from(value: db::CollectionVisibleItem) -> Self {
        Self {
            node: value.node,
            xml_payload: value.xml_payload,
        }
    }
}

impl From<db::PubSubSubscription> for PubSubSubscription {
    fn from(value: db::PubSubSubscription) -> Self {
        Self {
            node: value.node,
            jid: value.jid,
            state: value.state,
            subid: value.subid,
            deliver: value.deliver,
            digest: value.digest,
            digest_frequency: value.digest_frequency,
            expire: value.expire,
            include_body: value.include_body,
            show_values: value.show_values,
            subscription_type: value.subscription_type,
            subscription_depth: value.subscription_depth,
        }
    }
}

impl From<&PubSubSubscription> for db::PubSubSubscription {
    fn from(value: &PubSubSubscription) -> Self {
        Self {
            node: value.node.clone(),
            jid: value.jid.clone(),
            state: value.state.clone(),
            subid: value.subid.clone(),
            deliver: value.deliver,
            digest: value.digest,
            digest_frequency: value.digest_frequency,
            expire: value.expire,
            include_body: value.include_body,
            show_values: value.show_values.clone(),
            subscription_type: value.subscription_type.clone(),
            subscription_depth: value.subscription_depth,
        }
    }
}

impl From<db::PubSubSubscriptionOptions> for PubSubSubscriptionOptions {
    fn from(value: db::PubSubSubscriptionOptions) -> Self {
        Self {
            deliver: value.deliver,
            digest: value.digest,
            digest_frequency: value.digest_frequency,
            expire: value.expire,
            include_body: value.include_body,
            show_values: value.show_values,
            subscription_type: value.subscription_type,
            subscription_depth: value.subscription_depth,
        }
    }
}

impl From<&PubSubSubscriptionOptions> for db::PubSubSubscriptionOptions {
    fn from(value: &PubSubSubscriptionOptions) -> Self {
        Self {
            deliver: value.deliver,
            digest: value.digest,
            digest_frequency: value.digest_frequency,
            expire: value.expire,
            include_body: value.include_body,
            show_values: value.show_values.clone(),
            subscription_type: value.subscription_type.clone(),
            subscription_depth: value.subscription_depth,
        }
    }
}

impl From<db::PubSubAffiliation> for PubSubAffiliation {
    fn from(value: db::PubSubAffiliation) -> Self {
        Self {
            node: value.node,
            jid: value.jid,
            affiliation: value.affiliation,
        }
    }
}

impl From<db::PubSubDiscoNode> for PubSubDiscoNode {
    fn from(value: db::PubSubDiscoNode) -> Self {
        Self {
            node: value.node,
            title: value.title,
        }
    }
}

impl From<db::SubscriptionAuthorizationOutcome> for SubscriptionAuthorizationOutcome {
    fn from(value: db::SubscriptionAuthorizationOutcome) -> Self {
        match value {
            db::SubscriptionAuthorizationOutcome::Applied => Self::Applied,
            db::SubscriptionAuthorizationOutcome::NotFound => Self::NotFound,
            db::SubscriptionAuthorizationOutcome::Forbidden => Self::Forbidden,
            db::SubscriptionAuthorizationOutcome::Stale => Self::Stale,
        }
    }
}

impl From<PubSubOutboxSource> for db::PubSubOutboxSource {
    fn from(value: PubSubOutboxSource) -> Self {
        match value {
            PubSubOutboxSource::PubSub => Self::PubSub,
            PubSubOutboxSource::Pep => Self::Pep,
        }
    }
}

impl From<PubSubOutboxDeliveryKind> for db::PubSubOutboxDeliveryKind {
    fn from(value: PubSubOutboxDeliveryKind) -> Self {
        match value {
            PubSubOutboxDeliveryKind::PubSubChildren => Self::PubSubChildren,
            PubSubOutboxDeliveryKind::PubSubDigest => Self::PubSubDigest,
            PubSubOutboxDeliveryKind::PubSubDirect => Self::PubSubDirect,
            PubSubOutboxDeliveryKind::PepStanza => Self::PepStanza,
        }
    }
}

impl From<db::PubSubOutboxDeliveryKind> for PubSubOutboxDeliveryKind {
    fn from(value: db::PubSubOutboxDeliveryKind) -> Self {
        match value {
            db::PubSubOutboxDeliveryKind::PubSubChildren => Self::PubSubChildren,
            db::PubSubOutboxDeliveryKind::PubSubDigest => Self::PubSubDigest,
            db::PubSubOutboxDeliveryKind::PubSubDirect => Self::PubSubDirect,
            db::PubSubOutboxDeliveryKind::PepStanza => Self::PepStanza,
        }
    }
}

impl From<db::ClaimedPubSubOutboxDelivery> for ClaimedPubSubOutboxDelivery {
    fn from(inner: db::ClaimedPubSubOutboxDelivery) -> Self {
        Self {
            delivery_id: inner.delivery_id,
            event_id: inner.event_id,
            ordering_key: inner.ordering_key.clone(),
            event_sequence: inner.event_sequence,
            source: match inner.source {
                db::PubSubOutboxSource::PubSub => PubSubOutboxSource::PubSub,
                db::PubSubOutboxSource::Pep => PubSubOutboxSource::Pep,
            },
            source_node: inner.source_node.clone(),
            delivery_kind: inner.delivery_kind.into(),
            recipient_jid: inner.recipient_jid.clone(),
            target_domain: inner.target_domain.clone(),
            payload_xml: inner.payload_xml.clone(),
            show_values: inner.show_values.clone(),
            subscription_node_id: inner.subscription_node_id,
            digest_frequency_ms: inner.digest_frequency_ms,
            attempt_count: inner.attempt_count,
            lease_token: inner.lease_token,
            expires_at: inner.expires_at,
            security_sensitive: inner.security_sensitive,
            pep_subject: inner.pep_subject.clone(),
            legacy_unverifiable: inner.legacy_unverifiable,
            inner,
        }
    }
}

impl From<db::PubSubOutboxFailureDisposition> for PubSubOutboxFailureDisposition {
    fn from(value: db::PubSubOutboxFailureDisposition) -> Self {
        match value {
            db::PubSubOutboxFailureDisposition::Retry => Self::Retry,
            db::PubSubOutboxFailureDisposition::DeadLettered => Self::DeadLettered,
            db::PubSubOutboxFailureDisposition::LeaseLost => Self::LeaseLost,
        }
    }
}

impl From<db::PubSubOutboxSnapshot> for PubSubOutboxSnapshot {
    fn from(value: db::PubSubOutboxSnapshot) -> Self {
        Self {
            pending_rows: value.pending_rows,
            pending_bytes: value.pending_bytes,
            leased_rows: value.leased_rows,
            due_rows: value.due_rows,
            dead_letter_rows: value.dead_letter_rows,
        }
    }
}

impl From<db::DuePubSubDigest> for DuePubSubDigest {
    fn from(value: db::DuePubSubDigest) -> Self {
        Self {
            ids: value.ids,
            subscription_node_id: value.subscription_node_id,
            subscriber_jid: value.subscriber_jid,
            event_xml: value.event_xml,
            show_values: value.show_values,
        }
    }
}

fn db_outbox(entries: &[PubSubOutboxInsert]) -> Vec<db::PubSubOutboxInsert> {
    entries.iter().map(|entry| entry.inner.clone()).collect()
}

impl PubSubService {
    pub(crate) fn new(pool: PgPool, domain: &str) -> Self {
        let mutation_admission = Arc::new(PubSubMutationAdmission::new(
            pool.options().get_max_connections() as usize,
        ));
        Self {
            pool,
            domain: domain.to_owned(),
            service_jid: format!("pubsub.{domain}"),
            mutation_admission,
        }
    }

    pub(crate) const PEP_MAX_ITEMS: i32 = db::PEP_MAX_ITEMS;

    pub(crate) fn mutation_admission(&self) -> Arc<PubSubMutationAdmission> {
        Arc::clone(&self.mutation_admission)
    }

    async fn admit_mutation(
        &self,
        keys: &[&str],
        collection_graph: bool,
    ) -> Result<PubSubMutationPermit> {
        self.mutation_admission
            .acquire(keys, collection_graph)
            .await
            .map_err(|_| db::pubsub::PubSubMutationBusy.into())
    }

    async fn begin_mutation(&self) -> Result<Transaction<'_, Postgres>> {
        db::pubsub::begin_bounded_pubsub_mutation(&self.pool).await
    }

    pub(crate) fn default_pep_node_config(node: &str) -> PepNodeConfig {
        db::default_pep_node_config(node).into()
    }

    pub(crate) fn canonical_profile_item_id(node: &str, item_id: &str) -> Result<String> {
        db::profile_identity::canonical_profile_item_id(node, item_id)
    }

    // PEP query and mutation slice -------------------------------------------------

    pub(crate) async fn pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
    ) -> Result<Option<PepNodeConfig>> {
        Ok(db::pep_node(&self.pool, owner_id, node)
            .await?
            .map(Into::into))
    }

    pub(crate) async fn pep_items(
        &self,
        owner_id: Uuid,
        node: &str,
        item_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        db::pep_items(&self.pool, owner_id, node, item_id, limit).await
    }

    pub(crate) async fn pep_items_by_ids(
        &self,
        owner_id: Uuid,
        node: &str,
        item_ids: &[&str],
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        db::pep_items_by_ids(&self.pool, owner_id, node, item_ids, limit).await
    }

    pub(crate) async fn pep_items_with_timestamp(
        &self,
        owner_id: Uuid,
        node: &str,
        limit: i64,
    ) -> Result<Vec<PepItem>> {
        Ok(
            db::pep_items_with_timestamp(&self.pool, owner_id, node, limit)
                .await?
                .into_iter()
                .map(Into::into)
                .collect(),
        )
    }

    pub(crate) async fn pep_nodes(&self, owner_id: Uuid) -> Result<Vec<String>> {
        db::pep_nodes(&self.pool, owner_id).await
    }

    pub(crate) async fn pep_subscribers(
        &self,
        owner_id: Uuid,
        node: &str,
    ) -> Result<Vec<PepSubscription>> {
        Ok(db::pep_subscribers(&self.pool, owner_id, node)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub(crate) async fn pep_subscriptions_for_available_resource(
        &self,
        subscriber_jid: &str,
    ) -> Result<Vec<PepPresenceSubscription>> {
        Ok(
            db::pep_subscriptions_for_available_resource(&self.pool, subscriber_jid)
                .await?
                .into_iter()
                .map(Into::into)
                .collect(),
        )
    }

    pub(crate) async fn pep_owner_usernames_for_presence_subscriber(
        &self,
        subscriber_bare: &str,
    ) -> Result<Vec<String>> {
        db::pep_owner_usernames_for_presence_subscriber(&self.pool, subscriber_bare).await
    }

    pub(crate) async fn find_enabled_user(&self, username: &str) -> Result<Option<PubSubAccount>> {
        Ok(db::find_enabled_user(&self.pool, username)
            .await?
            .map(|user| PubSubAccount {
                id: user.id,
                username: user.username,
                auth_generation: user.auth_generation,
            }))
    }

    pub(crate) async fn roster(
        &self,
        owner_id: Uuid,
    ) -> Result<Vec<(String, Option<String>, String, Option<String>)>> {
        db::roster(&self.pool, owner_id).await
    }

    pub(crate) async fn roster_item(
        &self,
        owner_id: Uuid,
        jid: &str,
    ) -> Result<Option<(String, Option<String>, String, Option<String>)>> {
        db::roster_item(&self.pool, owner_id, jid).await
    }

    pub(crate) async fn is_blocked(&self, owner_id: Uuid, candidate: &str) -> Result<bool> {
        db::is_blocked(&self.pool, owner_id, candidate).await
    }

    pub(crate) async fn roster_group_allowed(
        &self,
        owner_id: Uuid,
        jid: &str,
        groups: &[String],
    ) -> Result<bool> {
        db::roster_group_allowed(&self.pool, owner_id, jid, groups).await
    }

    pub(crate) async fn create_pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
        config: &PepNodeConfig,
        max_nodes: i64,
    ) -> Result<PepCreateOutcome> {
        let owner_key = owner_id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        let config = db::PepNodeConfig::from(config);
        Ok(
            db::create_pep_node(&self.pool, owner_id, node, &config, max_nodes)
                .await?
                .into(),
        )
    }

    /// Creates an explicit PEP subscription from one authoritative policy
    /// snapshot. Identity, account incarnation, node policy, roster state,
    /// both locally enforceable block directions, quotas, the subscription
    /// row and the optional last-item outbox projection are linearized here.
    pub(crate) async fn subscribe_pep_node(
        &self,
        command: PepSubscribeCommand<'_>,
        factory: &dyn PepSubscribeOutboxFactory,
    ) -> Result<PepSubscribeResult> {
        validate_pep_subscribe_command(&command)?;
        let write = command.write;
        let owner_key = write.owner.id.to_string();
        let _permit = self
            .admit_mutation(&[&owner_key, write.subscriber_jid, write.node], false)
            .await?;
        let mut transaction = self.begin_mutation().await?;
        let Some(principal) = self
            .lock_pep_subscription_principal(
                &mut transaction,
                write.owner,
                &write.actor,
                write.subscriber_jid,
            )
            .await?
        else {
            transaction.rollback().await?;
            return Ok(PepSubscribeResult::from(PepSubscribeOutcome::Forbidden));
        };

        // Per-bare-JID quota first, then per-node serialization. All callers
        // use this order, so concurrent subscriptions cannot deadlock by
        // choosing different nodes for the same subscriber.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 4))")
            .bind(&principal.subscriber_bare)
            .execute(&mut *transaction)
            .await?;
        lock_pep_audience(&mut transaction, write.owner.id, write.node).await?;

        let policy = sqlx::query(
            "SELECT access_model,send_last_published_item,deliver_notifications,
                    roster_groups_allowed,access_whitelist
               FROM pep_nodes
              WHERE owner_id=$1 AND node=$2
              FOR SHARE",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(policy) = policy else {
            transaction.rollback().await?;
            return Ok(PepSubscribeResult::from(PepSubscribeOutcome::NotFound));
        };

        let mut block_owners = vec![write.owner.id];
        if let Some(subscriber_id) = principal.local_subscriber_id {
            block_owners.push(subscriber_id);
        }
        block_owners.sort_unstable();
        block_owners.dedup();
        for block_owner in &block_owners {
            lock_pep_block_policy(&mut transaction, *block_owner).await?;
        }
        let block_rows = sqlx::query(
            "SELECT owner_id,blocked_jid FROM blocked_jids
              WHERE owner_id=ANY($1)
              ORDER BY owner_id,blocked_jid
              FOR SHARE",
        )
        .bind(&block_owners)
        .fetch_all(&mut *transaction)
        .await?;
        let mut blocks: HashMap<Uuid, Vec<String>> = HashMap::new();
        for row in block_rows {
            blocks
                .entry(row.try_get("owner_id")?)
                .or_default()
                .push(row.try_get("blocked_jid")?);
        }

        let owner_blocks_subscriber = blocks.get(&write.owner.id).is_some_and(|patterns| {
            patterns
                .iter()
                .any(|pattern| db::roster::blocked_jid_matches(pattern, &principal.subscriber_jid))
        });
        let subscriber_blocks_owner = principal.local_subscriber_id.is_some_and(|subscriber_id| {
            blocks.get(&subscriber_id).is_some_and(|patterns| {
                patterns
                    .iter()
                    .any(|pattern| db::roster::blocked_jid_matches(pattern, &principal.owner_bare))
            })
        });

        let roster = sqlx::query("SELECT subscription,groups FROM roster_items WHERE owner_id=$1 AND contact_jid=$2 FOR SHARE")
            .bind(write.owner.id)
            .bind(&principal.subscriber_bare)
            .fetch_optional(&mut *transaction)
            .await?
            .map(|row| {
                Ok::<PepRosterAudienceEntry, anyhow::Error>(PepRosterAudienceEntry {
                    subscription: row.try_get("subscription")?,
                    groups: serde_json::from_value(row.try_get("groups")?)
                        .context("stored PEP roster groups are not a string array")?,
                })
            })
            .transpose()?;
        let access_model: String = policy.try_get("access_model")?;
        let authorized = if principal.subscriber_bare == principal.owner_bare {
            true
        } else if owner_blocks_subscriber || subscriber_blocks_owner {
            false
        } else {
            match access_model.as_str() {
                "open" => true,
                "whitelist" => {
                    let whitelist: Vec<String> = policy.try_get("access_whitelist")?;
                    whitelist.iter().any(|jid| {
                        crate::jid::canonical_bare_key(jid)
                            .is_ok_and(|jid| jid == principal.subscriber_bare)
                    })
                }
                "presence" => roster
                    .as_ref()
                    .is_some_and(|entry| matches!(entry.subscription.as_str(), "from" | "both")),
                "roster" => {
                    let allowed: Vec<String> = policy.try_get("roster_groups_allowed")?;
                    roster.as_ref().is_some_and(|entry| {
                        entry.groups.iter().any(|group| allowed.contains(group))
                    })
                }
                _ => false,
            }
        };
        if !authorized {
            transaction.rollback().await?;
            return Ok(PepSubscribeResult::from(
                PepSubscribeOutcome::NotAuthorized(access_model),
            ));
        }

        let existing = sqlx::query_scalar::<_, String>(
            "SELECT subid FROM pep_subscriptions
              WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3
              FOR UPDATE",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .bind(&principal.subscriber_jid)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(subid) = existing {
            transaction.commit().await?;
            return Ok(PepSubscribeResult::from(PepSubscribeOutcome::Subscribed(
                PepSubscription {
                    jid: principal.subscriber_jid,
                    subid,
                },
            )));
        }

        let subscriber_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pep_subscriptions
              WHERE split_part(subscriber_jid, '/', 1)=$1",
        )
        .bind(&principal.subscriber_bare)
        .fetch_one(&mut *transaction)
        .await?;
        let node_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pep_subscriptions WHERE owner_id=$1 AND node=$2",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .fetch_one(&mut *transaction)
        .await?;
        if write.max_subscriptions <= 0
            || subscriber_count >= write.max_subscriptions
            || node_count >= db::PEP_MAX_SUBSCRIBERS_PER_NODE
        {
            transaction.rollback().await?;
            return Ok(PepSubscribeResult::from(PepSubscribeOutcome::LimitExceeded));
        }

        let last_item = if policy.try_get::<bool, _>("deliver_notifications")?
            && policy.try_get::<String, _>("send_last_published_item")? != "never"
        {
            sqlx::query(
                "SELECT item_id,payload,updated_at FROM pep_items
                  WHERE owner_id=$1 AND node=$2
                  ORDER BY updated_at DESC,item_id DESC LIMIT 1
                  FOR SHARE",
            )
            .bind(write.owner.id)
            .bind(write.node)
            .fetch_optional(&mut *transaction)
            .await?
            .map(|row| {
                Ok::<PepItem, sqlx::Error>(PepItem {
                    item_id: row.try_get("item_id")?,
                    payload: row.try_get("payload")?,
                    updated_at: row.try_get("updated_at")?,
                })
            })
            .transpose()?
        } else {
            None
        };
        sqlx::query(
            "INSERT INTO pep_subscriptions(owner_id,node,subscriber_jid,subid)
             VALUES($1,$2,$3,$4)",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .bind(&principal.subscriber_jid)
        .bind(write.requested_subid)
        .execute(&mut *transaction)
        .await?;
        let snapshot = PepSubscribeSnapshot {
            owner_id: write.owner.id,
            owner_bare_jid: principal.owner_bare,
            node: write.node.to_owned(),
            subscriber_jid: principal.subscriber_jid.clone(),
            subscriber_account_id: principal.local_subscriber_id,
            local_domain: self.domain.clone(),
            last_item,
        };
        let outbox = db_outbox(&factory.build(&snapshot)?);
        anyhow::ensure!(
            outbox.iter().all(|entry| {
                entry.source == db::PubSubOutboxSource::Pep
                    && entry.delivery_kind == db::PubSubOutboxDeliveryKind::PepStanza
                    && entry.source_node == write.node
                    && entry.recipient_jid == principal.subscriber_jid
            }),
            "PEP subscription renderer escaped the transaction-owned recipient"
        );
        db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        transaction.commit().await?;
        Ok(PepSubscribeResult::from(PepSubscribeOutcome::Subscribed(
            PepSubscription {
                jid: principal.subscriber_jid,
                subid: write.requested_subid.to_owned(),
            },
        )))
    }

    /// Idempotently removes only the subscription identity controlled by the
    /// authenticated actor. A resource may remove its own full-JID row or a
    /// bare row, but cannot name a sibling resource's full-JID subscription.
    pub(crate) async fn unsubscribe_pep_node(
        &self,
        command: PepUnsubscribeCommand<'_>,
    ) -> Result<PepUnsubscribeResult> {
        validate_pep_unsubscribe_command(&command)?;
        let write = command.write;
        let owner_key = write.owner.id.to_string();
        let _permit = self
            .admit_mutation(&[&owner_key, write.subscriber_jid, write.node], false)
            .await?;
        let mut transaction = self.begin_mutation().await?;
        let Some(principal) = self
            .lock_pep_subscription_principal(
                &mut transaction,
                write.owner,
                &write.actor,
                write.subscriber_jid,
            )
            .await?
        else {
            transaction.rollback().await?;
            return Ok(PepUnsubscribeResult::from(PepUnsubscribeOutcome::Forbidden));
        };
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 4))")
            .bind(&principal.subscriber_bare)
            .execute(&mut *transaction)
            .await?;
        lock_pep_audience(&mut transaction, write.owner.id, write.node).await?;
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT TRUE FROM pep_nodes WHERE owner_id=$1 AND node=$2 FOR SHARE",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .fetch_optional(&mut *transaction)
        .await?;
        if exists.is_none() {
            transaction.rollback().await?;
            return Ok(PepUnsubscribeResult::from(PepUnsubscribeOutcome::NotFound));
        }
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT subid FROM pep_subscriptions
              WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3
              FOR UPDATE",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .bind(&principal.subscriber_jid)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(existing) = existing else {
            transaction.commit().await?;
            return Ok(PepUnsubscribeResult::from(
                PepUnsubscribeOutcome::Unsubscribed(None),
            ));
        };
        if write.subid.is_some_and(|subid| subid != existing.as_str()) {
            transaction.rollback().await?;
            return Ok(PepUnsubscribeResult::from(
                PepUnsubscribeOutcome::InvalidSubid,
            ));
        }
        sqlx::query(
            "DELETE FROM pep_subscriptions
              WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3 AND subid=$4",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .bind(&principal.subscriber_jid)
        .bind(&existing)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(PepUnsubscribeResult::from(
            PepUnsubscribeOutcome::Unsubscribed(Some(existing)),
        ))
    }

    async fn lock_pep_subscription_principal(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner: &PubSubAccount,
        actor: &PepSubscriptionActor<'_>,
        subscriber_jid: &str,
    ) -> Result<Option<LockedPepSubscriptionPrincipal>> {
        let actor_jid = crate::jid::CanonicalJid::parse(actor.jid)?;
        let subscriber = crate::jid::CanonicalJid::parse(subscriber_jid)?;
        if actor_jid.bare() != subscriber.bare()
            || subscriber.resourcepart().is_some()
                && actor_jid.to_string() != subscriber.to_string()
        {
            return Ok(None);
        }
        let actor_is_local = actor_jid.domainpart() == self.domain.as_str();
        let local_subscriber_id = match (actor_is_local, actor.local_account) {
            (true, Some(account)) if actor_jid.localpart() == Some(account.username.as_str()) => {
                Some(account.id)
            }
            (false, None) => None,
            _ => return Ok(None),
        };
        let owner_bare =
            crate::jid::CanonicalJid::parse_bare(&format!("{}@{}", owner.username, self.domain))?
                .to_string();

        // Node configuration/deletion takes the owner advisory first. Account
        // rows follow in UUID order, then subscriber/node advisories and block
        // policy locks. This order is shared with publication and revocation.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
            .bind(owner.id.to_string())
            .execute(&mut **transaction)
            .await?;
        let mut account_ids = vec![owner.id];
        if let Some(id) = local_subscriber_id {
            account_ids.push(id);
        }
        account_ids.sort_unstable();
        account_ids.dedup();
        let rows = sqlx::query(
            "SELECT id,username,auth_generation,is_disabled FROM users
              WHERE id=ANY($1) ORDER BY id FOR SHARE",
        )
        .bind(&account_ids)
        .fetch_all(&mut **transaction)
        .await?;
        if rows.len() != account_ids.len() {
            return Ok(None);
        }
        let mut accounts = HashMap::with_capacity(rows.len());
        for row in rows {
            accounts.insert(
                row.try_get::<Uuid, _>("id")?,
                (
                    row.try_get::<String, _>("username")?,
                    row.try_get::<i64, _>("auth_generation")?,
                    row.try_get::<bool, _>("is_disabled")?,
                ),
            );
        }
        if !accounts
            .get(&owner.id)
            .is_some_and(|(username, generation, disabled)| {
                username == &owner.username && *generation == owner.auth_generation && !*disabled
            })
        {
            return Ok(None);
        }
        if let Some(account) = actor.local_account {
            if !accounts
                .get(&account.id)
                .is_some_and(|(username, generation, disabled)| {
                    username == &account.username
                        && *generation == account.auth_generation
                        && !*disabled
                })
            {
                return Ok(None);
            }
        }
        Ok(Some(LockedPepSubscriptionPrincipal {
            subscriber_jid: subscriber.to_string(),
            subscriber_bare: subscriber.bare(),
            owner_bare,
            local_subscriber_id,
        }))
    }

    async fn begin_authorized_pep_owner_mutation(
        &self,
        owner: &PubSubAccount,
        node: &str,
    ) -> Result<Option<(Transaction<'_, Postgres>, String)>> {
        let mut transaction = self.begin_mutation().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
            .bind(owner.id.to_string())
            .execute(&mut *transaction)
            .await?;
        let username = sqlx::query_scalar::<_, String>(
            "SELECT username FROM users
              WHERE id=$1 AND username=$2 AND auth_generation=$3 AND NOT is_disabled
              FOR SHARE",
        )
        .bind(owner.id)
        .bind(&owner.username)
        .bind(owner.auth_generation)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(username) = username else {
            transaction.rollback().await?;
            return Ok(None);
        };
        lock_pep_audience(&mut transaction, owner.id, node).await?;
        let owner_bare_jid =
            crate::jid::CanonicalJid::parse_bare(&format!("{username}@{}", self.domain))?
                .to_string();
        Ok(Some((transaction, owner_bare_jid)))
    }

    async fn locked_pep_node_config(
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        node: &str,
    ) -> Result<Option<PepNodeConfig>> {
        let row = sqlx::query(
            "SELECT access_model,max_items,persist_items,send_last_published_item,
                    deliver_notifications,roster_groups_allowed,access_whitelist
               FROM pep_nodes
              WHERE owner_id=$1 AND node=$2
              FOR UPDATE",
        )
        .bind(owner_id)
        .bind(node)
        .fetch_optional(&mut **transaction)
        .await?;
        row.map(|row| {
            Ok(PepNodeConfig {
                access_model: row.try_get("access_model")?,
                max_items: row.try_get("max_items")?,
                persist_items: row.try_get("persist_items")?,
                send_last_published_item: row.try_get("send_last_published_item")?,
                deliver_notifications: row.try_get("deliver_notifications")?,
                roster_groups_allowed: row.try_get("roster_groups_allowed")?,
                access_whitelist: row.try_get("access_whitelist")?,
            })
        })
        .transpose()
    }

    async fn store_pep_node_config(
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        node: &str,
        config: &PepNodeConfig,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE pep_nodes
                SET access_model=$3,max_items=$4,persist_items=$5,
                    send_last_published_item=$6,deliver_notifications=$7,
                    roster_groups_allowed=$8,access_whitelist=$9,
                    updated_at=clock_timestamp()
              WHERE owner_id=$1 AND node=$2",
        )
        .bind(owner_id)
        .bind(node)
        .bind(&config.access_model)
        .bind(config.max_items)
        .bind(config.persist_items)
        .bind(&config.send_last_published_item)
        .bind(config.deliver_notifications)
        .bind(&config.roster_groups_allowed)
        .bind(&config.access_whitelist)
        .execute(&mut **transaction)
        .await?;
        if config.persist_items {
            sqlx::query(
                "DELETE FROM pep_items
                  WHERE owner_id=$1 AND node=$2
                    AND item_id NOT IN (
                        SELECT item_id FROM pep_items
                         WHERE owner_id=$1 AND node=$2
                         ORDER BY updated_at DESC,item_id DESC LIMIT $3
                    )",
            )
            .bind(owner_id)
            .bind(node)
            .bind(config.max_items)
            .execute(&mut **transaction)
            .await?;
        } else {
            sqlx::query("DELETE FROM pep_items WHERE owner_id=$1 AND node=$2")
                .bind(owner_id)
                .bind(node)
                .execute(&mut **transaction)
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn update_pep_node_config(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        expected: &PepNodeConfig,
        config: &PepNodeConfig,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let owner_key = owner.id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        let Some((mut transaction, _)) = self
            .begin_authorized_pep_owner_mutation(owner, node)
            .await?
        else {
            return Ok(PepOwnerMutationOutcome::Forbidden);
        };
        let Some(current) = Self::locked_pep_node_config(&mut transaction, owner.id, node).await?
        else {
            transaction.rollback().await?;
            return Ok(PepOwnerMutationOutcome::NotFound);
        };
        if &current != expected {
            transaction.rollback().await?;
            return Ok(PepOwnerMutationOutcome::Stale);
        }
        let outbox = self
            .exact_pep_outbox(
                &mut transaction,
                owner.id,
                &owner.username,
                Some(sender_connection_id),
                node,
                PepOutboxEventKind::Configuration,
                PepOutboxAuthorizationMode::CausalAudience,
                factory,
            )
            .await?;
        Self::store_pep_node_config(&mut transaction, owner.id, node, config).await?;
        db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        transaction.commit().await?;
        Ok(PepOwnerMutationOutcome::Applied(0))
    }

    pub(crate) async fn update_pep_affiliations(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        expected: &PepNodeConfig,
        changes: &[(String, String)],
        factory: &dyn PepDirectOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let owner_key = owner.id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        let Some((mut transaction, owner_bare_jid)) = self
            .begin_authorized_pep_owner_mutation(owner, node)
            .await?
        else {
            return Ok(PepOwnerMutationOutcome::Forbidden);
        };
        let Some(mut current) =
            Self::locked_pep_node_config(&mut transaction, owner.id, node).await?
        else {
            transaction.rollback().await?;
            return Ok(PepOwnerMutationOutcome::NotFound);
        };
        if &current != expected {
            transaction.rollback().await?;
            return Ok(PepOwnerMutationOutcome::Stale);
        }
        let mut whitelist = current
            .access_whitelist
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let mut transitions = Vec::with_capacity(changes.len());
        let mut seen = HashSet::new();
        for (jid, affiliation) in changes {
            let jid = crate::jid::canonicalize_bare(jid)?;
            if jid == owner_bare_jid
                || !matches!(affiliation.as_str(), "member" | "none")
                || !seen.insert(jid.clone())
            {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::Forbidden);
            }
            if affiliation == "member" {
                whitelist.insert(jid.clone());
            } else {
                whitelist.remove(&jid);
            }
            transitions.push(PepDirectStateTransition::Affiliation {
                recipient_jid: jid,
                affiliation: affiliation.clone(),
            });
        }
        if transitions.is_empty() || whitelist.len() > 10_000 {
            transaction.rollback().await?;
            return Ok(PepOwnerMutationOutcome::Forbidden);
        }
        current.access_whitelist = whitelist.into_iter().collect();
        current.access_whitelist.sort_unstable();
        let snapshot = PepDirectStateSnapshot {
            owner_bare_jid,
            node: node.to_owned(),
            transitions,
        };
        let outbox = self
            .direct_pep_outbox(
                &mut transaction,
                owner.id,
                Some(sender_connection_id),
                PepOutboxEventKind::AffiliationState,
                &snapshot,
                factory,
            )
            .await?;
        Self::store_pep_node_config(&mut transaction, owner.id, node, &current).await?;
        db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        transaction.commit().await?;
        Ok(PepOwnerMutationOutcome::Applied(0))
    }

    pub(crate) async fn purge_pep_node(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let owner_key = owner.id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        let Some((mut transaction, _)) = self
            .begin_authorized_pep_owner_mutation(owner, node)
            .await?
        else {
            return Ok(PepOwnerMutationOutcome::Forbidden);
        };
        if Self::locked_pep_node_config(&mut transaction, owner.id, node)
            .await?
            .is_none()
        {
            transaction.rollback().await?;
            return Ok(PepOwnerMutationOutcome::NotFound);
        }
        let outbox = self
            .exact_pep_outbox(
                &mut transaction,
                owner.id,
                &owner.username,
                Some(sender_connection_id),
                node,
                PepOutboxEventKind::Purge,
                PepOutboxAuthorizationMode::CausalAudience,
                factory,
            )
            .await?;
        sqlx::query("DELETE FROM pep_items WHERE owner_id=$1 AND node=$2")
            .bind(owner.id)
            .bind(node)
            .execute(&mut *transaction)
            .await?;
        db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        transaction.commit().await?;
        Ok(PepOwnerMutationOutcome::Applied(0))
    }

    pub(crate) async fn delete_pep_node(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let owner_key = owner.id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        let Some((mut transaction, _)) = self
            .begin_authorized_pep_owner_mutation(owner, node)
            .await?
        else {
            return Ok(PepOwnerMutationOutcome::Forbidden);
        };
        if Self::locked_pep_node_config(&mut transaction, owner.id, node)
            .await?
            .is_none()
        {
            transaction.rollback().await?;
            return Ok(PepOwnerMutationOutcome::NotFound);
        }
        let outbox = self
            .exact_pep_outbox(
                &mut transaction,
                owner.id,
                &owner.username,
                Some(sender_connection_id),
                node,
                PepOutboxEventKind::Delete,
                PepOutboxAuthorizationMode::CausalAudience,
                factory,
            )
            .await?;
        sqlx::query("DELETE FROM pep_nodes WHERE owner_id=$1 AND node=$2")
            .bind(owner.id)
            .bind(node)
            .execute(&mut *transaction)
            .await?;
        db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        transaction.commit().await?;
        Ok(PepOwnerMutationOutcome::Applied(0))
    }

    pub(crate) async fn retract_pep_items(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        item_ids: &[&str],
        notify: bool,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let owner_key = owner.id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        let Some((mut transaction, _)) = self
            .begin_authorized_pep_owner_mutation(owner, node)
            .await?
        else {
            return Ok(PepOwnerMutationOutcome::Forbidden);
        };
        if Self::locked_pep_node_config(&mut transaction, owner.id, node)
            .await?
            .is_none()
        {
            transaction.rollback().await?;
            return Ok(PepOwnerMutationOutcome::NotFound);
        }
        let matched: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pep_items
              WHERE owner_id=$1 AND node=$2 AND item_id=ANY($3)",
        )
        .bind(owner.id)
        .bind(node)
        .bind(item_ids)
        .fetch_one(&mut *transaction)
        .await?;
        if matched != i64::try_from(item_ids.len())? {
            transaction.rollback().await?;
            return Ok(PepOwnerMutationOutcome::NotFound);
        }
        let outbox = if notify {
            self.exact_pep_outbox(
                &mut transaction,
                owner.id,
                &owner.username,
                Some(sender_connection_id),
                node,
                PepOutboxEventKind::Retract,
                PepOutboxAuthorizationMode::CausalAudience,
                factory,
            )
            .await?
        } else {
            Vec::new()
        };
        let removed =
            sqlx::query("DELETE FROM pep_items WHERE owner_id=$1 AND node=$2 AND item_id=ANY($3)")
                .bind(owner.id)
                .bind(node)
                .bind(item_ids)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
        db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        transaction.commit().await?;
        Ok(PepOwnerMutationOutcome::Applied(removed))
    }

    pub(crate) async fn unsubscribe_pep_nodes_batch(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        changes: &[(String, Option<String>)],
        factory: &dyn PepDirectOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let owner_key = owner.id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        let Some((mut transaction, owner_bare_jid)) = self
            .begin_authorized_pep_owner_mutation(owner, node)
            .await?
        else {
            return Ok(PepOwnerMutationOutcome::Forbidden);
        };
        if Self::locked_pep_node_config(&mut transaction, owner.id, node)
            .await?
            .is_none()
        {
            transaction.rollback().await?;
            return Ok(PepOwnerMutationOutcome::NotFound);
        }
        let mut canonical = Vec::with_capacity(changes.len());
        let mut unique = HashSet::new();
        for (jid, requested_subid) in changes {
            let jid = crate::jid::canonicalize(jid)?;
            if !unique.insert((jid.clone(), requested_subid.clone())) {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotSubscribed);
            }
            let stored = sqlx::query_scalar::<_, String>(
                "SELECT subid FROM pep_subscriptions
                  WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3
                  FOR UPDATE",
            )
            .bind(owner.id)
            .bind(node)
            .bind(&jid)
            .fetch_optional(&mut *transaction)
            .await?;
            let Some(stored) = stored.filter(|stored| {
                requested_subid
                    .as_ref()
                    .is_none_or(|requested| requested == stored)
            }) else {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotSubscribed);
            };
            canonical.push((jid, stored));
        }
        if canonical.is_empty() {
            transaction.rollback().await?;
            return Ok(PepOwnerMutationOutcome::NotSubscribed);
        }
        let snapshot = PepDirectStateSnapshot {
            owner_bare_jid,
            node: node.to_owned(),
            transitions: canonical
                .iter()
                .map(
                    |(recipient_jid, subid)| PepDirectStateTransition::Subscription {
                        recipient_jid: recipient_jid.clone(),
                        subid: subid.clone(),
                        state: "none".to_owned(),
                    },
                )
                .collect(),
        };
        let outbox = self
            .direct_pep_outbox(
                &mut transaction,
                owner.id,
                Some(sender_connection_id),
                PepOutboxEventKind::SubscriptionState,
                &snapshot,
                factory,
            )
            .await?;
        for (jid, subid) in &canonical {
            sqlx::query(
                "DELETE FROM pep_subscriptions
                  WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3 AND subid=$4",
            )
            .bind(owner.id)
            .bind(node)
            .bind(jid)
            .bind(subid)
            .execute(&mut *transaction)
            .await?;
        }
        db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        transaction.commit().await?;
        Ok(PepOwnerMutationOutcome::Applied(u64::try_from(
            canonical.len(),
        )?))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn commit_legacy_bookmarks(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        private_xml: &str,
        items: &mut [(String, String)],
        expected_previous_items: &[(String, String)],
        max_private_bytes: i64,
        quotas: PepQuotas,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepBookmarkMutationOutcome> {
        const LEGACY_BOOKMARKS: &str = "storage:bookmarks";
        const BOOKMARKS2: &str = "urn:xmpp:bookmarks:1";
        let owner_key = owner.id.to_string();
        let _permit = self
            .admit_mutation(&[&owner_key, BOOKMARKS2], false)
            .await?;
        let Some((mut transaction, _)) = self
            .begin_authorized_pep_owner_mutation(owner, BOOKMARKS2)
            .await?
        else {
            return Ok(PepBookmarkMutationOutcome::Forbidden);
        };
        db::private::lock_private_xml_owner(&mut transaction, owner.id).await?;
        let previous_items = sqlx::query(
            "SELECT item_id,payload FROM pep_items
              WHERE owner_id=$1 AND node=$2
              ORDER BY item_id
              FOR UPDATE",
        )
        .bind(owner.id)
        .bind(BOOKMARKS2)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| Ok::<_, sqlx::Error>((row.try_get("item_id")?, row.try_get("payload")?)))
        .collect::<std::result::Result<Vec<(String, String)>, _>>()?;
        if previous_items != expected_previous_items {
            transaction.rollback().await?;
            return Ok(PepBookmarkMutationOutcome::ConcurrentChange);
        }
        let borrowed = items
            .iter()
            .map(|(item_id, payload)| (item_id.as_str(), payload.as_str()))
            .collect::<Vec<_>>();
        let config = db::default_pep_node_config(BOOKMARKS2);
        let pep_outcome = db::pep::replace_pep_items_in_transaction(
            &mut transaction,
            owner.id,
            BOOKMARKS2,
            &config,
            &borrowed,
            quotas.into(),
        )
        .await?;
        if pep_outcome != db::PepPublishOutcome::Published {
            transaction.rollback().await?;
            return Ok(PepBookmarkMutationOutcome::ResourceConstraint);
        }
        let private_outcome = db::private::set_private_xml_batch_in_transaction(
            &mut transaction,
            owner.id,
            &[db::PrivateXmlEntry {
                element_name: "storage",
                element_ns: LEGACY_BOOKMARKS,
                xml_data: private_xml,
            }],
            max_private_bytes,
        )
        .await?;
        if private_outcome != db::PrivateXmlWriteOutcome::Stored {
            transaction.rollback().await?;
            return Ok(PepBookmarkMutationOutcome::ResourceConstraint);
        }
        let outbox = self
            .exact_pep_outbox(
                &mut transaction,
                owner.id,
                &owner.username,
                Some(sender_connection_id),
                BOOKMARKS2,
                PepOutboxEventKind::Publish,
                PepOutboxAuthorizationMode::CausalAudience,
                factory,
            )
            .await?;
        db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        transaction.commit().await?;
        Ok(PepBookmarkMutationOutcome::Stored)
    }

    /// Publish generic PEP items and derive the durable notification audience
    /// inside the same transaction. `require_content_change` preserves the
    /// Bookmarks 2 duplicate-suppression behavior; other PEP nodes may emit a
    /// refresh event for an idempotent publication as before.
    pub(crate) async fn publish_pep_items(
        &self,
        command: PepPublishItemsCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepPublishItemsResult> {
        validate_pep_publish_command(&command)?;
        let write = command.write;
        let owner_key = write.user_id.to_string();
        let _permit = self
            .admit_mutation(&[&owner_key, write.node], false)
            .await?;
        let mut transaction = self.begin_mutation().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
            .bind(write.user_id.to_string())
            .execute(&mut *transaction)
            .await?;
        let owner_username = sqlx::query_scalar::<_, String>(
            "SELECT username FROM users
              WHERE id=$1 AND username=$2 AND auth_generation=$3 AND NOT is_disabled
              FOR SHARE",
        )
        .bind(write.user_id)
        .bind(write.username)
        .bind(write.auth_generation)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(owner_username) = owner_username else {
            transaction.rollback().await?;
            return Ok(PepPublishItemsResult {
                outcome: PepPublishItemsOutcome::Unauthorized,
                content_changed: false,
            });
        };
        lock_pep_audience(&mut transaction, write.user_id, write.node).await?;

        let item_ids = write
            .items
            .iter()
            .map(|(item_id, _)| *item_id)
            .collect::<Vec<_>>();
        let previous = sqlx::query(
            "SELECT item_id,payload FROM pep_items
              WHERE owner_id=$1 AND node=$2 AND item_id=ANY($3)
              FOR UPDATE",
        )
        .bind(write.user_id)
        .bind(write.node)
        .bind(&item_ids)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| {
            Ok::<_, sqlx::Error>((
                row.try_get::<String, _>("item_id")?,
                row.try_get::<String, _>("payload")?,
            ))
        })
        .collect::<std::result::Result<HashMap<_, _>, _>>()?;
        let changed = previous.len() != write.items.len()
            || write.items.iter().any(|(item_id, payload)| {
                previous.get(*item_id).map(String::as_str) != Some(*payload)
            });
        let requested = db::PepNodeConfig::from(write.requested);
        let outcome = db::pep::publish_pep_items_in_transaction(
            &mut transaction,
            write.user_id,
            write.node,
            &requested,
            write.enforce_preconditions,
            write.items,
            write.quotas.into(),
        )
        .await?;
        if outcome != db::PepPublishOutcome::Published {
            transaction.rollback().await?;
            return Ok(PepPublishItemsResult {
                outcome: PepPublishItemsOutcome::from(PepPublishOutcome::from(outcome)),
                content_changed: false,
            });
        }
        if changed || !command.require_content_change {
            let outbox = self
                .exact_pep_outbox(
                    &mut transaction,
                    write.user_id,
                    &owner_username,
                    Some(write.connection_id),
                    write.node,
                    PepOutboxEventKind::Publish,
                    PepOutboxAuthorizationMode::CausalAudience,
                    factory,
                )
                .await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        }
        transaction.commit().await?;
        Ok(PepPublishItemsResult {
            outcome: PepPublishItemsOutcome::Published,
            content_changed: changed,
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the transaction plus immutable PEP authority and event coordinates must stay explicit at this atomic outbox boundary"
    )]
    async fn exact_pep_outbox(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        owner_username: &str,
        sender_connection_id: Option<Uuid>,
        node: &str,
        event_kind: PepOutboxEventKind,
        authorization_mode: PepOutboxAuthorizationMode,
        factory: &dyn PepOutboxFactory,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let owner_bare_jid =
            crate::jid::CanonicalJid::parse_bare(&format!("{owner_username}@{}", self.domain))?
                .to_string();
        let policy = sqlx::query(
            "SELECT access_model,deliver_notifications,roster_groups_allowed,access_whitelist
               FROM pep_nodes
              WHERE owner_id=$1 AND node=$2
              FOR SHARE",
        )
        .bind(owner_id)
        .bind(node)
        .fetch_one(&mut **transaction)
        .await?;
        let deliver_notifications: bool = policy.try_get("deliver_notifications")?;
        if !deliver_notifications {
            return Ok(Vec::new());
        }
        let access_model: String = policy.try_get("access_model")?;
        let roster_groups_allowed: Vec<String> = policy.try_get("roster_groups_allowed")?;
        let access_whitelist = policy
            .try_get::<Vec<String>, _>("access_whitelist")?
            .into_iter()
            .map(|jid| crate::jid::canonical_bare_key(&jid))
            .collect::<Result<HashSet<_>>>()?;

        // The owner users row is held FOR SHARE by the caller. Production
        // roster mutations take it FOR UPDATE, so rows and groups below cannot
        // change until this event has been projected.
        let roster_rows = sqlx::query(
            "SELECT contact_jid,subscription,groups
               FROM roster_items
              WHERE owner_id=$1
              ORDER BY contact_jid
              FOR SHARE",
        )
        .bind(owner_id)
        .fetch_all(&mut **transaction)
        .await?;
        let mut roster = BTreeMap::new();
        for row in roster_rows {
            let jid = crate::jid::canonicalize_bare(&row.try_get::<String, _>("contact_jid")?)?;
            roster.insert(
                jid,
                PepRosterAudienceEntry {
                    subscription: row.try_get("subscription")?,
                    groups: serde_json::from_value(row.try_get("groups")?)
                        .context("stored PEP roster groups are not a string array")?,
                },
            );
        }

        // Subscribe/unsubscribe and roster-driven cancellation serialize on
        // this node advisory. FOR SHARE also protects direct legacy cleanup.
        let explicit = sqlx::query_scalar::<_, String>(
            "SELECT subscriber_jid FROM pep_subscriptions
              WHERE owner_id=$1 AND node=$2 AND state='subscribed'
              ORDER BY subscriber_jid
              FOR SHARE",
        )
        .bind(owner_id)
        .bind(node)
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|jid| crate::jid::canonicalize(&jid))
        .collect::<Result<Vec<_>>>()?;

        let mut localparts = roster
            .keys()
            .chain(explicit.iter())
            .filter_map(|jid| crate::jid::CanonicalJid::parse(jid).ok())
            .filter(|jid| jid.domainpart() == self.domain.as_str())
            .filter_map(|jid| jid.localpart().map(str::to_owned))
            .collect::<Vec<_>>();
        localparts.sort_unstable();
        localparts.dedup();
        let local_rows = sqlx::query(
            "SELECT id,username FROM users
              WHERE username=ANY($1) AND NOT is_disabled",
        )
        .bind(&localparts)
        .fetch_all(&mut **transaction)
        .await?;
        let mut local_accounts = HashMap::with_capacity(local_rows.len());
        let mut block_owners = vec![owner_id];
        for row in local_rows {
            let id: Uuid = row.try_get("id")?;
            let username: String = row.try_get("username")?;
            let bare =
                crate::jid::CanonicalJid::parse_bare(&format!("{username}@{}", self.domain))?
                    .to_string();
            local_accounts.insert(bare, id);
            block_owners.push(id);
        }
        block_owners.sort_unstable();
        block_owners.dedup();
        for block_owner in &block_owners {
            lock_pep_block_policy(transaction, *block_owner).await?;
        }
        let block_rows = sqlx::query(
            "SELECT owner_id,blocked_jid FROM blocked_jids
              WHERE owner_id=ANY($1)
              ORDER BY owner_id,blocked_jid",
        )
        .bind(&block_owners)
        .fetch_all(&mut **transaction)
        .await?;
        let mut blocks: HashMap<Uuid, Vec<String>> = HashMap::new();
        for row in block_rows {
            blocks
                .entry(row.try_get("owner_id")?)
                .or_default()
                .push(row.try_get("blocked_jid")?);
        }

        let authorized = |jid: &str,
                          roster_entry: Option<&PepRosterAudienceEntry>|
         -> Result<bool> {
            let bare = crate::jid::canonical_bare_key(jid)?;
            if bare == owner_bare_jid {
                return Ok(true);
            }
            let parsed = crate::jid::CanonicalJid::parse(jid)?;
            if parsed.domainpart() == self.domain && !local_accounts.contains_key(&bare) {
                return Ok(false);
            }
            if blocks.get(&owner_id).is_some_and(|patterns| {
                patterns
                    .iter()
                    .any(|pattern| db::roster::blocked_jid_matches(pattern, jid))
            }) {
                return Ok(false);
            }
            if let Some(recipient_id) = local_accounts.get(&bare) {
                if blocks.get(recipient_id).is_some_and(|patterns| {
                    patterns
                        .iter()
                        .any(|pattern| db::roster::blocked_jid_matches(pattern, &owner_bare_jid))
                }) {
                    return Ok(false);
                }
            }
            Ok(match access_model.as_str() {
                "open" => true,
                "whitelist" => access_whitelist.contains(&bare),
                "presence" => roster_entry
                    .is_some_and(|entry| matches!(entry.subscription.as_str(), "from" | "both")),
                "roster" => roster_entry.is_some_and(|entry| {
                    entry
                        .groups
                        .iter()
                        .any(|group| roster_groups_allowed.contains(group))
                }),
                _ => false,
            })
        };

        let mut roster_jids = Vec::new();
        for (jid, entry) in &roster {
            if matches!(entry.subscription.as_str(), "from" | "both")
                && authorized(jid, Some(entry))?
            {
                roster_jids.push(jid.clone());
            }
        }
        let mut explicit_jids = Vec::new();
        for jid in explicit {
            let bare = crate::jid::canonical_bare_key(&jid)?;
            if authorized(&jid, roster.get(&bare))? {
                explicit_jids.push(jid);
            }
        }
        let audience = PepAudienceSnapshot {
            owner_bare_jid: owner_bare_jid.clone(),
            roster_jids,
            explicit_jids,
        };
        let deliveries = factory.build(&audience)?;
        anyhow::ensure!(
            deliveries
                .iter()
                .all(|(recipient, _)| audience.authorizes_routed_jid(recipient)),
            "PEP renderer escaped the transaction-owned audience"
        );
        let event_id = Uuid::new_v4();
        let created_at = chrono::Utc::now();
        let mut seen = HashSet::new();
        deliveries
            .into_iter()
            .filter_map(|(recipient, payload)| {
                let recipient = crate::jid::canonicalize(&recipient).ok()?;
                seen.insert(recipient.clone())
                    .then_some((recipient, payload))
            })
            .map(|(recipient, payload)| {
                let recipient_bare = crate::jid::canonical_bare_key(&recipient)?;
                let recipient_account_id = if recipient_bare == owner_bare_jid {
                    Some(owner_id)
                } else {
                    local_accounts.get(&recipient_bare).copied()
                };
                db::PubSubOutboxInsert::new_pep_stanza(
                    event_id,
                    owner_id,
                    &owner_bare_jid,
                    sender_connection_id,
                    recipient,
                    recipient_account_id,
                    event_kind,
                    authorization_mode,
                    payload,
                    node,
                    &self.domain,
                    created_at,
                )
            })
            .collect()
    }

    async fn direct_pep_outbox(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        sender_connection_id: Option<Uuid>,
        event_kind: PepOutboxEventKind,
        snapshot: &PepDirectStateSnapshot,
        factory: &dyn PepDirectOutboxFactory,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let authorized = snapshot
            .transitions
            .iter()
            .map(|transition| transition.recipient_jid().to_owned())
            .collect::<HashSet<_>>();
        let deliveries = factory.build(snapshot)?;
        anyhow::ensure!(
            deliveries.iter().all(|(recipient, _)| {
                crate::jid::canonicalize(recipient)
                    .is_ok_and(|recipient| authorized.contains(&recipient))
            }),
            "PEP direct-state renderer escaped the transaction-owned recipients"
        );
        let mut localparts = authorized
            .iter()
            .filter_map(|jid| crate::jid::CanonicalJid::parse(jid).ok())
            .filter(|jid| jid.domainpart() == self.domain)
            .filter_map(|jid| jid.localpart().map(str::to_owned))
            .collect::<Vec<_>>();
        localparts.sort_unstable();
        localparts.dedup();
        let rows = sqlx::query(
            "SELECT id,username FROM users
              WHERE username=ANY($1) AND NOT is_disabled
              ORDER BY id
              FOR SHARE",
        )
        .bind(&localparts)
        .fetch_all(&mut **transaction)
        .await?;
        let mut local_accounts = HashMap::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            let username: String = row.try_get("username")?;
            let bare =
                crate::jid::CanonicalJid::parse_bare(&format!("{username}@{}", self.domain))?
                    .to_string();
            local_accounts.insert(bare, id);
        }
        let event_id = Uuid::new_v4();
        let created_at = chrono::Utc::now();
        let mut seen = HashSet::new();
        let mut outbox = Vec::new();
        for (recipient, payload) in deliveries {
            let recipient = crate::jid::canonicalize(&recipient)?;
            if !seen.insert(recipient.clone()) {
                continue;
            }
            let recipient_bare = crate::jid::canonical_bare_key(&recipient)?;
            let recipient_account_id = if recipient_bare == snapshot.owner_bare_jid {
                Some(owner_id)
            } else {
                local_accounts.get(&recipient_bare).copied()
            };
            if crate::jid::CanonicalJid::parse(&recipient)?.domainpart() == self.domain
                && recipient_account_id.is_none()
            {
                // Account deletion/disable committed before this mutation's
                // lock snapshot. There is no valid local delivery subject.
                continue;
            }
            outbox.push(db::PubSubOutboxInsert::new_pep_stanza(
                event_id,
                owner_id,
                &snapshot.owner_bare_jid,
                sender_connection_id,
                recipient,
                recipient_account_id,
                event_kind,
                PepOutboxAuthorizationMode::CausalAudience,
                payload,
                &snapshot.node,
                &self.domain,
                created_at,
            )?);
        }
        Ok(outbox)
    }

    pub(crate) async fn publish_profile_items(
        &self,
        profile_service: &ProfileService,
        write: PepProfileWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
        require_content_change: bool,
    ) -> Result<ProfilePublishResult> {
        let requested = db::PepNodeConfig::from(write.requested);
        profile_service
            .publish_profile_items(
                ProfilePepWrite {
                    user_id: write.user_id,
                    auth_generation: write.auth_generation,
                    connection_id: write.connection_id,
                    node: write.node,
                    requested: &requested,
                    enforce_preconditions: write.enforce_preconditions,
                    items: write.items,
                    max_nodes: write.max_nodes,
                    max_storage_bytes: write.max_storage_bytes,
                },
                explicit_factory,
                require_content_change,
            )
            .await
    }

    pub(crate) async fn publish_avatar_metadata(
        &self,
        profile_service: &ProfileService,
        write: PepProfileWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
    ) -> Result<ProfilePublishResult> {
        let requested = db::PepNodeConfig::from(write.requested);
        profile_service
            .publish_avatar_metadata(
                ProfilePepWrite {
                    user_id: write.user_id,
                    auth_generation: write.auth_generation,
                    connection_id: write.connection_id,
                    node: write.node,
                    requested: &requested,
                    enforce_preconditions: write.enforce_preconditions,
                    items: write.items,
                    max_nodes: write.max_nodes,
                    max_storage_bytes: write.max_storage_bytes,
                },
                explicit_factory,
            )
            .await
    }

    // XEP-0060 read slice ----------------------------------------------------------

    pub(crate) async fn get_node(&self, node: &str) -> Result<Option<PubSubNode>> {
        Ok(db::get_node(&self.pool, node).await?.map(Into::into))
    }

    pub(crate) async fn get_node_affiliation(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> Result<Option<String>> {
        db::get_node_affiliation(&self.pool, node_id, jid).await
    }

    pub(crate) async fn affiliations_for_jid(
        &self,
        jid: &str,
        node: Option<&str>,
    ) -> Result<Vec<PubSubAffiliation>> {
        Ok(db::affiliations_for_jid(&self.pool, jid, node)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub(crate) async fn node_affiliations(&self, node_id: Uuid) -> Result<Vec<PubSubAffiliation>> {
        Ok(db::node_affiliations(&self.pool, node_id)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub(crate) async fn is_subscribed(&self, node_id: Uuid, jid: &str) -> Result<bool> {
        db::is_subscribed(&self.pool, node_id, jid).await
    }

    pub(crate) async fn subscriptions_for_jid(
        &self,
        jid: &str,
        node: Option<&str>,
    ) -> Result<Vec<PubSubSubscription>> {
        Ok(db::subscriptions_for_jid(&self.pool, jid, node)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub(crate) async fn subscriptions_addressing_jid_page(
        &self,
        jid: &str,
        after: Option<(&str, &str)>,
        limit: i64,
    ) -> Result<Vec<PubSubSubscription>> {
        Ok(
            db::subscriptions_addressing_jid_page(&self.pool, jid, after, limit)
                .await?
                .into_iter()
                .map(Into::into)
                .collect(),
        )
    }

    pub(crate) async fn node_subscriptions(
        &self,
        node_id: Uuid,
    ) -> Result<Vec<PubSubSubscription>> {
        Ok(db::node_subscriptions(&self.pool, node_id)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub(crate) async fn get_subscription(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> Result<Option<PubSubSubscription>> {
        Ok(db::get_subscription(&self.pool, node_id, jid)
            .await?
            .map(Into::into))
    }

    pub(crate) async fn get_owner_jids(&self, node_id: Uuid) -> Result<Vec<String>> {
        db::get_owner_jids(&self.pool, node_id).await
    }

    pub(crate) async fn get_publisher_jids(&self, node_id: Uuid) -> Result<Vec<String>> {
        db::get_publisher_jids(&self.pool, node_id).await
    }

    pub(crate) async fn active_subscriber_count(&self, node_id: Uuid) -> Result<i64> {
        db::active_subscriber_count(&self.pool, node_id).await
    }

    pub(crate) async fn get_items(
        &self,
        node_id: Uuid,
        item_ids: &[String],
        limit: i64,
    ) -> Result<Vec<PubSubItem>> {
        Ok(db::get_items(&self.pool, node_id, item_ids, limit)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub(crate) async fn item_ids_for_disco(&self, node_id: Uuid) -> Result<Vec<String>> {
        db::item_ids_for_disco(&self.pool, node_id).await
    }

    pub(crate) async fn node_redirect(&self, node: &str) -> Result<Option<String>> {
        db::node_redirect(&self.pool, node).await
    }

    pub(crate) async fn collection_parents(&self, child_id: Uuid) -> Result<Vec<PubSubNode>> {
        Ok(db::collection_parents(&self.pool, child_id)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub(crate) async fn collection_children(&self, collection_id: Uuid) -> Result<Vec<PubSubNode>> {
        Ok(db::collection_children(&self.pool, collection_id)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub(crate) async fn collection_visible_items(
        &self,
        collection_id: Uuid,
        requester: &str,
        global_item_limit: i64,
        xml_byte_limit: i64,
    ) -> Result<Vec<CollectionVisibleItem>> {
        Ok(db::collection_visible_items(
            &self.pool,
            collection_id,
            requester,
            global_item_limit,
            xml_byte_limit,
        )
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
    }

    pub(crate) async fn visible_root_disco_count(&self, requester: &str) -> Result<i64> {
        db::visible_root_disco_count(&self.pool, requester).await
    }

    pub(crate) async fn visible_root_disco_cursor_exists(
        &self,
        requester: &str,
        cursor: &str,
    ) -> Result<bool> {
        db::visible_root_disco_cursor_exists(&self.pool, requester, cursor).await
    }

    pub(crate) async fn visible_root_disco_index(
        &self,
        requester: &str,
        node: &str,
    ) -> Result<i64> {
        db::visible_root_disco_index(&self.pool, requester, node).await
    }

    pub(crate) async fn visible_root_disco_page(
        &self,
        requester: &str,
        cursor: Option<&str>,
        backwards: bool,
        limit: i64,
    ) -> Result<Vec<PubSubDiscoNode>> {
        Ok(
            db::visible_root_disco_page(&self.pool, requester, cursor, backwards, limit)
                .await?
                .into_iter()
                .map(Into::into)
                .collect(),
        )
    }

    /// Cheap preflight used before expensive XML serialization.  Mutations
    /// repeat this decision under a node lock; this method is never the
    /// authority that permits a write.
    pub(crate) async fn can_publish(&self, node: &PubSubNode, requester: &str) -> Result<bool> {
        let affiliation = db::get_node_affiliation(&self.pool, node.id, requester).await?;
        let affiliation = affiliation
            .as_deref()
            .map(str::parse::<northstar_xep_0060::Affiliation>)
            .transpose()
            .map_err(|error| anyhow::anyhow!("invalid stored PubSub affiliation: {error}"))?;
        let publish_model = node
            .publish_model
            .parse::<northstar_xep_0060::PublishModel>()
            .map_err(|error| anyhow::anyhow!("invalid stored PubSub publish model: {error}"))?;
        let access_model = node
            .access_model
            .parse::<northstar_xep_0060::AccessModel>()
            .map_err(|error| anyhow::anyhow!("invalid stored PubSub access model: {error}"))?;
        let subscribed = db::is_subscribed(&self.pool, node.id, requester).await?;
        Ok(northstar_xep_0060::can_publish_pure(
            publish_model,
            access_model,
            affiliation,
            subscribed,
        ))
    }

    /// Preflight only. Every owner mutation rechecks this under its
    /// transaction lock before changing state.
    pub(crate) async fn is_owner(&self, node_id: Uuid, requester: &str) -> Result<bool> {
        Ok(db::get_node_affiliation(&self.pool, node_id, requester)
            .await?
            .as_deref()
            == Some("owner"))
    }

    // XEP-0060 mutation slice ------------------------------------------------------
    //
    // Keep every mutation which can change PubSub authority or project a
    // notification behind this capability.  The protocol module may validate
    // XML and map the domain outcome to a stanza error, but it must not obtain
    // a PgPool and compose a partial workflow itself.

    pub(crate) async fn update_subscription_options_checked(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: Option<&str>,
        options: &PubSubSubscriptionOptions,
    ) -> Result<SubscriptionOptionsOutcome> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[requester, subscriber_jid, &node_key], false)
            .await?;
        let options = db::PubSubSubscriptionOptions::from(options);
        Ok(db::update_subscription_options_checked(
            &self.pool,
            node_id,
            requester,
            subscriber_jid,
            expected_subid,
            &options,
        )
        .await?
        .into())
    }

    pub(crate) async fn create_node(
        &self,
        node: &str,
        creator_jid: &str,
        config: &PubSubNodeConfig,
        max_nodes_per_owner: i64,
    ) -> Result<CreateNodeOutcome> {
        let _permit = self.admit_mutation(&[creator_jid, node], true).await?;
        let config = db::PubSubNodeConfig::from(config);
        Ok(db::create_node_with_renderer(
            &self.pool,
            node,
            creator_jid,
            &config,
            max_nodes_per_owner,
            self,
        )
        .await?
        .into())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn publish_items(
        &self,
        node: &PubSubNode,
        publisher_jid: &str,
        items: &[(String, String)],
        max_storage_bytes_per_owner: i64,
    ) -> Result<PublishItemsOutcome> {
        let node_key = node.id.to_string();
        let _permit = self
            .admit_mutation(&[publisher_jid, &node_key], true)
            .await?;
        let node = db::PubSubNode::from(node);
        Ok(db::publish_items_with_renderer(
            &self.pool,
            &node,
            publisher_jid,
            items,
            false,
            max_storage_bytes_per_owner,
            self,
        )
        .await?
        .into())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn set_subscription_limited_with_options(
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
    ) -> Result<SubscribeOutcome> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[requester, jid, &node_key], false)
            .await?;
        let options = options.map(db::PubSubSubscriptionOptions::from);
        Ok(db::set_subscription_limited_with_options_and_renderer(
            &self.pool,
            node_id,
            requester,
            jid,
            state,
            expected_node_type,
            expected_access_model,
            max_subscriptions,
            options.as_ref(),
            requested_subid,
            self,
        )
        .await?
        .into())
    }

    pub(crate) async fn unsubscribe_checked(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: &str,
    ) -> Result<UnsubscribeOutcome> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[requester, subscriber_jid, &node_key], false)
            .await?;
        Ok(db::unsubscribe_checked_with_renderer(
            &self.pool,
            node_id,
            requester,
            subscriber_jid,
            expected_subid,
            self,
        )
        .await?
        .into())
    }

    pub(crate) async fn retract_items(
        &self,
        node_id: Uuid,
        item_ids: &[String],
        publisher_jid: &str,
        force_notification: bool,
    ) -> Result<RetractItemsOutcome> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[publisher_jid, &node_key], true)
            .await?;
        Ok(db::retract_items_with_renderer(
            &self.pool,
            node_id,
            item_ids,
            publisher_jid,
            force_notification,
            self,
        )
        .await?
        .into())
    }

    pub(crate) async fn associate_collection_child(
        &self,
        collection: &PubSubNode,
        child: &PubSubNode,
        requester: &str,
    ) -> Result<CollectionUpdateOutcome> {
        let collection_key = collection.id.to_string();
        let child_key = child.id.to_string();
        let _permit = self
            .admit_mutation(&[requester, &collection_key, &child_key], true)
            .await?;
        let collection = db::PubSubNode::from(collection);
        let child = db::PubSubNode::from(child);
        Ok(db::associate_collection_child_with_renderer(
            &self.pool,
            &collection,
            &child,
            requester,
            self,
        )
        .await?
        .into())
    }

    pub(crate) async fn dissociate_collection_child(
        &self,
        collection: &PubSubNode,
        child: &PubSubNode,
        requester: &str,
    ) -> Result<CollectionUpdateOutcome> {
        let collection_key = collection.id.to_string();
        let child_key = child.id.to_string();
        let _permit = self
            .admit_mutation(&[requester, &collection_key, &child_key], true)
            .await?;
        let collection = db::PubSubNode::from(collection);
        let child = db::PubSubNode::from(child);
        Ok(db::dissociate_collection_child_with_renderer(
            &self.pool,
            &collection,
            &child,
            requester,
            self,
        )
        .await?
        .into())
    }

    pub(crate) async fn update_node_config_and_graph_with_outbox(
        &self,
        node: &PubSubNode,
        requester: &str,
        expected: &PubSubNodeConfig,
        config: &PubSubNodeConfig,
    ) -> Result<PubSubConfigOutcome> {
        let node_key = node.id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], true).await?;
        let node = db::PubSubNode::from(node);
        let expected = db::PubSubNodeConfig::from(expected);
        let config = db::PubSubNodeConfig::from(config);
        Ok(db::update_node_config_and_graph_with_outbox(
            &self.pool, &node, requester, &expected, &config, self,
        )
        .await?
        .into())
    }

    pub(crate) async fn set_subscriptions(
        &self,
        node_id: Uuid,
        requester: &str,
        changes: &[(String, String, Option<String>)],
    ) -> Result<SetSubscriptionsOutcome> {
        let node_key = node_id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], false).await?;
        Ok(
            db::set_subscriptions_with_renderer(
                &self.pool, node_id, requester, changes, None, self,
            )
            .await?
            .into(),
        )
    }

    pub(crate) async fn set_affiliations(
        &self,
        node_id: Uuid,
        requester: &str,
        changes: &[(String, String)],
    ) -> Result<SetAffiliationsOutcome> {
        let node_key = node_id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], false).await?;
        Ok(db::set_affiliations_with_renderer(
            &self.pool, node_id, requester, changes, None, None, self,
        )
        .await?
        .into())
    }

    pub(crate) async fn purge_node_as_owner_with_outbox(
        &self,
        node_id: Uuid,
        requester: &str,
    ) -> Result<OwnerMutationOutcome> {
        let node_key = node_id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], true).await?;
        Ok(
            db::purge_node_as_owner_with_outbox(&self.pool, node_id, requester, self)
                .await?
                .into(),
        )
    }

    pub(crate) async fn delete_node_as_owner_with_redirect_and_outbox(
        &self,
        node_id: Uuid,
        requester: &str,
        redirect: Option<&str>,
    ) -> Result<OwnerMutationOutcome> {
        let node_key = node_id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], true).await?;
        Ok(db::delete_node_as_owner_with_redirect_and_outbox(
            &self.pool, node_id, requester, redirect, self,
        )
        .await?
        .into())
    }

    pub(crate) async fn resolve_pending_subscription(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: &str,
        allow: bool,
    ) -> Result<SubscriptionAuthorizationOutcome> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[requester, subscriber_jid, &node_key], false)
            .await?;
        Ok(db::resolve_pending_subscription_with_renderer(
            &self.pool,
            node_id,
            requester,
            subscriber_jid,
            expected_subid,
            allow,
            self,
        )
        .await?
        .into())
    }

    fn serialized_item_payload_matches_type(item_xml: &str, payload_type: &str) -> bool {
        roxmltree::Document::parse(item_xml)
            .ok()
            .is_some_and(|document| {
                document
                    .root_element()
                    .children()
                    .find(roxmltree::Node::is_element)
                    .and_then(|payload| payload.tag_name().namespace())
                    == Some(payload_type)
            })
    }

    fn item_xml_has_payload(item_xml: &str) -> bool {
        roxmltree::Document::parse(item_xml)
            .ok()
            .is_some_and(|document| {
                document
                    .root_element()
                    .children()
                    .any(|node| node.is_element())
            })
    }

    pub(crate) async fn execute_pubsub_publish(
        &self,
        command: PubSubPublishCommand<'_>,
    ) -> Result<PubSubPublishResult> {
        validate_pubsub_publish_command(&command)?;
        let write = command.write;
        if write.node == "serverinfo" {
            return Ok(PubSubPublishResult {
                outcome: PubSubPublishOutcome::Forbidden,
            });
        }
        let mut node = self.get_node(write.node).await?;
        let had_publish_options = write.publish_options.is_some();
        let effective_config = match (node.as_ref(), write.publish_options) {
            (Some(node), Some(options)) => {
                if options != &node.config() {
                    return Ok(PubSubPublishResult {
                        outcome: PubSubPublishOutcome::PreconditionNotMet,
                    });
                }
                options.clone()
            }
            (Some(node), None) => node.config(),
            (None, Some(options)) => options.clone(),
            (None, None) => PubSubNodeConfig::default(),
        };
        if effective_config.node_type != "leaf" {
            return Ok(PubSubPublishResult {
                outcome: PubSubPublishOutcome::NotLeafNode,
            });
        }
        if let Some(ref node) = node {
            if !self.can_publish(node, write.publisher_jid).await? {
                return Ok(PubSubPublishResult {
                    outcome: PubSubPublishOutcome::Forbidden,
                });
            }
        }
        if write.items.len() > effective_config.max_items as usize {
            return Ok(PubSubPublishResult {
                outcome: PubSubPublishOutcome::MaxItemsExceeded,
            });
        }
        if effective_config.persist_items && write.items.is_empty() {
            return Ok(PubSubPublishResult {
                outcome: PubSubPublishOutcome::ItemRequired,
            });
        }
        if !effective_config.persist_items && !effective_config.deliver_payloads && !write.items.is_empty() {
            return Ok(PubSubPublishResult {
                outcome: PubSubPublishOutcome::ItemForbidden,
            });
        }
        if !effective_config.persist_items && effective_config.deliver_payloads && write.items.is_empty() {
            return Ok(PubSubPublishResult {
                outcome: PubSubPublishOutcome::ItemRequired,
            });
        }
        if node.is_none() {
            match self
                .create_node(
                    write.node,
                    write.publisher_jid,
                    &effective_config,
                    write.max_nodes_per_owner,
                )
                .await?
            {
                CreateNodeOutcome::Created | CreateNodeOutcome::Conflict => {}
                CreateNodeOutcome::QuotaExceeded => {
                    return Ok(PubSubPublishResult {
                        outcome: PubSubPublishOutcome::QuotaExceeded,
                    });
                }
                CreateNodeOutcome::InvalidOptions
                | CreateNodeOutcome::Forbidden
                | CreateNodeOutcome::CollectionLimitExceeded
                | CreateNodeOutcome::Cycle => {
                    return Ok(PubSubPublishResult {
                        outcome: PubSubPublishOutcome::Conflict,
                    });
                }
            }
            node = self.get_node(write.node).await?;
        }
        let Some(node) = node else {
            return Ok(PubSubPublishResult {
                outcome: PubSubPublishOutcome::MissingNode,
            });
        };
        if node.node_type != "leaf"
            || write.items.len() > node.max_items as usize
            || (node.persist_items && write.items.is_empty())
            || (!node.persist_items && !node.deliver_payloads && !write.items.is_empty())
            || (!node.persist_items && node.deliver_payloads && write.items.is_empty())
            || (node.deliver_payloads
                && write
                    .items
                    .iter()
                    .any(|(_, item_xml)| !Self::item_xml_has_payload(item_xml)))
            || write
                .items
                .iter()
                .any(|(_, item_xml)| item_xml.len() > node.max_payload_size as usize)
            || node.payload_type.as_deref().is_some_and(|expected| {
                write
                    .items
                    .iter()
                    .any(|(_, item_xml)| !Self::serialized_item_payload_matches_type(item_xml, expected))
            })
        {
            return Ok(PubSubPublishResult {
                outcome: PubSubPublishOutcome::PreconditionNotMet,
            });
        }
        if had_publish_options && effective_config != node.config() {
            return Ok(PubSubPublishResult {
                outcome: PubSubPublishOutcome::PreconditionNotMet,
            });
        }
        if !self.can_publish(&node, write.publisher_jid).await? {
            return Ok(PubSubPublishResult {
                outcome: PubSubPublishOutcome::Forbidden,
            });
        }
        let outcome = self
            .publish_items(
                &node,
                write.publisher_jid,
                write.items,
                write.max_storage_bytes_per_owner,
            )
            .await?;
        let pubsub_outcome = match outcome {
            PublishItemsOutcome::Published => PubSubPublishOutcome::Published {
                item_ids: write.items.iter().map(|(id, _)| id.clone()).collect(),
            },
            PublishItemsOutcome::Conflict => PubSubPublishOutcome::Conflict,
            PublishItemsOutcome::QuotaExceeded => PubSubPublishOutcome::QuotaExceeded,
            PublishItemsOutcome::Forbidden => PubSubPublishOutcome::Forbidden,
            PublishItemsOutcome::PreconditionFailed => PubSubPublishOutcome::PreconditionNotMet,
        };
        Ok(PubSubPublishResult {
            outcome: pubsub_outcome,
        })
    }

    pub(crate) async fn execute_pubsub_subscribe(
        &self,
        command: PubSubSubscribeCommand<'_>,
    ) -> Result<PubSubSubscribeResult> {
        validate_pubsub_subscribe_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubSubscribeResult {
                outcome: PubSubSubscribeOutcome::NotFound,
            });
        };
        let affiliation = self.get_node_affiliation(node.id, write.requester).await?;
        if affiliation.as_deref() == Some("outcast") {
            return Ok(PubSubSubscribeResult {
                outcome: PubSubSubscribeOutcome::Forbidden,
            });
        }
        let existing_subscription = self.get_subscription(node.id, write.subscriber_jid).await?;
        if let Some(ref existing) = existing_subscription {
            if existing.state == "pending" {
                return Ok(PubSubSubscribeResult {
                    outcome: PubSubSubscribeOutcome::PendingSubscription,
                });
            }
            if existing.is_active() && write.options.is_none() {
                return Ok(PubSubSubscribeResult {
                    outcome: PubSubSubscribeOutcome::ExistingActive(existing.clone()),
                });
            }
        }
        let state_value = match node.access_model.as_str() {
            "open" => "subscribed",
            "whitelist"
                if matches!(
                    affiliation.as_deref(),
                    Some("owner" | "publisher" | "member")
                ) =>
            {
                "subscribed"
            }
            "authorize"
                if matches!(
                    affiliation.as_deref(),
                    Some("owner" | "publisher" | "member")
                ) =>
            {
                "subscribed"
            }
            "authorize" => "pending",
            "whitelist" => {
                return Ok(PubSubSubscribeResult {
                    outcome: PubSubSubscribeOutcome::ClosedNode,
                });
            }
            _ => {
                return Ok(PubSubSubscribeResult {
                    outcome: PubSubSubscribeOutcome::Forbidden,
                });
            }
        };
        let planned_subid = existing_subscription
            .as_ref()
            .map(|sub| sub.subid.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let default_options = PubSubSubscriptionOptions::for_node_type(&node.node_type);
        let effective_options = write.options.unwrap_or(&default_options);
        let outcome = self
            .set_subscription_limited_with_options(
                node.id,
                write.requester,
                write.subscriber_jid,
                state_value,
                &node.node_type,
                &node.access_model,
                write.max_subscriptions,
                Some(effective_options),
                &planned_subid,
            )
            .await?;
        let pubsub_outcome = match outcome {
            SubscribeOutcome::Subscribed(sub) => PubSubSubscribeOutcome::Subscribed(sub),
            SubscribeOutcome::LimitExceeded => PubSubSubscribeOutcome::LimitExceeded,
            SubscribeOutcome::NotFound => PubSubSubscribeOutcome::NotFound,
            SubscribeOutcome::Forbidden => PubSubSubscribeOutcome::Forbidden,
            SubscribeOutcome::ClosedNode => PubSubSubscribeOutcome::ClosedNode,
            SubscribeOutcome::PreconditionFailed => PubSubSubscribeOutcome::PreconditionFailed,
        };
        Ok(PubSubSubscribeResult {
            outcome: pubsub_outcome,
        })
    }

    pub(crate) async fn execute_pubsub_unsubscribe(
        &self,
        command: PubSubUnsubscribeCommand<'_>,
    ) -> Result<PubSubUnsubscribeResult> {
        validate_pubsub_unsubscribe_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubUnsubscribeResult {
                outcome: PubSubUnsubscribeOutcome::NotFound,
            });
        };
        let Some(subscription) = self.get_subscription(node.id, write.subscriber_jid).await?
        else {
            return Ok(PubSubUnsubscribeResult {
                outcome: PubSubUnsubscribeOutcome::NotSubscribed,
            });
        };
        if subscription.is_expired() {
            return Ok(PubSubUnsubscribeResult {
                outcome: PubSubUnsubscribeOutcome::NotSubscribed,
            });
        }
        if write.subid.is_some_and(|value| value != subscription.subid) {
            return Ok(PubSubUnsubscribeResult {
                outcome: PubSubUnsubscribeOutcome::InvalidSubid,
            });
        }
        let outcome = self
            .unsubscribe_checked(
                node.id,
                write.requester,
                write.subscriber_jid,
                &subscription.subid,
            )
            .await?;
        let pubsub_outcome = match outcome {
            UnsubscribeOutcome::Unsubscribed => PubSubUnsubscribeOutcome::Unsubscribed {
                subid: Some(subscription.subid),
            },
            UnsubscribeOutcome::NotFound => PubSubUnsubscribeOutcome::NotSubscribed,
            UnsubscribeOutcome::InvalidSubid => PubSubUnsubscribeOutcome::InvalidSubid,
            UnsubscribeOutcome::Forbidden => PubSubUnsubscribeOutcome::Forbidden,
        };
        Ok(PubSubUnsubscribeResult {
            outcome: pubsub_outcome,
        })
    }

    pub(crate) async fn execute_pubsub_retract(
        &self,
        command: PubSubRetractCommand<'_>,
    ) -> Result<PubSubRetractResult> {
        validate_pubsub_retract_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubRetractResult {
                outcome: PubSubRetractOutcome::NotFound,
            });
        };
        if node.node_type != "leaf" {
            return Ok(PubSubRetractResult {
                outcome: PubSubRetractOutcome::NotLeafNode,
            });
        }
        if !node.persist_items {
            return Ok(PubSubRetractResult {
                outcome: PubSubRetractOutcome::NotPersistent,
            });
        }
        if !self.can_publish(&node, write.requester).await? {
            return Ok(PubSubRetractResult {
                outcome: PubSubRetractOutcome::Forbidden,
            });
        }
        let outcome = self
            .retract_items(
                node.id,
                write.item_ids,
                write.requester,
                write.force_notification,
            )
            .await?;
        let pubsub_outcome = match outcome {
            RetractItemsOutcome::Retracted => PubSubRetractOutcome::Retracted,
            RetractItemsOutcome::NotFound => PubSubRetractOutcome::ItemNotFound,
            RetractItemsOutcome::Forbidden => PubSubRetractOutcome::Forbidden,
        };
        Ok(PubSubRetractResult {
            outcome: pubsub_outcome,
        })
    }

    pub(crate) async fn execute_pubsub_create_node(
        &self,
        command: PubSubCreateNodeCommand<'_>,
    ) -> Result<PubSubCreateNodeResult> {
        validate_pubsub_create_node_command(&command)?;
        let write = command.write;
        let outcome = self
            .create_node(
                write.node,
                write.creator_jid,
                write.config,
                write.max_nodes_per_owner,
            )
            .await?;
        Ok(PubSubCreateNodeResult { outcome })
    }

    pub(crate) async fn execute_pubsub_delete_node(
        &self,
        command: PubSubDeleteNodeCommand<'_>,
    ) -> Result<PubSubDeleteNodeResult> {
        validate_pubsub_delete_node_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubDeleteNodeResult {
                outcome: OwnerMutationOutcome::NotFound,
            });
        };
        let outcome = self
            .delete_node_as_owner_with_redirect_and_outbox(
                node.id,
                write.requester,
                write.redirect,
            )
            .await?;
        Ok(PubSubDeleteNodeResult { outcome })
    }

    pub(crate) async fn execute_pubsub_purge_node(
        &self,
        command: PubSubPurgeNodeCommand<'_>,
    ) -> Result<PubSubPurgeNodeResult> {
        validate_pubsub_purge_node_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubPurgeNodeResult {
                outcome: OwnerMutationOutcome::NotFound,
            });
        };
        if node.node_type != "leaf" || !node.persist_items {
            return Ok(PubSubPurgeNodeResult {
                outcome: OwnerMutationOutcome::Invalid,
            });
        }
        let outcome = self
            .purge_node_as_owner_with_outbox(node.id, write.requester)
            .await?;
        Ok(PubSubPurgeNodeResult { outcome })
    }

    pub(crate) async fn execute_pubsub_configure_node(
        &self,
        command: PubSubConfigureNodeCommand<'_>,
    ) -> Result<PubSubConfigureNodeResult> {
        validate_pubsub_configure_node_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubConfigureNodeResult {
                outcome: PubSubConfigOutcome::NotFound,
            });
        };
        let outcome = self
            .update_node_config_and_graph_with_outbox(
                &node,
                write.requester,
                write.expected,
                write.config,
            )
            .await?;
        Ok(PubSubConfigureNodeResult { outcome })
    }

    pub(crate) async fn execute_pubsub_set_subscriptions(
        &self,
        command: PubSubSetSubscriptionsCommand<'_>,
    ) -> Result<PubSubSetSubscriptionsResult> {
        validate_pubsub_set_subscriptions_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubSetSubscriptionsResult {
                outcome: SetSubscriptionsOutcome::NotFound,
            });
        };
        let outcome = self
            .set_subscriptions(node.id, write.requester, write.changes)
            .await?;
        Ok(PubSubSetSubscriptionsResult { outcome })
    }

    pub(crate) async fn execute_pubsub_set_affiliations(
        &self,
        command: PubSubSetAffiliationsCommand<'_>,
    ) -> Result<PubSubSetAffiliationsResult> {
        validate_pubsub_set_affiliations_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubSetAffiliationsResult {
                outcome: SetAffiliationsOutcome::NotFound,
            });
        };
        let outcome = self
            .set_affiliations(node.id, write.requester, write.changes)
            .await?;
        Ok(PubSubSetAffiliationsResult { outcome })
    }

    pub(crate) async fn execute_pep_retract(
        &self,
        command: PepRetractCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepRetractResult> {
        validate_pep_retract_command(&command)?;
        let write = command.write;
        let item_ids: Vec<&str> = write.item_ids.iter().map(String::as_str).collect();
        let outcome = self
            .retract_pep_items(
                write.owner,
                write.connection_id,
                write.node,
                &item_ids,
                write.notify,
                factory,
            )
            .await?;
        Ok(PepRetractResult { outcome })
    }

    pub(crate) async fn execute_pep_delete_node(
        &self,
        command: PepDeleteNodeCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepDeleteNodeResult> {
        validate_pep_delete_node_command(&command)?;
        let write = command.write;
        let outcome = self
            .delete_pep_node(write.owner, write.connection_id, write.node, factory)
            .await?;
        Ok(PepDeleteNodeResult { outcome })
    }

    pub(crate) async fn execute_pep_purge_node(
        &self,
        command: PepPurgeNodeCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepPurgeNodeResult> {
        validate_pep_purge_node_command(&command)?;
        let write = command.write;
        let outcome = self
            .purge_pep_node(write.owner, write.connection_id, write.node, factory)
            .await?;
        Ok(PepPurgeNodeResult { outcome })
    }

    pub(crate) async fn execute_pep_configure_node(
        &self,
        command: PepConfigureNodeCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepConfigureNodeResult> {
        validate_pep_configure_node_command(&command)?;
        let write = command.write;
        let outcome = self
            .update_pep_node_config(
                write.owner,
                write.connection_id,
                write.node,
                write.expected,
                write.config,
                factory,
            )
            .await?;
        Ok(PepConfigureNodeResult { outcome })
    }

    pub(crate) async fn execute_pep_set_affiliations(
        &self,
        command: PepSetAffiliationsCommand<'_>,
        factory: &dyn PepDirectOutboxFactory,
    ) -> Result<PepSetAffiliationsResult> {
        validate_pep_set_affiliations_command(&command)?;
        let write = command.write;
        let outcome = self
            .update_pep_affiliations(
                write.owner,
                write.connection_id,
                write.node,
                write.expected,
                write.changes,
                factory,
            )
            .await?;
        Ok(PepSetAffiliationsResult { outcome })
    }

    pub(crate) async fn local_account_blocks_pubsub(
        &self,
        username: &str,
        service: &str,
    ) -> Result<bool> {
        let Some(user) = db::find_enabled_user(&self.pool, username).await? else {
            return Ok(false);
        };
        db::is_blocked(&self.pool, user.id, service).await
    }

    pub(crate) async fn presence_delivery_denied(
        &self,
        recipient_id: Uuid,
        active_privacy_list: Option<&str>,
        connection_id: Uuid,
        service: &str,
    ) -> Result<bool> {
        if db::is_blocked(&self.pool, recipient_id, service).await? {
            return Ok(true);
        }
        if active_privacy_list.is_some() {
            db::refresh_active_privacy_session(&self.pool, recipient_id, connection_id).await?;
        }
        db::privacy_denies(
            &self.pool,
            recipient_id,
            active_privacy_list,
            service,
            db::PrivacyStanzaKind::Message,
        )
        .await
    }

    // Durable notification/digest delivery slice ----------------------------------

    /// Re-authorize a durable PEP delivery without consulting its XML payload,
    /// `from` attribute or ordering-key convention. Explicit denials are
    /// terminal and ACK-dropped by the worker; database/lock failures escape as
    /// errors so the immutable row is retried.
    pub(crate) async fn authorize_pep_outbox_delivery(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
    ) -> Result<PepOutboxAuthorizationOutcome> {
        let drop_unverifiable = || {
            db::record_unverifiable_pep_drop();
            PepOutboxAuthorizationOutcome::Drop(PepOutboxDropReason::UnverifiableIdentity)
        };
        if item.delivery_kind != PubSubOutboxDeliveryKind::PepStanza
            || item.source != PubSubOutboxSource::Pep
            || item.legacy_unverifiable
        {
            return Ok(drop_unverifiable());
        }
        let Some(subject) = item.pep_subject.as_ref() else {
            return Ok(drop_unverifiable());
        };
        if subject.sender_account_id.is_nil()
            || subject
                .sender_connection_id
                .is_some_and(|connection_id| connection_id.is_nil())
            || subject
                .recipient_account_id
                .is_some_and(|recipient_id| recipient_id.is_nil())
            || (subject.event_kind.requires_causal_authorization()
                && subject.authorization_mode != PepOutboxAuthorizationMode::CausalAudience)
            || item.security_sensitive != db::security_sensitive_pep_node(&item.source_node)
            || (item.security_sensitive
                && matches!(
                    subject.event_kind,
                    PepOutboxEventKind::Publish | PepOutboxEventKind::LastItem
                )
                && subject.authorization_mode != PepOutboxAuthorizationMode::LiveNodeAccess)
        {
            return Ok(drop_unverifiable());
        }

        let Ok(sender) = crate::jid::CanonicalJid::parse_bare(&subject.sender_bare_jid) else {
            return Ok(drop_unverifiable());
        };
        let Ok(recipient) = crate::jid::CanonicalJid::parse(&item.recipient_jid) else {
            return Ok(drop_unverifiable());
        };
        if sender.to_string() != subject.sender_bare_jid
            || sender.domainpart() != self.domain
            || sender.localpart().is_none()
            || recipient.to_string() != item.recipient_jid
            || recipient.domainpart() != item.target_domain
        {
            return Ok(drop_unverifiable());
        }
        let recipient_is_local = recipient.domainpart() == self.domain;
        if recipient_is_local != subject.recipient_is_local
            || subject.recipient_is_local != subject.recipient_account_id.is_some()
            || recipient_is_local && recipient.localpart().is_none()
        {
            return Ok(drop_unverifiable());
        }

        let mut transaction = self.begin_mutation().await?;
        let mut account_ids = vec![subject.sender_account_id];
        if let Some(recipient_id) = subject.recipient_account_id {
            account_ids.push(recipient_id);
        }
        account_ids.sort_unstable();
        account_ids.dedup();
        let rows = sqlx::query(
            "SELECT id,username,is_disabled FROM users
              WHERE id=ANY($1)
              ORDER BY id
              FOR SHARE",
        )
        .bind(&account_ids)
        .fetch_all(&mut *transaction)
        .await?;
        let accounts = rows
            .into_iter()
            .map(|row| {
                Ok::<_, sqlx::Error>((
                    row.try_get::<Uuid, _>("id")?,
                    (
                        row.try_get::<String, _>("username")?,
                        row.try_get::<bool, _>("is_disabled")?,
                    ),
                ))
            })
            .collect::<std::result::Result<HashMap<_, _>, _>>()?;
        let sender_matches =
            accounts
                .get(&subject.sender_account_id)
                .is_some_and(|(username, disabled)| {
                    !*disabled
                        && crate::jid::CanonicalJid::parse_bare(&format!(
                            "{username}@{}",
                            self.domain
                        ))
                        .is_ok_and(|jid| jid.to_string() == subject.sender_bare_jid)
                });
        if !sender_matches {
            transaction.rollback().await?;
            return Ok(PepOutboxAuthorizationOutcome::Drop(
                PepOutboxDropReason::SenderUnavailable,
            ));
        }
        if let Some(recipient_id) = subject.recipient_account_id {
            let recipient_matches =
                accounts
                    .get(&recipient_id)
                    .is_some_and(|(username, disabled)| {
                        !*disabled
                            && recipient.localpart() == Some(username.as_str())
                            && recipient.domainpart() == self.domain
                    });
            if !recipient_matches {
                transaction.rollback().await?;
                return Ok(PepOutboxAuthorizationOutcome::Drop(
                    PepOutboxDropReason::RecipientUnavailable,
                ));
            }
        }

        for owner_id in &account_ids {
            lock_pep_block_policy(&mut transaction, *owner_id).await?;
        }
        let block_rows = sqlx::query(
            "SELECT owner_id,blocked_jid FROM blocked_jids
              WHERE owner_id=ANY($1)
              ORDER BY owner_id,blocked_jid
              FOR SHARE",
        )
        .bind(&account_ids)
        .fetch_all(&mut *transaction)
        .await?;
        let mut blocks: HashMap<Uuid, Vec<String>> = HashMap::new();
        for row in block_rows {
            blocks
                .entry(row.try_get("owner_id")?)
                .or_default()
                .push(row.try_get("blocked_jid")?);
        }
        let same_account = subject.recipient_account_id == Some(subject.sender_account_id);
        let sender_blocks_recipient = !same_account
            && blocks
                .get(&subject.sender_account_id)
                .is_some_and(|patterns| {
                    patterns.iter().any(|pattern| {
                        db::roster::blocked_jid_matches(pattern, &item.recipient_jid)
                    })
                });
        let recipient_blocks_sender = !same_account
            && subject.recipient_account_id.is_some_and(|recipient_id| {
                blocks.get(&recipient_id).is_some_and(|patterns| {
                    patterns.iter().any(|pattern| {
                        db::roster::blocked_jid_matches(pattern, &subject.sender_bare_jid)
                    })
                })
            });
        if sender_blocks_recipient || recipient_blocks_sender {
            transaction.rollback().await?;
            return Ok(PepOutboxAuthorizationOutcome::Drop(
                PepOutboxDropReason::Blocked,
            ));
        }

        if !same_account
            && db::privacy::privacy_denies_in_transaction(
                &mut transaction,
                subject.sender_account_id,
                subject.sender_connection_id,
                &item.recipient_jid,
                db::PrivacyStanzaKind::Message,
            )
            .await?
        {
            transaction.rollback().await?;
            return Ok(PepOutboxAuthorizationOutcome::Drop(
                PepOutboxDropReason::PrivacyDenied,
            ));
        }
        if !same_account {
            if let Some(recipient_id) = subject.recipient_account_id {
                if db::privacy::privacy_denies_in_transaction(
                    &mut transaction,
                    recipient_id,
                    None,
                    &subject.sender_bare_jid,
                    db::PrivacyStanzaKind::Message,
                )
                .await?
                {
                    transaction.rollback().await?;
                    return Ok(PepOutboxAuthorizationOutcome::Drop(
                        PepOutboxDropReason::PrivacyDenied,
                    ));
                }
            }
        }

        if subject.authorization_mode == PepOutboxAuthorizationMode::LiveNodeAccess {
            lock_pep_audience(
                &mut transaction,
                subject.sender_account_id,
                &item.source_node,
            )
            .await?;
            let policy = sqlx::query(
                "SELECT access_model,deliver_notifications,roster_groups_allowed,access_whitelist
                   FROM pep_nodes
                  WHERE owner_id=$1 AND node=$2
                  FOR SHARE",
            )
            .bind(subject.sender_account_id)
            .bind(&item.source_node)
            .fetch_optional(&mut *transaction)
            .await?;
            let Some(policy) = policy else {
                transaction.rollback().await?;
                return Ok(PepOutboxAuthorizationOutcome::Drop(
                    PepOutboxDropReason::NodeAccessRevoked,
                ));
            };
            if !policy.try_get::<bool, _>("deliver_notifications")? {
                transaction.rollback().await?;
                return Ok(PepOutboxAuthorizationOutcome::Drop(
                    PepOutboxDropReason::NodeAccessRevoked,
                ));
            }
            let recipient_bare = recipient.bare();
            if recipient_bare != subject.sender_bare_jid {
                let roster = sqlx::query(
                    "SELECT subscription,groups FROM roster_items
                      WHERE owner_id=$1 AND contact_jid=$2
                      FOR SHARE",
                )
                .bind(subject.sender_account_id)
                .bind(&recipient_bare)
                .fetch_optional(&mut *transaction)
                .await?;
                let automatic = roster
                    .as_ref()
                    .map(|row| row.try_get::<String, _>("subscription"))
                    .transpose()?
                    .is_some_and(|subscription| matches!(subscription.as_str(), "from" | "both"));
                let access_model: String = policy.try_get("access_model")?;
                let access_allowed = match access_model.as_str() {
                    // The causal audience was already captured while the
                    // publication transaction held the node locks. `open`
                    // therefore remains open at delivery time; the live check
                    // detects a later restrictive policy without inventing a
                    // subscription requirement XEP-0060 does not impose.
                    "open" => true,
                    "whitelist" => policy
                        .try_get::<Vec<String>, _>("access_whitelist")?
                        .iter()
                        .any(|jid| {
                            crate::jid::canonical_bare_key(jid)
                                .is_ok_and(|jid| jid == recipient_bare)
                        }),
                    "presence" => automatic,
                    "roster" => match roster.as_ref() {
                        Some(row) => {
                            let groups = serde_json::from_value::<Vec<String>>(
                                row.try_get::<serde_json::Value, _>("groups")?,
                            )
                            .context("stored PEP roster groups are not a string array")?;
                            let allowed: Vec<String> = policy.try_get("roster_groups_allowed")?;
                            automatic && groups.iter().any(|group| allowed.contains(group))
                        }
                        None => false,
                    },
                    _ => false,
                };
                if !access_allowed {
                    transaction.rollback().await?;
                    return Ok(PepOutboxAuthorizationOutcome::Drop(
                        PepOutboxDropReason::NodeAccessRevoked,
                    ));
                }
            }
        }
        transaction.commit().await?;
        Ok(PepOutboxAuthorizationOutcome::Deliver)
    }

    pub(crate) async fn claim_pubsub_outbox(
        &self,
        limit: i64,
    ) -> Result<Vec<ClaimedPubSubOutboxDelivery>> {
        Ok(db::claim_pubsub_outbox(&self.pool, limit)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub(crate) async fn acknowledge_pubsub_outbox(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        db::acknowledge_pubsub_outbox(&self.pool, delivery_id, lease_token).await
    }

    pub(crate) async fn renew_pubsub_outbox_lease(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        db::renew_pubsub_outbox_lease(&self.pool, delivery_id, lease_token).await
    }

    pub(crate) async fn retry_pubsub_outbox(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
        error: &str,
    ) -> Result<PubSubOutboxFailureDisposition> {
        Ok(db::retry_pubsub_outbox(&self.pool, &item.inner, error)
            .await?
            .into())
    }

    pub(crate) async fn dead_letter_pubsub_outbox(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        reason: &str,
        error: &str,
    ) -> Result<PubSubOutboxFailureDisposition> {
        Ok(
            db::dead_letter_pubsub_outbox(&self.pool, delivery_id, lease_token, reason, error)
                .await?
                .into(),
        )
    }

    pub(crate) async fn expire_pubsub_outbox(&self, limit: i64) -> Result<u64> {
        db::expire_pubsub_outbox(&self.pool, limit).await
    }

    pub(crate) async fn cleanup_pubsub_dead_letters(&self, limit: i64) -> Result<u64> {
        db::cleanup_pubsub_dead_letters(&self.pool, limit).await
    }

    pub(crate) async fn cleanup_idle_pubsub_event_streams(&self, limit: i64) -> Result<u64> {
        db::cleanup_idle_pubsub_event_streams(&self.pool, limit).await
    }

    pub(crate) async fn pubsub_outbox_snapshot(&self) -> Result<PubSubOutboxSnapshot> {
        Ok(db::pubsub_outbox_snapshot(&self.pool).await?.into())
    }

    pub(crate) async fn enqueue_pubsub_digest_snapshot(
        &self,
        source_delivery_id: Uuid,
        node_id: Uuid,
        subscriber_jid: &str,
        event_xml: &str,
        frequency_ms: i32,
        show_values: &[String],
    ) -> Result<()> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[subscriber_jid, &node_key], false)
            .await?;
        db::enqueue_pubsub_digest_snapshot(
            &self.pool,
            source_delivery_id,
            node_id,
            subscriber_jid,
            event_xml,
            frequency_ms,
            show_values,
        )
        .await
    }

    pub(crate) async fn enqueue_pubsub_digest(
        &self,
        node_id: Uuid,
        subscriber_jid: &str,
        event_xml: &str,
        frequency_ms: i32,
    ) -> Result<bool> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[subscriber_jid, &node_key], false)
            .await?;
        db::enqueue_pubsub_digest(&self.pool, node_id, subscriber_jid, event_xml, frequency_ms)
            .await
    }

    pub(crate) async fn claim_due_pubsub_digests(
        &self,
        limit: i64,
    ) -> Result<Vec<DuePubSubDigest>> {
        Ok(db::claim_due_pubsub_digests(&self.pool, limit)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub(crate) async fn release_pubsub_digests(&self, ids: &[Uuid]) -> Result<()> {
        db::release_pubsub_digests(&self.pool, ids).await
    }

    pub(crate) async fn acknowledge_pubsub_digests(&self, ids: &[Uuid]) -> Result<()> {
        db::acknowledge_pubsub_digests(&self.pool, ids).await
    }

    pub(crate) async fn cleanup_expired_subscriptions(&self, limit: i64) -> Result<u64> {
        db::cleanup_expired_subscriptions(&self.pool, limit).await
    }
}

const NS_PUBSUB_EVENT: &str = "http://jabber.org/protocol/pubsub#event";
const NS_DATA: &str = "jabber:x:data";
const NODE_CONFIG_FORM: &str = "http://jabber.org/protocol/pubsub#node_config";

fn pubsub_config_field(
    variable: &str,
    field_type: Option<&str>,
    values: impl IntoIterator<Item = impl ToString>,
) -> XmlElement {
    let mut field = XmlElement::new("field")
        .attr("var", variable)
        .optional_attr("type", field_type);
    for value in values {
        field.push_child(XmlElement::new("value").text(value.to_string()));
    }
    field
}

fn pubsub_bool_text(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

/// Render a complete node-configuration form from a locked database snapshot.
/// The same helper is used for owner IQ responses and durable notifications so
/// notification XML cannot be assembled from a pre-lock request object.
pub(crate) fn pubsub_node_config_form(config: &PubSubNodeConfig, form_type: &str) -> String {
    let mut form = XmlElement::namespaced("x", NS_DATA).attr("type", form_type);
    form.push_child(pubsub_config_field(
        "FORM_TYPE",
        Some("hidden"),
        [NODE_CONFIG_FORM],
    ));
    for (variable, field_type, value) in [
        (
            "pubsub#title",
            "text-single",
            config.title.clone().unwrap_or_default(),
        ),
        (
            "pubsub#description",
            "text-single",
            config.description.clone().unwrap_or_default(),
        ),
        (
            "pubsub#access_model",
            "list-single",
            config.access_model.clone(),
        ),
        (
            "pubsub#publish_model",
            "list-single",
            config.publish_model.clone(),
        ),
        (
            "pubsub#max_items",
            "text-single",
            config.max_items.to_string(),
        ),
        (
            "pubsub#deliver_notifications",
            "boolean",
            pubsub_bool_text(config.deliver_notifications).to_owned(),
        ),
        (
            "pubsub#deliver_payloads",
            "boolean",
            pubsub_bool_text(config.deliver_payloads).to_owned(),
        ),
        (
            "pubsub#notify_config",
            "boolean",
            pubsub_bool_text(config.notify_config).to_owned(),
        ),
        (
            "pubsub#notify_delete",
            "boolean",
            pubsub_bool_text(config.notify_delete).to_owned(),
        ),
        (
            "pubsub#notify_retract",
            "boolean",
            pubsub_bool_text(config.notify_retract).to_owned(),
        ),
        (
            "pubsub#notify_sub",
            "boolean",
            pubsub_bool_text(config.notify_sub).to_owned(),
        ),
        (
            "pubsub#persist_items",
            "boolean",
            pubsub_bool_text(config.persist_items).to_owned(),
        ),
        (
            "pubsub#send_last_published_item",
            "list-single",
            config.send_last_published_item.clone(),
        ),
        (
            "pubsub#language",
            "text-single",
            config.language.clone().unwrap_or_default(),
        ),
        (
            "pubsub#type",
            "text-single",
            config.payload_type.clone().unwrap_or_default(),
        ),
        (
            "pubsub#max_payload_size",
            "text-single",
            config.max_payload_size.to_string(),
        ),
        ("pubsub#node_type", "list-single", config.node_type.clone()),
    ] {
        form.push_child(pubsub_config_field(variable, Some(field_type), [value]));
    }
    form.push_child(pubsub_config_field(
        "pubsub#collection",
        Some("text-multi"),
        config.collections.iter(),
    ));
    form.push_child(pubsub_config_field(
        "pubsub#children",
        Some("text-multi"),
        config.children.iter(),
    ));
    form.push_child(pubsub_config_field(
        "pubsub#children_max",
        Some("text-single"),
        [config.children_max.to_string()],
    ));
    form.push_child(pubsub_config_field(
        "pubsub#children_association_policy",
        Some("list-single"),
        [if config.children_association_policy == "owner" {
            "owners"
        } else {
            &config.children_association_policy
        }],
    ));
    form.push_child(pubsub_config_field(
        "pubsub#children_association_whitelist",
        Some("jid-multi"),
        config.children_association_whitelist.iter(),
    ));
    form.finish()
}
const SUBSCRIBE_AUTH_FORM: &str = "http://jabber.org/protocol/pubsub#subscribe_authorization";

impl PubSubService {
    fn render_transactional_node_event(
        &self,
        node: &db::PubSubNode,
        audience: &[db::PubSubNotificationDelivery],
        direct_recipients: &[String],
        event: &str,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let ordering_key = format!("pubsub:{}", node.id);
        let mut outbox = Vec::with_capacity(audience.len() + direct_recipients.len());
        for delivery in audience {
            let children = subscription_event_children(
                &delivery.subscription,
                event,
                delivery.collection.as_deref(),
                None,
            )?;
            let (kind, digest) = if delivery.subscription.digest {
                (
                    db::PubSubOutboxDeliveryKind::PubSubDigest,
                    Some((
                        delivery.subscription_node_id,
                        delivery.subscription.digest_frequency,
                    )),
                )
            } else {
                (db::PubSubOutboxDeliveryKind::PubSubChildren, None)
            };
            outbox.push(db::PubSubOutboxInsert::new(
                event_id,
                ordering_key.clone(),
                db::PubSubOutboxSource::PubSub,
                kind,
                delivery.subscription.jid.clone(),
                children,
                Some(delivery.subscription.show_values.clone()),
                digest,
                &node.node,
                None,
                created_at,
            )?);
        }
        for recipient in direct_recipients {
            let mut wrapper = XmlElement::namespaced("event", NS_PUBSUB_EVENT);
            wrapper.push_validated_fragment(event)?;
            let message = XmlElement::namespaced("message", "jabber:client")
                .attr("type", "headline")
                .attr("id", event_id)
                .attr("from", &self.service_jid)
                .attr("to", recipient)
                .child(wrapper)
                .finish();
            outbox.push(db::PubSubOutboxInsert::new(
                event_id,
                ordering_key.clone(),
                db::PubSubOutboxSource::PubSub,
                db::PubSubOutboxDeliveryKind::PubSubDirect,
                recipient.clone(),
                message,
                None,
                None,
                &node.node,
                None,
                created_at,
            )?);
        }
        Ok(outbox)
    }
}

impl db::PubSubMutationOutboxRenderer for PubSubService {
    fn render_create(
        &self,
        node: &db::PubSubNode,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let event = XmlElement::new("create").attr("node", &node.node).finish();
        self.render_transactional_node_event(node, audience, &[], &event, event_id, created_at)
    }

    fn render_items(
        &self,
        node: &db::PubSubNode,
        items: &[(String, String)],
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let mut event = XmlElement::new("items").attr("node", &node.node);
        for (item_id, payload) in items {
            if node.deliver_payloads {
                event.push_validated_fragment(payload)?;
            } else {
                event.push_child(XmlElement::new("item").attr("id", item_id));
            }
        }
        self.render_transactional_node_event(
            node,
            audience,
            &[],
            &event.finish(),
            event_id,
            created_at,
        )
    }

    fn render_purge(
        &self,
        node: &db::PubSubNode,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let event = XmlElement::new("purge").attr("node", &node.node).finish();
        self.render_transactional_node_event(node, audience, &[], &event, event_id, created_at)
    }

    fn render_retract(
        &self,
        node: &db::PubSubNode,
        item_ids: &[String],
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let mut items = XmlElement::new("items").attr("node", &node.node);
        for item_id in item_ids {
            items.push_child(XmlElement::new("retract").attr("id", item_id));
        }
        self.render_transactional_node_event(
            node,
            audience,
            &[],
            &items.finish(),
            event_id,
            created_at,
        )
    }

    fn render_delete(
        &self,
        node: &db::PubSubNode,
        redirect: Option<&str>,
        audience: &[db::PubSubNotificationDelivery],
        nonactive_recipients: &[String],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        if !node.notify_delete {
            return Ok(Vec::new());
        }
        let mut delete = XmlElement::new("delete").attr("node", &node.node);
        if let Some(uri) = redirect {
            delete.push_child(XmlElement::new("redirect").attr("uri", uri));
        }
        self.render_transactional_node_event(
            node,
            audience,
            nonactive_recipients,
            &delete.finish(),
            event_id,
            created_at,
        )
    }

    fn render_configuration(
        &self,
        node: &db::PubSubNode,
        config: &db::PubSubNodeConfig,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let config = PubSubNodeConfig::from(config.clone());
        let form = pubsub_node_config_form(&config, "result");
        let mut event = XmlElement::new("configuration").attr("node", &node.node);
        event.push_validated_fragment(&form)?;
        self.render_transactional_node_event(
            node,
            audience,
            &[],
            &event.finish(),
            event_id,
            created_at,
        )
    }

    fn render_collection_edge(
        &self,
        source: &db::PubSubNode,
        action: &str,
        target_node: &str,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        anyhow::ensure!(matches!(action, "associate" | "dissociate"));
        let action = XmlElement::dynamic(action)
            .map_err(|error| anyhow::anyhow!("invalid collection action QName: {error}"))?
            .attr("node", target_node);
        let event = XmlElement::new("collection")
            .attr("node", &source.node)
            .child(action)
            .finish();
        self.render_transactional_node_event(source, audience, &[], &event, event_id, created_at)
    }

    fn render_subscription_transition(
        &self,
        node: &db::PubSubNode,
        subscription: &db::PubSubSubscription,
        notify_recipients: &[String],
        authorization_recipients: &[String],
        last_item: Option<&db::PubSubItem>,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let transition = XmlElement::new("subscription")
            .attr("node", &node.node)
            .attr("jid", &subscription.jid)
            .attr("subscription", &subscription.state)
            .attr("subid", &subscription.subid)
            .finish();
        let mut outbox = self.render_transactional_node_event(
            node,
            &[],
            notify_recipients,
            &transition,
            event_id,
            created_at,
        )?;

        if !authorization_recipients.is_empty() {
            let authorization_event_id = Uuid::new_v4();
            let form = XmlElement::namespaced("x", NS_DATA)
                .attr("type", "form")
                .child(data_form_field(
                    "FORM_TYPE",
                    Some("hidden"),
                    SUBSCRIBE_AUTH_FORM,
                ))
                .child(data_form_field("pubsub#node", None, &node.node))
                .child(data_form_field(
                    "pubsub#subscriber_jid",
                    None,
                    &subscription.jid,
                ))
                .child(data_form_field("pubsub#subid", None, &subscription.subid))
                .child(data_form_field("pubsub#allow", Some("boolean"), "false"))
                .finish();
            for recipient in authorization_recipients {
                let mut message = XmlElement::namespaced("message", "jabber:client")
                    .attr("id", Uuid::new_v4())
                    .attr("from", &self.service_jid)
                    .attr("to", recipient);
                message.push_validated_fragment(&form)?;
                outbox.push(db::PubSubOutboxInsert::new(
                    authorization_event_id,
                    format!("pubsub:{}", node.id),
                    db::PubSubOutboxSource::PubSub,
                    db::PubSubOutboxDeliveryKind::PubSubDirect,
                    recipient.clone(),
                    message.finish(),
                    None,
                    None,
                    &node.node,
                    None,
                    created_at,
                )?);
            }
        }

        if let Some(item) = last_item {
            let last_item_event_id = Uuid::new_v4();
            let mut event = XmlElement::new("items").attr("node", &node.node);
            if node.deliver_payloads {
                event.push_validated_fragment(&item.xml_payload)?;
            } else {
                event.push_child(XmlElement::new("item").attr("id", &item.item_id));
            }
            let children = subscription_event_children(
                subscription,
                &event.finish(),
                None,
                Some(item.created_at),
            )?;
            let (kind, digest) = if subscription.digest {
                (
                    db::PubSubOutboxDeliveryKind::PubSubDigest,
                    Some((node.id, subscription.digest_frequency)),
                )
            } else {
                (db::PubSubOutboxDeliveryKind::PubSubChildren, None)
            };
            outbox.push(db::PubSubOutboxInsert::new(
                last_item_event_id,
                format!("pubsub:{}", node.id),
                db::PubSubOutboxSource::PubSub,
                kind,
                subscription.jid.clone(),
                children,
                Some(subscription.show_values.clone()),
                digest,
                &node.node,
                None,
                created_at,
            )?);
        }
        Ok(outbox)
    }

    fn render_affiliation_transition(
        &self,
        node: &db::PubSubNode,
        jid: &str,
        affiliation: &str,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let event = XmlElement::new("affiliation")
            .attr("node", &node.node)
            .attr("jid", jid)
            .attr("affiliation", affiliation)
            .finish();
        self.render_transactional_node_event(
            node,
            &[],
            &[jid.to_owned()],
            &event,
            event_id,
            created_at,
        )
    }
}

fn data_form_field(var: &str, field_type: Option<&str>, value: &str) -> XmlElement {
    let mut field = XmlElement::new("field").attr("var", var);
    if let Some(field_type) = field_type {
        field = field.attr("type", field_type);
    }
    field.child(XmlElement::new("value").text(value.to_owned()))
}

fn subscription_event_children(
    subscription: &db::PubSubSubscription,
    event: &str,
    collection: Option<&str>,
    delay: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<String> {
    let mut headers = XmlElement::namespaced("headers", "http://jabber.org/protocol/shim").child(
        XmlElement::new("header")
            .attr("name", "SubID")
            .text(subscription.subid.clone()),
    );
    if let Some(collection) = collection {
        headers.push_child(
            XmlElement::new("header")
                .attr("name", "Collection")
                .text(collection.to_owned()),
        );
    }
    let mut children = XmlElement::new("northstar-children");
    let mut wrapper = XmlElement::namespaced("event", NS_PUBSUB_EVENT);
    wrapper.push_validated_fragment(event)?;
    children.push_child(wrapper);
    if subscription.include_body {
        if let Some(body) = pubsub_event_body(event)? {
            children.push_child(XmlElement::new("body").text(body));
        }
    }
    children.push_child(headers);
    if let Some(stamp) = delay {
        children.push_child(
            XmlElement::namespaced("delay", "urn:xmpp:delay").attr("stamp", stamp.to_rfc3339()),
        );
    }
    Ok(children.finish_children())
}

fn pubsub_event_body(event: &str) -> Result<Option<String>> {
    northstar_xep_0060::extract_atom_event_body(event)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    #[test]
    fn atom_event_body_limit_never_splits_a_utf8_character() {
        let summary = format!("{}ƞ", "a".repeat(1_023));
        let event = format!(
            "<entry xmlns='http://www.w3.org/2005/Atom'><summary>{summary}</summary></entry>"
        );
        let body = pubsub_event_body(&event).unwrap().unwrap();
        assert_eq!(body.len(), 1_023);
        assert_eq!(body, "a".repeat(1_023));
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
                let config = PubSubService::default_pep_node_config(&node);
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
    fn node_config_mapping_round_trips_every_policy_field() {
        let service = PubSubNodeConfig {
            access_model: "whitelist".to_owned(),
            publish_model: "subscribers".to_owned(),
            max_items: 37,
            title: Some("A title".to_owned()),
            description: Some("A description".to_owned()),
            deliver_payloads: false,
            notify_delete: false,
            notify_retract: false,
            persist_items: false,
            send_last_published_item: "never".to_owned(),
            node_type: "collection".to_owned(),
            deliver_notifications: false,
            notify_config: false,
            notify_sub: false,
            language: Some("en".to_owned()),
            payload_type: Some("urn:example:payload".to_owned()),
            max_payload_size: 65_535,
            children_max: 23,
            children_association_policy: "whitelist".to_owned(),
            children_association_whitelist: vec!["owner@example.test".to_owned()],
            collections: vec!["parent".to_owned()],
            children: vec!["child".to_owned()],
        };

        let repository = db::PubSubNodeConfig::from(&service);
        let round_trip = PubSubNodeConfig::from(repository);

        assert_eq!(round_trip, service);
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
        let first = PubSubOutboxInsert {
            inner: db::PubSubOutboxInsert::new(
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
            .unwrap(),
        };
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
        let unsubscribed_record =
            db::subscribe_pep_node(&pool, owner_id, &node, &unsubscribed, 100)
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
            tokio::spawn(
                async move { db::block_jids(&block_pool, owner_id, &[blocked_jid]).await },
            );
        let roster_pool = pool.clone();
        let roster_jid = roster.clone();
        let mut roster_removal =
            tokio::spawn(
                async move { db::delete_roster(&roster_pool, owner_id, &roster_jid).await },
            );
        let config_pool = pool.clone();
        let config_node = node.clone();
        let mut restricted_config = config.clone();
        restricted_config.access_model = "whitelist".to_owned();
        restricted_config.access_whitelist.clear();
        let mut access_change = tokio::spawn(async move {
            db::update_pep_node_config(&config_pool, owner_id, &config_node, &restricted_config)
                .await
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
}
