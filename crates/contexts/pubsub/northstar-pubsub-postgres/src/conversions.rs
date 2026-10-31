//! Conversions between the PostgreSQL PubSub/PEP rows and the service-level PubSub types.

use northstar_pubsub_application::profile::ProfilePublishStatus;
use northstar_pubsub_core::{
    CollectionUpdateOutcome, CollectionVisibleItem, CreateNodeOutcome, DuePubSubDigest,
    OwnerMutationOutcome, PepCreateOutcome, PepItem, PepNodeConfig, PepPresenceSubscription,
    PepPublishOutcome, PepQuotas, PepSubscription, PubSubAffiliation, PubSubConfigOutcome,
    PubSubItem, PubSubSubscription, PubSubSubscriptionOptions, PublishItemsOutcome,
    RetractItemsOutcome, SetAffiliationsOutcome, SetSubscriptionsOutcome, SubscribeOutcome,
    SubscriptionAuthorizationOutcome, SubscriptionOptionsOutcome, UnsubscribeOutcome,
};

impl From<crate::CreateNodeOutcome> for CreateNodeOutcome {
    fn from(value: crate::CreateNodeOutcome) -> Self {
        match value {
            crate::CreateNodeOutcome::Created(_) => Self::Created,
            crate::CreateNodeOutcome::Conflict => Self::Conflict,
            crate::CreateNodeOutcome::QuotaExceeded => Self::QuotaExceeded,
            crate::CreateNodeOutcome::InvalidOptions => Self::InvalidOptions,
            crate::CreateNodeOutcome::Forbidden => Self::Forbidden,
            crate::CreateNodeOutcome::CollectionLimitExceeded => Self::CollectionLimitExceeded,
            crate::CreateNodeOutcome::Cycle => Self::Cycle,
        }
    }
}

impl From<crate::PublishItemsOutcome> for PublishItemsOutcome {
    fn from(value: crate::PublishItemsOutcome) -> Self {
        match value {
            crate::PublishItemsOutcome::Published => Self::Published,
            crate::PublishItemsOutcome::Conflict => Self::Conflict,
            crate::PublishItemsOutcome::QuotaExceeded => Self::QuotaExceeded,
            crate::PublishItemsOutcome::Forbidden => Self::Forbidden,
            crate::PublishItemsOutcome::PreconditionFailed => Self::PreconditionFailed,
        }
    }
}

impl From<crate::RetractItemsOutcome> for RetractItemsOutcome {
    fn from(value: crate::RetractItemsOutcome) -> Self {
        match value {
            crate::RetractItemsOutcome::Retracted => Self::Retracted,
            crate::RetractItemsOutcome::NotFound => Self::NotFound,
            crate::RetractItemsOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<crate::CollectionUpdateOutcome> for CollectionUpdateOutcome {
    fn from(value: crate::CollectionUpdateOutcome) -> Self {
        match value {
            crate::CollectionUpdateOutcome::Updated => Self::Updated,
            crate::CollectionUpdateOutcome::NotFound => Self::NotFound,
            crate::CollectionUpdateOutcome::NotAssociated => Self::NotAssociated,
            crate::CollectionUpdateOutcome::NotCollection => Self::NotCollection,
            crate::CollectionUpdateOutcome::Forbidden => Self::Forbidden,
            crate::CollectionUpdateOutcome::LimitExceeded => Self::LimitExceeded,
            crate::CollectionUpdateOutcome::DepthExceeded => Self::DepthExceeded,
            crate::CollectionUpdateOutcome::Cycle => Self::Cycle,
        }
    }
}

impl From<crate::PubSubConfigOutcome> for PubSubConfigOutcome {
    fn from(value: crate::PubSubConfigOutcome) -> Self {
        match value {
            crate::PubSubConfigOutcome::Updated => Self::Updated,
            crate::PubSubConfigOutcome::Conflict => Self::Conflict,
            crate::PubSubConfigOutcome::NotFound => Self::NotFound,
            crate::PubSubConfigOutcome::InvalidOptions => Self::InvalidOptions,
            crate::PubSubConfigOutcome::Forbidden => Self::Forbidden,
            crate::PubSubConfigOutcome::LimitExceeded => Self::LimitExceeded,
            crate::PubSubConfigOutcome::Cycle => Self::Cycle,
        }
    }
}

impl From<crate::SetSubscriptionsOutcome> for SetSubscriptionsOutcome {
    fn from(value: crate::SetSubscriptionsOutcome) -> Self {
        match value {
            crate::SetSubscriptionsOutcome::Updated(transitions) => Self::Updated(transitions),
            crate::SetSubscriptionsOutcome::LimitExceeded => Self::LimitExceeded,
            crate::SetSubscriptionsOutcome::InvalidSubid => Self::InvalidSubid,
            crate::SetSubscriptionsOutcome::NotFound => Self::NotFound,
            crate::SetSubscriptionsOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<crate::SetAffiliationsOutcome> for SetAffiliationsOutcome {
    fn from(value: crate::SetAffiliationsOutcome) -> Self {
        match value {
            crate::SetAffiliationsOutcome::Updated {
                revoked_subscriptions,
                approved_subscriptions,
            } => Self::Updated {
                revoked_subscriptions,
                approved_subscriptions,
            },
            crate::SetAffiliationsOutcome::LastOwner => Self::LastOwner,
            crate::SetAffiliationsOutcome::NotFound => Self::NotFound,
            crate::SetAffiliationsOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<crate::OwnerMutationOutcome> for OwnerMutationOutcome {
    fn from(value: crate::OwnerMutationOutcome) -> Self {
        match value {
            crate::OwnerMutationOutcome::Applied => Self::Applied,
            crate::OwnerMutationOutcome::NotFound => Self::NotFound,
            crate::OwnerMutationOutcome::Forbidden => Self::Forbidden,
            crate::OwnerMutationOutcome::Invalid => Self::Invalid,
        }
    }
}

impl From<crate::SubscribeOutcome> for SubscribeOutcome {
    fn from(value: crate::SubscribeOutcome) -> Self {
        match value {
            crate::SubscribeOutcome::Subscribed(subscription) => {
                Self::Subscribed(subscription.into())
            }
            crate::SubscribeOutcome::LimitExceeded => Self::LimitExceeded,
            crate::SubscribeOutcome::NotFound => Self::NotFound,
            crate::SubscribeOutcome::Forbidden => Self::Forbidden,
            crate::SubscribeOutcome::ClosedNode => Self::ClosedNode,
            crate::SubscribeOutcome::PreconditionFailed => Self::PreconditionFailed,
            crate::SubscribeOutcome::InvalidOptions => Self::InvalidOptions,
        }
    }
}

impl From<crate::UnsubscribeOutcome> for UnsubscribeOutcome {
    fn from(value: crate::UnsubscribeOutcome) -> Self {
        match value {
            crate::UnsubscribeOutcome::Unsubscribed => Self::Unsubscribed,
            crate::UnsubscribeOutcome::NotFound => Self::NotFound,
            crate::UnsubscribeOutcome::InvalidSubid => Self::InvalidSubid,
            crate::UnsubscribeOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<crate::SubscriptionOptionsOutcome> for SubscriptionOptionsOutcome {
    fn from(value: crate::SubscriptionOptionsOutcome) -> Self {
        match value {
            crate::SubscriptionOptionsOutcome::Updated => Self::Updated,
            crate::SubscriptionOptionsOutcome::NotFound => Self::NotFound,
            crate::SubscriptionOptionsOutcome::InvalidSubid => Self::InvalidSubid,
            crate::SubscriptionOptionsOutcome::InvalidOptions => Self::InvalidOptions,
            crate::SubscriptionOptionsOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<crate::PepNodeConfig> for PepNodeConfig {
    fn from(value: crate::PepNodeConfig) -> Self {
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

impl From<&PepNodeConfig> for crate::PepNodeConfig {
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

impl From<PepQuotas> for crate::PepQuotas {
    fn from(value: PepQuotas) -> Self {
        Self {
            max_nodes: value.max_nodes,
            max_storage_bytes: value.max_storage_bytes,
        }
    }
}

impl From<crate::PepCreateOutcome> for PepCreateOutcome {
    fn from(value: crate::PepCreateOutcome) -> Self {
        match value {
            crate::PepCreateOutcome::Created => Self::Created,
            crate::PepCreateOutcome::Conflict => Self::Conflict,
            crate::PepCreateOutcome::QuotaExceeded => Self::QuotaExceeded,
        }
    }
}

impl From<crate::PepPublishOutcome> for PepPublishOutcome {
    fn from(value: crate::PepPublishOutcome) -> Self {
        match value {
            crate::PepPublishOutcome::Published => Self::Published,
            crate::PepPublishOutcome::PreconditionFailed => Self::PreconditionFailed,
            crate::PepPublishOutcome::MaxItemsExceeded => Self::MaxItemsExceeded,
            crate::PepPublishOutcome::QuotaExceeded => Self::QuotaExceeded,
        }
    }
}

impl From<crate::PepSubscription> for PepSubscription {
    fn from(value: crate::PepSubscription) -> Self {
        Self {
            jid: value.jid,
            subid: value.subid,
        }
    }
}

impl From<crate::PepPresenceSubscription> for PepPresenceSubscription {
    fn from(value: crate::PepPresenceSubscription) -> Self {
        Self {
            owner_id: value.owner_id,
            owner_username: value.owner_username,
            node: value.node,
        }
    }
}

impl From<crate::PepItem> for PepItem {
    fn from(value: crate::PepItem) -> Self {
        Self {
            item_id: value.item_id,
            payload: value.payload,
            updated_at: value.updated_at,
        }
    }
}

impl From<crate::PubSubItem> for PubSubItem {
    fn from(value: crate::PubSubItem) -> Self {
        Self {
            item_id: value.item_id,
            xml_payload: value.xml_payload,
            created_at: value.created_at,
        }
    }
}

impl From<crate::CollectionVisibleItem> for CollectionVisibleItem {
    fn from(value: crate::CollectionVisibleItem) -> Self {
        Self {
            node: value.node,
            xml_payload: value.xml_payload,
        }
    }
}

impl From<crate::PubSubSubscription> for PubSubSubscription {
    fn from(value: crate::PubSubSubscription) -> Self {
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

impl From<&PubSubSubscription> for crate::PubSubSubscription {
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

impl From<crate::PubSubSubscriptionOptions> for PubSubSubscriptionOptions {
    fn from(value: crate::PubSubSubscriptionOptions) -> Self {
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

impl From<&PubSubSubscriptionOptions> for crate::PubSubSubscriptionOptions {
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

impl From<crate::PubSubAffiliation> for PubSubAffiliation {
    fn from(value: crate::PubSubAffiliation) -> Self {
        Self {
            node: value.node,
            jid: value.jid,
            affiliation: value.affiliation,
        }
    }
}

impl From<crate::SubscriptionAuthorizationOutcome> for SubscriptionAuthorizationOutcome {
    fn from(value: crate::SubscriptionAuthorizationOutcome) -> Self {
        match value {
            crate::SubscriptionAuthorizationOutcome::Applied => Self::Applied,
            crate::SubscriptionAuthorizationOutcome::NotFound => Self::NotFound,
            crate::SubscriptionAuthorizationOutcome::Forbidden => Self::Forbidden,
            crate::SubscriptionAuthorizationOutcome::Stale => Self::Stale,
        }
    }
}

impl From<crate::DuePubSubDigest> for DuePubSubDigest {
    fn from(value: crate::DuePubSubDigest) -> Self {
        Self {
            ids: value.ids,
            subscription_node_id: value.subscription_node_id,
            subscriber_jid: value.subscriber_jid,
            event_xml: value.event_xml,
            show_values: value.show_values,
        }
    }
}

impl From<crate::PepPublishOutcome> for ProfilePublishStatus {
    fn from(value: crate::PepPublishOutcome) -> Self {
        match value {
            crate::PepPublishOutcome::Published => Self::Published,
            crate::PepPublishOutcome::PreconditionFailed => Self::PreconditionFailed,
            crate::PepPublishOutcome::MaxItemsExceeded => Self::MaxItemsExceeded,
            crate::PepPublishOutcome::QuotaExceeded => Self::QuotaExceeded,
        }
    }
}
