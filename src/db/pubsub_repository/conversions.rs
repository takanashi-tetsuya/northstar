//! Conversions between the PostgreSQL PubSub/PEP rows and the service-level PubSub types.

use super::*;

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
            db::SubscribeOutcome::InvalidOptions => Self::InvalidOptions,
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
            db::SubscriptionOptionsOutcome::InvalidOptions => Self::InvalidOptions,
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
