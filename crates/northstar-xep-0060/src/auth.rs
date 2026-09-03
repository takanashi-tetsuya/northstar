//! Pure authorization, access model decisions, and item retrieval access checks for XEP-0060.

use crate::error::PubSubError;
use crate::models::{AccessModel, Affiliation, PublishModel, SubscriptionState};

/// Pure access control check for item retrieval operations.
///
/// Implements XEP-0060 Section 6.5.7 rules without database or session dependencies:
/// 1. Outcasts are forbidden unconditionally.
/// 2. If a `subid` is provided, it must match one of the caller's active subscriptions;
///    otherwise `not-acceptable` / `invalid-subid` is returned.
/// 3. If multiple active subscriptions exist and no `subid` is supplied,
///    `bad-request` / `subid-required` is returned.
/// 4. Owners, Publishers, Members, Open access models, or active subscribers are granted access.
/// 5. Otherwise, `closed-node` (whitelist), `not-subscribed` (authorize), or `forbidden` is returned.
pub fn item_retrieval_access(
    access_model: AccessModel,
    affiliation: Option<Affiliation>,
    active_subscription_subids: &[&str],
    supplied_subid: Option<&str>,
) -> Result<(), PubSubError> {
    if affiliation == Some(Affiliation::Outcast) {
        return Err(PubSubError::forbidden());
    }

    if let Some(subid) = supplied_subid {
        if !active_subscription_subids.contains(&subid) {
            return Err(PubSubError::new("not-acceptable", "invalid-subid"));
        }
    } else if active_subscription_subids.len() > 1 {
        return Err(PubSubError::new("bad-request", "subid-required"));
    }

    if matches!(
        affiliation,
        Some(Affiliation::Owner | Affiliation::Publisher | Affiliation::Member)
    ) || access_model == AccessModel::Open
        || !active_subscription_subids.is_empty()
    {
        return Ok(());
    }

    Err(match access_model {
        AccessModel::Whitelist => PubSubError::new("not-allowed", "closed-node"),
        AccessModel::Authorize => PubSubError::new("not-authorized", "not-subscribed"),
        _ => PubSubError::forbidden(),
    })
}

/// Pure decision check for item / node disco retrieval visibility.
pub fn can_retrieve_pure(
    access_model: AccessModel,
    affiliation: Option<Affiliation>,
    is_subscribed: bool,
) -> bool {
    if affiliation == Some(Affiliation::Outcast) {
        return false;
    }
    if access_model == AccessModel::Open {
        return true;
    }
    matches!(
        affiliation,
        Some(Affiliation::Owner | Affiliation::Publisher | Affiliation::Member)
    ) || is_subscribed
}

/// Pure publication authorization check based on node configuration and requester identity.
pub fn can_publish_pure(
    publish_model: PublishModel,
    access_model: AccessModel,
    affiliation: Option<Affiliation>,
    is_subscribed: bool,
) -> bool {
    if affiliation == Some(Affiliation::Outcast) {
        return false;
    }
    if matches!(
        affiliation,
        Some(Affiliation::Owner | Affiliation::Publisher | Affiliation::PublishOnly)
    ) {
        return true;
    }

    match publish_model {
        PublishModel::Open => {
            if access_model == AccessModel::Open {
                true
            } else {
                matches!(affiliation, Some(Affiliation::Member)) || is_subscribed
            }
        }
        PublishModel::Subscribers => is_subscribed,
        PublishModel::Publishers => false,
    }
}

/// Compute the initial subscription state when an entity requests a subscription.
pub fn subscription_initial_state(
    access_model: AccessModel,
    affiliation: Option<Affiliation>,
) -> Result<SubscriptionState, PubSubError> {
    if affiliation == Some(Affiliation::Outcast) {
        return Err(PubSubError::forbidden());
    }

    match access_model {
        AccessModel::Open => Ok(SubscriptionState::Subscribed),
        AccessModel::Whitelist => {
            if matches!(
                affiliation,
                Some(Affiliation::Owner | Affiliation::Publisher | Affiliation::Member)
            ) {
                Ok(SubscriptionState::Subscribed)
            } else {
                Err(PubSubError::new("not-allowed", "closed-node"))
            }
        }
        AccessModel::Authorize => {
            if matches!(
                affiliation,
                Some(Affiliation::Owner | Affiliation::Publisher | Affiliation::Member)
            ) {
                Ok(SubscriptionState::Subscribed)
            } else {
                Ok(SubscriptionState::Pending)
            }
        }
    }
}

/// Helper for presence/policy delivery logic: returns true if suppression was due
/// to active privacy rules rather than absence of online presence.
pub fn pubsub_policy_suppression_is_terminal(
    show_eligible_resources: usize,
    policy_eligible_resources: usize,
) -> bool {
    show_eligible_resources > 0 && policy_eligible_resources == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_retrieval_access_enforces_subid_and_outcast_checks() {
        let subids = ["sub-1", "sub-2"];

        // Multiple subs without subid -> subid-required
        let err = item_retrieval_access(AccessModel::Authorize, None, &subids, None).unwrap_err();
        assert_eq!(err.condition, "bad-request");
        assert_eq!(err.pubsub_condition, Some("subid-required"));

        // Invalid subid -> invalid-subid
        let err = item_retrieval_access(AccessModel::Authorize, None, &subids, Some("sub-x"))
            .unwrap_err();
        assert_eq!(err.condition, "not-acceptable");
        assert_eq!(err.pubsub_condition, Some("invalid-subid"));

        // Valid subid -> OK
        assert!(
            item_retrieval_access(AccessModel::Authorize, None, &subids, Some("sub-1")).is_ok()
        );

        // Outcast -> forbidden
        let err = item_retrieval_access(
            AccessModel::Open,
            Some(Affiliation::Outcast),
            &subids,
            Some("sub-1"),
        )
        .unwrap_err();
        assert_eq!(err.condition, "forbidden");

        // Closed whitelist node without sub or member
        let err = item_retrieval_access(AccessModel::Whitelist, None, &[], None).unwrap_err();
        assert_eq!(err.condition, "not-allowed");
        assert_eq!(err.pubsub_condition, Some("closed-node"));
    }

    #[test]
    fn can_publish_pure_rules() {
        // Outcast can never publish
        assert!(!can_publish_pure(
            PublishModel::Open,
            AccessModel::Open,
            Some(Affiliation::Outcast),
            true
        ));

        // Publisher / Owner / PublishOnly can always publish
        assert!(can_publish_pure(
            PublishModel::Publishers,
            AccessModel::Authorize,
            Some(Affiliation::Publisher),
            false
        ));
        assert!(can_publish_pure(
            PublishModel::Publishers,
            AccessModel::Authorize,
            Some(Affiliation::PublishOnly),
            false
        ));

        // Subscriber on Subscribers model
        assert!(can_publish_pure(
            PublishModel::Subscribers,
            AccessModel::Authorize,
            None,
            true
        ));
        assert!(!can_publish_pure(
            PublishModel::Subscribers,
            AccessModel::Authorize,
            None,
            false
        ));
    }
}
