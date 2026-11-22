//! Sparse subscription forms and decisions evaluated against locked state.

use crate::{
    PubSubSubscribeOutcome, PubSubSubscribePolicy, PubSubSubscription, PubSubSubscriptionOptions,
};
use northstar_time::{DateTime, Utc};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionLeasePatch {
    Clear,
    Until(DateTime<Utc>),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubscriptionOptionsPatch {
    pub deliver: Option<bool>,
    pub digest: Option<bool>,
    pub digest_frequency: Option<i32>,
    pub include_body: Option<bool>,
    pub show_values: Option<Vec<String>>,
    pub subscription_type: Option<String>,
    /// `Some(None)` is the submitted depth `all`.
    pub subscription_depth: Option<Option<i32>>,
    pub expire: Option<SubscriptionLeasePatch>,
}

impl SubscriptionOptionsPatch {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    pub fn apply_to(&self, base: &PubSubSubscriptionOptions) -> PubSubSubscriptionOptions {
        PubSubSubscriptionOptions {
            deliver: self.deliver.unwrap_or(base.deliver),
            digest: self.digest.unwrap_or(base.digest),
            digest_frequency: self.digest_frequency.unwrap_or(base.digest_frequency),
            include_body: self.include_body.unwrap_or(base.include_body),
            show_values: self
                .show_values
                .as_ref()
                .unwrap_or(&base.show_values)
                .clone(),
            subscription_type: self
                .subscription_type
                .as_ref()
                .unwrap_or(&base.subscription_type)
                .clone(),
            subscription_depth: self.subscription_depth.unwrap_or(base.subscription_depth),
            expire: match self.expire {
                None => base.expire,
                Some(SubscriptionLeasePatch::Clear) => None,
                Some(SubscriptionLeasePatch::Until(expire)) => Some(expire),
            },
        }
    }
}

/// The request's optional echo of the stored subscription identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestedSubId<'a>(pub Option<&'a str>);

impl RequestedSubId<'_> {
    pub fn matches(self, stored: &str) -> bool {
        self.0.is_none_or(|requested| requested == stored)
    }
}

pub enum PubSubSubscribeDecision {
    Reply(PubSubSubscribeOutcome),
    Write(&'static str),
}

impl PubSubSubscribePolicy {
    pub fn subscription_decision(
        self,
        existing: Option<&PubSubSubscription>,
        options_submitted: bool,
        now: DateTime<Utc>,
    ) -> PubSubSubscribeDecision {
        use PubSubSubscribeDecision::{Reply, Write};
        if self == Self::Forbidden {
            return Reply(PubSubSubscribeOutcome::Forbidden);
        }
        if let Some(existing) = existing {
            if existing.state == "pending" {
                return Reply(PubSubSubscribeOutcome::PendingSubscription);
            }
            if existing.is_active_at(now) && !options_submitted {
                return Reply(PubSubSubscribeOutcome::ExistingActive(existing.clone()));
            }
        }
        match self {
            Self::Subscribed => Write("subscribed"),
            Self::Pending => Write("pending"),
            Self::ClosedNode => Reply(PubSubSubscribeOutcome::ClosedNode),
            Self::Forbidden => Reply(PubSubSubscribeOutcome::Forbidden),
        }
    }
}

#[cfg(test)]
mod tests;
