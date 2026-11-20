//! Stored authorization facts for service item retrieval.

use crate::PubSubSubscription;
use northstar_time::{DateTime, Utc};
use std::str::FromStr;

/// Apply the supplied XEP-0060 decision to the node's stored policy and all
/// active subscriptions of the requester's bare account, including resources.
/// The policy supplies its own model, affiliation and error types.
pub fn item_retrieval_access<Model, Affiliation, Error>(
    access_model: &str,
    affiliation: Option<&str>,
    subscriptions: &[PubSubSubscription],
    supplied_subid: Option<&str>,
    read_at: DateTime<Utc>,
    decide: impl FnOnce(Model, Option<Affiliation>, &[&str], Option<&str>) -> Result<(), Error>,
) -> Result<(), Error>
where
    Model: FromStr<Err = Error>,
    Affiliation: FromStr<Err = Error>,
{
    let access_model = access_model.parse::<Model>()?;
    let affiliation = affiliation.map(str::parse::<Affiliation>).transpose()?;
    let subids = subscriptions
        .iter()
        .filter(|subscription| subscription.is_active_at(read_at))
        .map(|subscription| subscription.subid.as_str())
        .collect::<Vec<_>>();
    decide(access_model, affiliation, &subids, supplied_subid)
}
