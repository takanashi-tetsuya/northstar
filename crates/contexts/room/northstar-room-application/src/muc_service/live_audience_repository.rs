use crate::{MucDiscussion, MucDiscussionAdmission, MucRetractionMutation, MucRetractionOutcome};
use anyhow::Result;
use northstar_room_core::occupancy::MucOccupantRoute;
use std::{future::Future, sync::Arc};

/// The live routes and their hosting nodes at room admission, not a delivery receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveAudience(Arc<[(String, MucOccupantRoute)]>);

impl LiveAudience {
    pub const LIMIT: usize = 10_000;

    pub fn new(routes: Vec<(String, MucOccupantRoute)>) -> Result<Self> {
        anyhow::ensure!(
            routes.len() <= Self::LIMIT,
            "MUC live audience exceeds its bound"
        );
        anyhow::ensure!(
            routes
                .iter()
                .all(|(node, route)| !node.is_empty() && route.is_exact()),
            "MUC live audience contains an inexact route"
        );
        Ok(Self(routes.into()))
    }

    pub fn routes(&self) -> &[(String, MucOccupantRoute)] {
        &self.0
    }
}

/// No audience is returned for rejected or replayed traffic. Compatibility
/// adapters with process-local authority may also omit it on fresh admission.
#[derive(Debug)]
pub struct DiscussionCommit {
    pub outcome: MucDiscussionAdmission,
    pub audience: Option<LiveAudience>,
}

#[derive(Debug)]
pub struct RetractionCommit {
    pub outcome: MucRetractionOutcome,
    pub audience: Option<LiveAudience>,
}

pub trait MucLiveAudienceRepository: Send + Sync {
    fn admit_live_discussion(
        &self,
        command: &MucDiscussion,
    ) -> impl Future<Output = Result<DiscussionCommit>> + Send;

    fn commit_live_retraction(
        &self,
        mutation: MucRetractionMutation<'_>,
    ) -> impl Future<Output = Result<RetractionCommit>> + Send;
}
