use super::*;

impl MucJoinContinuityRepository for Repository {
    unused_async! {
        fn commit_muc_join(&self, request: ClusterMucJoin<'_>, projection: MucJoinProjectionRequest<'_>) -> Result<MucJoinCommitOutcome>;
        fn resume_muc_authority(&self, request: SmMucResume<'_>) -> Result<Option<ClusterMucOccupancy>>;
    }
}
