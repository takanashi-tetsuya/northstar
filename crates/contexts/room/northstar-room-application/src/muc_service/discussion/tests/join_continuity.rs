use super::*;

impl MucJoinContinuityRepository for Repository {
    unused_ports! {
        commit_muc_join(request: ClusterMucJoin<'_>, projection: MucJoinProjectionRequest<'_>) -> MucJoinCommitOutcome;
        resume_muc_authority(request: SmMucResume<'_>) -> Option<ClusterMucOccupancy>;
    }
}
