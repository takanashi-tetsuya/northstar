use super::{PostgresMucRepository, RoomEffects};
use crate::cluster_muc::{commit_cluster_muc_join, ClusterJoinCommit};
use anyhow::Result;
use northstar_room_application::muc_service::{
    ClusterMucJoin, ClusterMucOccupancy, MucJoinCommitOutcome, MucJoinContinuityRepository,
    MucJoinProjectionRequest, SmMucResume,
};

impl<E: RoomEffects> MucJoinContinuityRepository for PostgresMucRepository<E> {
    async fn commit_muc_join(
        &self,
        request: ClusterMucJoin<'_>,
        projection: MucJoinProjectionRequest<'_>,
    ) -> Result<MucJoinCommitOutcome> {
        let request = super::conversions::cluster_join_into_db(request);
        Ok(
            match commit_cluster_muc_join(&self.pool, request, Some(projection)).await? {
                ClusterJoinCommit::Committed(projection) => {
                    MucJoinCommitOutcome::Committed(projection)
                }
                ClusterJoinCommit::Claim(outcome) => {
                    MucJoinCommitOutcome::Claim(Box::new((*outcome).into()))
                }
                ClusterJoinCommit::PasswordChanged => MucJoinCommitOutcome::PasswordChanged,
            },
        )
    }

    async fn resume_muc_authority(
        &self,
        request: SmMucResume<'_>,
    ) -> Result<Option<ClusterMucOccupancy>> {
        crate::cluster_muc::resume_cluster_muc_authority(&self.pool, request).await
    }
}
