use super::*;

pub struct MucJoinProjectionRequest<'a> {
    pub room_jid: &'a str,
    pub verified_password_hash: Option<&'a str>,
    pub include_history: bool,
    pub history_since: Option<DateTime<Utc>>,
}

pub struct MucJoinProjection {
    pub actor: ClusterMucOccupancy,
    pub occupant_id: String,
    pub non_anonymous: bool,
    pub logging_enabled: bool,
    pub max_occupants: i32,
    pub subject: Option<String>,
    pub subject_changed_at: Option<DateTime<Utc>>,
    pub occupant_id_secret: Vec<u8>,
    pub roster: Vec<SerializableMucOccupant>,
    pub history: Vec<MucMessage>,
}

pub enum MucJoinCommitOutcome {
    Committed(Box<MucJoinProjection>),
    Claim(Box<ClusterMucJoinOutcome>),
    PasswordChanged,
}

pub struct SmMucResume<'a> {
    pub operation_id: Uuid,
    pub target: &'a ClusterMucOccupancyTarget,
    pub owner_node_id: &'a str,
    pub connection_id: Uuid,
    pub sm_session_id: Uuid,
    pub lease: Duration,
}

pub trait MucJoinContinuityRepository {
    fn commit_muc_join(
        &self,
        request: ClusterMucJoin<'_>,
        projection: MucJoinProjectionRequest<'_>,
    ) -> impl std::future::Future<Output = Result<MucJoinCommitOutcome>> + Send;

    fn resume_muc_authority(
        &self,
        request: SmMucResume<'_>,
    ) -> impl std::future::Future<Output = Result<Option<ClusterMucOccupancy>>> + Send;
}

impl<R: MucRepository> MucService<R> {
    pub async fn commit_muc_join(
        &self,
        request: ClusterMucJoin<'_>,
        projection: MucJoinProjectionRequest<'_>,
    ) -> Result<MucJoinCommitOutcome> {
        self.repository.commit_muc_join(request, projection).await
    }

    pub async fn resume_muc_authority(
        &self,
        request: SmMucResume<'_>,
    ) -> Result<Option<ClusterMucOccupancy>> {
        self.repository.resume_muc_authority(request).await
    }
}
