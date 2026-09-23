//! Typed administrative intents for the durable operation journal.
use crate::services::api_mutations::{
    AdminMutationAdmission, ApiMutationOutcome, ApiMutationRejection, StoredApiResponse,
};

pub(crate) struct RoomDestructionTarget {
    localpart: String,
    room_jid: String,
}
impl RoomDestructionTarget {
    pub(crate) fn localpart(&self) -> &str {
        &self.localpart
    }
    pub(crate) fn room_jid(&self) -> &str {
        &self.room_jid
    }
}

pub(crate) trait AdminDispatchRepository: Send + Sync {
    fn reload_tls(
        &self,
        admission: AdminMutationAdmission<'_>,
    ) -> impl std::future::Future<Output = anyhow::Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
    fn panic_disconnect(
        &self,
        admission: AdminMutationAdmission<'_>,
    ) -> impl std::future::Future<Output = anyhow::Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
    fn set_island_mode(
        &self,
        admission: AdminMutationAdmission<'_>,
        enabled: bool,
    ) -> impl std::future::Future<Output = anyhow::Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
    fn destroy_room(
        &self,
        admission: AdminMutationAdmission<'_>,
        room: &RoomDestructionTarget,
    ) -> impl std::future::Future<Output = anyhow::Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
    fn broadcast(
        &self,
        admission: AdminMutationAdmission<'_>,
        message: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
}

#[derive(Clone)]
pub(crate) struct AdminDispatchService<R> {
    repository: R,
    domain: String,
}
impl<R: AdminDispatchRepository> AdminDispatchService<R> {
    pub(crate) fn new(repository: R, domain: String) -> Self {
        Self { repository, domain }
    }
    pub(crate) async fn reload_tls(
        &self,
        admission: AdminMutationAdmission<'_>,
    ) -> anyhow::Result<ApiMutationOutcome<StoredApiResponse>> {
        self.repository.reload_tls(admission).await
    }
    pub(crate) async fn panic_disconnect(
        &self,
        admission: AdminMutationAdmission<'_>,
    ) -> anyhow::Result<ApiMutationOutcome<StoredApiResponse>> {
        self.repository.panic_disconnect(admission).await
    }
    pub(crate) async fn set_island_mode(
        &self,
        admission: AdminMutationAdmission<'_>,
        enabled: bool,
    ) -> anyhow::Result<ApiMutationOutcome<StoredApiResponse>> {
        self.repository.set_island_mode(admission, enabled).await
    }
    pub(crate) fn room_target(
        &self,
        localpart: String,
    ) -> Result<RoomDestructionTarget, ApiMutationRejection> {
        let room_jid = format!("{}@conference.{}", localpart, self.domain);
        let canonical = crate::jid::CanonicalJid::parse(&room_jid)
            .map_err(|_| ApiMutationRejection::BadRequest("room localpart is invalid"))?;
        if canonical.resourcepart().is_some()
            || canonical.localpart().is_none()
            || canonical.to_string() != room_jid
        {
            return Err(ApiMutationRejection::BadRequest(
                "room JID is not canonical",
            ));
        }
        Ok(RoomDestructionTarget {
            localpart,
            room_jid,
        })
    }
    pub(crate) async fn destroy_room(
        &self,
        admission: AdminMutationAdmission<'_>,
        room: &RoomDestructionTarget,
    ) -> anyhow::Result<ApiMutationOutcome<StoredApiResponse>> {
        self.repository.destroy_room(admission, room).await
    }
    pub(crate) async fn broadcast(
        &self,
        admission: AdminMutationAdmission<'_>,
        message: &str,
    ) -> anyhow::Result<ApiMutationOutcome<StoredApiResponse>> {
        let message = message.trim();
        if message.is_empty() || message.len() > 32_768 {
            return Ok(ApiMutationOutcome::Rejected(
                ApiMutationRejection::BadRequest("broadcast message must contain 1 to 32768 bytes"),
            ));
        }
        self.repository.broadcast(admission, message).await
    }
}
