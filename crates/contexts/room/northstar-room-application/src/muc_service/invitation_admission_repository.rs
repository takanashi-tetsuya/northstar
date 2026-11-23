use super::{
    ClusterMucInviteAuthority, DurableMucInviteOutcome, FederatedInvitePolicy, MucRepository,
    MucService, OfflineStorePolicy,
};
use anyhow::Result;
use std::future::Future;
use uuid::Uuid;

pub struct LocalMediatedInvitation<'a> {
    pub room_id: Uuid,
    pub recipient_id: Uuid,
    pub recipient_bare_jid: &'a str,
    pub room_jid: &'a str,
    pub grant_stanza: &'a str,
    pub delay_grant_stanza: &'a (dyn Fn() -> String + Sync),
    pub storage_permitted: bool,
    pub grant_available: bool,
    pub policy: OfflineStorePolicy,
    pub authority: &'a ClusterMucInviteAuthority,
}

#[derive(Debug)]
pub enum LocalMediatedInvitationOutcome {
    Open,
    Blocked,
    StorageRequired,
    GrantUnavailable,
    Durable(DurableMucInviteOutcome),
}

pub struct FederatedMediatedInvitation<'a> {
    pub room_id: Uuid,
    pub invitee_bare_jid: &'a str,
    pub target_domain: &'a str,
    pub stanza: &'a str,
    pub bounce_to: &'a str,
    pub grant_available: bool,
    pub policy: FederatedInvitePolicy,
    pub authority: &'a ClusterMucInviteAuthority,
}

#[derive(Debug, Eq, PartialEq)]
pub enum FederatedMediatedInvitationOutcome {
    Open,
    Granted,
    Rejected,
    Stale,
    GrantUnavailable,
}

pub trait MucInvitationAdmissionRepository {
    fn admit_local_mediated_invitation(
        &self,
        request: LocalMediatedInvitation<'_>,
    ) -> impl Future<Output = Result<LocalMediatedInvitationOutcome>> + Send;

    fn admit_federated_mediated_invitation(
        &self,
        request: FederatedMediatedInvitation<'_>,
    ) -> impl Future<Output = Result<FederatedMediatedInvitationOutcome>> + Send;
}

impl<R: MucRepository> MucService<R> {
    pub async fn admit_local_mediated_invitation(
        &self,
        request: LocalMediatedInvitation<'_>,
    ) -> Result<LocalMediatedInvitationOutcome> {
        self.repository
            .admit_local_mediated_invitation(request)
            .await
    }

    pub async fn admit_federated_mediated_invitation(
        &self,
        request: FederatedMediatedInvitation<'_>,
    ) -> Result<FederatedMediatedInvitationOutcome> {
        self.repository
            .admit_federated_mediated_invitation(request)
            .await
    }
}
