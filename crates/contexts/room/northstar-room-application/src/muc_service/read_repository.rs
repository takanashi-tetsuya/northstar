use super::*;
use northstar_room_core::occupancy::MucOccupantRoute;
use std::future::Future;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucOccupantIdSecretState {
    Present,
    AbsentLegacy,
}

#[derive(Debug)]
pub struct MucRoomRead {
    pub room: MucRoom,
    pub occupant_id_secret_state: MucOccupantIdSecretState,
    pub configuration_expired: bool,
}

#[derive(Clone, Copy)]
pub enum MucReadPrincipal<'a> {
    Local { user_id: Uuid, bare_jid: &'a str },
    Federated { bare_jid: &'a str, domain: &'a str },
}

#[derive(Clone, Copy)]
pub struct MucOccupancyProof<'a> {
    pub route: &'a MucOccupantRoute,
    pub authenticated_domain: Option<&'a str>,
    pub node_id: &'a str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MucRoomViewKind {
    Info { include_mirror: bool },
    ReservedNick,
    Items,
    Registration,
}

#[derive(Clone, Copy)]
pub struct MucRoomViewer<'a> {
    pub full_jid: Option<&'a str>,
    pub principal: Option<MucReadPrincipal<'a>>,
    pub federated: bool,
    pub occupancy: Option<MucOccupancyProof<'a>>,
}

#[derive(Debug)]
pub enum MucRoomView {
    Missing,
    Unauthorized,
    Found {
        room: Box<MucRoomRead>,
        reserved_nick: Option<String>,
        mirror_linked: bool,
        nicks: Vec<String>,
    },
}

#[derive(Clone, Copy)]
pub struct MucManagementViewer<'a> {
    pub principal: MucReadPrincipal<'a>,
    pub full_jid: &'a str,
    pub occupancy: Option<MucOccupancyProof<'a>>,
}

#[derive(Clone, Copy)]
pub enum MucAdminListKind<'a> {
    Role(&'a str),
    Affiliation(&'a str),
    Invalid,
}

pub enum MucAdminList {
    Roles(MucAdminRoleList),
    Affiliations(Vec<MucAdminAffiliationEntry>),
    Invalid,
}

#[derive(Debug)]
pub struct MucOccupantIqView {
    pub room_visible: bool,
    pub sender: Option<MucOccupantRoute>,
    pub target: Option<MucOccupantRoute>,
}

pub trait MucReadRepository {
    fn read_room(
        &self,
        localpart: &str,
    ) -> impl Future<Output = Result<Option<MucRoomRead>>> + Send;
    fn room_view(
        &self,
        localpart: &str,
        viewer: MucRoomViewer<'_>,
        kind: MucRoomViewKind,
    ) -> impl Future<Output = Result<MucRoomView>> + Send;
    fn owner_form(
        &self,
        localpart: &str,
        viewer: MucManagementViewer<'_>,
        local_domain: &str,
    ) -> impl Future<Output = Result<MucAdminSnapshot<MucRoomRead>>> + Send;
    fn admin_list(
        &self,
        localpart: &str,
        viewer: MucManagementViewer<'_>,
        local_domain: &str,
        kind: MucAdminListKind<'_>,
    ) -> impl Future<Output = Result<MucAdminSnapshot<MucAdminList>>> + Send;
    fn occupant_iq(
        &self,
        localpart: &str,
        sender: Option<MucOccupancyProof<'_>>,
        target_nick: &str,
        node_id: &str,
        federated_viewer: Option<&str>,
    ) -> impl Future<Output = Result<MucOccupantIqView>> + Send;
    fn refresh_muc_occupant_activity(
        &self,
        localpart: &str,
        proof: MucOccupancyProof<'_>,
    ) -> impl Future<Output = Result<Option<MucOccupantRoute>>> + Send;
}

impl<R: MucRepository> MucService<R> {
    pub async fn read_room(&self, localpart: &str) -> Result<Option<MucRoomRead>> {
        self.repository.read_room(localpart).await
    }

    pub async fn room_view(
        &self,
        localpart: &str,
        viewer: MucRoomViewer<'_>,
        kind: MucRoomViewKind,
    ) -> Result<MucRoomView> {
        self.repository.room_view(localpart, viewer, kind).await
    }

    pub async fn owner_form(
        &self,
        localpart: &str,
        viewer: MucManagementViewer<'_>,
    ) -> Result<MucAdminSnapshot<MucRoomRead>> {
        self.repository
            .owner_form(localpart, viewer, &self.configured_domain)
            .await
    }

    pub async fn admin_list(
        &self,
        localpart: &str,
        viewer: MucManagementViewer<'_>,
        kind: MucAdminListKind<'_>,
    ) -> Result<MucAdminSnapshot<MucAdminList>> {
        self.repository
            .admin_list(localpart, viewer, &self.configured_domain, kind)
            .await
    }

    pub async fn occupant_iq(
        &self,
        localpart: &str,
        sender: Option<MucOccupancyProof<'_>>,
        target_nick: &str,
        node_id: &str,
        federated_viewer: Option<&str>,
    ) -> Result<MucOccupantIqView> {
        self.repository
            .occupant_iq(localpart, sender, target_nick, node_id, federated_viewer)
            .await
    }

    pub async fn refresh_muc_occupant_activity(
        &self,
        localpart: &str,
        proof: MucOccupancyProof<'_>,
    ) -> Result<Option<MucOccupantRoute>> {
        self.repository
            .refresh_muc_occupant_activity(localpart, proof)
            .await
    }
}
