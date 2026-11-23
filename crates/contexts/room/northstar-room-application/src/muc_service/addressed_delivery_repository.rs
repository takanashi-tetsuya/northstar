use anyhow::Result;
use northstar_room_core::occupancy::MucOccupantRoute;
use std::future::Future;
use uuid::Uuid;

use super::{MucRepository, MucService};

#[derive(Clone, Copy)]
pub enum MucAddressedActor<'a> {
    Local {
        account_id: Uuid,
        full_jid: &'a str,
        connection_id: Uuid,
        occupant_incarnation: Uuid,
    },
    Federated {
        authenticated_domain: &'a str,
        full_jid: &'a str,
    },
}

#[derive(Clone, Copy)]
pub enum MucAddressedRequest<'a> {
    Private {
        actor: MucAddressedActor<'a>,
        nick: &'a str,
    },
    Decline {
        nick: Option<&'a str>,
    },
    Voice {
        actor: MucAddressedActor<'a>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum MucAddressedOutcome {
    MissingRoom,
    NotJoined,
    NotAuthorized,
    Forbidden,
    Private {
        sender_nick: String,
        sender_occupant_id: String,
        target: Option<MucOccupantRoute>,
    },
    Decline {
        target: Option<MucOccupantRoute>,
    },
    Voice {
        requester: MucOccupantRoute,
        moderators: Vec<MucOccupantRoute>,
    },
}

pub trait MucAddressedDeliveryRepository: Send + Sync {
    fn muc_addressed_authority(
        &self,
        room_localpart: &str,
        request: MucAddressedRequest<'_>,
    ) -> impl Future<Output = Result<MucAddressedOutcome>> + Send;

    fn current_muc_moderators(
        &self,
        room_localpart: &str,
        candidates: &[MucOccupantRoute],
    ) -> impl Future<Output = Result<Vec<MucOccupantRoute>>> + Send;
}

impl<R: MucRepository> MucService<R> {
    pub async fn muc_addressed_authority(
        &self,
        room_localpart: &str,
        request: MucAddressedRequest<'_>,
    ) -> Result<MucAddressedOutcome> {
        self.repository
            .muc_addressed_authority(room_localpart, request)
            .await
    }

    pub async fn current_muc_moderators(
        &self,
        room_localpart: &str,
        candidates: &[MucOccupantRoute],
    ) -> Result<Vec<MucOccupantRoute>> {
        self.repository
            .current_muc_moderators(room_localpart, candidates)
            .await
    }
}
