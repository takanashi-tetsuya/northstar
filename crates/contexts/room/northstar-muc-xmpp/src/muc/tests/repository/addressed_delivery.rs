use super::*;
use northstar_room_core::occupancy::MucOccupantRoute;

impl MucAddressedDeliveryRepository for Repository {
    async fn muc_addressed_authority(
        &self,
        _: &str,
        _: MucAddressedRequest<'_>,
    ) -> anyhow::Result<MucAddressedOutcome> {
        panic!("unexpected addressed delivery authority read")
    }

    async fn current_muc_moderators(
        &self,
        room: &str,
        candidates: &[MucOccupantRoute],
    ) -> anyhow::Result<Vec<MucOccupantRoute>> {
        assert_eq!(room, localpart(ROOM_JID));
        assert!(candidates.iter().all(|route| route.nick == "Bob"));
        Ok(candidates.to_vec())
    }
}

impl MucInvitationAdmissionRepository for Repository {
    async fn admit_local_mediated_invitation(
        &self,
        _: LocalMediatedInvitation<'_>,
    ) -> anyhow::Result<LocalMediatedInvitationOutcome> {
        panic!("unexpected mediated invitation admission")
    }

    async fn admit_federated_mediated_invitation(
        &self,
        _: northstar_room_application::muc_service::FederatedMediatedInvitation<'_>,
    ) -> anyhow::Result<northstar_room_application::muc_service::FederatedMediatedInvitationOutcome>
    {
        panic!("unexpected federated mediated invitation admission")
    }
}
