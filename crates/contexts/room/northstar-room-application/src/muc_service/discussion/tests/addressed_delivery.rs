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
        _: &str,
        _: &[MucOccupantRoute],
    ) -> anyhow::Result<Vec<MucOccupantRoute>> {
        panic!("unexpected moderator recipient read")
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
        _: FederatedMediatedInvitation<'_>,
    ) -> anyhow::Result<FederatedMediatedInvitationOutcome> {
        panic!("unexpected federated mediated invitation admission")
    }
}
