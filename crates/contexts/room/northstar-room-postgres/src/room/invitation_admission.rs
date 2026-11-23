use super::{PostgresMucRepository, RoomEffects};
use crate::{
    cluster_muc::{locked_federated_mediated_invite, LockedMediatedInviteMode},
    muc::{
        grant_federated_muc_invite_affiliation_in_transaction, lock_federated_invitee,
        FederatedMucInviteAffiliationOutcome,
    },
};
use anyhow::Result;
use northstar_room_application::muc_service::{
    FederatedMediatedInvitation, FederatedMediatedInvitationOutcome, LocalMediatedInvitation,
    LocalMediatedInvitationOutcome, MucInvitationAdmissionRepository,
};

impl<E: RoomEffects> MucInvitationAdmissionRepository for PostgresMucRepository<E> {
    async fn admit_local_mediated_invitation(
        &self,
        request: LocalMediatedInvitation<'_>,
    ) -> Result<LocalMediatedInvitationOutcome> {
        let authority = request.authority.into();
        crate::muc::admit_local_muc_invite_inner(
            &self.effects,
            &self.pool,
            request.authority.operation_id,
            request.room_id,
            request.recipient_id,
            request.recipient_bare_jid,
            request.room_jid,
            request.grant_stanza,
            false,
            request.policy,
            Some(&authority),
            Some(&request),
        )
        .await
    }

    async fn admit_federated_mediated_invitation(
        &self,
        request: FederatedMediatedInvitation<'_>,
    ) -> Result<FederatedMediatedInvitationOutcome> {
        use FederatedMediatedInvitationOutcome as Outcome;
        let mut authority: crate::cluster_muc::ClusterMucInviteAuthority = request.authority.into();
        let mut enqueue_grant = false;
        for _attempt in 0..3 {
            let mut transaction = self.pool.begin().await?;
            if enqueue_grant {
                self.effects
                    .enqueue_federated_stanza(
                        &mut transaction,
                        request.target_domain,
                        request.stanza,
                        Some(request.bounce_to),
                        request.policy,
                    )
                    .await?;
            }
            lock_federated_invitee(&mut transaction, request.room_id, request.invitee_bare_jid)
                .await?;
            let mode =
                locked_federated_mediated_invite(&mut transaction, request.room_id, &authority)
                    .await?;
            match mode {
                LockedMediatedInviteMode::Open if !enqueue_grant => {
                    transaction.commit().await?;
                    return Ok(Outcome::Open);
                }
                LockedMediatedInviteMode::Open => {
                    transaction.rollback().await?;
                    enqueue_grant = false;
                }
                LockedMediatedInviteMode::Grant(_) if !request.grant_available => {
                    transaction.rollback().await?;
                    return Ok(Outcome::GrantUnavailable);
                }
                LockedMediatedInviteMode::Grant(_) if !enqueue_grant => {
                    transaction.rollback().await?;
                    enqueue_grant = true;
                }
                LockedMediatedInviteMode::Grant(version) => {
                    authority.expected_config_version = version;
                    let affiliation = grant_federated_muc_invite_affiliation_in_transaction(
                        &mut transaction,
                        request.room_id,
                        request.invitee_bare_jid,
                        Some(&authority),
                    )
                    .await?;
                    if matches!(affiliation, FederatedMucInviteAffiliationOutcome::Stored) {
                        transaction.commit().await?;
                        return Ok(Outcome::Granted);
                    }
                    transaction.rollback().await?;
                    return Ok(match affiliation {
                        FederatedMucInviteAffiliationOutcome::Replay => Outcome::Granted,
                        FederatedMucInviteAffiliationOutcome::Rejected => Outcome::Rejected,
                        FederatedMucInviteAffiliationOutcome::Stale => Outcome::Stale,
                        FederatedMucInviteAffiliationOutcome::Stored => unreachable!(),
                    });
                }
                LockedMediatedInviteMode::Rejected => {
                    transaction.rollback().await?;
                    return Ok(Outcome::Rejected);
                }
                LockedMediatedInviteMode::Stale => {
                    transaction.rollback().await?;
                    return Ok(Outcome::Stale);
                }
            }
        }
        Ok(Outcome::Stale)
    }
}
