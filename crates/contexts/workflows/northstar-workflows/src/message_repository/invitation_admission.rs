use super::{durable_target_full_jid, PostgresMessageRepository};
use anyhow::Result;
use northstar_message_application::messaging::{
    invitation_admission::{
        DirectInvitation, DirectInvitationGrant, DirectInvitationOutcome as Outcome,
        DirectInvitationRefusal as Refusal, DirectInvitationRepository,
    },
    LocalRecipient, PersonalMessageDestination,
};
use northstar_message_postgres::personal_history::{
    C2sDeliveryCapacityExceeded, PersonalC2sDeliveryAdmission, PersonalHistoryAdmission,
    PersonalHistoryIdentityConflict, PersonalS2sOutboxAdmission,
};
use northstar_room_postgres::{
    accounts::{self, EnabledAccount},
    muc::{
        self, DirectInvitationMode as Mode, DirectInvitationRoom, DurableMucInviteOutcome,
        FederatedMucInviteAffiliationOutcome,
    },
};
use northstar_roster_application::{CommunicationPolicyQuery, PolicyDirection, PolicySubject};
use northstar_xep_0016::PrivacyStanzaKind;
use northstar_xmpp_types::jid::CanonicalJid;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

impl DirectInvitationRepository for PostgresMessageRepository {
    async fn admit_direct_invitation(
        &self,
        invitation: &DirectInvitation<'_>,
        grant: Option<DirectInvitationGrant<'_>>,
    ) -> Result<Outcome> {
        let actor = CanonicalJid::parse(invitation.actor_jid)?;
        self.validate_local_recipient_authority(&actor.bare())?;
        anyhow::ensure!(
            actor.resourcepart().is_some(),
            "a direct inviter needs an authenticated full JID"
        );
        if invitation.actor.is_some_and(|authority| {
            authority.account_id != invitation.actor_id || authority.full_jid != actor
        }) {
            return Ok(Outcome::Refused(Refusal::Unavailable));
        }
        let invitee = CanonicalJid::parse(invitation.invitee_jid)?;
        let addresses = InvitationAddresses {
            invitation,
            actor,
            invitee,
        };
        match grant {
            None => self.probe_direct_invitation(&addresses).await,
            Some(grant) => self.commit_direct_invitation(&addresses, grant).await,
        }
    }
}

struct InvitationAddresses<'a> {
    invitation: &'a DirectInvitation<'a>,
    actor: CanonicalJid,
    invitee: CanonicalJid,
}

impl InvitationAddresses<'_> {
    async fn lock_accounts(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(bool, Option<EnabledAccount>)> {
        let recipient = match self.invitation.local_recipient_name {
            Some(username) => accounts::find_enabled_user(&mut **tx, username).await?,
            None => None,
        };
        let locked = muc::lock_direct_invitation_accounts(
            tx,
            self.invitation.actor_id,
            &self.actor,
            recipient.as_ref(),
        )
        .await?;
        Ok((locked, recipient))
    }

    async fn mode(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        room: DirectInvitationRoom<'_>,
        recipient_id: Option<Uuid>,
    ) -> Result<Mode> {
        use northstar_roster_postgres::roster::blocking_match_candidates;
        let invitee_bare = self.invitee.bare();
        let sender_candidates = if self.actor.bare() == invitee_bare {
            Vec::new()
        } else {
            blocking_match_candidates(&self.invitee)
        };
        let recipient_candidates =
            if recipient_id.is_none() || recipient_id == Some(self.invitation.actor_id) {
                Vec::new()
            } else {
                blocking_match_candidates(&self.actor)
            };
        muc::locked_direct_invitation_mode(
            tx,
            room,
            self.invitation.actor_id,
            recipient_id,
            &invitee_bare,
            &sender_candidates,
            &recipient_candidates,
        )
        .await
    }

    async fn privacy_denies(&self, tx: &mut Transaction<'_, Postgres>) -> Result<bool> {
        let request = self.invitation;
        let subject = match request.actor {
            Some(actor) => PolicySubject::Connection {
                connection_id: actor.connection_id,
                expects_active: request.active_privacy.is_some(),
            },
            None if request.active_privacy.is_some() => return Ok(true),
            None => PolicySubject::AccountDefault,
        };
        let policy = CommunicationPolicyQuery {
            account_id: request.actor_id,
            expected_auth_generation: request.actor.map(|actor| actor.auth_generation),
            subject,
            peer: request.invitee_jid.to_owned(),
            kind: PrivacyStanzaKind::Message,
            direction: PolicyDirection::Outbound,
            // The locked room-mode read already checks both block directions.
            check_owner_block: false,
            check_peer_block: false,
        };
        let decisions =
            northstar_roster_postgres::privacy::read_communication_policies(&mut **tx, &[policy])
                .await?;
        Ok(!matches!(decisions.as_slice(), [decision] if decision.allows()))
    }
}

impl PostgresMessageRepository {
    async fn probe_direct_invitation(
        &self,
        addresses: &InvitationAddresses<'_>,
    ) -> Result<Outcome> {
        let mut transaction = self.pool.begin().await?;
        let room =
            muc::lock_direct_invitation_namespace(&mut transaction, addresses.invitation.room)
                .await?;
        let (true, recipient) = addresses.lock_accounts(&mut transaction).await? else {
            return Ok(Outcome::Refused(Refusal::Unavailable));
        };
        let recipient = recipient.map(|account| LocalRecipient {
            id: account.id,
            username: account.username,
        });
        let mode = addresses
            .mode(
                &mut transaction,
                room,
                recipient.as_ref().map(|account| account.id),
            )
            .await?;
        let outcome = match mode {
            Mode::Open => Outcome::Open { recipient },
            Mode::MembersOnly {
                room_epoch,
                config_version,
                ..
            } => Outcome::GrantRequired {
                recipient,
                room_epoch,
                config_version,
            },
            refused => return Ok(Outcome::Refused(refusal(refused))),
        };
        if addresses.privacy_denies(&mut transaction).await? {
            return Ok(Outcome::Refused(Refusal::Unavailable));
        }
        if matches!(outcome, Outcome::Open { .. }) {
            transaction.commit().await?;
        } else {
            transaction.rollback().await?;
        }
        Ok(outcome)
    }

    async fn commit_direct_invitation(
        &self,
        addresses: &InvitationAddresses<'_>,
        grant: DirectInvitationGrant<'_>,
    ) -> Result<Outcome> {
        let request = addresses.invitation;
        anyhow::ensure!(
            grant.message.local_actor_id == Some(request.actor_id)
                && grant
                    .message
                    .local_actor_fence
                    .is_none_or(|fence| fence.account_id == request.actor_id),
            "direct invitation projection has a different inviter"
        );
        let identity = grant
            .message
            .identity
            .as_ref()
            .map(|identity| self.db_identity(identity))
            .transpose()?;
        let mut transaction = self.pool.begin().await?;
        if self.cluster.is_some()
            && matches!(
                grant.message.destination,
                PersonalMessageDestination::Local(_)
            )
        {
            northstar_postgres::cluster_lock::lock_direct_spool_instance_claims_in_transaction(
                &mut transaction,
            )
            .await?;
        }
        self.fence_live_invite(&mut transaction).await?;
        let room = muc::lock_direct_invitation_namespace(&mut transaction, request.room).await?;
        let (locked, recipient) = addresses.lock_accounts(&mut transaction).await?;
        if !locked
            || !crate::message_policy::actor_generation_matches(
                &mut transaction,
                grant.message.local_actor_fence,
            )
            .await?
        {
            transaction.rollback().await?;
            return Ok(Outcome::Refused(Refusal::Unavailable));
        }
        let recipient_id = recipient.as_ref().map(|account| account.id);
        let target_full_jid = match grant.message.destination {
            PersonalMessageDestination::Local(delivery) => {
                self.validate_local_recipient_authority(delivery.recipient_bare_jid)?;
                if recipient_id != Some(delivery.recipient_id) {
                    return Ok(Outcome::Refused(Refusal::Unavailable));
                }
                anyhow::ensure!(
                    delivery.sender_jid == request.actor_jid
                        && CanonicalJid::parse_bare(delivery.recipient_bare_jid)?.localpart()
                            == recipient.as_ref().map(|account| account.username.as_str()),
                    "direct invitation local delivery differs from its authority"
                );
                durable_target_full_jid(delivery.stanza)?
            }
            PersonalMessageDestination::Federation(outbox) => {
                anyhow::ensure!(
                    request.local_recipient_name.is_none()
                        && outbox.local_actor_id == request.actor_id
                        && outbox.target_domain == addresses.invitee.domainpart(),
                    "direct invitation outbox address differs from its authority"
                );
                None
            }
        };
        let (local, remote) = match grant.message.destination {
            PersonalMessageDestination::Local(delivery) => (
                Some(PersonalC2sDeliveryAdmission {
                    id: delivery.delivery_id,
                    recipient_id: delivery.recipient_id,
                    recipient_bare_jid: delivery.recipient_bare_jid,
                    local_actor_id: Some(request.actor_id),
                    sender_jid: delivery.sender_jid,
                    stanza: delivery.stanza,
                    target_full_jid: target_full_jid.as_deref(),
                    encrypted: delivery.encrypted,
                    policy: self.offline_policy(false),
                }),
                None,
            ),
            PersonalMessageDestination::Federation(outbox) => (
                None,
                Some(PersonalS2sOutboxAdmission {
                    local_actor_id: request.actor_id,
                    target_domain: outbox.target_domain,
                    stanza: outbox.stanza,
                    bounce_to: outbox.bounce_to,
                    policy: outbox.limits,
                }),
            ),
        };
        let history = crate::personal_history::admit_personal_history_in_transaction(
            &mut transaction,
            identity.as_ref(),
            grant.message.archives,
            remote.as_ref(),
            local.as_ref(),
        )
        .await;
        let history = match history {
            Ok(history) => history,
            Err(error) => {
                transaction.rollback().await?;
                return match self.probe_direct_invitation(addresses).await? {
                    Outcome::GrantRequired { .. } if error.is::<C2sDeliveryCapacityExceeded>() => {
                        Ok(Outcome::Refused(Refusal::Capacity))
                    }
                    Outcome::GrantRequired { .. }
                        if remote.is_some() && error.is::<PersonalHistoryIdentityConflict>() =>
                    {
                        Ok(Outcome::Refused(Refusal::Conflict))
                    }
                    Outcome::GrantRequired { .. } => Err(error),
                    outcome => Ok(outcome),
                };
            }
        };
        if matches!(history, PersonalHistoryAdmission::AccountUnavailable) {
            return Ok(Outcome::Refused(Refusal::Unavailable));
        }
        let (room_id, room_epoch, config_version) =
            match addresses.mode(&mut transaction, room, recipient_id).await? {
                Mode::MembersOnly {
                    room_id,
                    room_epoch,
                    config_version,
                } => (room_id, room_epoch, config_version),
                Mode::Open => {
                    transaction.rollback().await?;
                    return match self.probe_direct_invitation(addresses).await? {
                        Outcome::GrantRequired { .. } => Ok(Outcome::Refused(Refusal::Stale)),
                        outcome => Ok(outcome),
                    };
                }
                refused => return Ok(Outcome::Refused(refusal(refused))),
            };
        if addresses.privacy_denies(&mut transaction).await? {
            return Ok(Outcome::Refused(Refusal::Unavailable));
        }
        if matches!(history, PersonalHistoryAdmission::Replay(_)) {
            self.commit_live_invite(transaction, None).await?;
            return Ok(Outcome::Replay);
        }
        let authority = grant.cluster_authority.map(|authority| {
            let mut authority: northstar_room_postgres::cluster_muc::ClusterMucInviteAuthority =
                authority.into();
            authority.expected_room_epoch = room_epoch;
            authority.expected_config_version = config_version;
            authority
        });
        if let Some(delivery) = local {
            let outcome = muc::grant_local_muc_invite_affiliation_in_transaction(
                &mut transaction,
                delivery.id,
                room_id,
                delivery.recipient_id,
                authority.as_ref(),
            )
            .await?;
            return match outcome {
                DurableMucInviteOutcome::Stored { .. } => {
                    let live_claim_id = self
                        .commit_live_invite(transaction, Some((delivery.recipient_id, delivery.id)))
                        .await?;
                    Ok(Outcome::Granted { live_claim_id })
                }
                DurableMucInviteOutcome::Replay { .. } => Ok(Outcome::Replay),
                DurableMucInviteOutcome::QuotaExceeded => Ok(Outcome::Refused(Refusal::Capacity)),
                DurableMucInviteOutcome::RecipientUnavailable => {
                    Ok(Outcome::Refused(Refusal::Unavailable))
                }
                DurableMucInviteOutcome::Outcast | DurableMucInviteOutcome::AuthorityRejected => {
                    Ok(Outcome::Refused(Refusal::Forbidden))
                }
                DurableMucInviteOutcome::Stale => Ok(Outcome::Refused(Refusal::Stale)),
            };
        }
        let outcome = muc::grant_federated_muc_invite_affiliation_in_transaction(
            &mut transaction,
            room_id,
            &addresses.invitee.bare(),
            authority.as_ref(),
        )
        .await?;
        Ok(match outcome {
            FederatedMucInviteAffiliationOutcome::Stored => {
                self.commit_live_invite(transaction, None).await?;
                Outcome::Granted {
                    live_claim_id: None,
                }
            }
            FederatedMucInviteAffiliationOutcome::Replay => Outcome::Replay,
            FederatedMucInviteAffiliationOutcome::Rejected => Outcome::Refused(Refusal::Forbidden),
            FederatedMucInviteAffiliationOutcome::Stale => Outcome::Refused(Refusal::Stale),
        })
    }
}

fn refusal(mode: Mode) -> Refusal {
    match mode {
        Mode::Forbidden => Refusal::Forbidden,
        Mode::SenderBlocked => Refusal::SenderBlocked,
        Mode::RecipientBlocked => Refusal::Unavailable,
        Mode::Stale => Refusal::Stale,
        Mode::Open | Mode::MembersOnly { .. } => {
            unreachable!("expected a direct invitation refusal")
        }
    }
}
