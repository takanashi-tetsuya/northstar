use super::*;
use northstar_abuse_policy::ContentIdentityAuthenticators;
pub use northstar_room_core::mix::MixRealJid;
use northstar_room_core::mix::{MixChannelAddress, MixChannelId, MixParticipantNick};

pub struct PreparedMessage {
    pub channel_id: MixChannelId,
    pub actor: MixRealJid,
    pub item_id: Uuid,
    pub children: String,
    pub identity: Option<MixReplayIdentity>,
    pub encrypted: bool,
}

pub struct LockedPublisher {
    pub channel: MixChannelAddress,
    pub nick: Option<MixParticipantNick>,
    pub archive_jid: Option<MixRealJid>,
}

pub type PublicationRenderer = fn(&PreparedMessage, &LockedPublisher) -> Result<String>;

#[derive(Debug, Eq, PartialEq)]
pub enum PublicationOutcome {
    Published(Uuid),
    Replay(Uuid),
    Absent,
    Conflict,
    TooLarge,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MixDeliveryRecipientAuthority {
    Local {
        address: MixRealJid,
        account_id: Uuid,
    },
    Remote(MixRealJid),
}

pub trait MixPublicationRepository: Send + Sync {
    fn publish_message(
        &self,
        message: &PreparedMessage,
        renderer: PublicationRenderer,
        authenticators: Option<&ContentIdentityAuthenticators>,
        observation: Option<&foreground::StoreRequest>,
    ) -> impl std::future::Future<Output = Result<StoreMixMessageAdmission>> + Send;

    fn claimed_recipient_account(
        &self,
        source: northstar_delivery_core::MixDelivery,
        address: &MixRealJid,
    ) -> impl std::future::Future<Output = Result<Option<Uuid>>> + Send;
}

impl<R: MixRepository> MixService<R> {
    pub async fn publish_message(
        &self,
        message: &PreparedMessage,
        renderer: PublicationRenderer,
        observation: Option<&foreground::Observation>,
    ) -> Result<PublicationOutcome> {
        let authenticators = message.identity.as_ref().map(|identity| {
            self.message_identity
                .authenticators(&identity.canonical_semantics)
        });
        let _admission = self.delivery_admission_guard().await;
        let outcome = if let Some(owner) = observation {
            let request = owner.publication_request(message)?;
            let completion = crate::mix::admit_observed(
                &request,
                &self.configured_mix_domain,
                self.repository.publish_message(
                    message,
                    renderer,
                    authenticators.as_ref(),
                    Some(&request),
                ),
            )
            .await
            .map_err(foreground::effect_error)?;
            let (result, wake) = completion.into_wake(owner)?;
            if let Some(wake) = wake {
                wake.invoke(|| self.publish_delivery_local_commit())?;
            }
            result.outcome
        } else {
            let result = self
                .repository
                .publish_message(message, renderer, authenticators.as_ref(), None)
                .await?;
            if matches!(result.outcome, StoreEventOutcome::Stored(_))
                && !result.recipients.is_empty()
            {
                self.publish_delivery_local_commit();
            }
            result.outcome
        };
        Ok(match outcome {
            StoreEventOutcome::Stored(id) => PublicationOutcome::Published(id),
            StoreEventOutcome::Replay(id) => PublicationOutcome::Replay(id),
            StoreEventOutcome::NotParticipant => PublicationOutcome::Absent,
            StoreEventOutcome::Conflict => PublicationOutcome::Conflict,
            StoreEventOutcome::TooLarge => PublicationOutcome::TooLarge,
            StoreEventOutcome::IdentityPolicyChanged => {
                anyhow::bail!("locked MIX publication cannot return stale publisher identity")
            }
        })
    }

    pub async fn outbox_claimed_recipient_account(
        &self,
        source: northstar_delivery_core::MixDelivery,
        address: &MixRealJid,
    ) -> Result<Option<Uuid>> {
        let _permit = self.outbox_db_admission_guard().await;
        self.repository
            .claimed_recipient_account(source, address)
            .await
    }
}
