use super::*;
use northstar_abuse_policy::ContentIdentityAuthenticators;
use northstar_room_core::mix::MixRealJid;

impl<E: RoomEffects> MixPublicationRepository for PostgresMixRepository<E> {
    async fn publish_message(
        &self,
        message: &PreparedMessage,
        renderer: PublicationRenderer,
        authenticators: Option<&ContentIdentityAuthenticators>,
        observation: Option<&foreground::StoreRequest>,
    ) -> Result<StoreMixMessageAdmission> {
        let identity = message
            .identity
            .as_ref()
            .zip(authenticators)
            .map(|(identity, keys)| {
                let primary = keys.primary();
                crate::mix::MixBusinessIdentity {
                    client_id: &identity.client_id,
                    semantic_key_id: primary.key_id(),
                    semantic_mac: primary.mac(),
                }
            });
        let admission = crate::mix::publish_message(
            &self.pool,
            message,
            renderer,
            identity,
            &MixPayloads,
            observation,
        )
        .await?;
        let outcome = match admission.outcome {
            crate::mix::StoreEventOutcome::Existing(existing) => {
                let exact = authenticators.is_some_and(|keys| {
                    existing.target_id.is_none()
                        && keys.verifies(&existing.semantic_key_id, &existing.semantic_mac)
                });
                if let Some(request) = observation {
                    request.authenticated(
                        &crate::mix::foreground_existing(&existing),
                        if exact {
                            MixBusinessReplay::Replay(existing.authoritative_id)
                        } else {
                            MixBusinessReplay::Conflict
                        },
                    )?;
                }
                if exact {
                    StoreEventOutcome::Replay(existing.authoritative_id)
                } else {
                    StoreEventOutcome::Conflict
                }
            }
            outcome => store_event_outcome(outcome),
        };
        Ok(StoreMixMessageAdmission {
            outcome,
            recipients: admission.recipients,
        })
    }

    async fn claimed_recipient_account(
        &self,
        source: northstar_delivery_core::MixDelivery,
        address: &MixRealJid,
    ) -> Result<Option<Uuid>> {
        crate::mix::claimed_recipient_account(&self.pool, source, address).await
    }
}
