use super::*;
use northstar_room_core::mix::MixPamState;

impl MixPamDeliveryRepository for Repository {
    async fn pam_delivery_view(
        &self,
        query: PamDeliveryQuery<'_>,
    ) -> Result<Option<PamDeliveryAuthority>> {
        Ok(self
            .0
            .reflection_membership
            .lock()
            .unwrap()
            .as_ref()
            .filter(|membership| membership.channel_jid == query.channel.as_str())
            .map(|membership| PamDeliveryAuthority {
                account_id: membership.user_id,
                enabled: true,
                state: Some(MixPamState::parse(&membership.state).unwrap()),
                subscriptions: membership.subscriptions.clone(),
                blocked: self.0.reflection_blocked.load(Ordering::SeqCst),
            }))
    }
}

impl Repository {
    pub(super) async fn admit_archive_reflection(
        &self,
        request: VerifiedMixReflection<'_>,
    ) -> Result<ReflectedMixArchiveOutcome> {
        let action = request.authoritative_stanza_id;
        let channel = request.channel.as_str();
        match request.kind {
            MixReflectionKind::Original { recipient } => {
                let query = PamDeliveryQuery {
                    recipient,
                    channel: request.channel,
                };
                let Some(account_id) = self
                    .pam_delivery_view(query)
                    .await?
                    .and_then(|authority| authority.receiving_account(NODE_MESSAGES))
                else {
                    return Ok(ReflectedMixArchiveOutcome::Denied);
                };
                let archive = self
                    .archive_mix_message_once(
                        request.personal_archive_id,
                        account_id,
                        channel,
                        action,
                        request.stanza,
                        request.encrypted,
                        Some(&action.to_string()),
                    )
                    .await?;
                let archive = if self.0.archive_replay.load(Ordering::SeqCst) {
                    SourceArchiveAdmission::Replay(action)
                } else {
                    archive
                };
                Ok(ReflectedMixArchiveOutcome::AdmittedOriginal {
                    account_id,
                    archive,
                })
            }
            MixReflectionKind::Retraction {
                owner_id,
                target_id,
                source_participant,
            } => {
                self.0.record(Call::ReflectedRetraction(
                    owner_id,
                    channel.into(),
                    target_id,
                    action,
                    source_participant.as_str().into(),
                ));
                if self.0.reflection_conflict.load(Ordering::SeqCst) {
                    return Ok(ReflectedMixArchiveOutcome::Conflict);
                }
                let outcome = if self.0.archive_replay.load(Ordering::SeqCst) {
                    SourceArchiveAdmission::Replay(action)
                } else {
                    SourceArchiveAdmission::Stored(request.personal_archive_id)
                };
                Ok(ReflectedMixArchiveOutcome::Archived(outcome))
            }
        }
    }
}
