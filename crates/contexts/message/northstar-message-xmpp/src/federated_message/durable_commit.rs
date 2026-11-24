use super::{
    authoritative_remote_stanza_identity, degraded::inbound_direct_spool_eligibility,
    inbound_message_error,
};
use crate::ports::FederatedMessageHost;
use anyhow::Result;
use northstar_message_application::messaging::{
    ArchiveCandidate, DurableAdmissionOutcome, IdentityAuthority, LocalDelivery, LocalRecipient,
    MessageIdentity, MessagePostCommit, PersonalMessageDestination, ValidatedPersonalMessage,
};
use northstar_message_core::{DirectDeliveryMode, DirectPostCommitMode};
use northstar_xml_builder::message_policy::add_delay_from;
use std::ops::ControlFlow::{self, Break, Continue};
use uuid::Uuid;

#[expect(
    clippy::too_many_arguments,
    reason = "retain the exact prepared inputs and outer admission state"
)]
pub(super) async fn commit<H: FederatedMessageHost>(
    state: &H,
    root: roxmltree::Node<'_, '_>,
    recipient: &LocalRecipient,
    personal_retraction: bool,
    message_type: &str,
    direct_delivery_mode: DirectDeliveryMode,
    durable_content_allowed: bool,
    persistence_allowed: bool,
    authenticated_domain: &str,
    recipient_bare: &str,
    authoritative_raw: &str,
    annotated: &str,
    candidate: &Option<ArchiveCandidate<'_>>,
    stable_id: Uuid,
    canonical_from: &str,
    encrypted: bool,
    degraded_spool_eligible: bool,
    default_privacy_denied: bool,
    history_committed: &mut bool,
    durable_c2s_delivery: &mut Option<Uuid>,
    live_claim_id: &mut Option<Uuid>,
) -> Result<ControlFlow<Option<String>>> {
    if !personal_retraction
        && matches!(message_type, "normal" | "chat")
        && northstar_message_core::durable_direct_delivery_allowed(
            direct_delivery_mode,
            durable_content_allowed,
        )
    {
        if !persistence_allowed {
            // DirectDeliveryMode::Durable is defined by this condition. Keep
            // this assertion close to the admission boundary so future policy
            // changes cannot accidentally create a non-recoverable write.
            anyhow::bail!("durable inbound message lost its persistence projection");
        }
        let identity_parts = authoritative_remote_stanza_identity(root, authenticated_domain);
        let identity =
            identity_parts
                .as_ref()
                .map(
                    |(actor_scope_raw, actor_scope, identity_value)| MessageIdentity {
                        authority: IdentityAuthority::AuthenticatedRemoteStanza,
                        actor_scope_raw,
                        actor_scope,
                        target_scope: recipient_bare,
                        value: identity_value,
                        payload: authoritative_raw,
                    },
                );
        let delayed = add_delay_from(
            annotated,
            state.message_events().now(),
            Some(state.local_domain()),
        );
        let delivery = ValidatedPersonalMessage {
            local_actor_id: None,
            local_actor_fence: None,
            identity,
            archives: candidate.as_slice(),
            destination: PersonalMessageDestination::Local(LocalDelivery {
                delivery_id: stable_id,
                recipient_id: recipient.id,
                recipient_bare_jid: recipient_bare,
                sender_jid: canonical_from,
                stanza: &delayed,
                encrypted,
            }),
        };
        let eligibility =
            inbound_direct_spool_eligibility(degraded_spool_eligible, default_privacy_denied);
        match state
            .message_service()
            .admit_personal_message_with_mode(&delivery, eligibility)
            .await
            .map(|admitted| (admitted.commit, admitted.mode, admitted.live_claim_id))
        {
            Ok((
                DurableAdmissionOutcome::Stored {
                    archive_written,
                    post_commit,
                },
                post_commit_mode,
                admitted_claim_id,
            )) => {
                *history_committed = archive_written;
                let MessagePostCommit::RouteLocalDelivery { delivery_id, .. } = post_commit else {
                    state.record_s2s_post_accept_failure();
                    tracing::warn!(%stable_id, "committed S2S ingress returned a non-local delivery plan");
                    return Ok(Break(None));
                };
                *durable_c2s_delivery = Some(delivery_id);
                *live_claim_id = admitted_claim_id;
                // A committed spool row has no safe live owner during Redis
                // degradation. A second read covers a mode change after the
                // PostgreSQL commit; neither case may trigger local/cluster
                // routing, Carbons, Push, or an offline fallback.
                if post_commit_mode != DirectPostCommitMode::Live
                    || state.message_service().direct_mode() != DirectPostCommitMode::Live
                {
                    state
                        .message_service()
                        .rearm_unrouted_live_direct(recipient.id, delivery_id, live_claim_id)
                        .await;
                    tracing::debug!(%stable_id, recipient_id = %recipient.id,
                        "S2S direct committed to PostgreSQL spool for recovery");
                    return Ok(Break(None));
                }
            }
            Ok((DurableAdmissionOutcome::Replay, _, _)) => return Ok(Break(None)),
            Ok((DurableAdmissionOutcome::AccountUnavailable, _, _)) => return Ok(Break(None)),
            Err(error) => {
                tracing::warn!(?error, %authenticated_domain, "inbound message history/C2S admission failed atomically");
                return Ok(Break(inbound_message_error(
                    root,
                    "wait",
                    "resource-constraint",
                )));
            }
        }
    }
    Ok(Continue(()))
}
