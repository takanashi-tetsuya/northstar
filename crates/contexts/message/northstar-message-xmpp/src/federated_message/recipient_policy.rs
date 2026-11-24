use super::{degraded::degraded_inbound_privacy_uses_default, inbound_message_error};
use crate::ports::FederatedMessageHost;
use anyhow::Result;
use northstar_message_application::messaging::{FullJidFallbackPort, LocalRecipient};
use std::ops::ControlFlow::{self, Break, Continue};
use std::sync::atomic::Ordering;

pub(super) struct RecipientPolicy {
    pub(super) privacy_selections: Vec<northstar_message_core::PrivacySelection>,
    pub(super) remote_route_exists: bool,
}

#[expect(
    clippy::too_many_arguments,
    reason = "retain the inbound policy inputs at the existing decision point"
)]
pub(super) async fn select<H: FederatedMessageHost>(
    state: &H,
    root: roxmltree::Node<'_, '_>,
    from: &str,
    to: &str,
    recipient: &LocalRecipient,
    message_type: &str,
    bare_target: bool,
    degraded_spool_eligible: bool,
) -> Result<ControlFlow<Option<String>, RecipientPolicy>> {
    if bare_target {
        match northstar_message_core::bare_message_route(message_type) {
            northstar_message_core::BareMessageRoute::Reject => {
                return Ok(Break(inbound_message_error(
                    root,
                    "cancel",
                    "service-unavailable",
                )));
            }
            northstar_message_core::BareMessageRoute::Ignore => return Ok(Break(None)),
            northstar_message_core::BareMessageRoute::Primary
            | northstar_message_core::BareMessageRoute::All => {}
        }
    }
    // Resolve local per-resource privacy policy before any archive or delivery
    // admission.  A resource's active list replaces the account default; if
    // there is no online route, the durable default governs offline storage.
    // A degraded node cannot trust cached sessions or a Redis route to choose
    // a resource policy, so use the account default for the spool admission.
    let Some(spool_only_privacy) = degraded_inbound_privacy_uses_default(
        state.message_service().direct_mode(),
        degraded_spool_eligible,
    ) else {
        return Ok(Break(inbound_message_error(
            root,
            "wait",
            "service-unavailable",
        )));
    };
    let mut privacy_candidates = if spool_only_privacy {
        Vec::new()
    } else {
        state.session_entries_for(to)
    };
    if bare_target {
        privacy_candidates.retain(|(_, session)| {
            session.available.load(Ordering::Relaxed)
                && session.priority.load(Ordering::Relaxed) >= 0
        });
    }
    let unfiltered_privacy_candidates = privacy_candidates.len();
    let mut privacy_allowed = false;
    for (_, target) in &privacy_candidates {
        if FullJidFallbackPort::privacy_allows_fallback(state, target, from).await? {
            privacy_allowed = true;
            break;
        }
    }
    if unfiltered_privacy_candidates > 0 && !privacy_allowed {
        return Ok(Break(inbound_message_error(
            root,
            "cancel",
            "service-unavailable",
        )));
    }
    let remote_route_exists =
        !spool_only_privacy && state.s2s_remote_recipient_route_exists(to).await;
    let no_live_route = unfiltered_privacy_candidates == 0 && !remote_route_exists;
    if no_live_route
        && state
            .message_service()
            .default_recipient_privacy_denies(recipient.id, from)
            .await?
    {
        return Ok(Break(inbound_message_error(
            root,
            "cancel",
            "service-unavailable",
        )));
    }
    // Deterministic full-resource failure is still a truthful stanza error
    // before admission. After the durable transaction commits, the same
    // condition can only be a routing race and must be recovered from the
    // resource-affine outbox without returning an error.
    if !bare_target && unfiltered_privacy_candidates == 0 && !remote_route_exists {
        match northstar_message_core::full_no_match_route(message_type) {
            northstar_message_core::FullNoMatchRoute::Ignore => return Ok(Break(None)),
            northstar_message_core::FullNoMatchRoute::Reject => {
                return Ok(Break(inbound_message_error(
                    root,
                    "cancel",
                    "service-unavailable",
                )));
            }
            northstar_message_core::FullNoMatchRoute::FallbackChat => {}
        }
    }
    Ok(Continue(RecipientPolicy {
        privacy_selections: privacy_candidates
            .iter()
            .map(|(_, session)| northstar_message_core::PrivacySelection {
                connection_id: session.connection_id,
                expects_active: session.privacy_active_snapshot().is_some(),
            })
            .collect(),
        remote_route_exists,
    }))
}
