use super::{degraded::degraded_inbound_privacy_uses_default, inbound_message_error};
use crate::ports::FederatedMessageHost;
use anyhow::Result;
use northstar_message_application::messaging::{FullJidFallbackPort, LocalRecipient};
use northstar_stream::local_routes::session::OnlineSession;
use std::ops::ControlFlow::{self, Break, Continue};
use std::sync::atomic::Ordering;

pub(super) struct RecipientPolicy {
    pub(super) privacy_candidates: Vec<(String, OnlineSession)>,
    pub(super) remote_route_exists: bool,
    pub(super) default_privacy_denied: bool,
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
    // Even with a healthy resource route, a statically spoolable message
    // might enter SpoolOnly during its PostgreSQL transaction. Bind that
    // transition to the account-default privacy decision before admission.
    let no_live_route = unfiltered_privacy_candidates == 0 && !remote_route_exists;
    let default_privacy_denied = if degraded_spool_eligible || no_live_route {
        match state
            .message_service()
            .default_recipient_privacy_denies(recipient.id, from)
            .await
        {
            Ok(denied) => denied,
            Err(error) if !no_live_route => {
                tracing::warn!(?error, recipient_id = %recipient.id,
                    "account-default privacy unavailable; S2S message remains live-only");
                true
            }
            Err(error) => return Err(error),
        }
    } else {
        false
    };
    if no_live_route && default_privacy_denied {
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
        privacy_candidates,
        remote_route_exists,
        default_privacy_denied,
    }))
}
