use super::availability::{answer_directed_presence_probe, unsubscribed_probe_response};
use super::{presence_probe_status_response, PresenceSession};
use anyhow::Result;
use northstar_roster_core::PresenceAccount;
use northstar_xmpp_types::jid::CanonicalJid;
use northstar_xmpp_types::jid_text::bare_jid;
use roxmltree::Node;
use std::ops::ControlFlow;

pub(super) async fn route_probe<S: PresenceSession>(
    session: &S,
    root: Node<'_, '_>,
    target_jid: &CanonicalJid,
    canonical_to: &str,
    from: &str,
    target_user: Option<PresenceAccount>,
) -> Result<ControlFlow<Option<String>>> {
    let target_bare = target_jid.bare();
    let probe_id = root.attribute("id");
    if let Some(target) = target_user {
        let requester_bare = bare_jid(from);
        let authorized = session
            .presence_service()
            .roster_subscription(target.id, requester_bare)
            .await?
            .is_some_and(|subscription| matches!(subscription.as_str(), "from" | "both"));
        if authorized {
            if target_jid.resourcepart().is_some() {
                session
                    .presence_answer_full_probe(canonical_to, &target_bare, from, probe_id)
                    .await?;
            } else {
                let local_available = session.presence_has_available_resource(&target_bare);
                let delegated = session
                    .presence_probe_has_remote_owner(&target_bare)
                    .await?;
                session.presence_send_current(&target_bare, from).await;
                if !local_available && !delegated {
                    session.presence_try_send(presence_probe_status_response(
                        &target_bare,
                        from,
                        "unavailable",
                        probe_id,
                    ));
                }
            }
        } else if target_jid.resourcepart().is_some()
            && answer_directed_presence_probe(session, canonical_to, &target_bare, from, probe_id)
                .await?
        {
            return Ok(ControlFlow::Break(None));
        } else {
            session.presence_try_send(unsubscribed_probe_response(&target_bare, from, probe_id));
        }
    } else {
        session.presence_try_send(unsubscribed_probe_response(&target_bare, from, probe_id));
    }
    Ok(ControlFlow::Continue(()))
}
