use super::availability::unsubscribed_probe_response;
use super::PresenceSession;
use crate::exact_presence::ExactPresenceHost;
use anyhow::Result;
use northstar_roster_core::PresenceAccount;
use northstar_xmpp_types::jid::CanonicalJid;
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
    let probe_id = root.attribute("id");
    if let Some(owner) = target_user {
        if let Some(requester) = session.roster_actor() {
            session
                .exact_presence_host()
                .answer_presence_probe(
                    &owner,
                    canonical_to,
                    &requester,
                    session.privacy_active_list(),
                    probe_id,
                )
                .await?;
        }
    } else {
        session.presence_try_send(unsubscribed_probe_response(
            &target_jid.bare(),
            from,
            probe_id,
        ));
    }
    Ok(ControlFlow::Continue(()))
}
