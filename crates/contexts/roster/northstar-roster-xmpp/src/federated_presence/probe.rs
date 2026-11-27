use super::render::presence_probe_status_response;
use crate::{FederatedPresenceHandoff, FederatedPresenceOwnerHost};
use anyhow::Result;
use northstar_federation_core::wire::s2s_stanza_error;
use northstar_roster_application::probe_decision::ProbeStatus;
use northstar_roster_core::PresenceAccount;
use roxmltree::Node;

pub(super) async fn route_inbound_presence_probe(
    state: &impl FederatedPresenceOwnerHost,
    root: Node<'_, '_>,
    recipient: &PresenceAccount,
    recipient_bare: &str,
    handoff: FederatedPresenceHandoff<'_>,
) -> Result<Option<String>> {
    let routes = state
        .capture_federated_presence(handoff.target, recipient)
        .await?;
    let kind = match state
        .handoff_federated_presence(recipient, handoff, &routes)
        .await
    {
        Ok(Some(ProbeStatus::Unavailable)) => "unavailable",
        Ok(Some(ProbeStatus::Unsubscribed)) => "unsubscribed",
        Ok(_) => return Ok(None),
        Err(error) => {
            tracing::warn!(
                ?error,
                target = handoff.target,
                "federated probe handoff failed"
            );
            return Ok(Some(s2s_stanza_error(root, "wait", "resource-constraint")));
        }
    };
    Ok(Some(presence_probe_status_response(
        recipient_bare,
        handoff.sender,
        kind,
        root.attribute("id"),
    )))
}
