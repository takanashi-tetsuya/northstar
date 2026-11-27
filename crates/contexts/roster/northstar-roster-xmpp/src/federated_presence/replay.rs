use crate::{
    FederatedPresenceEffect, FederatedPresenceHandoff, FederatedPresenceHost,
    FederatedPresenceOwnerHost,
};
use northstar_roster_application::probe_decision::PresenceRoute;
use northstar_roster_core::PresenceAccount;
use northstar_xml_builder::XmlElement;

pub(super) async fn send_unavailable_presence_to_remote(
    state: &(impl FederatedPresenceHost + FederatedPresenceOwnerHost),
    account: &PresenceAccount,
    handoff: FederatedPresenceHandoff<'_>,
    contact: &str,
    routes: &[PresenceRoute],
) {
    replay(
        state,
        account,
        handoff,
        contact,
        routes,
        Some("unavailable"),
    )
    .await;
}

pub(super) async fn send_current_presence_to_remote(
    state: &(impl FederatedPresenceHost + FederatedPresenceOwnerHost),
    account: &PresenceAccount,
    handoff: FederatedPresenceHandoff<'_>,
    contact: &str,
    routes: &[PresenceRoute],
) {
    replay(state, account, handoff, contact, routes, None).await;
}

async fn replay(
    state: &(impl FederatedPresenceHost + FederatedPresenceOwnerHost),
    account: &PresenceAccount,
    handoff: FederatedPresenceHandoff<'_>,
    contact: &str,
    routes: &[PresenceRoute],
    kind: Option<&str>,
) {
    let stanza = XmlElement::namespaced("presence", "jabber:client")
        .attr("from", contact)
        .attr("to", handoff.target)
        .optional_attr("type", kind)
        .finish();
    let handoff = FederatedPresenceHandoff {
        sender: contact,
        stanza: &stanza,
        effect: FederatedPresenceEffect::Replay,
        ..handoff
    };
    if let Err(error) = state
        .handoff_federated_presence(account, handoff, routes)
        .await
    {
        state.post_accept_failure_telemetry().record_failure();
        tracing::warn!(?error, owner = handoff.target, %contact, "federated subscription replay failed after commit");
    }
}
