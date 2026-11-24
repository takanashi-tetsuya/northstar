use super::*;
use northstar_message_application::message_carbons::{
    prepare_received_carbons, prepare_sent_carbons, CarbonDeliveryPort, PreparedCarbonFanout,
};
use northstar_message_application::messaging::{ExactMessageRoute, LocalRecipient};
use uuid::Uuid;

#[expect(
    clippy::too_many_arguments,
    reason = "retain the exact Carbon inputs from the accepted route"
)]
pub(super) async fn prepare<'a, H: MessageHost>(
    state: &H,
    root: Node<'_, '_>,
    local_direct: bool,
    recipient: &LocalRecipient,
    user_id: Uuid,
    delivered_key: Option<CarbonExclusion<'a>>,
    from: &'a str,
    sender_archive: &'a str,
    origin: Option<&'a ExactMessageRoute>,
) -> Option<PreparedCarbonFanout<'a, <H as CarbonDeliveryPort>::Session>> {
    if should_carbon(root)
        && (!local_direct || state.message_service().direct_mode() == DirectPostCommitMode::Live)
    {
        let delivered_self = (recipient.id == user_id).then_some(delivered_key).flatten();
        return prepare_sent_carbons(state, from, sender_archive, delivered_self, None, origin)
            .await;
    }
    None
}

pub(super) async fn prepare_received<'a, H: MessageHost>(
    state: &H,
    root: Node<'_, '_>,
    local_direct: bool,
    recipient: (Uuid, &'a str),
    sender_id: Uuid,
    primary: Option<CarbonExclusion<'a>>,
    forwarded: &'a str,
) -> Option<PreparedCarbonFanout<'a, <H as CarbonDeliveryPort>::Session>> {
    if should_carbon(root)
        && primary.is_some()
        && recipient.0 != sender_id
        && (!local_direct || state.message_service().direct_mode() == DirectPostCommitMode::Live)
    {
        return prepare_received_carbons(state, recipient.1, primary, forwarded, Some(recipient.0))
            .await;
    }
    None
}

pub(super) fn origin(session: &impl MessageSession) -> Option<ExactMessageRoute> {
    let actor = session.message_actor()?;
    Some(ExactMessageRoute {
        full_jid: actor.full_jid.to_string(),
        account_id: actor.account_id,
        auth_generation: actor.auth_generation,
        connection_id: actor.connection_id,
        node_id: None,
        priority: None,
        available: None,
    })
}
