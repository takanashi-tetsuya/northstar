use super::*;
use northstar_message_application::messaging::LocalRecipient;
use uuid::Uuid;

#[expect(
    clippy::too_many_arguments,
    reason = "retain the exact Carbon inputs from the accepted route"
)]
pub(super) async fn send<H: MessageHost>(
    state: &H,
    root: Node<'_, '_>,
    local_direct: bool,
    recipient: &LocalRecipient,
    user_id: Uuid,
    delivered_key: &Option<String>,
    from: &str,
    sender_archive: &str,
) {
    if should_carbon(root)
        && (!local_direct || state.message_service().direct_mode() == DirectPostCommitMode::Live)
    {
        let delivered_self = (recipient.id == user_id)
            .then_some(delivered_key.as_deref())
            .flatten();
        send_sent_carbons(state, from, sender_archive, delivered_self, None).await;
    }
}
