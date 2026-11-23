use super::*;

/// Deliver the latest persisted roster change between `user` and the MIX
/// channel (XEP-0405). The stored change decides whether the item is removed,
/// so `_removed` is unused; a joined membership adds its participant id.
pub async fn push_mix_roster_update(
    state: &Arc<impl MixHost>,
    user: &northstar_room_application::mix_service::MixAccount,
    channel_jid: &str,
    _removed: bool,
) -> Result<()> {
    let Some(change) = state
        .mix_service()
        .latest_roster_change_for_contact(user.id, channel_jid)
        .await?
    else {
        return Ok(());
    };
    let participant_id = if change.removed {
        None
    } else {
        let participant_id = state
            .mix_service()
            .pam_membership(user.id, channel_jid)
            .await?
            .filter(|membership| membership.state == "joined")
            .and_then(|membership| membership.participant_id);
        participant_id
    };
    state
        .deliver_roster_change(user.id, &user.username, &change, participant_id.as_deref())
        .await
}
