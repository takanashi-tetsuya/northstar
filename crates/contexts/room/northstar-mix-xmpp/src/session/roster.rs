use super::*;
use northstar_room_application::mix_service::CommittedMixRosterDelta;

/// Route the immutable roster transition through the existing sync/version gates.
pub async fn push_mix_roster_update(
    state: &Arc<impl MixHost>,
    delta: &CommittedMixRosterDelta,
) -> Result<()> {
    debug_assert_eq!(delta.version, delta.change.version);
    let participant_id = committed_annotation(delta);
    state
        .deliver_roster_change(
            delta.account.id,
            &delta.account.username,
            &delta.change,
            participant_id.as_deref(),
        )
        .await
}

fn committed_annotation(delta: &CommittedMixRosterDelta) -> Option<String> {
    delta
        .participant_annotation
        .as_ref()
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests;
