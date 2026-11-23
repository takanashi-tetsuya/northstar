use crate::ports::MucHost;
use northstar_room_application::muc_service::{
    CommittedRoomRetirement, LocalMucOccupantIdentity, SerializableMucOccupant,
};

pub(crate) fn take_retired_occupants<T>(
    retirement: &CommittedRoomRetirement,
    room_jid: &str,
    mut remove_exact: impl FnMut(LocalMucOccupantIdentity<'_>) -> Option<T>,
) -> Vec<T> {
    retirement
        .occupants
        .iter()
        .filter_map(|occupant| remove_exact(occupant.route.identity(room_jid)))
        .collect()
}

pub(crate) fn remove_retired_muc_memberships(
    host: &impl MucHost,
    room_jid: &str,
    retirement: Option<CommittedRoomRetirement>,
) {
    if let Some(retirement) = retirement {
        for occupant in take_retired_occupants(&retirement, room_jid, |identity| {
            host.remove_local_muc_occupant_exact(identity)
        }) {
            host.remove_live_muc_membership(&SerializableMucOccupant::from(&occupant));
        }
    }
}
