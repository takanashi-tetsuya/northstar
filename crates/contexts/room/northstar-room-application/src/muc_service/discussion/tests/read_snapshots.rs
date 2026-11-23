use super::*;
use northstar_room_core::occupancy::MucOccupantRoute;

impl MucReadRepository for Repository {
    unused_ports! {
        read_room(localpart: &str) -> Option<MucRoomRead>;
        room_view(localpart: &str, viewer: MucRoomViewer<'_>, kind: MucRoomViewKind) -> MucRoomView;
        owner_form(localpart: &str, viewer: MucManagementViewer<'_>, local_domain: &str) -> MucAdminSnapshot<MucRoomRead>;
        admin_list(localpart: &str, viewer: MucManagementViewer<'_>, local_domain: &str, kind: MucAdminListKind<'_>) -> MucAdminSnapshot<MucAdminList>;
        occupant_iq(localpart: &str, sender: Option<MucOccupancyProof<'_>>, target_nick: &str, node_id: &str, federated_viewer: Option<&str>) -> MucOccupantIqView;
        refresh_muc_occupant_activity(localpart: &str, proof: MucOccupancyProof<'_>) -> Option<MucOccupantRoute>;
    }
}
