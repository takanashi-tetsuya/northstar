use super::*;
use northstar_room_core::occupancy::MucOccupantRoute;

impl MucReadRepository for Repository {
    async fn owner_form(
        &self,
        localpart: &str,
        viewer: MucManagementViewer<'_>,
        local_domain: &str,
    ) -> Result<MucAdminSnapshot<MucRoomRead>> {
        assert_eq!(
            (localpart, viewer.full_jid, local_domain),
            ("room", SENDER, "local.test")
        );
        self.0.record(Event::Room);
        Ok(MucAdminSnapshot::Stale)
    }

    async fn refresh_muc_occupant_activity(
        &self,
        localpart: &str,
        proof: MucOccupancyProof<'_>,
    ) -> Result<Option<MucOccupantRoute>> {
        assert_eq!(localpart, "room");
        assert_eq!(proof.route.full_jid, SENDER);
        assert_eq!(proof.route.nick, "Alice");
        assert_eq!(proof.route.connection_id, CONNECTION_ID);
        assert_eq!(proof.route.cluster_epoch, OCCUPANT_EPOCH);
        assert_eq!(proof.authenticated_domain, None);
        assert_eq!(proof.node_id, "node-original");
        self.0.record(Event::Renew);
        Ok(Some(proof.route.clone()))
    }

    unused_async! {
        fn read_room(&self, localpart: &str) -> Result<Option<MucRoomRead>>;
        fn room_view(&self, localpart: &str, viewer: MucRoomViewer<'_>, kind: MucRoomViewKind) -> Result<MucRoomView>;
        fn admin_list(&self, localpart: &str, viewer: MucManagementViewer<'_>, local_domain: &str, kind: MucAdminListKind<'_>) -> Result<MucAdminSnapshot<MucAdminList>>;
        fn occupant_iq(&self, localpart: &str, sender: Option<MucOccupancyProof<'_>>, target_nick: &str, node_id: &str, federated_viewer: Option<&str>) -> Result<MucOccupantIqView>;
    }
}
