//! The node side of `northstar_muc_xmpp::resume::MucResumeHost`: the room module's live tables, the session table
//! and the cluster's MUC soft-state calls.

use crate::node::*;
use northstar_muc_xmpp::resume::MucResumeHost;

impl MucResumeHost for ServerNode {
    type MucWake = northstar_cluster::ClusterManager;

    fn muc_occupant_table(&self) -> &LocalMucOccupantTable {
        &self.room.muc_occupants
    }

    fn suspended_muc_sessions(&self) -> &DashMap<uuid::Uuid, Arc<SuspendedMucEndpoint>> {
        &self.room.suspended_muc_sessions
    }

    fn local_session_table(&self) -> &LocalSessionTable {
        &self.sessions
    }

    fn muc_cluster_enabled(&self) -> bool {
        self.cluster.is_enabled()
    }

    fn muc_wake(&self) -> &Self::MucWake {
        &self.cluster
    }

    async fn resume_cluster_muc_occupant(
        &self,
        previous: &SerializableMucOccupant,
        resumed: &SerializableMucOccupant,
    ) -> anyhow::Result<bool> {
        self.cluster.resume_muc_occupant(previous, resumed).await
    }

    async fn unregister_cluster_muc_occupant_epoch(
        &self,
        room_jid: &str,
        nick: &str,
        cluster_epoch: uuid::Uuid,
        connection_id: uuid::Uuid,
    ) -> anyhow::Result<bool> {
        self.cluster
            .unregister_muc_occupant_epoch(room_jid, nick, cluster_epoch, connection_id)
            .await
    }

    async fn register_suspended_cluster_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        sm_session_id: uuid::Uuid,
        json: &str,
    ) -> anyhow::Result<bool> {
        self.cluster
            .register_suspended_muc_occupant(room_jid, nick, sm_session_id, json)
            .await
    }
}
