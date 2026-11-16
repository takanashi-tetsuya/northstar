//! Root bindings for stream-owned durable SM teardown effects.

use crate::cluster::listener_sm_muc_teardown::ClusterListenerSmMucTeardown;
use crate::cluster::ClusterSmMucTeardown;
use crate::node::{
    adapters::cluster_adapters::PostgresClusterAdapters,
    adapters::session_cleanup_unavailable::SessionCleanupUnavailableAdapters,
    adapters::sm_teardown_muc_projection::SmTeardownMucProjection,
    adapters::sm_teardown_session::SmTeardownSessionEffects, ServerNode,
};
use northstar_room_application::muc_service::SerializableMucOccupant;
use northstar_stream::session_cleanup::sm_teardown::{
    SmTeardownPorts, SmTeardownRuntime, SmTeardownSnapshot,
};
use northstar_workflows::message_repository::PostgresMessageRepository;
use northstar_workflows::sm_teardown_presence_repository::PostgresSmTeardownPresenceRepository;
use uuid::Uuid;

pub(crate) type AppSmTeardownRuntime = SmTeardownRuntime<
    PostgresSmTeardownPresenceRepository,
    PostgresMessageRepository,
    SessionCleanupUnavailableAdapters,
    SmTeardownAdapters,
>;

pub(crate) struct SmTeardownAdapters {
    session: SmTeardownSessionEffects,
    muc_projection: SmTeardownMucProjection,
    muc_cluster: ClusterSmMucTeardown,
    muc_local: ClusterListenerSmMucTeardown<PostgresClusterAdapters>,
}

impl ServerNode {
    pub(crate) fn sm_teardown_runtime(&self) -> AppSmTeardownRuntime {
        let session = self.sm_teardown_session_effects();
        let unavailable = self.session_cleanup_unavailable();
        let local = self.sm_teardown_local_effects();
        SmTeardownRuntime::new(
            unavailable,
            local,
            SmTeardownAdapters {
                session,
                muc_projection: self.sm_teardown_muc_projection(),
                muc_cluster: self.sm_teardown_muc_cluster(),
                muc_local: self.cluster_listener_sm_muc_teardown(),
            },
        )
    }
}

/// Project the workflow-owned lease into the stream renderer's borrowed input.
pub(in crate::node) fn sm_teardown_snapshot(
    snapshot: &northstar_workflows::sm::SmTeardownSnapshot,
) -> SmTeardownSnapshot<'_> {
    SmTeardownSnapshot {
        session_id: snapshot.session_id,
        user_id: snapshot.user_id,
        full_jid: &snapshot.full_jid,
        available: snapshot.available,
        active_privacy_list: snapshot.active_privacy_list.as_deref(),
        joined_rooms: &snapshot.joined_rooms,
        directed_presence: &snapshot.directed_presence,
    }
}

impl SmTeardownPorts for SmTeardownAdapters {
    async fn fence_and_notify(&self, full_jid: &str, sm_session_id: Uuid) -> anyhow::Result<()> {
        self.session.fence_and_notify(full_jid, sm_session_id).await
    }

    async fn occupant(
        &self,
        sm_session_id: Uuid,
        user_id: Uuid,
        full_jid: &str,
        room_jid: &str,
        nick: &str,
    ) -> anyhow::Result<SerializableMucOccupant> {
        self.muc_projection
            .occupant(sm_session_id, user_id, full_jid, room_jid, nick)
            .await
    }

    async fn send_sm_muc_teardown(
        &self,
        room_jid: &str,
        sm_session_id: Uuid,
        occupant: &SerializableMucOccupant,
    ) -> anyhow::Result<()> {
        self.muc_cluster
            .send_sm_muc_teardown(room_jid, sm_session_id, occupant)
            .await
    }

    async fn teardown_exact(
        &self,
        sm_session_id: Uuid,
        occupant: &SerializableMucOccupant,
    ) -> anyhow::Result<usize> {
        self.muc_local.teardown_exact(sm_session_id, occupant).await
    }
}
