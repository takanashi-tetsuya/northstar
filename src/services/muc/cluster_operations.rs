//! Clustered room mutations, occupancy transitions, administration, and committed-operation wakes.

use super::*;

impl<R: MucRepository> MucService<R> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn mutate_local_cluster_registration(
        &self,
        operation_id: Uuid,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        principal: &ClusterMucPrincipal,
        actor_full_jid: &str,
        reserved_nick: Option<&str>,
    ) -> Result<ClusterMucRegistrationOutcome> {
        self.repository
            .mutate_local_cluster_registration(
                operation_id,
                room_id,
                expected_room_epoch,
                expected_config_version,
                principal,
                actor_full_jid,
                reserved_nick,
            )
            .await
    }

    pub(crate) async fn set_local_cluster_subject(
        &self,
        operation_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        actor: &ClusterMucOccupancyTarget,
        mutation: MucSubjectMutation<'_>,
        archive: bool,
    ) -> Result<ClusterMucTransitionOutcome> {
        self.repository
            .set_local_cluster_subject(
                operation_id,
                expected_room_epoch,
                expected_config_version,
                actor,
                mutation,
                archive,
            )
            .await
    }

    pub(crate) async fn claim_local_cluster_occupancy(
        &self,
        request: ClusterMucJoin<'_>,
    ) -> Result<ClusterMucJoinOutcome> {
        self.repository.claim_local_cluster_occupancy(request).await
    }

    pub(crate) async fn renew_local_cluster_occupancy(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        lease: Duration,
    ) -> Result<bool> {
        self.repository
            .renew_local_cluster_occupancy(target, owner_node_id, lease)
            .await
    }

    pub(crate) async fn refresh_local_cluster_presence(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        presence_payload: &str,
        lease: Duration,
    ) -> Result<bool> {
        self.repository
            .refresh_local_cluster_presence(target, owner_node_id, presence_payload, lease)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn transition_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        transition: &str,
        owner_node_id: &str,
        new_connection_uuid: Option<Uuid>,
        new_connection_epoch: Option<i64>,
        sm_session_id: Option<Uuid>,
        lease: Duration,
    ) -> Result<ClusterMucTransitionOutcome> {
        self.repository
            .transition_local_cluster_occupancy(
                operation_id,
                target,
                transition,
                owner_node_id,
                new_connection_uuid,
                new_connection_epoch,
                sm_session_id,
                lease,
            )
            .await
    }

    pub(crate) async fn rebind_federated_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        authenticated_domain: &str,
        new_connection_uuid: Uuid,
        lease: Duration,
    ) -> Result<ClusterMucTransitionOutcome> {
        self.repository
            .rebind_federated_cluster_occupancy(
                operation_id,
                target,
                owner_node_id,
                authenticated_domain,
                new_connection_uuid,
                lease,
            )
            .await
    }

    pub(crate) async fn disconnect_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
    ) -> Result<ClusterMucTransitionOutcome> {
        self.repository
            .disconnect_local_cluster_occupancy(operation_id, target, owner_node_id)
            .await
    }

    pub(crate) async fn rename_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        new_nick: &str,
    ) -> Result<ClusterMucTransitionOutcome> {
        self.repository
            .rename_local_cluster_occupancy(operation_id, target, owner_node_id, new_nick)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn update_local_cluster_config(
        &self,
        operation_id: Uuid,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        actor_target: &ClusterMucOccupancyTarget,
        principal: &ClusterMucPrincipal,
        actor_full_jid: &str,
        config: MucConfigUpdate<'_>,
    ) -> Result<ClusterMucConfigurationOutcome> {
        self.repository
            .update_local_cluster_config(
                operation_id,
                room_id,
                expected_room_epoch,
                expected_config_version,
                actor_target,
                principal,
                actor_full_jid,
                config,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn apply_local_cluster_affiliations_batch(
        &self,
        operation_id: Uuid,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        actor_target: &ClusterMucOccupancyTarget,
        actor: &ClusterMucPrincipal,
        actor_full_jid: &str,
        changes: &[MucAffiliationChange],
    ) -> Result<MucAffiliationBatchOutcome> {
        self.repository
            .apply_local_cluster_affiliations_batch(
                operation_id,
                room_id,
                expected_room_epoch,
                expected_config_version,
                actor_target,
                actor,
                actor_full_jid,
                changes,
            )
            .await
    }

    /// The IQ identity intentionally excludes its items. A changed retry on
    /// the same authenticated stream and IQ id must hit the stored digest and
    /// fail as a conflict, even if a target nick no longer exists.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn apply_local_cluster_admin_batch(
        &self,
        stream_id: Uuid,
        iq_id: &str,
        room_jid: &str,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        actor_target: Option<&ClusterMucOccupancyTarget>,
        actor: &ClusterMucPrincipal,
        actor_full_jid: &str,
        changes: &[MucAdminBatchChange],
    ) -> Result<MucAdminBatchResult> {
        anyhow::ensure!(!iq_id.is_empty() && iq_id.len() <= 256, "invalid MUC IQ id");
        let canonical_room = crate::jid::CanonicalJid::parse_bare(room_jid)?;
        anyhow::ensure!(
            canonical_room.to_string() == room_jid,
            "noncanonical MUC room JID"
        );
        let operation_id = operation_id(&serde_json::json!({
            "kind":"admin_batch","stream":stream_id,"iq_id":iq_id,"room":room_jid,
        }))?;
        let outcome = self
            .repository
            .apply_local_cluster_admin_batch(
                operation_id,
                room_id,
                expected_room_epoch,
                expected_config_version,
                actor_target,
                actor,
                actor_full_jid,
                &self.configured_domain,
                changes,
            )
            .await?;
        Ok(MucAdminBatchResult {
            operation_id,
            outcome,
        })
    }

    pub(crate) async fn kick_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        actor: &ClusterMucOccupancyTarget,
        target: &ClusterMucOccupancyTarget,
        reason: Option<&str>,
    ) -> Result<ClusterMucTransitionOutcome> {
        self.repository
            .kick_local_cluster_occupancy(operation_id, actor, target, reason)
            .await
    }

    pub(crate) async fn change_local_cluster_role(
        &self,
        operation_id: Uuid,
        actor: &ClusterMucOccupancyTarget,
        target: &ClusterMucOccupancyTarget,
        new_role: &str,
        reason: Option<&str>,
    ) -> Result<ClusterMucTransitionOutcome> {
        self.repository
            .change_local_cluster_role(operation_id, actor, target, new_role, reason)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn destroy_local_cluster_room(
        &self,
        operation_id: Uuid,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        actor: Option<&ClusterMucOccupancyTarget>,
        authorization_source: &str,
        actor_jid: Option<&str>,
        alternate_jid: Option<&str>,
        reason: Option<&str>,
    ) -> Result<ClusterMucTransitionOutcome> {
        self.repository
            .destroy_local_cluster_room(
                operation_id,
                room_id,
                expected_room_epoch,
                actor,
                authorization_source,
                actor_jid,
                alternate_jid,
                reason,
            )
            .await
    }

    pub(crate) async fn local_cluster_occupancy_target(
        &self,
        room_id: Uuid,
        occupant_incarnation: Uuid,
        connection_uuid: Uuid,
    ) -> Result<Option<ClusterMucOccupancyTarget>> {
        self.repository
            .local_cluster_occupancy_target(room_id, occupant_incarnation, connection_uuid)
            .await
    }

    pub(crate) async fn local_cluster_occupancy_target_by_nick(
        &self,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        nick: &str,
    ) -> Result<Option<ClusterMucOccupancyTarget>> {
        self.repository
            .local_cluster_occupancy_target_by_nick(room_id, expected_room_epoch, nick)
            .await
    }

    pub(crate) async fn exact_local_cluster_occupancy_snapshot(
        &self,
        target: &ClusterMucOccupancyTarget,
    ) -> Result<Option<ClusterMucOccupancy>> {
        self.repository
            .exact_local_cluster_occupancy_snapshot(target)
            .await
    }

    pub(crate) async fn cluster_room_is_empty(&self, room_id: Uuid) -> Result<bool> {
        self.repository.cluster_room_is_empty(room_id).await
    }

    pub(crate) async fn wake_committed_operation<W: MucWakePort>(
        &self,
        wake: &W,
        operation_id: Uuid,
    ) -> Result<()> {
        notify_committed_operation(
            self.repository.committed_wake(operation_id),
            wake,
            operation_id,
        )
        .await;
        Ok(())
    }
}
