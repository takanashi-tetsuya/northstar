//! Database adapters for exact occupancy departure and maintenance operations.

use super::*;

impl ClusterMucOccupancyDepartureRepository for PostgresClusterMucOccupancyDepartureRepository {
    #[allow(clippy::too_many_arguments)]
    async fn find_exact_for_disconnect(
        &self,
        room_localpart: &str,
        full_jid: &str,
        nick: &str,
        occupant_incarnation: Uuid,
        connection_uuid: Uuid,
        owner_node_id: &str,
    ) -> Result<Option<ClusterMucOccupancyTarget>> {
        Ok(db::cluster_muc_occupancy_target_for_disconnect(
            &self.pool,
            room_localpart,
            full_jid,
            nick,
            occupant_incarnation,
            connection_uuid,
            owner_node_id,
        )
        .await?
        .map(occupancy_target_from_db))
    }

    async fn leave_exact(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        lease: Duration,
    ) -> Result<ClusterMucTransitionOutcome> {
        Ok(db::transition_cluster_muc_occupancy(
            &self.pool,
            operation_id,
            &target.into(),
            "leave",
            owner_node_id,
            None,
            None,
            None,
            lease,
        )
        .await?
        .into())
    }
}

impl ClusterMucOccupancyMaintenanceRepository for PostgresClusterMucOccupancyMaintenanceRepository {
    async fn authoritative_for_node(
        &self,
        node_id: &str,
    ) -> Result<Vec<ClusterMucOccupancyTarget>> {
        Ok(
            db::authoritative_cluster_muc_occupancies_for_node(&self.pool, node_id)
                .await?
                .into_iter()
                .map(|occupancy| occupancy_target_from_db((&occupancy).into()))
                .collect(),
        )
    }

    async fn resolve_exact_batch(
        &self,
        candidates: &[MucOccupancyLookup],
        owner_node_id: &str,
    ) -> Result<Vec<MucResolvedOccupancy>> {
        let candidates = candidates
            .iter()
            .map(|candidate| db::ClusterMucOccupancyLookup {
                room_localpart: candidate.room_localpart.clone(),
                full_jid: candidate.full_jid.clone(),
                nick: candidate.nick.clone(),
                occupant_incarnation: candidate.occupant_incarnation,
                connection_uuid: candidate.connection_uuid,
            })
            .collect::<Vec<_>>();
        Ok(
            db::resolve_cluster_muc_occupancies_batch(&self.pool, &candidates, owner_node_id)
                .await?
                .into_iter()
                .map(|resolved| MucResolvedOccupancy {
                    room_localpart: resolved.room_localpart,
                    target: occupancy_target_from_db(resolved.target),
                })
                .collect(),
        )
    }

    async fn committed_terminal_exact_batch(
        &self,
        candidates: &[MucOccupancyLookup],
        owner_node_id: &str,
    ) -> Result<Vec<MucOccupancyLookup>> {
        let candidates = candidates
            .iter()
            .map(|candidate| db::ClusterMucOccupancyLookup {
                room_localpart: candidate.room_localpart.clone(),
                full_jid: candidate.full_jid.clone(),
                nick: candidate.nick.clone(),
                occupant_incarnation: candidate.occupant_incarnation,
                connection_uuid: candidate.connection_uuid,
            })
            .collect::<Vec<_>>();
        Ok(db::committed_terminal_cluster_muc_occupancies_batch(
            &self.pool,
            &candidates,
            owner_node_id,
        )
        .await?
        .into_iter()
        .map(|candidate| MucOccupancyLookup {
            room_localpart: candidate.room_localpart,
            full_jid: candidate.full_jid,
            nick: candidate.nick,
            occupant_incarnation: candidate.occupant_incarnation,
            connection_uuid: candidate.connection_uuid,
        })
        .collect())
    }

    async fn renew_exact(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        lease: Duration,
    ) -> Result<bool> {
        let target = target.into();
        db::renew_cluster_muc_occupancy(&self.pool, &target, owner_node_id, lease).await
    }

    async fn renew_exact_batch(
        &self,
        targets: &[ClusterMucOccupancyTarget],
        owner_node_id: &str,
        lease: Duration,
    ) -> Result<Vec<ClusterMucOccupancyTarget>> {
        let targets = targets.iter().map(Into::into).collect::<Vec<_>>();
        Ok(
            db::renew_cluster_muc_occupancies_batch(&self.pool, &targets, owner_node_id, lease)
                .await?
                .into_iter()
                .map(occupancy_target_from_db)
                .collect(),
        )
    }
}
