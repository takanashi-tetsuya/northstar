use super::*;

impl ProtocolSession {
    pub(super) async fn handle_muc_unavailable_presence(
        &mut self,
        root: Node<'_, '_>,
        full_jid: String,
        room_jid: String,
    ) -> Result<Action> {
        let Some(joined) = self
            .joined_rooms
            .get(&room_jid)
            .map(|entry| entry.value().clone())
        else {
            return Ok(Action::None);
        };
        let mut local_departure_room = None;
        let local_departure_guard = if self.state.muc_pg_authority_enabled() {
            None
        } else {
            let Some(initial_room) = self
                .state
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await?
            else {
                self.joined_rooms.remove_if(&room_jid, |_, current| {
                    current.cluster_epoch == joined.cluster_epoch
                });
                return Ok(Action::None);
            };
            let guard = self
                .state
                .muc_service()
                .lock_local_room_mutation(initial_room.id)
                .await;
            let Some(refreshed_room) = self
                .state
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await?
            else {
                self.state.remove_local_muc_occupant_exact(
                    crate::state::LocalMucOccupantIdentity {
                        room_jid: &room_jid,
                        nick: &joined.nick,
                        full_jid: &full_jid,
                        connection_id: self.connection_id,
                        cluster_epoch: joined.cluster_epoch,
                    },
                );
                self.joined_rooms.remove_if(&room_jid, |_, current| {
                    current.cluster_epoch == joined.cluster_epoch
                });
                return Ok(Action::None);
            };
            if refreshed_room.room_epoch != initial_room.room_epoch {
                self.state.remove_local_muc_occupant_exact(
                    crate::state::LocalMucOccupantIdentity {
                        room_jid: &room_jid,
                        nick: &joined.nick,
                        full_jid: &full_jid,
                        connection_id: self.connection_id,
                        cluster_epoch: joined.cluster_epoch,
                    },
                );
                self.joined_rooms.remove_if(&room_jid, |_, current| {
                    current.cluster_epoch == joined.cluster_epoch
                });
                return Ok(Action::None);
            }
            local_departure_room = Some(refreshed_room);
            Some(guard)
        };
        let mut clustered_leave = false;
        let mut clustered_event_id = None;
        let mut clustered_room_id = None;
        if self.state.muc_pg_authority_enabled() {
            if let Some(room) = self
                .state
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await?
            {
                clustered_room_id = Some(room.id);
                if let Some(target) = self
                    .state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        joined.cluster_epoch,
                        self.connection_id,
                    )
                    .await?
                {
                    let cluster_operation_id = uuid::Uuid::new_v4();
                    match self
                        .state
                        .muc_service()
                        .transition_local_cluster_occupancy(
                            cluster_operation_id,
                            &target,
                            "leave",
                            self.state.muc_cluster_node_id(),
                            None,
                            None,
                            self.sm.db_id,
                            std::time::Duration::from_secs(90),
                        )
                        .await?
                    {
                        ClusterMucTransitionOutcome::Applied
                        | ClusterMucTransitionOutcome::Replay => {
                            clustered_leave = true;
                            clustered_event_id = Some(cluster_operation_id.to_string());
                        }
                        ClusterMucTransitionOutcome::Stale
                        | ClusterMucTransitionOutcome::Destroyed => {}
                        ClusterMucTransitionOutcome::Conflict
                        | ClusterMucTransitionOutcome::Unauthorized => {
                            return Ok(Action::Send(muc_stanza_error(
                                root,
                                &full_jid,
                                "cancel",
                                "not-acceptable",
                            )));
                        }
                    }
                    if let Err(error) = self
                        .state
                        .wake_committed_muc_operation(cluster_operation_id)
                        .await
                    {
                        tracing::warn!(?error, %room_jid, operation_id=%cluster_operation_id,
                            "MUC leave committed; signed wake failed and PostgreSQL polling will catch up");
                    }
                }
            }
        }
        self.joined_rooms
            .remove_if(&room_jid, |_, current| current == &joined);
        let Some(departed) =
            self.state
                .remove_local_muc_occupant_exact(crate::state::LocalMucOccupantIdentity {
                    room_jid: &room_jid,
                    nick: &joined.nick,
                    full_jid: &full_jid,
                    connection_id: self.connection_id,
                    cluster_epoch: joined.cluster_epoch,
                })
        else {
            return Ok(Action::None);
        };

        let serializable = crate::state::SerializableMucOccupant::from(&departed);
        let locally_empty = self.state.muc_occupants_for(&room_jid).is_empty();
        if locally_empty {
            if let Some(room) = local_departure_room.as_ref() {
                // Keep the room gate until the conditional temporary-room
                // delete commits. A concurrent join cannot otherwise
                // publish an occupant between the empty check and delete.
                self.state
                    .muc_service()
                    .delete_temporary_room(room.id, room.room_epoch, room.config_version)
                    .await?;
            }
        }
        drop(local_departure_guard);
        let removed_globally = self
            .state
            .remove_exact_muc_soft_state(&departed)
            .await
            .unwrap_or(false);
        if locally_empty {
            self.state.leave_cluster_muc_room(&room_jid).await?;
        }
        if !clustered_leave {
            self.state
                .publish_muc_cluster_presence_with_id(
                    &room_jid,
                    &serializable,
                    true,
                    false,
                    root.attribute("id"),
                )
                .await?;
        }
        let remaining = self.state.muc_occupants_for(&room_jid);
        if !clustered_leave {
            for (_, target) in &remaining {
                let presence = muc_presence_stanza(
                    &crate::state::SerializableMucOccupant::from(&departed),
                    &target.full_jid,
                    true,
                    false,
                    false,
                    None,
                    departed.room_non_anonymous || target.role == "moderator",
                );
                let _ = self.state.deliver_to_muc_occupant(target, presence).await;
            }
        }
        let self_presence = muc_presence_stanza(
            &crate::state::SerializableMucOccupant::from(&departed),
            &full_jid,
            true,
            true,
            false,
            root.attribute("id").or(clustered_event_id.as_deref()),
            true,
        );
        let globally_empty = if let Some(room_id) = clustered_room_id {
            self.state
                .muc_service()
                .cluster_room_is_empty(room_id)
                .await?
        } else {
            removed_globally
                && self
                    .state
                    .cached_muc_cluster_occupants(&room_jid)
                    .await?
                    .is_empty()
        };
        if self.state.muc_pg_authority_enabled() && remaining.is_empty() && globally_empty {
            if let Some(room) = self
                .state
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await?
            {
                self.state
                    .muc_service()
                    .delete_temporary_room(room.id, room.room_epoch, room.config_version)
                    .await?;
            }
        }
        Ok(Action::Send(self_presence))
    }
}
