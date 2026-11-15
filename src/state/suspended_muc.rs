//! `AppState` methods for suspended SM MUC endpoints that need the cluster or the SM suspension context; the
//! endpoint predicates, pause/resume transitions and buffer operations are in northstar-stream's
//! `local_routes::suspended_muc`.

use super::*;

impl AppState {
    /// Associate MUC occupants which were joined before SM enable with the
    /// newly-created durable stream epoch and update their Redis control
    /// records. This also makes active-session revocation exact and immune to
    /// nick reuse races.
    pub async fn associate_local_muc_sm_session(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        memberships: &DashMap<String, JoinedMucMembership>,
    ) {
        // Install the session-global gate even when the resource has not joined
        // a room yet. Future joins carry `sm_session_id` and therefore route
        // through this same Arc from their first stanza onward.
        let Some(live_sender) = self.sessions.get(full_jid).and_then(|session| {
            (session.connection_id == connection_id).then(|| session.sender.clone())
        }) else {
            tracing::warn!(%full_jid, %connection_id, %sm_session_id,
                "could not install the live SM MUC route gate");
            return;
        };
        let proposed = Arc::new(SuspendedMucEndpoint::new_live(sm_session_id, live_sender));
        let _endpoint = canonical_suspended_muc_endpoint(
            &self.room.suspended_muc_sessions,
            sm_session_id,
            proposed,
        );
        for (room_jid, membership) in local_muc_membership_snapshots(memberships) {
            let key = northstar_room_core::stanza::muc_occupant_key(&room_jid, &membership.nick);
            let serializable = {
                let Some(mut occupant) = self.room.muc_occupants.get_mut(&key) else {
                    continue;
                };
                if !muc_actor_identity_matches(
                    &occupant,
                    full_jid,
                    connection_id,
                    &room_jid,
                    &membership,
                ) {
                    continue;
                }
                occupant.sm_session_id = Some(sm_session_id);
                SerializableMucOccupant::from(&*occupant)
            };
            let encoded = serde_json::to_string(&serializable).unwrap_or_default();
            if self.cluster.is_enabled() {
                let association = async {
                    let room = self
                        .muc_service()
                        .local_room_snapshot(crate::state::localpart(&serializable.room_jid))
                        .await?
                        .context("SM association references a missing MUC room")?;
                    let target = self
                        .muc_service()
                        .local_cluster_occupancy_target(
                            room.id,
                            serializable.cluster_epoch,
                            serializable.connection_id,
                        )
                        .await?
                        .context("SM association lost its exact MUC occupancy")?;
                    anyhow::ensure!(
                        self.muc_service()
                            .associate_local_cluster_sm_session(
                                &target,
                                &self.cluster.node_id,
                                sm_session_id,
                            )
                            .await?,
                        "SM association lost its PG occupancy fence"
                    );
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if let Err(error) = association {
                    tracing::warn!(?error, room=%serializable.room_jid, nick=%serializable.nick,
                        "failed to associate PG-authoritative MUC occupancy with SM epoch");
                }
            }
            if let Err(error) = self
                .cluster
                .register_suspended_muc_occupant(
                    &serializable.room_jid,
                    &serializable.nick,
                    sm_session_id,
                    &encoded,
                )
                .await
            {
                tracing::warn!(?error, room = %serializable.room_jid, nick = %serializable.nick, "failed to associate clustered MUC occupant with SM epoch");
            }
        }
    }

    pub async fn mark_suspended_muc_durable(
        &self,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
    ) -> bool {
        self.sm_suspension_context()
            .mark_suspended_muc_durable(endpoints)
            .await
    }

    pub async fn seal_suspended_muc_endpoints(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        self.sm_suspension_context()
            .seal_suspended_muc_endpoints(endpoints)
            .await
    }
}
