//! `AppState` methods for suspended SM MUC endpoints; the endpoint predicates and buffer operations are in `xmpp::local_routes::suspended_muc`.

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
        let _endpoint =
            canonical_suspended_muc_endpoint(&self.suspended_muc_sessions, sm_session_id, proposed);
        for (room_jid, membership) in local_muc_membership_snapshots(memberships) {
            let key = crate::services::xml_util::muc_occupant_key(&room_jid, &membership.nick);
            let serializable = {
                let Some(mut occupant) = self.muc_occupants.get_mut(&key) else {
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
                    let room =
                        db::muc_room(&self.pool, crate::state::localpart(&serializable.room_jid))
                            .await?
                            .context("SM association references a missing MUC room")?;
                    let target = db::cluster_muc_occupancy_target(
                        &self.pool,
                        room.id,
                        serializable.cluster_epoch,
                        serializable.connection_id,
                    )
                    .await?
                    .context("SM association lost its exact MUC occupancy")?;
                    anyhow::ensure!(
                        db::associate_cluster_muc_sm_session(
                            &self.pool,
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

    pub async fn pause_suspended_muc_delivery(
        &self,
        sm_session_id: uuid::Uuid,
    ) -> Vec<Arc<SuspendedMucEndpoint>> {
        let mut endpoints = self
            .muc_occupants
            .iter()
            .filter_map(|occupant| match &occupant.endpoint {
                MucOccupantEndpoint::Suspended(endpoint)
                    if endpoint.sm_session_id == sm_session_id =>
                {
                    Some(Arc::clone(endpoint))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if let Some(endpoint) = self.suspended_muc_sessions.get(&sm_session_id) {
            endpoints.push(Arc::clone(&endpoint));
        }
        let mut seen = HashSet::new();
        endpoints.retain(|endpoint| seen.insert(Arc::as_ptr(endpoint) as usize));
        if let Some(endpoint) = endpoints.first() {
            match self.suspended_muc_sessions.entry(sm_session_id) {
                dashmap::mapref::entry::Entry::Vacant(slot) => {
                    slot.insert(Arc::clone(endpoint));
                }
                dashmap::mapref::entry::Entry::Occupied(_) => {}
            }
        }
        for endpoint in &endpoints {
            let transition_from_live = {
                let mut route = endpoint
                    .route
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if matches!(&*route, SuspendedMucRoute::Live(_)) {
                    *route = SuspendedMucRoute::Transitioning;
                    true
                } else {
                    false
                }
            };
            let mut buffer = endpoint.buffer.lock().await;
            buffer.phase = match buffer.phase.clone() {
                SuspendedMucPhase::Durable
                | SuspendedMucPhase::Collecting
                | SuspendedMucPhase::Resuming
                | SuspendedMucPhase::Sealed => SuspendedMucPhase::Waiting,
                SuspendedMucPhase::Reserved => SuspendedMucPhase::Reserved,
                SuspendedMucPhase::Dormant => SuspendedMucPhase::Waiting,
                SuspendedMucPhase::Waiting
                | SuspendedMucPhase::Committing
                | SuspendedMucPhase::CheckpointOwned => SuspendedMucPhase::Sealed,
            };
            drop(buffer);
            if transition_from_live {
                *endpoint
                    .route
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                    SuspendedMucRoute::Suspended;
            }
            endpoint.changed.notify_waiters();
        }
        endpoints
    }

    /// Install the exact post-finalization replay base. `claim_resume` is only
    /// a preliminary snapshot: acknowledgements may advance before the
    /// PostgreSQL activation CAS returns. Keeping the endpoint in `Waiting`
    /// until this method prevents that stale claim size from opening excess
    /// stanza or byte budget.
    pub async fn begin_suspended_muc_resume(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        base_stanzas: usize,
        base_bytes: usize,
    ) -> bool {
        let mut complete = true;
        let mut seen = HashSet::new();
        for endpoint in endpoints {
            if !seen.insert(Arc::as_ptr(endpoint) as usize) {
                continue;
            }
            let mut buffer = endpoint.buffer.lock().await;
            match buffer.phase.clone() {
                SuspendedMucPhase::Waiting | SuspendedMucPhase::Sealed => {
                    buffer.base_stanzas = base_stanzas;
                    buffer.base_bytes = base_bytes;
                    buffer.phase = SuspendedMucPhase::Resuming;
                }
                SuspendedMucPhase::Reserved => {
                    buffer.base_stanzas = base_stanzas;
                    buffer.base_bytes = base_bytes;
                }
                _ => complete = false,
            }
            drop(buffer);
            endpoint.changed.notify_waiters();
        }
        complete
    }

    pub async fn seal_suspended_muc_endpoints(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        self.sm_suspension_context()
            .seal_suspended_muc_endpoints(endpoints)
            .await
    }

    pub(crate) fn clear_suspended_sm_capacity(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        for endpoint in endpoints {
            endpoint
                .sm_capacity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
    }
}
