//! Suspended MUC endpoints: actor identity checks, buffered delivery, route transitions and SM association.

use super::*;

pub(crate) fn muc_actor_identity_matches(
    occupant: &MucOccupant,
    full_jid: &str,
    connection_id: uuid::Uuid,
    room_jid: &str,
    membership: &JoinedMucMembership,
) -> bool {
    muc_actor_epoch_matches(occupant, full_jid, connection_id, room_jid, membership)
        && matches!(occupant.endpoint, MucOccupantEndpoint::Local(_))
}

pub(super) fn muc_actor_epoch_matches(
    occupant: &MucOccupant,
    full_jid: &str,
    connection_id: uuid::Uuid,
    room_jid: &str,
    membership: &JoinedMucMembership,
) -> bool {
    !connection_id.is_nil()
        && !membership.cluster_epoch.is_nil()
        && occupant.full_jid == full_jid
        && occupant.room_jid == room_jid
        && occupant.nick == membership.nick
        && occupant.connection_id == connection_id
        && occupant.cluster_epoch == membership.cluster_epoch
}

/// Exact-identity removal guard for a suspended occupancy created by the
/// calling restore: a failure path may only ever remove the endpoint it just
/// created, never a concurrent joiner's or a winning resume's occupant.
pub(super) fn suspended_occupant_is_created(
    occupant: &MucOccupant,
    created: &Arc<SuspendedMucEndpoint>,
) -> bool {
    matches!(
        &occupant.endpoint,
        MucOccupantEndpoint::Suspended(endpoint) if Arc::ptr_eq(endpoint, created)
    )
}

pub(super) fn suspended_muc_resume_actor_matches(
    current: &MucOccupant,
    endpoint: &Arc<SuspendedMucEndpoint>,
    full_jid: &str,
    connection_id: uuid::Uuid,
    cluster_epoch: uuid::Uuid,
    sm_session_id: uuid::Uuid,
) -> bool {
    !connection_id.is_nil()
        && !cluster_epoch.is_nil()
        && current.full_jid == full_jid
        && current.connection_id == connection_id
        && current.cluster_epoch == cluster_epoch
        && current.sm_session_id == Some(sm_session_id)
        && matches!(
            &current.endpoint,
            MucOccupantEndpoint::Suspended(current_endpoint)
                if Arc::ptr_eq(current_endpoint, endpoint)
                    && current_endpoint.sm_session_id == sm_session_id
        )
}

pub(crate) fn muc_suspended_teardown_identity_matches(
    current: &MucOccupant,
    sm_session_id: uuid::Uuid,
    expected: &SerializableMucOccupant,
) -> bool {
    !expected.cluster_epoch.is_nil()
        && !expected.connection_id.is_nil()
        && current.sm_session_id == Some(sm_session_id)
        && current.full_jid == expected.full_jid
        && current.room_jid == expected.room_jid
        && current.nick == expected.nick
        && current.cluster_epoch == expected.cluster_epoch
        && current.connection_id == expected.connection_id
        && matches!(
            &current.endpoint,
            MucOccupantEndpoint::Suspended(endpoint)
                if endpoint.sm_session_id == sm_session_id
        )
}

/// Promote the process-local suspension prefix to PostgreSQL in strict FIFO
/// order.  The caller owns the endpoint mutex for the complete operation, so
/// a concurrently arriving stanza can neither overtake this prefix nor race a
/// resume claim. A failed append leaves that exact stanza and every successor
/// in the buffer; only successfully committed rows are removed.
pub(super) async fn promote_suspended_muc_buffer<F, Fut>(
    buffer: &mut SuspendedMucBuffer,
    mut append: F,
) -> bool
where
    F: FnMut(uuid::Uuid, String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    buffer.phase = SuspendedMucPhase::Sealed;
    while let Some(stanza) = buffer.stanzas.front().cloned() {
        if !append(stanza.source_id, stanza.xml).await {
            return false;
        }
        buffer.commit_front();
    }
    buffer.base_stanzas = 0;
    buffer.base_bytes = 0;
    buffer.snapshot_owned = false;
    buffer.phase = SuspendedMucPhase::Durable;
    true
}

/// Seal one session-global FIFO and clone its exact suffix for a prospective
/// SM checkpoint.  Ownership is deliberately not transferred here: if the
/// checkpoint or capacity validation fails, the original endpoint still owns
/// every byte and cleanup can promote it durably.
pub(super) async fn snapshot_suspended_muc_buffer_for_resume(
    endpoint: &SuspendedMucEndpoint,
) -> Option<Vec<String>> {
    let mut buffer = endpoint.buffer.lock().await;
    if !matches!(
        &buffer.phase,
        SuspendedMucPhase::Resuming | SuspendedMucPhase::Reserved | SuspendedMucPhase::Sealed
    ) {
        return None;
    }
    buffer.phase = SuspendedMucPhase::Committing;
    Some(if buffer.snapshot_owned {
        Vec::new()
    } else {
        buffer
            .stanzas
            .iter()
            .map(|stanza| stanza.xml.clone())
            .collect()
    })
}

pub(super) async fn seal_suspended_muc_buffer(endpoint: &SuspendedMucEndpoint) {
    let mut buffer = endpoint.buffer.lock().await;
    if !matches!(&buffer.phase, SuspendedMucPhase::Dormant) {
        buffer.phase = SuspendedMucPhase::Sealed;
    }
    drop(buffer);
    finalize_suspended_muc_route_transition(endpoint);
    endpoint.changed.notify_waiters();
}

pub(super) fn finalize_suspended_muc_route_transition(endpoint: &SuspendedMucEndpoint) {
    let mut route = endpoint
        .route
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if matches!(&*route, SuspendedMucRoute::Transitioning) {
        *route = SuspendedMucRoute::Suspended;
    }
}

pub(super) fn begin_suspended_muc_route_transition(
    endpoint: &SuspendedMucEndpoint,
    base_stanzas: usize,
    base_bytes: usize,
) {
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
    if !transition_from_live {
        return;
    }
    // The ordinary live state has an idle buffer. If a post-replay commit
    // currently owns it, keep the route fenced as Transitioning; that commit
    // observes the fence and refuses Live publication, while async cleanup
    // seals/finalizes the transition after the mutex is released.
    if let Ok(mut buffer) = endpoint.buffer.try_lock() {
        buffer.phase = SuspendedMucPhase::Collecting;
        buffer.base_stanzas = base_stanzas;
        buffer.base_bytes = base_bytes;
        buffer.bytes = 0;
        buffer.stanzas.clear();
        buffer.snapshot_owned = false;
        drop(buffer);
        finalize_suspended_muc_route_transition(endpoint);
        endpoint.changed.notify_waiters();
    }
}

pub(super) fn transfer_muc_suffix_to_checkpoint(buffer: &mut SuspendedMucBuffer) -> bool {
    if !matches!(&buffer.phase, SuspendedMucPhase::Committing) {
        return false;
    }
    buffer.stanzas.clear();
    buffer.bytes = 0;
    buffer.base_stanzas = 0;
    buffer.base_bytes = 0;
    buffer.snapshot_owned = true;
    buffer.phase = SuspendedMucPhase::CheckpointOwned;
    true
}

pub(super) fn complete_snapshot_owned_handoff(buffer: &mut SuspendedMucBuffer) -> bool {
    if !buffer.snapshot_owned {
        return false;
    }
    buffer.stanzas.clear();
    buffer.bytes = 0;
    buffer.base_stanzas = 0;
    buffer.base_bytes = 0;
    buffer.snapshot_owned = false;
    buffer.phase = SuspendedMucPhase::Durable;
    true
}

/// Add the volatile MUC suffix to the exact XEP-0198 snapshot which will be
/// committed by the same suspension transaction.  Validation is completed
/// before either counter or queue is mutated, so an invariant failure leaves
/// the caller's original snapshot intact and the endpoint remains its owner.
pub(super) fn append_suspended_muc_suffix_to_snapshot(
    snapshot: &mut crate::services::sm::SmSessionSnapshot,
    suffix: &VecDeque<SuspendedMucStanza>,
    max_stanzas: usize,
    max_bytes: usize,
) -> anyhow::Result<()> {
    let total_stanzas = snapshot
        .unacked
        .len()
        .checked_add(suffix.len())
        .context("SM stanza count overflow while fencing a MUC disconnect")?;
    let existing_bytes = snapshot
        .unacked
        .iter()
        .try_fold(0usize, |total, entry| total.checked_add(entry.stanza.len()))
        .context("SM byte count overflow while fencing a MUC disconnect")?;
    let total_bytes = suffix.iter().try_fold(existing_bytes, |total, stanza| {
        total.checked_add(stanza.xml.len())
    });
    let total_bytes =
        total_bytes.context("MUC suffix byte count overflow while fencing a disconnect")?;
    anyhow::ensure!(
        total_stanzas <= max_stanzas && total_bytes <= max_bytes,
        "MUC disconnect suffix exceeds the global SM replay budget"
    );

    for stanza in suffix {
        snapshot.outbound_h = snapshot.outbound_h.wrapping_add(1);
        snapshot
            .unacked
            .push(crate::xmpp::outbound::SmUnackedStanza::with_delivery(
                stanza.xml.clone(),
                None,
            ));
    }
    Ok(())
}

/// Publish or adopt the one process-local route gate for an exact SM epoch.
/// Callers may have observed a miss before asynchronous database work; the
/// entry operation is the only publication point and can never replace a gate
/// installed by a concurrent join, disconnect, or winning resume.
pub(super) fn canonical_suspended_muc_endpoint(
    registry: &DashMap<uuid::Uuid, Arc<SuspendedMucEndpoint>>,
    sm_session_id: uuid::Uuid,
    proposed: Arc<SuspendedMucEndpoint>,
) -> Arc<SuspendedMucEndpoint> {
    match registry.entry(sm_session_id) {
        dashmap::mapref::entry::Entry::Vacant(slot) => {
            slot.insert(Arc::clone(&proposed));
            proposed
        }
        dashmap::mapref::entry::Entry::Occupied(slot) => Arc::clone(slot.get()),
    }
}

/// Restore publication is insert-only. A joiner or another exact resume that
/// won while this task awaited PostgreSQL remains authoritative.
pub(super) fn insert_restored_muc_occupant(
    occupants: &DashMap<String, MucOccupant>,
    key: String,
    occupant: MucOccupant,
) -> bool {
    match occupants.entry(key) {
        dashmap::mapref::entry::Entry::Vacant(slot) => {
            slot.insert(occupant);
            true
        }
        dashmap::mapref::entry::Entry::Occupied(_) => false,
    }
}

/// Own the membership identities before any asynchronous association work.
/// Even an iterator whose yielded item has been cloned can retain its current
/// DashMap shard guard. No live map iterator may cross the backend await.
pub(super) fn local_muc_membership_snapshots(
    memberships: &DashMap<String, JoinedMucMembership>,
) -> Vec<(String, JoinedMucMembership)> {
    memberships
        .iter()
        .map(|entry| (entry.key().clone(), entry.value().clone()))
        .collect()
}

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
