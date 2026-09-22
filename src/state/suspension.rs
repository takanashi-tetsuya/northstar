//! Shared process-local MUC suspension state and its durable handoff.
use super::{
    append_suspended_muc_suffix_to_snapshot, begin_suspended_muc_route_transition,
    canonical_suspended_muc_endpoint, complete_snapshot_owned_handoff,
    finalize_suspended_muc_route_transition, localpart, muc_actor_epoch_matches,
    promote_suspended_muc_buffer, seal_suspended_muc_buffer, JoinedMucMembership, MucOccupant,
    MucOccupantEndpoint, SerializableMucOccupant, SuspendedMucEndpoint, SuspendedMucPhase,
    SuspendedMucRoute,
};
use crate::services::sm_suspension::{
    MucSuspensionRequest, SmSuspensionLimits, SmSuspensionRepository, SmSuspensionRequest,
};
use anyhow::Result;
use dashmap::DashMap;
use std::{collections::HashSet, sync::Arc, time::Duration};

pub(crate) struct SmSuspensionContext<R> {
    repository: R,
    limits: SmSuspensionLimits,
    muc_occupants: Arc<DashMap<String, MucOccupant>>,
    suspended_muc_sessions: Arc<DashMap<uuid::Uuid, Arc<SuspendedMucEndpoint>>>,
    cluster: crate::cluster::ClusterManager,
}

impl<R: SmSuspensionRepository> SmSuspensionContext<R> {
    pub(crate) fn new(
        repository: R,
        limits: SmSuspensionLimits,
        muc_occupants: Arc<DashMap<String, MucOccupant>>,
        suspended_muc_sessions: Arc<DashMap<uuid::Uuid, Arc<SuspendedMucEndpoint>>>,
        cluster: crate::cluster::ClusterManager,
    ) -> Self {
        Self {
            repository,
            limits,
            muc_occupants,
            suspended_muc_sessions,
            cluster,
        }
    }

    pub(crate) async fn suspend_exact_session(
        &self,
        request: SmSuspensionRequest<'_>,
    ) -> Result<bool> {
        self.repository
            .suspend_exact_session(request, self.limits)
            .await
    }

    pub(crate) fn suspend_local_muc_occupants(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        memberships: &DashMap<String, JoinedMucMembership>,
        base_stanzas: usize,
        base_bytes: usize,
    ) -> Vec<Arc<SuspendedMucEndpoint>> {
        // Publish the session fence before walking independent room entries.
        // Delivery consults this registry ahead of each endpoint, so no room
        // can continue accepting into the disappearing transport while a
        // later room has already switched to the suspension FIFO.
        let proposed = Arc::new(SuspendedMucEndpoint::new_collecting(
            sm_session_id,
            base_stanzas,
            base_bytes,
        ));
        let endpoint =
            canonical_suspended_muc_endpoint(&self.suspended_muc_sessions, sm_session_id, proposed);
        begin_suspended_muc_route_transition(&endpoint, base_stanzas, base_bytes);
        for membership in memberships {
            let room_jid = membership.key();
            let membership = membership.value();
            let key = crate::xmpp::xml_util::muc_occupant_key(room_jid, &membership.nick);
            let Some(mut occupant) = self.muc_occupants.get_mut(&key) else {
                continue;
            };
            if !muc_actor_epoch_matches(&occupant, full_jid, connection_id, room_jid, membership)
                || occupant.sm_session_id != Some(sm_session_id)
            {
                continue;
            }
            match &occupant.endpoint {
                MucOccupantEndpoint::Local(_) => {
                    occupant.endpoint = MucOccupantEndpoint::Suspended(Arc::clone(&endpoint));
                }
                MucOccupantEndpoint::Suspended(current)
                    if Arc::ptr_eq(current, &endpoint)
                        && current.sm_session_id == sm_session_id => {}
                MucOccupantEndpoint::Suspended(_) | MucOccupantEndpoint::Federated { .. } => {}
            }
        }
        // Even a stale membership plan returns the published fence: an
        // in-flight delivery may already hold its Arc and must be promoted (or
        // remain visibly sealed) instead of being acknowledged into a dropped
        // buffer.
        vec![endpoint]
    }

    pub(crate) async fn mark_suspended_muc_durable(
        &self,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
    ) -> bool {
        let mut complete = true;
        let mut seen = HashSet::new();
        for endpoint in endpoints {
            if !seen.insert(Arc::as_ptr(&endpoint) as usize) {
                continue;
            }
            let route_is_live = {
                let route = endpoint
                    .route
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                matches!(&*route, SuspendedMucRoute::Live(_))
            };
            if route_is_live {
                continue;
            }
            let mut buffer = endpoint.buffer.lock().await;
            let sm_session_id = endpoint.sm_session_id;
            let repository = &self.repository;
            let max_stanzas = self.limits.max_stanzas;
            let max_bytes = self.limits.max_bytes;
            let promoted = match buffer.phase.clone() {
                SuspendedMucPhase::Durable => true,
                // The caller invokes this method only after the exact SM
                // suspension CAS succeeded. Snapshot ownership is orthogonal
                // to Sealed/Waiting/CheckpointOwned so a lost COMMIT response
                // followed by an immediate claim cannot erase the fact that
                // PostgreSQL already contains this suffix.
                _ if buffer.snapshot_owned => complete_snapshot_owned_handoff(&mut buffer),
                SuspendedMucPhase::Dormant => {
                    buffer.phase = SuspendedMucPhase::Sealed;
                    false
                }
                _ => {
                    promote_suspended_muc_buffer(&mut buffer, |source_id, stanza| async move {
                        match repository
                            .append_suspended_stanza(
                                sm_session_id,
                                source_id,
                                &stanza,
                                max_stanzas,
                                max_bytes,
                            )
                            .await
                        {
                            Ok(stored) => stored,
                            Err(error) => {
                                tracing::warn!(
                                    ?error,
                                    %sm_session_id,
                                    "could not append the suspended MUC queue to durable SM storage"
                                );
                                false
                            }
                        }
                    })
                    .await
                }
            };
            if promoted {
                endpoint.changed.notify_waiters();
            }
            drop(buffer);
            if !promoted {
                complete = false;
                tracing::warn!(
                    sm_session_id = %endpoint.sm_session_id,
                    "retained bounded MUC traffic because durable SM storage is unavailable"
                );
            }
            // Replace the Redis occupant value with the exact suspended SM
            // epoch. Any node that later wins PostgreSQL expiry can now
            // remove the cluster record immediately without risking a newly
            // resumed/rejoined occupant which reused the same nick.
            let occupants = self
                .muc_occupants
                .iter()
                .filter_map(|occupant| match &occupant.endpoint {
                    MucOccupantEndpoint::Suspended(current) if Arc::ptr_eq(current, &endpoint) => {
                        Some(SerializableMucOccupant::from(&*occupant))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            for occupant in occupants {
                let encoded = serde_json::to_string(&occupant).unwrap_or_default();
                if self.cluster.is_enabled() {
                    let suspend = async {
                        let operation_id = uuid::Uuid::new_v4();
                        let outcome = self
                            .repository
                            .suspend_muc_occupant(MucSuspensionRequest {
                                operation_id,
                                room_localpart: localpart(&occupant.room_jid),
                                occupant_incarnation: occupant.cluster_epoch,
                                connection_id: occupant.connection_id,
                                sm_session_id: endpoint.sm_session_id,
                                node_id: &self.cluster.node_id,
                                lease: Duration::from_secs(90),
                            })
                            .await?;
                        anyhow::ensure!(
                            matches!(
                                outcome,
                                crate::services::muc::ClusterMucTransitionOutcome::Applied
                                    | crate::services::muc::ClusterMucTransitionOutcome::Replay
                            ),
                            "PG MUC suspension rejected stale occupancy: {outcome:?}"
                        );
                        crate::services::muc::notify_committed_operation(
                            self.repository.committed_muc_wake(operation_id),
                            &self.cluster,
                            operation_id,
                        )
                        .await;
                        Ok::<_, anyhow::Error>(())
                    }
                    .await;
                    if let Err(error) = suspend {
                        complete = false;
                        tracing::warn!(?error, room=%occupant.room_jid, nick=%occupant.nick,
                            "could not commit PG-authoritative MUC suspension");
                        continue;
                    }
                }
                if let Err(error) = self
                    .cluster
                    .register_suspended_muc_occupant(
                        &occupant.room_jid,
                        &occupant.nick,
                        endpoint.sm_session_id,
                        &encoded,
                    )
                    .await
                {
                    complete = false;
                    tracing::warn!(?error, room = %occupant.room_jid, nick = %occupant.nick, "failed to mark clustered MUC occupant as SM-suspended");
                }
            }
        }
        complete
    }

    pub(crate) async fn seal_suspended_muc_endpoints(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
    ) {
        let mut seen = HashSet::new();
        for endpoint in endpoints {
            if seen.insert(Arc::as_ptr(endpoint) as usize) {
                seal_suspended_muc_buffer(endpoint).await;
            }
        }
    }

    pub(crate) fn retain_suspended_sm_capacity(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        capacity: crate::services::sm_capacity::SmCapacityLease,
    ) {
        for endpoint in endpoints {
            *endpoint
                .sm_capacity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(capacity.clone());
        }
    }

    pub(crate) async fn snapshot_suspended_muc_for_disconnect(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        snapshot: &mut crate::services::sm::SmSessionSnapshot,
    ) -> anyhow::Result<()> {
        let mut unique = Vec::new();
        let mut seen = HashSet::new();
        for endpoint in endpoints {
            if seen.insert(Arc::as_ptr(endpoint) as usize) {
                unique.push(endpoint);
            }
        }
        anyhow::ensure!(
            unique.len() <= 1,
            "one SM epoch exposed multiple process-local MUC FIFOs"
        );
        let Some(endpoint) = unique.into_iter().next() else {
            return Ok(());
        };
        let mut buffer = endpoint.buffer.lock().await;
        match buffer.phase.clone() {
            SuspendedMucPhase::Collecting
            | SuspendedMucPhase::Waiting
            | SuspendedMucPhase::Resuming
            | SuspendedMucPhase::Reserved
            | SuspendedMucPhase::Sealed => {
                if !buffer.snapshot_owned {
                    append_suspended_muc_suffix_to_snapshot(
                        snapshot,
                        &buffer.stanzas,
                        self.limits.max_stanzas,
                        self.limits.max_bytes,
                    )?;
                }
            }
            // These phases already correspond to the current ProtocolSession
            // snapshot. Re-appending their backup would duplicate replay.
            SuspendedMucPhase::Committing
            | SuspendedMucPhase::CheckpointOwned
            | SuspendedMucPhase::Durable => {}
            SuspendedMucPhase::Dormant => {
                anyhow::bail!("live MUC route was not fenced before SM suspension")
            }
        }
        buffer.snapshot_owned = true;
        buffer.phase = SuspendedMucPhase::Sealed;
        drop(buffer);
        finalize_suspended_muc_route_transition(endpoint);
        endpoint.changed.notify_waiters();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::muc::{ClusterMucTransitionOutcome, ClusterMucWakeDescriptor};
    use std::{collections::HashMap, sync::Mutex};
    use uuid::Uuid;

    #[derive(Default)]
    struct LostAppendResponse {
        stored: Mutex<HashMap<Uuid, String>>,
        attempts: Mutex<Vec<Uuid>>,
    }

    impl SmSuspensionRepository for Arc<LostAppendResponse> {
        async fn suspend_exact_session(
            &self,
            _: SmSuspensionRequest<'_>,
            _: SmSuspensionLimits,
        ) -> Result<bool> {
            unreachable!()
        }
        async fn append_suspended_stanza(
            &self,
            _: Uuid,
            source_id: Uuid,
            stanza: &str,
            max_stanzas: usize,
            max_bytes: usize,
        ) -> Result<bool> {
            assert_eq!((max_stanzas, max_bytes), (8, 4096));
            let mut attempts = self.attempts.lock().unwrap();
            attempts.push(source_id);
            self.stored
                .lock()
                .unwrap()
                .entry(source_id)
                .or_insert_with(|| stanza.to_owned());
            if attempts.len() == 2 {
                anyhow::bail!("append committed but its response was lost");
            }
            Ok(true)
        }
        async fn suspend_muc_occupant(
            &self,
            _: MucSuspensionRequest<'_>,
        ) -> Result<ClusterMucTransitionOutcome> {
            unreachable!()
        }
        async fn committed_muc_wake(&self, _: Uuid) -> Result<Option<ClusterMucWakeDescriptor>> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn lost_append_response_retains_the_exact_suffix_across_context_recreation() {
        let repository = Arc::new(LostAppendResponse::default());
        let occupants = Arc::new(DashMap::new());
        let suspended = Arc::new(DashMap::new());
        let cluster =
            crate::cluster::ClusterManager::new(None, "example.test", None, None, None, None)
                .await
                .unwrap();
        let context = || {
            SmSuspensionContext::new(
                Arc::clone(&repository),
                SmSuspensionLimits {
                    max_stanzas: 8,
                    max_bytes: 4096,
                },
                Arc::clone(&occupants),
                Arc::clone(&suspended),
                cluster.clone(),
            )
        };
        let session_id = Uuid::new_v4();
        let first = context();
        let endpoints = first.suspend_local_muc_occupants(
            "alice@example.test/phone",
            Uuid::new_v4(),
            session_id,
            &DashMap::new(),
            0,
            0,
        );
        let endpoint = Arc::clone(&endpoints[0]);
        {
            let mut buffer = endpoint.buffer.lock().await;
            for stanza in ["first", "middle", "last"] {
                assert!(buffer.enqueue_volatile(stanza.to_owned(), 8, 4096));
            }
        }
        assert!(
            !first
                .mark_suspended_muc_durable(vec![Arc::clone(&endpoint), Arc::clone(&endpoint)])
                .await
        );
        let pending_source = {
            let buffer = endpoint.buffer.lock().await;
            assert!(matches!(buffer.phase, SuspendedMucPhase::Sealed));
            assert_eq!(
                buffer
                    .stanzas
                    .iter()
                    .map(|s| s.xml.as_str())
                    .collect::<Vec<_>>(),
                ["middle", "last"]
            );
            assert_eq!(buffer.bytes, "middlelast".len());
            buffer.stanzas[0].source_id
        };
        drop(first);
        let second = context();
        assert!(Arc::ptr_eq(
            &endpoint,
            suspended.get(&session_id).unwrap().value()
        ));
        assert!(second.mark_suspended_muc_durable(endpoints).await);
        let buffer = endpoint.buffer.lock().await;
        assert!(matches!(buffer.phase, SuspendedMucPhase::Durable));
        assert!(buffer.stanzas.is_empty());
        assert_eq!(buffer.bytes, 0);
        let attempts = repository.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 4);
        assert_eq!(attempts[1], pending_source);
        assert_eq!(attempts[2], pending_source);
        assert_eq!(repository.stored.lock().unwrap().len(), 3);
    }
}
