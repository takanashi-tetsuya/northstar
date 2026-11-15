//! Shared process-local MUC suspension state and its durable handoff.

use crate::local_routes::muc::{
    MucOccupant, MucOccupantEndpoint, SuspendedMucEndpoint, SuspendedMucPhase, SuspendedMucRoute,
};
use crate::local_routes::suspended_muc::{
    append_suspended_muc_suffix_to_snapshot, complete_snapshot_owned_handoff,
    finalize_suspended_muc_route_transition, promote_suspended_muc_buffer,
    seal_suspended_muc_buffer,
};
use anyhow::Result;
use dashmap::DashMap;
use northstar_room_application::muc_service::{MucWakePort, SerializableMucOccupant};
use northstar_session_application::sm_suspension::{
    MucSuspensionRequest, SmSuspensionLimits, SmSuspensionRepository, SmSuspensionRequest,
};
use northstar_xmpp_types::jid_text::localpart;
use std::{collections::HashSet, sync::Arc, time::Duration};

/// The cluster calls SM suspension makes: whether PostgreSQL MUC authority is on, this node's id, the wake of a
/// committed MUC operation, and the Redis record of a suspended occupant.
pub trait SmSuspensionCluster: MucWakePort + Send + Sync {
    fn is_enabled(&self) -> bool;
    fn node_id(&self) -> &str;
    fn register_suspended_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        sm_session_id: uuid::Uuid,
        json: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}

pub struct SmSuspensionContext<R, C> {
    repository: R,
    limits: SmSuspensionLimits,
    muc_occupants: Arc<DashMap<String, MucOccupant>>,
    cluster: C,
}

impl<R: SmSuspensionRepository, C: SmSuspensionCluster> SmSuspensionContext<R, C> {
    pub fn new(
        repository: R,
        limits: SmSuspensionLimits,
        muc_occupants: Arc<DashMap<String, MucOccupant>>,
        cluster: C,
    ) -> Self {
        Self {
            repository,
            limits,
            muc_occupants,
            cluster,
        }
    }

    pub async fn suspend_exact_session(&self, request: SmSuspensionRequest<'_>) -> Result<bool> {
        self.repository
            .suspend_exact_session(request, self.limits)
            .await
    }

    pub async fn mark_suspended_muc_durable(
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
                                node_id: self.cluster.node_id(),
                                lease: Duration::from_secs(90),
                            })
                            .await?;
                        anyhow::ensure!(
                            matches!(
                                outcome,
                                northstar_room_application::muc_service::ClusterMucTransitionOutcome::Applied
                                    | northstar_room_application::muc_service::ClusterMucTransitionOutcome::Replay
                            ),
                            "PG MUC suspension rejected stale occupancy: {outcome:?}"
                        );
                        northstar_room_application::muc_service::notify_committed_operation(
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

    pub async fn seal_suspended_muc_endpoints(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        let mut seen = HashSet::new();
        for endpoint in endpoints {
            if seen.insert(Arc::as_ptr(endpoint) as usize) {
                seal_suspended_muc_buffer(endpoint).await;
            }
        }
    }

    pub fn retain_suspended_sm_capacity(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
    ) {
        crate::local_routes::suspended_muc::retain_suspended_sm_capacity(endpoints, capacity);
    }

    pub async fn snapshot_suspended_muc_for_disconnect(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        snapshot: &mut northstar_session_application::sm::SmSessionSnapshot,
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
    use northstar_room_application::muc_service::{
        ClusterMucTransitionOutcome, ClusterMucWakeDescriptor,
    };
    use std::{collections::HashMap, sync::Mutex};
    use uuid::Uuid;

    #[derive(Clone, Copy)]
    struct DisabledCluster;

    impl MucWakePort for DisabledCluster {
        async fn wake(&self, _descriptor: &ClusterMucWakeDescriptor) -> Result<()> {
            Ok(())
        }

        fn record_failure(&self, _error: &anyhow::Error) {}
    }

    impl SmSuspensionCluster for DisabledCluster {
        fn is_enabled(&self) -> bool {
            false
        }

        fn node_id(&self) -> &str {
            "example.test"
        }

        async fn register_suspended_muc_occupant(
            &self,
            _room_jid: &str,
            _nick: &str,
            _sm_session_id: uuid::Uuid,
            _json: &str,
        ) -> Result<bool> {
            Ok(true)
        }
    }

    #[derive(Default)]
    struct LostAppendResponse {
        stored: Mutex<HashMap<Uuid, String>>,
        attempts: Mutex<Vec<Uuid>>,
    }

    /// The recreated contexts share one repository, as they share one pool.
    #[derive(Clone, Default)]
    struct SharedLostAppend(Arc<LostAppendResponse>);

    impl std::ops::Deref for SharedLostAppend {
        type Target = LostAppendResponse;

        fn deref(&self) -> &LostAppendResponse {
            &self.0
        }
    }

    impl SmSuspensionRepository for SharedLostAppend {
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
        let repository = SharedLostAppend::default();
        let occupants = Arc::new(DashMap::new());
        let suspended = Arc::new(DashMap::new());
        let cluster = DisabledCluster;
        let context = || {
            SmSuspensionContext::new(
                repository.clone(),
                SmSuspensionLimits {
                    max_stanzas: 8,
                    max_bytes: 4096,
                },
                Arc::clone(&occupants),
                cluster,
            )
        };
        let session_id = Uuid::new_v4();
        let first = context();
        let endpoint = crate::local_routes::suspended_muc::canonical_suspended_muc_endpoint(
            &suspended,
            session_id,
            Arc::new(SuspendedMucEndpoint::new(session_id)),
        );
        let endpoints = vec![Arc::clone(&endpoint)];
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
