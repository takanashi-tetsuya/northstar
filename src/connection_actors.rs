//! Bounded ownership and shutdown supervision for long-lived network actors.
//!
//! Listener services remain responsible for accepting sockets and protocol
//! actors remain responsible for their exact-once protocol cleanup. This
//! registry owns every spawned actor task so root shutdown can first close
//! admission, then signal cooperative cancellation, and finally abort and reap
//! actors which exceed the bounded grace period.

use futures::FutureExt;
use std::{
    collections::HashMap,
    future::Future,
    panic::AssertUnwindSafe,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{sync::Semaphore, task::AbortHandle};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionActorKind {
    C2sTcp,
    C2sDirectTls,
    C2sWebSocket,
    C2sBosh,
    S2sInboundStartTls,
    S2sInboundDirectTls,
    S2sOutbound,
    ComponentAccept,
    ComponentConnect,
}

impl ConnectionActorKind {
    fn label(self) -> &'static str {
        match self {
            Self::C2sTcp => "c2s-tcp",
            Self::C2sDirectTls => "c2s-direct-tls",
            Self::C2sWebSocket => "c2s-websocket",
            Self::C2sBosh => "c2s-bosh",
            Self::S2sInboundStartTls => "s2s-inbound-starttls",
            Self::S2sInboundDirectTls => "s2s-inbound-direct-tls",
            Self::S2sOutbound => "s2s-outbound",
            Self::ComponentAccept => "component-accept",
            Self::ComponentConnect => "component-connect",
        }
    }

    fn category(self) -> ConnectionActorCategory {
        match self {
            Self::C2sTcp | Self::C2sDirectTls | Self::C2sWebSocket | Self::C2sBosh => {
                ConnectionActorCategory::Client
            }
            Self::S2sInboundStartTls | Self::S2sInboundDirectTls | Self::S2sOutbound => {
                ConnectionActorCategory::S2s
            }
            Self::ComponentAccept | Self::ComponentConnect => ConnectionActorCategory::Component,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionActorCategory {
    Client,
    S2s,
    Component,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionActorCapacityError {
    Overflow,
    ExceedsRuntimeLimit,
}

impl std::fmt::Display for ConnectionActorCapacityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overflow => formatter.write_str("connection actor capacity overflowed usize"),
            Self::ExceedsRuntimeLimit => formatter
                .write_str("connection actor capacity exceeds Tokio semaphore's runtime limit"),
        }
    }
}

impl std::error::Error for ConnectionActorCapacityError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionActorSpawnError {
    AdmissionClosed,
    CapacityReached,
}

impl std::fmt::Display for ConnectionActorSpawnError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdmissionClosed => formatter.write_str("connection actor admission is closed"),
            Self::CapacityReached => {
                formatter.write_str("connection actor registry reached its configured capacity")
            }
        }
    }
}

impl std::error::Error for ConnectionActorSpawnError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionActorShutdownReport {
    pub graceful: bool,
    pub aborted: usize,
    pub remaining: usize,
}

#[derive(Clone)]
pub struct ConnectionActorRegistry {
    inner: Arc<RegistryInner>,
}

struct RegistryInner {
    accepting: AtomicBool,
    total_capacity: Arc<Semaphore>,
    client_capacity: Arc<Semaphore>,
    s2s_capacity: Arc<Semaphore>,
    component_capacity: Arc<Semaphore>,
    shutdown: CancellationToken,
    tracker: TaskTracker,
    // This mutex is both the bounded task index and the admission/shutdown
    // serialization gate. It prevents a spawn from racing past `close()`.
    tasks: Mutex<HashMap<Uuid, AbortHandle>>,
}

struct ActorRegistrationGuard {
    inner: Arc<RegistryInner>,
    actor_id: Uuid,
}

impl Drop for ActorRegistrationGuard {
    fn drop(&mut self) {
        self.inner
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.actor_id);
    }
}

impl ConnectionActorRegistry {
    /// Construct the process-wide bound from the already-validated transport
    /// limits. BOSH and WebSocket actors consume the shared C2S limit;
    /// inbound/outbound federation consume the shared S2S limit; accept- and
    /// connect-mode component connections consume the component limit.
    ///
    /// Keep this arithmetic checked even though each individual configuration
    /// value is bounded: widening a future limit must not wrap the global
    /// semaphore into a much smaller admission boundary.
    pub fn for_transport_limits(
        max_client_connections: usize,
        max_s2s_connections: usize,
        max_component_connections: usize,
    ) -> Result<Self, ConnectionActorCapacityError> {
        let capacity = max_client_connections
            .checked_add(max_s2s_connections)
            .and_then(|total| total.checked_add(max_component_connections))
            .ok_or(ConnectionActorCapacityError::Overflow)?;
        if capacity > Semaphore::MAX_PERMITS {
            return Err(ConnectionActorCapacityError::ExceedsRuntimeLimit);
        }
        Ok(Self::with_capacities(
            capacity,
            max_client_connections,
            max_s2s_connections,
            max_component_connections,
        ))
    }

    #[cfg(test)]
    pub fn new(capacity: usize) -> Self {
        Self::with_capacities(capacity, capacity, capacity, capacity)
    }

    fn with_capacities(total: usize, client: usize, s2s: usize, component: usize) -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                accepting: AtomicBool::new(true),
                total_capacity: Arc::new(Semaphore::new(total)),
                client_capacity: Arc::new(Semaphore::new(client)),
                s2s_capacity: Arc::new(Semaphore::new(s2s)),
                component_capacity: Arc::new(Semaphore::new(component)),
                shutdown: CancellationToken::new(),
                tracker: TaskTracker::new(),
                tasks: Mutex::new(HashMap::with_capacity(total.min(4096))),
            }),
        }
    }

    fn category_capacity(&self, kind: ConnectionActorKind) -> &Arc<Semaphore> {
        match kind.category() {
            ConnectionActorCategory::Client => &self.inner.client_capacity,
            ConnectionActorCategory::S2s => &self.inner.s2s_capacity,
            ConnectionActorCategory::Component => &self.inner.component_capacity,
        }
    }

    pub fn shutdown_token(&self) -> CancellationToken {
        self.inner.shutdown.clone()
    }

    pub fn active_count(&self) -> usize {
        self.inner
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Spawn one connection actor without ever extending the configured bound.
    ///
    /// Actor futures should perform their protocol-specific asynchronous
    /// finalizer before returning. Panics are caught and logged here so they
    /// cannot disappear merely because the caller does not retain a JoinHandle.
    pub fn try_spawn<F>(
        &self,
        kind: ConnectionActorKind,
        peer: Option<String>,
        actor: F,
    ) -> Result<Uuid, ConnectionActorSpawnError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut tasks = self
            .inner
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.inner.accepting.load(Ordering::Acquire) || self.inner.shutdown.is_cancelled() {
            return Err(ConnectionActorSpawnError::AdmissionClosed);
        }
        let category_permit = Arc::clone(self.category_capacity(kind))
            .try_acquire_owned()
            .map_err(|_| ConnectionActorSpawnError::CapacityReached)?;
        let total_permit = match Arc::clone(&self.inner.total_capacity).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                drop(category_permit);
                return Err(ConnectionActorSpawnError::CapacityReached);
            }
        };
        let actor_id = Uuid::new_v4();
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let registration = ActorRegistrationGuard {
            inner: Arc::clone(&self.inner),
            actor_id,
        };
        let task = self.inner.tracker.spawn(async move {
            // Registration installs the AbortHandle before releasing the actor,
            // eliminating the finish-before-index-insert race.
            let _ = start_rx.await;
            let _registration = registration;
            let outcome = AssertUnwindSafe(actor).catch_unwind().await;
            drop(category_permit);
            drop(total_permit);
            if outcome.is_err() {
                tracing::error!(
                    %actor_id,
                    actor_kind = kind.label(),
                    peer = peer.as_deref().unwrap_or("unknown"),
                    "connection actor panicked"
                );
            }
        });
        tasks.insert(actor_id, task.abort_handle());
        // The receiver can only be gone if the task was externally cancelled
        // between spawn and registration; dropping the actor is then correct.
        let _ = start_tx.send(());
        drop(tasks);
        Ok(actor_id)
    }

    /// Atomically stop new actor admission and signal all existing actors.
    pub fn begin_shutdown(&self) {
        let _tasks = self
            .inner
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.inner.accepting.store(false, Ordering::Release);
        self.inner.tracker.close();
        self.inner.shutdown.cancel();
    }

    /// Join cooperatively, then abort and reap actors which exceeded `grace`.
    pub async fn join_or_abort(
        &self,
        grace: Duration,
        abort_grace: Duration,
    ) -> ConnectionActorShutdownReport {
        self.begin_shutdown();
        if tokio::time::timeout(grace, self.inner.tracker.wait())
            .await
            .is_ok()
        {
            return ConnectionActorShutdownReport {
                graceful: true,
                aborted: 0,
                remaining: 0,
            };
        }

        let handles = self
            .inner
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let aborted = handles.len();
        for handle in handles {
            handle.abort();
        }
        let reaped = tokio::time::timeout(abort_grace, self.inner.tracker.wait())
            .await
            .is_ok();
        let remaining = self.active_count();
        if !reaped || remaining != 0 {
            tracing::error!(
                aborted,
                remaining,
                "connection actors could not all be reaped"
            );
        }
        ConnectionActorShutdownReport {
            graceful: false,
            aborted,
            remaining,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registry_bounds_admission_and_cooperatively_drains() {
        let registry = ConnectionActorRegistry::new(1);
        let shutdown = registry.shutdown_token();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        registry
            .try_spawn(ConnectionActorKind::C2sTcp, None, async move {
                shutdown.cancelled().await;
                let _ = finished_tx.send(());
            })
            .unwrap();
        assert_eq!(
            registry.try_spawn(ConnectionActorKind::C2sTcp, None, async {}),
            Err(ConnectionActorSpawnError::CapacityReached)
        );
        registry.begin_shutdown();
        assert_eq!(
            registry.try_spawn(ConnectionActorKind::C2sTcp, None, async {}),
            Err(ConnectionActorSpawnError::AdmissionClosed)
        );
        let report = registry
            .join_or_abort(Duration::from_secs(1), Duration::from_secs(1))
            .await;
        assert!(report.graceful);
        assert_eq!(report.remaining, 0);
        finished_rx.await.unwrap();
    }

    #[tokio::test]
    async fn registry_aborts_and_reaps_non_cooperative_actors() {
        let registry = ConnectionActorRegistry::new(1);
        registry
            .try_spawn(ConnectionActorKind::S2sOutbound, None, async {
                std::future::pending::<()>().await;
            })
            .unwrap();
        let report = registry
            .join_or_abort(Duration::from_millis(10), Duration::from_secs(1))
            .await;
        assert!(!report.graceful);
        assert_eq!(report.aborted, 1);
        assert_eq!(report.remaining, 0);
    }

    #[test]
    fn transport_capacity_is_checked_before_constructing_the_semaphore() {
        let registry = ConnectionActorRegistry::for_transport_limits(10, 20, 30).unwrap();
        assert_eq!(registry.inner.total_capacity.available_permits(), 60);
        assert_eq!(registry.inner.client_capacity.available_permits(), 10);
        assert_eq!(registry.inner.s2s_capacity.available_permits(), 20);
        assert_eq!(registry.inner.component_capacity.available_permits(), 30);
        assert_eq!(
            ConnectionActorRegistry::for_transport_limits(usize::MAX, 1, 1).err(),
            Some(ConnectionActorCapacityError::Overflow)
        );
        if Semaphore::MAX_PERMITS < usize::MAX {
            assert_eq!(
                ConnectionActorRegistry::for_transport_limits(Semaphore::MAX_PERMITS, 1, 0).err(),
                Some(ConnectionActorCapacityError::ExceedsRuntimeLimit)
            );
        }
    }

    #[tokio::test]
    async fn actor_categories_are_independently_bounded_and_zero_means_disabled() {
        let registry = ConnectionActorRegistry::for_transport_limits(2, 1, 0).unwrap();
        let hold = std::future::pending::<()>();
        registry
            .try_spawn(ConnectionActorKind::C2sTcp, None, hold)
            .unwrap();
        registry
            .try_spawn(
                ConnectionActorKind::C2sWebSocket,
                None,
                std::future::pending::<()>(),
            )
            .unwrap();
        assert_eq!(
            registry.try_spawn(ConnectionActorKind::C2sBosh, None, async {}),
            Err(ConnectionActorSpawnError::CapacityReached)
        );
        registry
            .try_spawn(
                ConnectionActorKind::S2sInboundStartTls,
                None,
                std::future::pending::<()>(),
            )
            .unwrap();
        assert_eq!(
            registry.try_spawn(ConnectionActorKind::S2sOutbound, None, async {}),
            Err(ConnectionActorSpawnError::CapacityReached)
        );
        assert_eq!(
            registry.try_spawn(ConnectionActorKind::ComponentAccept, None, async {}),
            Err(ConnectionActorSpawnError::CapacityReached)
        );
        assert_eq!(
            registry.try_spawn(ConnectionActorKind::ComponentConnect, None, async {}),
            Err(ConnectionActorSpawnError::CapacityReached)
        );
        registry
            .join_or_abort(Duration::from_millis(1), Duration::from_secs(1))
            .await;
    }
}
