//! Durable federation admission and post-commit delivery wake-ups.
//! The repository owns PostgreSQL; protocol callers receive only this port.
use std::{collections::HashSet, future::Future, sync::Arc};

use tokio::sync::mpsc;

use northstar_federation_core::{FederationOutboxAdmission, FederationRoute, S2sOutboxPolicy};

pub trait FederationOutboxRepository: Clone + Send + Sync {
    fn enqueue<'a>(
        &'a self,
        target_domain: &'a str,
        stanza: &'a str,
        bounce_to: Option<&'a str>,
        policy: S2sOutboxPolicy,
    ) -> impl Future<Output = anyhow::Result<()>> + Send + 'a;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentRoute {
    NotConfigured,
    Delivered,
    Unavailable,
}

/// Wakes the current socket owner of a configured component domain after a durable enqueue commits.
/// The owner claims its own rows; `NotConfigured` leaves delivery to the generic federation dispatcher.
pub trait ComponentWake: Send + Sync {
    fn wake_route(&self, configured_domains: &HashSet<String>, target: &str) -> ComponentRoute;
}

#[derive(Clone)]
pub struct FederationOutboxService<R> {
    repository: R,
    wake: mpsc::Sender<()>,
    policy: S2sOutboxPolicy,
    components: Arc<dyn ComponentWake>,
    component_domains: Arc<HashSet<String>>,
}

impl<R: FederationOutboxRepository> FederationOutboxService<R> {
    pub fn channel(
        repository: R,
        policy: S2sOutboxPolicy,
        components: Arc<dyn ComponentWake>,
        component_domains: HashSet<String>,
    ) -> (Self, mpsc::Receiver<()>) {
        // Only PostgreSQL owns delivery. A coalesced wake-up never loses a row.
        let (wake, receiver) = mpsc::channel(1);
        (
            Self {
                repository,
                wake,
                policy,
                components,
                component_domains: Arc::new(component_domains),
            },
            receiver,
        )
    }

    pub async fn send(
        &self,
        target_domain: &str,
        stanza: String,
        bounce_to: Option<String>,
    ) -> bool {
        match self
            .repository
            .enqueue(target_domain, &stanza, bounce_to.as_deref(), self.policy)
            .await
        {
            Ok(()) => {
                // Enqueue commits before either wake-up. The component's
                // current socket owner claims its own durable rows.
                let route = self
                    .components
                    .wake_route(&self.component_domains, target_domain);
                if route == ComponentRoute::NotConfigured {
                    let _ = self.wake.try_send(());
                }
                true
            }
            Err(error) => {
                tracing::warn!(%target_domain, ?error, "federation stanza was not persisted");
                false
            }
        }
    }

    /// Snapshot for callers that enqueue within their own transaction.
    pub fn outbox_policy(&self) -> S2sOutboxPolicy {
        self.policy
    }

    /// Call only after a caller-owned outbox transaction commits.
    pub fn wake_outbox(&self) {
        let _ = self.wake.try_send(());
    }

    /// The MAM service needs only a clone of this edge-triggered sender.
    pub fn outbox_wakeup(&self) -> mpsc::Sender<()> {
        self.wake.clone()
    }
}

impl<R: FederationOutboxRepository> FederationOutboxAdmission for FederationOutboxService<R> {
    fn admit<'a>(
        &'a self,
        target_domain: &'a str,
        stanza: String,
    ) -> impl Future<Output = bool> + Send + 'a {
        self.send(target_domain, stanza, None)
    }
}

impl<R: FederationOutboxRepository + 'static> FederationRoute for FederationOutboxService<R> {
    fn outbox_policy(&self) -> S2sOutboxPolicy {
        FederationOutboxService::outbox_policy(self)
    }

    fn wake_outbox(&self) {
        FederationOutboxService::wake_outbox(self);
    }

    async fn send(&self, target_domain: &str, stanza: String, bounce_to: Option<String>) -> bool {
        FederationOutboxService::send(self, target_domain, stanza, bounce_to).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::sync::{oneshot, Notify};

    struct NoComponents;

    impl ComponentWake for NoComponents {
        fn wake_route(&self, _domains: &HashSet<String>, _target: &str) -> ComponentRoute {
            ComponentRoute::NotConfigured
        }
    }

    #[derive(Clone)]
    struct GatedRepository {
        entered: Arc<Notify>,
        result: Arc<Mutex<Option<oneshot::Receiver<anyhow::Result<()>>>>>,
    }

    impl FederationOutboxRepository for GatedRepository {
        async fn enqueue<'a>(
            &'a self,
            _target_domain: &'a str,
            _stanza: &'a str,
            _bounce_to: Option<&'a str>,
            _policy: S2sOutboxPolicy,
        ) -> anyhow::Result<()> {
            let receiver = self.result.lock().unwrap().take().unwrap();
            self.entered.notify_one();
            receiver.await.unwrap()
        }
    }

    fn gated_service() -> (
        FederationOutboxService<GatedRepository>,
        mpsc::Receiver<()>,
        Arc<Notify>,
        oneshot::Sender<anyhow::Result<()>>,
    ) {
        let (send, receive) = oneshot::channel();
        let entered = Arc::new(Notify::new());
        let repository = GatedRepository {
            entered: Arc::clone(&entered),
            result: Arc::new(Mutex::new(Some(receive))),
        };
        let (service, wake) = FederationOutboxService::channel(
            repository,
            S2sOutboxPolicy::new(300, 100, 1_000_000, 100),
            Arc::new(NoComponents),
            HashSet::new(),
        );
        (service, wake, entered, send)
    }

    #[tokio::test]
    async fn successful_commit_wakes_only_after_repository_completes() {
        let (service, mut wake, entered, finish) = gated_service();
        let task = tokio::spawn(async move {
            service
                .send("remote.example", "<message/>".into(), None)
                .await
        });
        entered.notified().await;
        assert!(wake.try_recv().is_err());
        finish.send(Ok(())).unwrap();
        assert!(task.await.unwrap());
        assert!(wake.try_recv().is_ok());
    }

    #[tokio::test]
    async fn failed_enqueue_never_wakes() {
        let (service, mut wake, entered, finish) = gated_service();
        let task = tokio::spawn(async move {
            service
                .send("remote.example", "<message/>".into(), None)
                .await
        });
        entered.notified().await;
        finish.send(Err(anyhow::anyhow!("rejected"))).unwrap();
        assert!(!task.await.unwrap());
        assert!(wake.try_recv().is_err());
    }
}
