//! Ordered live effects after MUC admission. This owner has no repository,
//! acknowledgement or retry authority. The caller retains its room gate.

use std::future::Future;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MucFanoutDisposition {
    Accepted,
    Replay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MucFanoutStage {
    Cluster,
    Local,
}

pub(crate) trait MucFanoutPort: Sync {
    type Recipient: Send + Sync;
    type Blocked: Send;

    fn enter(&self, stage: MucFanoutStage);
    /// Best effort: the adapter records cluster failure without undoing admission.
    fn publish_cluster(&self) -> impl Future<Output = ()> + Send;
    fn recipients(&self) -> Vec<Self::Recipient>;
    /// Retains the existing fail-closed local-account policy on backend error.
    fn blocked<'a>(
        &'a self,
        recipients: &'a [Self::Recipient],
    ) -> impl Future<Output = Self::Blocked> + Send + 'a;
    fn is_blocked(&self, recipient: &Self::Recipient, blocked: &Self::Blocked) -> bool;
    fn deliver(&self, recipient: &Self::Recipient) -> impl Future<Output = bool> + Send;
    fn record_failure(&self, recipient: &Self::Recipient);
}

/// Returns whether a fresh accepted message attempted its effects, never an
/// acknowledgement. A replay does not re-publish, fetch recipients or emit a
/// routed-message metric. Dropping this future does not retry admission.
pub(crate) async fn run_muc_fanout(
    port: &impl MucFanoutPort,
    disposition: MucFanoutDisposition,
) -> bool {
    if disposition == MucFanoutDisposition::Replay {
        return false;
    }
    port.enter(MucFanoutStage::Cluster);
    port.publish_cluster().await;
    port.enter(MucFanoutStage::Local);
    // Own all recipients before the privacy or endpoint futures are awaited.
    let recipients = port.recipients();
    let blocked = port.blocked(&recipients).await;
    for recipient in recipients {
        if port.is_blocked(&recipient, &blocked) {
            continue;
        }
        if !port.deliver(&recipient).await {
            port.record_failure(&recipient);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Stage(MucFanoutStage),
        Cluster,
        ClusterFailed,
        Snapshot,
        Blocklist,
        Deliver(u8),
        Failed(u8),
    }

    struct Port {
        events: Mutex<Vec<Event>>,
        blocked: Vec<u8>,
        failed: Vec<u8>,
        cluster_failed: bool,
        pause: Option<MucFanoutStage>,
        pause_recipient: Option<u8>,
    }

    impl Port {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                blocked: Vec::new(),
                failed: Vec::new(),
                cluster_failed: false,
                pause: None,
                pause_recipient: None,
            }
        }

        fn record(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }
    }

    impl MucFanoutPort for Port {
        type Recipient = u8;
        type Blocked = Vec<u8>;

        fn enter(&self, stage: MucFanoutStage) {
            self.record(Event::Stage(stage));
        }

        async fn publish_cluster(&self) {
            self.record(Event::Cluster);
            if self.pause == Some(MucFanoutStage::Cluster) {
                std::future::pending::<()>().await;
            }
            if self.cluster_failed {
                self.record(Event::ClusterFailed);
            }
        }

        fn recipients(&self) -> Vec<u8> {
            self.record(Event::Snapshot);
            vec![1, 2, 3]
        }

        async fn blocked<'a>(&'a self, recipients: &'a [u8]) -> Vec<u8> {
            assert_eq!(recipients, [1, 2, 3]);
            self.record(Event::Blocklist);
            if self.pause == Some(MucFanoutStage::Local) {
                std::future::pending::<()>().await;
            }
            self.blocked.clone()
        }

        fn is_blocked(&self, recipient: &u8, blocked: &Vec<u8>) -> bool {
            blocked.contains(recipient)
        }

        async fn deliver(&self, recipient: &u8) -> bool {
            self.record(Event::Deliver(*recipient));
            if self.pause_recipient == Some(*recipient) {
                std::future::pending::<()>().await;
            }
            !self.failed.contains(recipient)
        }

        fn record_failure(&self, recipient: &u8) {
            self.record(Event::Failed(*recipient));
        }
    }

    #[tokio::test]
    async fn accepted_fanout_preserves_snapshot_privacy_and_endpoint_order() {
        let mut port = Port::new();
        port.blocked.push(2);
        assert!(run_muc_fanout(&port, MucFanoutDisposition::Accepted).await);
        assert_eq!(
            *port.events.lock().unwrap(),
            [
                Event::Stage(MucFanoutStage::Cluster),
                Event::Cluster,
                Event::Stage(MucFanoutStage::Local),
                Event::Snapshot,
                Event::Blocklist,
                Event::Deliver(1),
                Event::Deliver(3),
            ]
        );
    }

    #[tokio::test]
    async fn replay_does_not_publish_snapshot_filter_or_deliver_again() {
        let port = Port::new();
        assert!(!run_muc_fanout(&port, MucFanoutDisposition::Replay).await);
        assert!(port.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cluster_and_queue_failure_preserve_acceptance_and_remaining_recipients() {
        let mut port = Port::new();
        port.cluster_failed = true;
        port.failed = vec![1, 2];
        assert!(run_muc_fanout(&port, MucFanoutDisposition::Accepted).await);
        assert_eq!(
            *port.events.lock().unwrap(),
            [
                Event::Stage(MucFanoutStage::Cluster),
                Event::Cluster,
                Event::ClusterFailed,
                Event::Stage(MucFanoutStage::Local),
                Event::Snapshot,
                Event::Blocklist,
                Event::Deliver(1),
                Event::Failed(1),
                Event::Deliver(2),
                Event::Failed(2),
                Event::Deliver(3),
            ]
        );
    }

    #[tokio::test]
    async fn fail_closed_recipient_set_never_reaches_endpoint_delivery() {
        let mut port = Port::new();
        port.blocked = vec![1, 2, 3];
        assert!(run_muc_fanout(&port, MucFanoutDisposition::Accepted).await);
        assert!(!port
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| { matches!(event, Event::Deliver(_) | Event::Failed(_)) }));
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_fanout_releases_the_caller_gate_without_later_effects() {
        for stage in [MucFanoutStage::Cluster, MucFanoutStage::Local] {
            let mut port = Port::new();
            port.pause = Some(stage);
            let gate = tokio::sync::Mutex::new(());
            let work = async {
                let _authority = gate.lock().await;
                run_muc_fanout(&port, MucFanoutDisposition::Accepted).await
            };
            let mut work = Box::pin(work);
            assert!(futures::poll!(&mut work).is_pending());
            assert!(gate.try_lock().is_err());
            drop(work);
            assert!(gate.try_lock().is_ok());
            let events = port.events.lock().unwrap();
            assert_eq!(
                events
                    .iter()
                    .filter_map(|event| match event {
                        Event::Stage(stage) => Some(*stage),
                        _ => None,
                    })
                    .next_back(),
                Some(stage)
            );
            assert!(!events
                .iter()
                .any(|event| matches!(event, Event::Deliver(_))));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_during_endpoint_wait_keeps_prior_acceptance_and_skips_later_recipients() {
        let mut port = Port::new();
        port.pause_recipient = Some(2);
        let gate = tokio::sync::Mutex::new(());
        let work = async {
            let _authority = gate.lock().await;
            run_muc_fanout(&port, MucFanoutDisposition::Accepted).await
        };
        let mut work = Box::pin(work);
        assert!(futures::poll!(&mut work).is_pending());
        assert!(gate.try_lock().is_err());
        let expected = vec![
            Event::Stage(MucFanoutStage::Cluster),
            Event::Cluster,
            Event::Stage(MucFanoutStage::Local),
            Event::Snapshot,
            Event::Blocklist,
            Event::Deliver(1),
            Event::Deliver(2),
        ];
        // Reaching recipient 2 proves that recipient 1's success completed.
        // The pending second attempt must not pre-queue recipient 3.
        assert_eq!(*port.events.lock().unwrap(), expected);
        drop(work);
        assert!(gate.try_lock().is_ok());
        assert_eq!(*port.events.lock().unwrap(), expected);
    }
}
