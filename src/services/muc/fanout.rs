//! Ordered live effects after MUC admission. This owner has no repository,
//! acknowledgement or retry authority. The caller retains its room gate.

use northstar_room_application::discussion::{Fanout, FanoutPermit, Rejected};
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
    run_muc_fanout_effects(port, None)
        .await
        .expect("unobserved fanout has no retained state to reject");
    true
}

/// Only the accepted discussion envelope can supply this consuming permit.
/// Replay has no permit and uses the unchanged zero-effects disposition.
pub(crate) async fn run_muc_discussion_fanout(
    port: &impl MucFanoutPort,
    permit: FanoutPermit,
) -> Result<bool, Rejected> {
    let progress = permit.start()?;
    run_muc_fanout_effects(port, Some(&progress)).await?;
    progress.complete()?;
    Ok(true)
}

async fn run_muc_fanout_effects(
    port: &impl MucFanoutPort,
    progress: Option<&Fanout>,
) -> Result<(), Rejected> {
    if let Some(progress) = progress {
        progress.enter_cluster()?;
    }
    port.enter(MucFanoutStage::Cluster);
    port.publish_cluster().await;
    if let Some(progress) = progress {
        progress.cluster_returned()?;
    }
    port.enter(MucFanoutStage::Local);
    // Own all recipients before the privacy or endpoint futures are awaited.
    let recipients = port.recipients();
    if let Some(progress) = progress {
        progress.enter_privacy(recipients.len())?;
    }
    let blocked = port.blocked(&recipients).await;
    if let Some(progress) = progress {
        progress.privacy_returned()?;
    }
    for (index, recipient) in recipients.into_iter().enumerate() {
        if port.is_blocked(&recipient, &blocked) {
            if let Some(progress) = progress {
                progress.blocked(index)?;
            }
            continue;
        }
        if let Some(progress) = progress {
            progress.enter_delivery(index)?;
        }
        let accepted = port.deliver(&recipient).await;
        if let Some(progress) = progress {
            progress.delivery_returned(index, accepted)?;
        }
        if !accepted {
            port.record_failure(&recipient);
        }
    }
    Ok(())
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
        recipients: Vec<u8>,
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
                recipients: vec![1, 2, 3],
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
            self.recipients.clone()
        }

        async fn blocked<'a>(&'a self, recipients: &'a [u8]) -> Vec<u8> {
            assert_eq!(recipients, self.recipients.as_slice());
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

    #[tokio::test]
    async fn observed_discussion_keeps_acquired_order_and_completed_prefix() {
        use crate::services::muc::discussion::fixture;
        use northstar_room_application::discussion::FanoutStage;
        let (observation, completion) = fixture::accepted().await;
        let permit = completion.into_fanout(&observation).unwrap().unwrap();
        let mut port = Port::new();
        port.recipients = vec![3, 1, 2];
        port.blocked = vec![1];
        port.failed = vec![3];
        port.cluster_failed = true;
        assert!(run_muc_discussion_fanout(&port, permit).await.unwrap());
        let delivered = port
            .events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                Event::Deliver(recipient) => Some(*recipient),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(delivered, [3, 2]);
        let prefix = observation.snapshot().fanout;
        assert_eq!(prefix.stage, FanoutStage::Completed);
        assert_eq!(
            (prefix.blocked, prefix.accepted, prefix.rejected),
            (1, 1, 1)
        );
        assert_eq!(prefix.next_recipient, 3);
    }

    #[tokio::test]
    async fn observed_discussion_cancellation_retains_receipt_and_actual_effect_prefix() {
        use crate::services::muc::discussion::fixture;
        use northstar_room_application::discussion::{FanoutStage, KnowledgeClass, TerminalReason};
        for cut in 0..3 {
            let (observation, completion) = fixture::accepted().await;
            let permit = completion.into_fanout(&observation).unwrap().unwrap();
            let mut port = Port::new();
            if cut == 0 {
                port.pause = Some(MucFanoutStage::Cluster);
            }
            if cut == 1 {
                port.pause = Some(MucFanoutStage::Local);
            }
            if cut == 2 {
                port.pause_recipient = Some(2);
            }
            let gate = tokio::sync::Mutex::new(());
            let mut work = Box::pin(async {
                let _authority = gate.lock().await;
                run_muc_discussion_fanout(&port, permit).await
            });
            assert!(futures::poll!(&mut work).is_pending());
            assert!(gate.try_lock().is_err());
            let before = observation.snapshot();
            let events = port.events.lock().unwrap().clone();
            drop(work);
            assert!(gate.try_lock().is_ok());
            let summary = observation.retire(TerminalReason::Cancelled);
            assert_eq!(summary.knowledge, KnowledgeClass::ReceiptKnown);
            assert_eq!(summary.fanout, before.fanout);
            assert_eq!(*port.events.lock().unwrap(), events);
            assert_eq!(
                summary.fanout.stage,
                match cut {
                    0 => FanoutStage::ClusterEntered,
                    1 => FanoutStage::PrivacyEntered,
                    _ => FanoutStage::Delivering,
                }
            );
            assert_eq!(summary.fanout.accepted, usize::from(cut == 2));
            assert_eq!(summary.fanout.endpoint_pending, cut == 2);
        }
    }

    #[tokio::test]
    async fn retired_discussion_permit_cannot_start_any_live_effect() {
        use crate::services::muc::discussion::fixture;
        use northstar_room_application::discussion::TerminalReason;
        let (observation, completion) = fixture::accepted().await;
        let permit = completion.into_fanout(&observation).unwrap().unwrap();
        observation.retire(TerminalReason::Cancelled);
        let port = Port::new();
        assert_eq!(
            run_muc_discussion_fanout(&port, permit).await,
            Err(Rejected::Retired)
        );
        assert!(port.events.lock().unwrap().is_empty());
    }
}
