//! The island-mode gate in front of every federation write.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::RwLock;

pub struct FederationWritePolicy {
    gate: RwLock<()>,
    island_mode: Arc<AtomicBool>,
}

impl FederationWritePolicy {
    pub fn new(island_mode: bool) -> Self {
        Self {
            gate: RwLock::new(()),
            island_mode: Arc::new(AtomicBool::new(island_mode)),
        }
    }

    /// The HTTP API reports island mode from this flag without taking the gate.
    pub fn island_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.island_mode)
    }

    pub fn enabled(&self) -> bool {
        self.island_mode.load(Ordering::Acquire)
    }

    pub async fn apply(&self, enabled: bool) {
        let _write_guard = self.gate.write().await;
        self.island_mode.store(enabled, Ordering::Release);
    }

    pub async fn permit(&self) -> Option<tokio::sync::RwLockReadGuard<'_, ()>> {
        let guard = self.gate.read().await;
        (!self.island_mode.load(Ordering::Acquire)).then_some(guard)
    }

    pub async fn refresh(&self, enabled: bool) -> bool {
        // An unchanged observation linearizes at this acquire load. It must
        // not wait behind a socket write merely to publish the same value.
        // Actual transitions still drain and fence writes under the gate.
        let previous = self.island_mode.load(Ordering::Acquire);
        if previous == enabled {
            return previous;
        }
        let _write_guard = self.gate.write().await;
        self.island_mode.swap(enabled, Ordering::AcqRel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn unchanged_island_refresh_does_not_wait_for_held_read_guard() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        for enabled in [false, true] {
            let policy = FederationWritePolicy::new(enabled);
            let held_read = if enabled {
                // A raw reader also proves the true no-op does not acquire
                // the exclusive gate; delivery itself is already forbidden.
                policy.gate.read().await
            } else {
                policy.permit().await.expect("federation starts enabled")
            };
            let mut refresh = std::pin::pin!(policy.refresh(enabled));
            let mut context = Context::from_waker(Waker::noop());
            assert_eq!(refresh.as_mut().poll(&mut context), Poll::Ready(enabled));
            assert_eq!(policy.enabled(), enabled);
            drop(held_read);
        }
    }
    #[tokio::test]
    async fn island_refresh_transition_fences_queued_delivery_despite_concurrent_noop() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        let policy = FederationWritePolicy::new(false);
        let held_read = policy.permit().await.expect("federation starts enabled");
        let mut transition = std::pin::pin!(policy.refresh(true));
        let mut queued_delivery = std::pin::pin!(policy.permit());
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(transition.as_mut().poll(&mut context), Poll::Pending);
        assert!(queued_delivery.as_mut().poll(&mut context).is_pending());

        let mut unchanged = std::pin::pin!(policy.refresh(false));
        assert_eq!(unchanged.as_mut().poll(&mut context), Poll::Ready(false));
        assert!(!policy.enabled());
        assert_eq!(transition.as_mut().poll(&mut context), Poll::Pending);
        assert!(queued_delivery.as_mut().poll(&mut context).is_pending());

        drop(held_read);
        assert_eq!(transition.as_mut().poll(&mut context), Poll::Ready(false));
        assert!(policy.enabled());
        assert!(matches!(
            queued_delivery.as_mut().poll(&mut context),
            Poll::Ready(None)
        ));
    }
    #[tokio::test]
    async fn island_refresh_reopening_waits_for_gate_and_returns_locked_previous_value() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        for concurrent_apply in [false, true] {
            let policy = FederationWritePolicy::new(true);
            let held_read = policy.gate.read().await;
            let mut earlier_apply = std::pin::pin!(policy.apply(false));
            let mut context = Context::from_waker(Waker::noop());
            if concurrent_apply {
                assert_eq!(earlier_apply.as_mut().poll(&mut context), Poll::Pending);
            }
            let mut transition = std::pin::pin!(policy.refresh(false));
            let mut queued_delivery = std::pin::pin!(policy.permit());
            assert_eq!(transition.as_mut().poll(&mut context), Poll::Pending);
            assert!(queued_delivery.as_mut().poll(&mut context).is_pending());
            assert!(policy.enabled());

            drop(held_read);
            if concurrent_apply {
                assert_eq!(earlier_apply.as_mut().poll(&mut context), Poll::Ready(()));
                assert!(queued_delivery.as_mut().poll(&mut context).is_pending());
            }
            // The slow path returns the swap's value after the exclusive
            // wait, including when an earlier apply changed the initial read.
            assert_eq!(
                transition.as_mut().poll(&mut context),
                Poll::Ready(!concurrent_apply)
            );
            assert!(!policy.enabled());
            assert!(matches!(
                queued_delivery.as_mut().poll(&mut context),
                Poll::Ready(Some(_))
            ));
        }
    }
    #[tokio::test]
    async fn island_mode_transition_waits_for_and_fences_federation_writes() {
        let policy = Arc::new(FederationWritePolicy::new(false));
        let permit = policy.permit().await.expect("federation starts enabled");
        let transition_policy = Arc::clone(&policy);
        let transition = tokio::spawn(async move {
            transition_policy.apply(true).await;
        });

        tokio::task::yield_now().await;
        assert!(
            !transition.is_finished(),
            "the kill switch must wait for an in-flight socket-write boundary"
        );
        drop(permit);
        tokio::time::timeout(Duration::from_secs(1), transition)
            .await
            .expect("island transition completes after the write boundary")
            .expect("island transition task succeeds");
        assert!(policy.enabled());
        assert!(
            policy.permit().await.is_none(),
            "queued writers must observe island mode after the transition"
        );

        policy.apply(false).await;
        assert!(policy.permit().await.is_some());
    }
}
