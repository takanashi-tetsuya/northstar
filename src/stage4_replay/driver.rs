//! Test-only one-poll and side-recording helpers. No scheduler, timer, task,
//! retry loop, output oracle, owning permit, or production error substitution.
#![cfg(test)]
use super::{BudgetStop, DriverConfigurationError, Fact, PollSite, Recorder, ResourceStop};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
};

pub(crate) type Capture = Arc<Mutex<Recorder>>;

// Only this recorder mutex's poison is handled. Projection/owner panics are
// not caught. In particular, a domain future is never polled under this lock.
fn locked(capture: &Capture) -> MutexGuard<'_, Recorder> {
    match capture.lock() {
        Ok(recorder) => recorder,
        Err(poison) => {
            let mut recorder = poison.into_inner();
            recorder.missing_observation();
            recorder
        }
    }
}

pub(crate) fn lost(capture: &Capture) {
    locked(capture).missing_observation();
}

/// Factual side recording only. Recording loss cannot change an owner result.
pub(crate) fn emit(capture: &Capture, fact: Fact) {
    let mut recorder = locked(capture);
    if recorder.capture(fact).is_err() {
        recorder.missing_observation();
    }
}

/// Only data projection belongs here, never preparation or an owner operation.
/// The closure runs outside the recorder lock. Its error is missing evidence,
/// not a callback false, backend failure, or replacement domain result.
pub(crate) fn project<T, E>(capture: &Capture, make: impl FnOnce() -> Result<T, E>) -> Option<T> {
    match make() {
        Ok(value) => Some(value),
        Err(_) => {
            lost(capture);
            None
        }
    }
}

pub(crate) fn emit_projected<E>(capture: &Capture, make: impl FnOnce() -> Result<Fact, E>) {
    if let Some(fact) = project(capture, make) {
        emit(capture, fact);
    }
}

pub(crate) fn resource_stop(capture: &Capture) -> Option<BudgetStop> {
    locked(capture)
        .resource_stop()
        .cloned()
        .map(|resource_stop| BudgetStop { resource_stop })
}

/// A writer supplies its actual independently bounded counter/preflight result.
/// Invalid internal metadata is a construction error, never input rejection or
/// a synthetic IO failure. Validate item ordinals before constructing owners.
pub(crate) fn latch_resource_stop(
    capture: &Capture,
    stop: ResourceStop,
) -> Result<BudgetStop, DriverConfigurationError> {
    locked(capture).latch_resource_stop(stop)
}

/// Poll one declared owner exactly once. Validate `site` before constructing
/// owners. No lock survives into Future::poll, and no capture error is propagated
/// into that future's output. A nested stop takes precedence over both Pending
/// and Ready; the caller must drop its still-retained future before classifying
/// the cut or capturing post-drop terminal state.
///
/// Meter each declared owning boundary once. Normal Publisher callback/service
/// awaits are not additional sites. Do not meter both a wrapper and the same
/// child owner again. A nested writer latches a cut and yields one Pending; this
/// function immediately sees that latch, with no scheduled retry or hang.
pub(crate) fn poll_once<F: Future + ?Sized>(
    capture: &Capture,
    site: PollSite,
    future: Pin<&mut F>,
    context: &mut Context<'_>,
) -> Result<Poll<F::Output>, BudgetStop> {
    {
        let mut recorder = locked(capture);
        recorder.reserve_owner_poll(site)?;
    }
    let actual = future.poll(context);
    {
        let mut recorder = locked(capture);
        // This is a retained observation count only; admission was charged once
        // above, independently of this call's success or an earlier sticky loss.
        let _ = recorder.polled(site.owner(), site.owner_ordinal(), &actual);
        if let Some(stop) = recorder.resource_stop() {
            return Err(BudgetStop {
                resource_stop: stop.clone(),
            });
        }
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stage4_replay::{self as wire, DriverOwner, Loss, NativeResourceStop};
    use std::{cell::Cell, rc::Rc, task::Waker};

    fn capture() -> Capture {
        Arc::new(Mutex::new(Recorder::new(&wire::tests::input_case())))
    }
    fn site() -> PollSite {
        PollSite::new(DriverOwner::Worker, 0).unwrap()
    }
    struct CountedPending {
        polls: Rc<Cell<u8>>,
        dropped: Rc<Cell<bool>>,
        capture: Capture,
    }
    impl Future for CountedPending {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            // Reentrant side recording proves the recorder lock was released.
            assert!(self.capture.try_lock().is_ok());
            self.polls.set(self.polls.get() + 1);
            Poll::Pending
        }
    }
    impl Drop for CountedPending {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    #[test]
    fn no_sixty_fifth_future_poll_after_sticky_capture_loss() {
        let capture = capture();
        lost(&capture);
        let polls = Rc::new(Cell::new(0));
        let dropped = Rc::new(Cell::new(false));
        let mut future = Box::pin(CountedPending {
            polls: polls.clone(),
            dropped: dropped.clone(),
            capture: capture.clone(),
        });
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..64 {
            assert!(matches!(
                poll_once(&capture, site(), future.as_mut(), &mut context),
                Ok(Poll::Pending)
            ));
        }
        assert!(poll_once(&capture, site(), future.as_mut(), &mut context).is_err());
        assert_eq!(polls.get(), 64);
        assert_eq!(locked(&capture).admitted_owner_polls(), 64);
        assert!(!dropped.get());
        drop(future);
        assert!(dropped.get());
        assert!(matches!(
            resource_stop(&capture).unwrap().resource_stop,
            ResourceStop::DriverPoll(wire::DriverResourceStop {
                admitted_calls: 64,
                ..
            })
        ));
    }

    struct NestedCut {
        capture: Capture,
        ready: bool,
        polls: Rc<Cell<u8>>,
    }
    impl Future for NestedCut {
        type Output = Result<bool, &'static str>;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.set(self.polls.get() + 1);
            latch_resource_stop(
                &self.capture,
                ResourceStop::NativeWrite(NativeResourceStop {
                    item_ordinal: 4,
                    admitted_calls: 0,
                }),
            )
            .unwrap();
            if self.ready {
                Poll::Ready(Ok(true))
            } else {
                Poll::Pending
            }
        }
    }

    #[test]
    fn nested_cut_is_checked_before_interpreting_pending_or_ready() {
        for ready in [false, true] {
            let capture = capture();
            let polls = Rc::new(Cell::new(0));
            let mut future = Box::pin(NestedCut {
                capture: capture.clone(),
                ready,
                polls: polls.clone(),
            });
            let mut context = Context::from_waker(Waker::noop());
            let stop = poll_once(
                &capture,
                PollSite::new(DriverOwner::Muc, 0).unwrap(),
                future.as_mut(),
                &mut context,
            )
            .unwrap_err();
            assert_eq!(
                stop.resource_stop,
                ResourceStop::NativeWrite(NativeResourceStop {
                    item_ordinal: 4,
                    admitted_calls: 0
                })
            );
            assert_eq!(polls.get(), 1);
            drop(future);
        }
    }

    #[test]
    fn side_emit_and_projection_loss_never_replace_real_owner_output() {
        let capture = capture();
        assert!(project::<(), _>(&capture, || Err("projection only")).is_none());
        emit_projected(&capture, || Err::<Fact, _>("projection only"));
        let mut future = Box::pin(std::future::ready(Err::<(), _>("actual owner error")));
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            poll_once(&capture, site(), future.as_mut(), &mut context),
            Ok(Poll::Ready(Err("actual owner error")))
        );
        emit(
            &capture,
            Fact::Driver(wire::DriverPoll {
                owner: DriverOwner::Worker,
                owner_ordinal: 0,
                result: wire::PollResult::Ready,
            }),
        );
        assert!(resource_stop(&capture).is_none());
        assert_eq!(locked(&capture).admitted_owner_polls(), 1);
        // Projection executes outside the recorder lock, even when already lost.
        assert_eq!(
            project(&capture, || {
                assert!(capture.try_lock().is_ok());
                Ok::<_, ()>(7)
            }),
            Some(7)
        );
        drop(future);
        let recorder = Arc::try_unwrap(capture).ok().unwrap().into_inner().unwrap();
        let envelope = recorder.finish(wire::Execution::Failed).unwrap();
        assert!(matches!(
            envelope.observation_status,
            wire::ObservationStatus::Lost(wire::LostObservation {
                reason: Loss::MissingObservation,
                ..
            })
        ));
    }

    #[test]
    fn non_stopped_pending_remains_pending_without_fabricated_failure() {
        let capture = capture();
        let mut future = Box::pin(std::future::pending::<Result<bool, &'static str>>());
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            poll_once(&capture, site(), future.as_mut(), &mut context),
            Ok(Poll::Pending)
        );
        assert!(resource_stop(&capture).is_none());
        drop(future);
    }

    #[test]
    fn scoped_recorder_poison_marks_loss_without_changing_owner_result() {
        let capture = capture();
        // Only the control deliberately induces/catches a panic. Production
        // helpers do not catch owner/projection panics or claim broad recovery.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = capture.lock().unwrap();
            panic!("recorder poison control");
        }));
        let mut future = Box::pin(std::future::ready(41));
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            poll_once(&capture, site(), future.as_mut(), &mut context),
            Ok(Poll::Ready(41))
        );
        assert_eq!(locked(&capture).admitted_owner_polls(), 1);
        assert!(resource_stop(&capture).is_none());
        drop(future);
        let recorder = Arc::try_unwrap(capture)
            .ok()
            .unwrap()
            .into_inner()
            .unwrap_or_else(|p| p.into_inner());
        assert!(matches!(
            recorder
                .finish(wire::Execution::Complete)
                .unwrap()
                .observation_status,
            wire::ObservationStatus::Lost(wire::LostObservation {
                reason: Loss::MissingObservation,
                ..
            })
        ));
    }
}
