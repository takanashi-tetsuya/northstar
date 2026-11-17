use crate::mix_service::outbox::{core, fixture};
use anyhow::Result;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

struct Child<T> {
    output: Option<Result<T>>,
    terminal: Box<dyn Fn() -> Option<core::TerminalReason> + Send>,
    drops: Arc<Mutex<Vec<Option<core::TerminalReason>>>>,
    pending: bool,
    poll_panics: bool,
    drop_panics: bool,
}

impl<T: Unpin> Future for Child<T> {
    type Output = Result<T>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        assert!(!this.poll_panics, "child poll panic");
        if this.pending {
            Poll::Pending
        } else {
            Poll::Ready(this.output.take().expect("polled once"))
        }
    }
}

impl<T> Drop for Child<T> {
    fn drop(&mut self) {
        self.drops.lock().unwrap().push((self.terminal)());
        assert!(!self.drop_panics, "child destruction panic");
    }
}

pub(super) fn worker_holders_destroy_children_before_retirement_even_during_panics() {
    for (label, pending, poll_panics, drop_panics, fails, expected) in [
        (
            "completed",
            false,
            false,
            false,
            false,
            core::TerminalReason::Completed,
        ),
        (
            "backend failed",
            false,
            false,
            false,
            true,
            core::TerminalReason::BackendFailure,
        ),
        (
            "cancelled",
            true,
            false,
            false,
            false,
            core::TerminalReason::Cancelled,
        ),
        (
            "poll panic",
            false,
            true,
            false,
            false,
            core::TerminalReason::Panicked,
        ),
        (
            "pending destruction panic",
            true,
            false,
            true,
            false,
            core::TerminalReason::Panicked,
        ),
        (
            "ready destruction panic",
            false,
            false,
            true,
            false,
            core::TerminalReason::Panicked,
        ),
    ] {
        macro_rules! holder {
            ($factory:path, $output:expr) => {{
                let drops = Arc::new(Mutex::new(Vec::new()));
                let witness = drops.clone();
                let (owner, mut run) = $factory(|owner| {
                    let observation = owner.clone();
                    Box::pin(Child {
                        output: Some(if fails {
                            Err(anyhow::anyhow!("child failure"))
                        } else {
                            Ok($output)
                        }),
                        terminal: Box::new(move || observation.snapshot().terminal),
                        drops: witness,
                        pending,
                        poll_panics,
                        drop_panics,
                    })
                });
                let outcome = catch_unwind(AssertUnwindSafe(move || {
                    let mut context = Context::from_waker(futures::task::noop_waker_ref());
                    match Pin::new(&mut run).poll(&mut context) {
                        Poll::Pending => assert!(pending, "{label}"),
                        Poll::Ready(result) => {
                            assert!(!pending, "{label}");
                            assert_eq!(result.is_err(), fails, "{label}");
                        }
                    }
                    drop(run);
                }));
                assert_eq!(outcome.is_err(), poll_panics || drop_panics, "{label}");
                assert_eq!(
                    *drops.lock().unwrap(),
                    [None],
                    "child dropped before retirement: {label}"
                );
                assert_eq!(owner.snapshot().terminal, Some(expected), "{label}");
            }};
        }
        holder!(fixture::claim_probe, Vec::new());
        holder!(fixture::attempt_probe, ());
    }
}
