use std::{
    cell::{Cell, RefCell},
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

type CommitResult = Result<(), &'static str>;

#[derive(Clone, Default)]
pub(crate) struct CommitControl {
    pub(crate) result: Rc<Cell<Option<CommitResult>>>,
    pub(crate) events: Rc<RefCell<Vec<&'static str>>>,
}

impl CommitControl {
    pub(crate) fn future<F: Fn() + Unpin>(&self, check_entry: F) -> ControlledCommit<F> {
        ControlledCommit {
            control: self.clone(),
            check_entry,
        }
    }
}

pub(crate) struct ControlledCommit<F> {
    control: CommitControl,
    check_entry: F,
}

impl<F: Fn() + Unpin> Future for ControlledCommit<F> {
    type Output = CommitResult;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        (self.check_entry)();
        self.control.events.borrow_mut().push("poll");
        match self.control.result.take() {
            Some(result) => Poll::Ready(result),
            None => Poll::Pending,
        }
    }
}

impl<F> Drop for ControlledCommit<F> {
    fn drop(&mut self) {
        self.control.events.borrow_mut().push("drop");
    }
}
