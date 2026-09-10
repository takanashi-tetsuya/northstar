//! Admission capability for background durable-delivery database turns.
//!
//! The primary application pool serves both foreground protocol work and
//! durable outbox workers.  A worker may wait for an external transport, but
//! it must never reserve a primary-pool connection while doing so.  This
//! capability therefore covers only one short database turn at a time across
//! MIX, PubSub, and clustered MUC delivery.  It deliberately does not gate
//! foreground mutations or socket/federation I/O.

use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_BACKGROUND_DATABASE_TURNS: usize = 16;

/// Clone-shared, FIFO admission for short durable-outbox database turns.
///
/// At least one configured primary-pool connection remains available to
/// foreground protocol traffic.  A one-connection deployment still permits a
/// single background recovery turn: withholding all recovery would make the
/// durable queue permanently unavailable.
#[derive(Clone, Debug)]
pub(crate) struct DurableOutboxDatabaseAdmission {
    permits: Arc<Semaphore>,
    capacity: usize,
}

impl DurableOutboxDatabaseAdmission {
    pub(crate) fn for_primary_pool(primary_pool_max_connections: u32) -> Self {
        let capacity = Self::capacity_for_primary_pool(primary_pool_max_connections);
        Self {
            permits: Arc::new(Semaphore::new(capacity)),
            capacity,
        }
    }

    pub(crate) fn capacity_for_primary_pool(primary_pool_max_connections: u32) -> usize {
        (primary_pool_max_connections as usize)
            .saturating_sub(1)
            .clamp(1, MAX_BACKGROUND_DATABASE_TURNS)
    }

    pub(crate) const fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    #[cfg(test)]
    pub(crate) fn shares_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.permits, &other.permits)
    }

    pub(crate) async fn acquire(&self) -> OwnedSemaphorePermit {
        self.permits
            .clone()
            .acquire_owned()
            .await
            .expect("durable outbox admission is owned by the application state")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_reserves_foreground_primary_pool_space() {
        assert_eq!(
            DurableOutboxDatabaseAdmission::capacity_for_primary_pool(1),
            1
        );
        assert_eq!(
            DurableOutboxDatabaseAdmission::capacity_for_primary_pool(2),
            1
        );
        assert_eq!(
            DurableOutboxDatabaseAdmission::capacity_for_primary_pool(3),
            2
        );
        assert_eq!(
            DurableOutboxDatabaseAdmission::capacity_for_primary_pool(17),
            16
        );
        assert_eq!(
            DurableOutboxDatabaseAdmission::capacity_for_primary_pool(u32::MAX),
            16
        );
    }

    #[tokio::test]
    async fn clones_share_one_fifo_database_admission() {
        let admission = DurableOutboxDatabaseAdmission::for_primary_pool(2);
        let first = admission.clone();
        let second = admission.clone();
        assert!(admission.shares_with(&first));
        assert!(admission.shares_with(&second));
        assert_eq!(admission.capacity(), 1);

        let held = admission.acquire().await;
        let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel();
        let (order_tx, mut order_rx) = tokio::sync::mpsc::unbounded_channel();
        let first_ready = ready_tx.clone();
        let first_order = order_tx.clone();
        let first_waiter = tokio::spawn(async move {
            first_ready.send(()).expect("test receiver remains open");
            let _guard = first.acquire().await;
            first_order.send(1_u8).expect("test receiver remains open");
        });
        ready_rx.recv().await.expect("first waiter started");
        tokio::task::yield_now().await;

        let second_waiter = tokio::spawn(async move {
            ready_tx.send(()).expect("test receiver remains open");
            let _guard = second.acquire().await;
            order_tx.send(2_u8).expect("test receiver remains open");
        });
        ready_rx.recv().await.expect("second waiter started");
        tokio::task::yield_now().await;

        drop(held);
        assert_eq!(order_rx.recv().await, Some(1));
        assert_eq!(order_rx.recv().await, Some(2));
        first_waiter.await.expect("first waiter completed");
        second_waiter.await.expect("second waiter completed");
    }
}
