//! Bounded admission for PubSub mutations.

use anyhow::{Error, Result};
use northstar_telemetry::admission_gauges::{
    PUBSUB_MUTATION_ADMISSION_ACTIVE, PUBSUB_MUTATION_ADMISSION_REJECTIONS_TOTAL,
    PUBSUB_MUTATION_ADMISSION_WAITERS,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout_at, Instant};

const PUBSUB_MUTATION_ADMISSION_TIMEOUT: Duration = Duration::from_secs(2);
const PUBSUB_MUTATION_OWNER_STRIPES: usize = 64;
const PUBSUB_MUTATION_MAX_TRANSACTIONS: usize = 8;

#[derive(Debug)]
pub struct PubSubMutationBusy;

impl std::fmt::Display for PubSubMutationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pubsub mutation admission rejected due to bounded concurrency")
    }
}

impl std::error::Error for PubSubMutationBusy {}

/// True only for retryable PubSub capacity/lock pressure errors.
pub fn is_pubsub_mutation_busy(error: &Error) -> bool {
    error.downcast_ref::<PubSubMutationBusy>().is_some()
}

struct PubSubAdmissionWaiter;

impl PubSubAdmissionWaiter {
    fn enter() -> Self {
        PUBSUB_MUTATION_ADMISSION_WAITERS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for PubSubAdmissionWaiter {
    fn drop(&mut self) {
        PUBSUB_MUTATION_ADMISSION_WAITERS.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub struct PubSubMutationPermit {
    _owner_permits: Vec<OwnedSemaphorePermit>,
    _graph_permit: Option<OwnedSemaphorePermit>,
    _transaction_permit: OwnedSemaphorePermit,
}

impl Drop for PubSubMutationPermit {
    fn drop(&mut self) {
        PUBSUB_MUTATION_ADMISSION_ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct PubSubMutationAdmission {
    owner_stripes: Box<[Arc<Semaphore>]>,
    graph: Arc<Semaphore>,
    transactions: Arc<Semaphore>,
}

impl PubSubMutationAdmission {
    pub fn new(pool_max_connections: usize) -> Self {
        let transaction_limit = pool_max_connections
            .saturating_sub(1)
            .clamp(1, PUBSUB_MUTATION_MAX_TRANSACTIONS);
        Self {
            owner_stripes: (0..PUBSUB_MUTATION_OWNER_STRIPES)
                .map(|_| Arc::new(Semaphore::new(1)))
                .collect(),
            graph: Arc::new(Semaphore::new(1)),
            transactions: Arc::new(Semaphore::new(transaction_limit)),
        }
    }

    fn stripe(key: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish() as usize % PUBSUB_MUTATION_OWNER_STRIPES
    }

    async fn acquire_owned_before(
        semaphore: Arc<Semaphore>,
        deadline: Instant,
    ) -> Result<OwnedSemaphorePermit> {
        timeout_at(deadline, semaphore.acquire_owned())
            .await
            .map_err(|_| PubSubMutationBusy)?
            .map_err(|_| PubSubMutationBusy.into())
    }

    pub async fn acquire(&self, keys: &[&str], graph: bool) -> Result<PubSubMutationPermit> {
        self.acquire_with_timeout(keys, graph, PUBSUB_MUTATION_ADMISSION_TIMEOUT)
            .await
    }

    pub async fn acquire_with_timeout(
        &self,
        keys: &[&str],
        graph: bool,
        wait: Duration,
    ) -> Result<PubSubMutationPermit> {
        let _waiter = PubSubAdmissionWaiter::enter();
        let deadline = Instant::now() + wait;
        let mut stripes = keys.iter().map(|key| Self::stripe(key)).collect::<Vec<_>>();
        stripes.sort_unstable();
        stripes.dedup();

        let result = async {
            let mut owner_permits = Vec::with_capacity(stripes.len());
            for stripe in stripes {
                owner_permits.push(
                    Self::acquire_owned_before(Arc::clone(&self.owner_stripes[stripe]), deadline)
                        .await?,
                );
            }
            let graph_permit = if graph {
                Some(Self::acquire_owned_before(Arc::clone(&self.graph), deadline).await?)
            } else {
                None
            };
            let transaction_permit =
                Self::acquire_owned_before(Arc::clone(&self.transactions), deadline).await?;
            Ok(PubSubMutationPermit {
                _owner_permits: owner_permits,
                _graph_permit: graph_permit,
                _transaction_permit: transaction_permit,
            })
        }
        .await;

        match result {
            Ok(permit) => {
                PUBSUB_MUTATION_ADMISSION_ACTIVE.fetch_add(1, Ordering::Relaxed);
                Ok(permit)
            }
            Err(error) => {
                PUBSUB_MUTATION_ADMISSION_REJECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
                Err(error)
            }
        }
    }

    pub fn available_transaction_permits(&self) -> usize {
        self.transactions.available_permits()
    }
}
