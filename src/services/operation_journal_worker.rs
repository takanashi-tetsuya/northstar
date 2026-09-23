//! Claim the next administrator-operation target after renewing its parent lease.
//! A cancellation acknowledgement is attempted only after a no-target claim has
//! committed, so it cannot race with an uncommitted target transition.

use anyhow::Result;
use serde_json::Value;
use std::future::Future;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) enum TargetClaim<T> {
    LeaseLost,
    Claimed(T),
    NoTarget,
}

pub(crate) enum NextTarget<T> {
    LeaseLost,
    Claimed(T),
    Cancelled,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseRenewal {
    Renewed,
    Lost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TargetSettlement {
    Succeeded,
    Indeterminate,
    NotApplied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParentTerminalization {
    Succeeded,
    FailedIncomplete,
    LeaseLost,
}

pub(crate) trait OperationJournalWorkerRepository: Send + Sync {
    type Parent;
    type Target;

    fn claim_target(
        &self,
        parent: &Self::Parent,
        worker_id: Uuid,
        lease_seconds: i64,
    ) -> impl Future<Output = Result<TargetClaim<Self::Target>>> + Send;

    fn acknowledge_cancel(
        &self,
        parent: &Self::Parent,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn renew_effect_leases(
        &self,
        parent: &Self::Parent,
        target: &Self::Target,
        lease_seconds: i64,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn succeed_target(
        &self,
        target: &Self::Target,
        result: &Value,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn mark_target_indeterminate(
        &self,
        parent: &Self::Parent,
        target: &Self::Target,
        operation_id: Uuid,
        target_id: Uuid,
        error: &anyhow::Error,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn terminalize_parent(
        &self,
        parent: &Self::Parent,
    ) -> impl Future<Output = Result<ParentTerminalization>> + Send;
}

pub(crate) struct OperationJournalWorkerService<R> {
    repository: R,
}

impl<R: OperationJournalWorkerRepository> OperationJournalWorkerService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn next_target(
        &self,
        parent: &R::Parent,
        worker_id: Uuid,
        lease_seconds: i64,
    ) -> Result<NextTarget<R::Target>> {
        match self
            .repository
            .claim_target(parent, worker_id, lease_seconds)
            .await?
        {
            TargetClaim::LeaseLost => Ok(NextTarget::LeaseLost),
            TargetClaim::Claimed(target) => Ok(NextTarget::Claimed(target)),
            TargetClaim::NoTarget => {
                if self.repository.acknowledge_cancel(parent).await? {
                    Ok(NextTarget::Cancelled)
                } else {
                    Ok(NextTarget::Exhausted)
                }
            }
        }
    }

    pub(crate) async fn renew_effect_leases(
        &self,
        parent: &R::Parent,
        target: &R::Target,
        lease_seconds: i64,
    ) -> Result<LeaseRenewal> {
        if self
            .repository
            .renew_effect_leases(parent, target, lease_seconds)
            .await?
        {
            Ok(LeaseRenewal::Renewed)
        } else {
            Ok(LeaseRenewal::Lost)
        }
    }

    /// The effect has already crossed its durable point of no return. An
    /// executor error therefore becomes indeterminate rather than retryable.
    pub(crate) async fn settle_target(
        &self,
        parent: &R::Parent,
        target: &R::Target,
        operation_id: Uuid,
        target_id: Uuid,
        effect: Result<Value>,
    ) -> Result<TargetSettlement> {
        match effect {
            Ok(result) => {
                if self.repository.succeed_target(target, &result).await? {
                    Ok(TargetSettlement::Succeeded)
                } else {
                    Ok(TargetSettlement::NotApplied)
                }
            }
            Err(error) => {
                if self
                    .repository
                    .mark_target_indeterminate(parent, target, operation_id, target_id, &error)
                    .await?
                {
                    Ok(TargetSettlement::Indeterminate)
                } else {
                    Ok(TargetSettlement::NotApplied)
                }
            }
        }
    }

    pub(crate) async fn terminalize_parent(
        &self,
        parent: &R::Parent,
    ) -> Result<ParentTerminalization> {
        self.repository.terminalize_parent(parent).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct RecordingRepository {
        events: Arc<Mutex<Vec<&'static str>>>,
        claim: TargetClaim<usize>,
        cancelled: bool,
        renewed: bool,
        target_settled: bool,
        parent_terminalization: ParentTerminalization,
        details: Arc<Mutex<Option<Value>>>,
    }

    impl OperationJournalWorkerRepository for RecordingRepository {
        type Parent = ();
        type Target = usize;

        async fn claim_target(&self, _: &(), _: Uuid, _: i64) -> Result<TargetClaim<usize>> {
            self.events.lock().unwrap().push("claim-committed");
            Ok(match self.claim {
                TargetClaim::LeaseLost => TargetClaim::LeaseLost,
                TargetClaim::Claimed(target) => TargetClaim::Claimed(target),
                TargetClaim::NoTarget => TargetClaim::NoTarget,
            })
        }

        async fn acknowledge_cancel(&self, _: &()) -> Result<bool> {
            self.events.lock().unwrap().push("cancel-committed");
            Ok(self.cancelled)
        }

        async fn renew_effect_leases(&self, _: &(), _: &usize, _: i64) -> Result<bool> {
            self.events.lock().unwrap().push("renew-committed");
            Ok(self.renewed)
        }

        async fn succeed_target(&self, _: &usize, _: &Value) -> Result<bool> {
            self.events.lock().unwrap().push("target-success-committed");
            Ok(self.target_settled)
        }

        async fn mark_target_indeterminate(
            &self,
            _: &(),
            _: &usize,
            _: Uuid,
            _: Uuid,
            error: &anyhow::Error,
        ) -> Result<bool> {
            self.events
                .lock()
                .unwrap()
                .push("target-indeterminate-committed");
            *self.details.lock().unwrap() = Some(serde_json::json!({"message":error.to_string()}));
            Ok(self.target_settled)
        }

        async fn terminalize_parent(&self, _: &()) -> Result<ParentTerminalization> {
            self.events
                .lock()
                .unwrap()
                .push("parent-terminal-committed");
            Ok(self.parent_terminalization)
        }
    }

    #[tokio::test]
    async fn cancellation_only_follows_a_committed_no_target_claim() {
        for (claim, cancelled, expected, expected_events) in [
            (
                TargetClaim::LeaseLost,
                false,
                "lease-lost",
                vec!["claim-committed"],
            ),
            (
                TargetClaim::Claimed(7),
                false,
                "claimed",
                vec!["claim-committed"],
            ),
            (
                TargetClaim::NoTarget,
                true,
                "cancelled",
                vec!["claim-committed", "cancel-committed"],
            ),
            (
                TargetClaim::NoTarget,
                false,
                "exhausted",
                vec!["claim-committed", "cancel-committed"],
            ),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let service = OperationJournalWorkerService::new(RecordingRepository {
                events: Arc::clone(&events),
                claim,
                cancelled,
                renewed: true,
                target_settled: true,
                parent_terminalization: ParentTerminalization::Succeeded,
                details: Arc::new(Mutex::new(None)),
            });
            let outcome = service.next_target(&(), Uuid::new_v4(), 60).await.unwrap();
            let actual = match outcome {
                NextTarget::LeaseLost => "lease-lost",
                NextTarget::Claimed(7) => "claimed",
                NextTarget::Claimed(_) => "unexpected-target",
                NextTarget::Cancelled => "cancelled",
                NextTarget::Exhausted => "exhausted",
            };
            assert_eq!(actual, expected);
            assert_eq!(*events.lock().unwrap(), expected_events);
        }
    }

    #[tokio::test]
    async fn heartbeat_reports_exact_joint_lease_outcome() {
        for (renewed, expected) in [(true, LeaseRenewal::Renewed), (false, LeaseRenewal::Lost)] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let service = OperationJournalWorkerService::new(RecordingRepository {
                events: Arc::clone(&events),
                claim: TargetClaim::NoTarget,
                cancelled: false,
                renewed,
                target_settled: true,
                parent_terminalization: ParentTerminalization::Succeeded,
                details: Arc::new(Mutex::new(None)),
            });
            assert_eq!(
                service.renew_effect_leases(&(), &7, 60).await.unwrap(),
                expected
            );
            assert_eq!(*events.lock().unwrap(), vec!["renew-committed"]);
        }
    }

    #[tokio::test]
    async fn post_ponr_error_is_recorded_as_indeterminate_and_never_as_success() {
        for (target_settled, expected) in [
            (true, TargetSettlement::Indeterminate),
            (false, TargetSettlement::NotApplied),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let details = Arc::new(Mutex::new(None));
            let service = OperationJournalWorkerService::new(RecordingRepository {
                events: Arc::clone(&events),
                claim: TargetClaim::NoTarget,
                cancelled: false,
                renewed: true,
                target_settled,
                parent_terminalization: ParentTerminalization::Succeeded,
                details: Arc::clone(&details),
            });
            assert_eq!(
                service
                    .settle_target(
                        &(),
                        &7,
                        Uuid::new_v4(),
                        Uuid::new_v4(),
                        Err(anyhow::anyhow!("effect acknowledgement lost")),
                    )
                    .await
                    .unwrap(),
                expected
            );
            assert_eq!(
                *events.lock().unwrap(),
                vec!["target-indeterminate-committed"]
            );
            assert_eq!(
                *details.lock().unwrap(),
                Some(serde_json::json!({"message":"effect acknowledgement lost"}))
            );
        }
    }

    #[tokio::test]
    async fn successful_effect_only_records_target_success() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let details = Arc::new(Mutex::new(None));
        let service = OperationJournalWorkerService::new(RecordingRepository {
            events: Arc::clone(&events),
            claim: TargetClaim::NoTarget,
            cancelled: false,
            renewed: true,
            target_settled: true,
            parent_terminalization: ParentTerminalization::Succeeded,
            details: Arc::clone(&details),
        });
        assert_eq!(
            service
                .settle_target(
                    &(),
                    &7,
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    Ok(serde_json::json!({"delivered":true})),
                )
                .await
                .unwrap(),
            TargetSettlement::Succeeded
        );
        assert_eq!(*events.lock().unwrap(), vec!["target-success-committed"]);
        assert_eq!(*details.lock().unwrap(), None);
    }
}
