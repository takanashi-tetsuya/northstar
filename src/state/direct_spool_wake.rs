//! Process-local, bounded consumer of committed direct-spool wake hints.
//! PostgreSQL owns each wake revision; this state only remembers one finite
//! route sweep between short, compare-and-swap deferred claims.

use super::{cluster_recovery_replay::RecoveryReplayStatus, AppState};
use crate::{
    cluster::{ClusterReadinessAuthority, DirectPostCommitMode},
    db::direct_spool_wake_repository::PostgresDirectSpoolWakeRepository,
    services::direct_spool_wake::{
        ClaimedDirectSpoolWake, DirectSpoolWakeRoute, DirectSpoolWakeService,
        DIRECT_SPOOL_WAKE_PAGE,
    },
};
use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::Duration,
};
use uuid::Uuid;

const CLAIMS_PER_PASS: i32 = 8;
const MAX_LOCAL_PLANS: usize = 256;
const MAX_ROUTE_OBSERVATIONS: u8 = 4;
const SHORT_RETRY: Duration = Duration::from_secs(1);
const INCOMPLETE_RETRY: Duration = Duration::from_secs(300);

struct PendingRoute {
    route: DirectSpoolWakeRoute,
    observations: u8,
}

struct RecipientPlan {
    instance_uuid: Uuid,
    instance_epoch: i64,
    epoch: u64,
    cutoff: DateTime<Utc>,
    cursor: Option<String>,
    pending: VecDeque<PendingRoute>,
    exhausted: bool,
    incomplete: bool,
}

impl RecipientPlan {
    fn new(instance_uuid: Uuid, instance_epoch: i64, epoch: u64, cutoff: DateTime<Utc>) -> Self {
        Self {
            instance_uuid,
            instance_epoch,
            epoch,
            cutoff,
            cursor: None,
            pending: VecDeque::new(),
            exhausted: false,
            incomplete: false,
        }
    }
}

fn take_plan(
    plans: &mut HashMap<(Uuid, Uuid), RecipientPlan>,
    wake: &ClaimedDirectSpoolWake,
    instance_uuid: Uuid,
    instance_epoch: i64,
    next_epoch: impl FnOnce() -> u64,
) -> RecipientPlan {
    let key = (wake.recipient_id, wake.revision);
    plans.retain(|(recipient_id, revision), _| {
        *recipient_id != wake.recipient_id || *revision == wake.revision
    });
    plans
        .remove(&key)
        .filter(|plan| plan.instance_uuid == instance_uuid && plan.instance_epoch == instance_epoch)
        .unwrap_or_else(|| {
            RecipientPlan::new(instance_uuid, instance_epoch, next_epoch(), wake.cutoff)
        })
}

pub(crate) struct DirectSpoolWakeConsumer {
    service: DirectSpoolWakeService<PostgresDirectSpoolWakeRepository>,
    replay: super::cluster_recovery_replay::ClusterRecoveryReplayWake,
    plans: Mutex<HashMap<(Uuid, Uuid), RecipientPlan>>,
}

impl DirectSpoolWakeConsumer {
    pub(crate) fn new(
        service: DirectSpoolWakeService<PostgresDirectSpoolWakeRepository>,
        replay: super::cluster_recovery_replay::ClusterRecoveryReplayWake,
    ) -> Self {
        Self {
            service,
            replay,
            plans: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn cleanup(&self) -> Result<i64> {
        self.service.cleanup(DIRECT_SPOOL_WAKE_PAGE).await
    }

    pub(crate) async fn drive_once(
        &self,
        authority: &ClusterReadinessAuthority,
        mut next_epoch: impl FnMut() -> u64,
    ) -> Result<()> {
        if self.replay.direct_mode() != DirectPostCommitMode::Live {
            return Ok(());
        }
        let wakes = self.service.claim(authority, CLAIMS_PER_PASS).await?;
        for wake in wakes {
            if self.replay.direct_mode() != DirectPostCommitMode::Live {
                // A revision stays durable even when this best-effort release
                // fails; its PostgreSQL claim expires for the next healthy pass.
                let _ = self.service.defer(authority, &wake, SHORT_RETRY).await;
                continue;
            }
            if let Err(error) = self.process_one(authority, &wake, &mut next_epoch).await {
                let _ = self.service.defer(authority, &wake, INCOMPLETE_RETRY).await;
                return Err(error);
            }
        }
        Ok(())
    }

    async fn process_one(
        &self,
        authority: &ClusterReadinessAuthority,
        wake: &ClaimedDirectSpoolWake,
        next_epoch: &mut impl FnMut() -> u64,
    ) -> Result<()> {
        let mut plan = {
            let mut plans = self.plans.lock().unwrap_or_else(|e| e.into_inner());
            take_plan(
                &mut plans,
                wake,
                authority.instance_uuid,
                authority.instance_epoch,
                next_epoch,
            )
        };
        ensure!(plan.epoch != 0, "direct spool wake epoch exhausted");

        if plan.pending.is_empty() && !plan.exhausted {
            let routes = self
                .service
                .routes_page(
                    authority,
                    wake.recipient_id,
                    plan.cursor.as_deref(),
                    DIRECT_SPOOL_WAKE_PAGE,
                )
                .await?;
            ensure!(
                routes.len() <= DIRECT_SPOOL_WAKE_PAGE as usize
                    && routes
                        .windows(2)
                        .all(|pair| pair[0].full_jid < pair[1].full_jid)
                    && routes.first().is_none_or(|first| {
                        plan.cursor
                            .as_deref()
                            .is_none_or(|cursor| first.full_jid.as_str() > cursor)
                    }),
                "direct spool route page is not strictly ordered"
            );
            if routes.is_empty() {
                plan.exhausted = true;
            } else {
                plan.exhausted = routes.len() < DIRECT_SPOOL_WAKE_PAGE as usize;
                plan.cursor = routes.last().map(|route| route.full_jid.clone());
                plan.pending
                    .extend(routes.into_iter().map(|route| PendingRoute {
                        route,
                        observations: 0,
                    }));
            }
        }

        let count = plan.pending.len().min(DIRECT_SPOOL_WAKE_PAGE as usize);
        for _ in 0..count {
            if self.replay.direct_mode() != DirectPostCommitMode::Live {
                self.defer_and_retain(authority, wake, plan, SHORT_RETRY)
                    .await?;
                return Ok(());
            }
            let mut pending = plan.pending.pop_front().expect("bounded route page");
            match self.replay.recipient_completion_state(
                wake.recipient_id,
                &pending.route.full_jid,
                pending.route.connection_id,
                plan.epoch,
            ) {
                RecoveryReplayStatus::Complete => {}
                RecoveryReplayStatus::Stale
                | RecoveryReplayStatus::Ineligible
                | RecoveryReplayStatus::AwaitEligibility => {
                    plan.incomplete = true;
                }
                RecoveryReplayStatus::InFlight => {
                    pending.observations = pending.observations.saturating_add(1);
                    if pending.observations < MAX_ROUTE_OBSERVATIONS {
                        plan.pending.push_back(pending);
                    } else {
                        plan.incomplete = true;
                    }
                }
                RecoveryReplayStatus::Retryable => {
                    let _ = self.replay.request_for_recipient(
                        wake.recipient_id,
                        &pending.route.full_jid,
                        pending.route.connection_id,
                        plan.cutoff,
                        plan.epoch,
                    );
                    pending.observations = pending.observations.saturating_add(1);
                    if pending.observations < MAX_ROUTE_OBSERVATIONS {
                        plan.pending.push_back(pending);
                    } else {
                        plan.incomplete = true;
                    }
                }
            }
        }

        if plan.exhausted && plan.pending.is_empty() {
            if self.replay.direct_mode() != DirectPostCommitMode::Live {
                self.defer_and_retain(authority, wake, plan, SHORT_RETRY)
                    .await?;
                return Ok(());
            }
            // PostgreSQL serializes this empty-queue probe and revision ACK
            // against a producer upsert. Route completion alone cannot prove
            // that a late bind or resource-affine row is safe to forget.
            if self.service.acknowledge_if_empty(authority, wake).await? {
                return Ok(());
            }
            if plan.incomplete {
                tracing::debug!(recipient_id = %wake.recipient_id, revision = %wake.revision,
                    "direct spool wake route sweep incomplete; durable row retained for retry");
            }
            self.service
                .defer(authority, wake, INCOMPLETE_RETRY)
                .await?;
            return Ok(());
        }
        self.defer_and_retain(authority, wake, plan, SHORT_RETRY)
            .await
    }

    async fn defer_and_retain(
        &self,
        authority: &ClusterReadinessAuthority,
        wake: &ClaimedDirectSpoolWake,
        plan: RecipientPlan,
        delay: Duration,
    ) -> Result<()> {
        if !self.service.defer(authority, wake, delay).await? {
            return Ok(());
        }
        if delay == INCOMPLETE_RETRY {
            // A later sweep needs a fresh PG cutoff and epoch. Keep no stale
            // completion marker while the durable wake waits in PostgreSQL.
            return Ok(());
        }
        let mut plans = self.plans.lock().unwrap_or_else(|e| e.into_inner());
        if plans.len() >= MAX_LOCAL_PLANS {
            if let Some(oldest) = plans.keys().next().copied() {
                plans.remove(&oldest);
            }
        }
        plans.insert((wake.recipient_id, wake.revision), plan);
        Ok(())
    }
}

impl AppState {
    pub(crate) fn direct_spool_wake_consumer(
        &self,
        replay: super::cluster_recovery_replay::ClusterRecoveryReplayWake,
    ) -> DirectSpoolWakeConsumer {
        DirectSpoolWakeConsumer::new(
            DirectSpoolWakeService::new(PostgresDirectSpoolWakeRepository::new(self.pool.clone())),
            replay,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_revision_cannot_reuse_an_earlier_cutoff_or_completion_epoch() {
        let recipient_id = Uuid::new_v4();
        let first = ClaimedDirectSpoolWake {
            recipient_id,
            revision: Uuid::new_v4(),
            claim_token: Uuid::new_v4(),
            cutoff: Utc::now(),
        };
        let later = ClaimedDirectSpoolWake {
            recipient_id,
            revision: Uuid::new_v4(),
            claim_token: Uuid::new_v4(),
            cutoff: first.cutoff + chrono::Duration::seconds(1),
        };
        let mut plans = HashMap::new();
        let instance_uuid = Uuid::new_v4();
        let mut first_plan = take_plan(&mut plans, &first, instance_uuid, 1, || 7);
        first_plan.exhausted = true;
        plans.insert((first.recipient_id, first.revision), first_plan);

        let later_plan = take_plan(&mut plans, &later, instance_uuid, 1, || 8);
        assert_eq!(later_plan.epoch, 8);
        assert_eq!(later_plan.cutoff, later.cutoff);
        assert!(!later_plan.exhausted);
        assert!(plans.is_empty());
    }

    #[test]
    fn a_replacement_instance_cannot_reuse_a_previous_claim_plan() {
        let wake = ClaimedDirectSpoolWake {
            recipient_id: Uuid::new_v4(),
            revision: Uuid::new_v4(),
            claim_token: Uuid::new_v4(),
            cutoff: Utc::now(),
        };
        let mut plans = HashMap::new();
        let old_instance = Uuid::new_v4();
        let mut old_plan = take_plan(&mut plans, &wake, old_instance, 3, || 12);
        old_plan.exhausted = true;
        plans.insert((wake.recipient_id, wake.revision), old_plan);

        let new_plan = take_plan(&mut plans, &wake, Uuid::new_v4(), 4, || 13);
        assert_eq!(new_plan.epoch, 13);
        assert!(!new_plan.exhausted);
    }

    #[test]
    fn an_expired_claim_resumes_only_its_exact_revision_and_instance() {
        let wake = ClaimedDirectSpoolWake {
            recipient_id: Uuid::new_v4(),
            revision: Uuid::new_v4(),
            claim_token: Uuid::new_v4(),
            cutoff: Utc::now(),
        };
        let instance_uuid = Uuid::new_v4();
        let mut plans = HashMap::new();
        let mut plan = take_plan(&mut plans, &wake, instance_uuid, 2, || 41);
        plan.cursor = Some("alice@example.test/Mobile".to_owned());
        plans.insert((wake.recipient_id, wake.revision), plan);

        let reclaimed = ClaimedDirectSpoolWake {
            claim_token: Uuid::new_v4(),
            cutoff: wake.cutoff + chrono::Duration::seconds(90),
            ..wake.clone()
        };
        let resumed = take_plan(&mut plans, &reclaimed, instance_uuid, 2, || {
            panic!("same revision must keep its bounded page")
        });
        assert_eq!(resumed.epoch, 41);
        assert_eq!(resumed.cursor.as_deref(), Some("alice@example.test/Mobile"));
        assert_eq!(resumed.cutoff, wake.cutoff);
    }
}
