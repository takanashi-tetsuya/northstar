//! PostgreSQL MUC occupancy renewal when Redis clustering is disabled.

use crate::{
    services::muc::{
        ClusterMucOccupancyTarget, MucOccupancyLookup, MucResolvedOccupancy,
        MAX_MUC_OCCUPANCY_RENEW_BATCH,
    },
    state::cluster_maintenance_context::StandaloneMucMaintenanceContext,
    workers::WorkerHeartbeat,
};
use anyhow::{ensure, Result};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const RENEW_INTERVAL: Duration = Duration::from_secs(15);
const OCCUPANCY_LEASE: Duration = Duration::from_secs(90);
const PASS_BUDGET: Duration = Duration::from_secs(30);

fn target_key(target: &ClusterMucOccupancyTarget) -> (Uuid, Uuid, Uuid, i64, Uuid, i64) {
    (
        target.room_id,
        target.room_epoch,
        target.occupant_incarnation,
        target.occupancy_epoch,
        target.connection_uuid,
        target.connection_epoch,
    )
}

fn exact_local_target(lookup: &MucOccupancyLookup, resolved: &MucResolvedOccupancy) -> bool {
    resolved.room_localpart == lookup.room_localpart
        && resolved.target.occupant_incarnation == lookup.occupant_incarnation
        && resolved.target.connection_uuid == lookup.connection_uuid
        && resolved.target.full_jid == lookup.full_jid
        && resolved.target.nick == lookup.nick
}

fn room_in_configured_domain(room_jid: &str, muc_domain: &str) -> bool {
    crate::jid::CanonicalJid::parse_bare(room_jid).is_ok_and(|room| room.domainpart() == muc_domain)
}

fn remaining_lease(last_complete: Instant, now: Instant) -> Duration {
    OCCUPANCY_LEASE.saturating_sub(now.saturating_duration_since(last_complete))
}

async fn within_pass_budget<T>(
    budget: Duration,
    work: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(budget, work)
        .await
        .map_err(|_| anyhow::anyhow!("PostgreSQL MUC occupancy renewal exceeded its budget"))?
}

fn fence_local_actors(context: &StandaloneMucMaintenanceContext) {
    for occupant in context.locals.muc_occupant_snapshots() {
        context.locals.remove_stale_muc_actor(&occupant);
    }
}

/// A complete pass alone refreshes the safety deadline. Every lookup and
/// renewal is bounded to the same 128 local actors; a slow or unavailable
/// database cannot extend local authority beyond the lease deadline.
async fn renew_once(context: &StandaloneMucMaintenanceContext) -> Result<()> {
    let occupants = context.locals.muc_occupant_snapshots();
    for chunk in occupants.chunks(MAX_MUC_OCCUPANCY_RENEW_BATCH) {
        let mut candidates = Vec::with_capacity(chunk.len());
        let mut stale = Vec::new();
        for occupant in chunk {
            if !room_in_configured_domain(&occupant.room_jid, &context.muc_domain) {
                tracing::warn!(room=%occupant.room_jid,
                    "local MUC actor is outside the configured room domain");
                stale.push(occupant);
                continue;
            }
            match MucOccupancyLookup::new(
                &occupant.room_jid,
                &occupant.full_jid,
                &occupant.nick,
                occupant.cluster_epoch,
                occupant.connection_id,
            ) {
                Ok(lookup) => candidates.push((occupant, lookup)),
                Err(error) => {
                    tracing::warn!(?error, room=%occupant.room_jid,
                        "local MUC actor has an invalid authority identity");
                    stale.push(occupant);
                }
            }
        }
        let lookups = candidates
            .iter()
            .map(|(_, lookup)| lookup.clone())
            .collect::<Vec<_>>();
        let resolved = context
            .occupancy
            .resolve_exact_batch(&lookups, &context.node_id)
            .await?;
        let mut by_identity = HashMap::with_capacity(resolved.len());
        for result in resolved {
            ensure!(
                by_identity
                    .insert(
                        (
                            result.room_localpart.clone(),
                            result.target.occupant_incarnation,
                            result.target.connection_uuid,
                        ),
                        result,
                    )
                    .is_none(),
                "duplicate PostgreSQL MUC occupancy lookup result"
            );
        }
        let mut exact = Vec::with_capacity(candidates.len());
        for (occupant, lookup) in candidates {
            let key = (
                lookup.room_localpart.clone(),
                lookup.occupant_incarnation,
                lookup.connection_uuid,
            );
            match by_identity.get(&key) {
                Some(result) if exact_local_target(&lookup, result) => {
                    exact.push((occupant, result.target.clone()));
                }
                _ => stale.push(occupant),
            }
        }
        let requested = exact
            .iter()
            .map(|(_, target)| target.clone())
            .collect::<Vec<_>>();
        let renewed = context
            .occupancy
            .renew_exact_batch(&requested, &context.node_id)
            .await?;
        ensure!(
            renewed.len() <= requested.len(),
            "invalid MUC renewal result size"
        );
        let mut renewed_keys = HashSet::with_capacity(renewed.len());
        for target in renewed {
            ensure!(
                requested.contains(&target),
                "MUC renewal returned an unrequested target"
            );
            ensure!(
                renewed_keys.insert(target_key(&target)),
                "duplicate MUC renewal result"
            );
        }
        for (occupant, target) in exact {
            if !renewed_keys.contains(&target_key(&target)) {
                stale.push(occupant);
            }
        }
        for occupant in stale {
            context.locals.remove_stale_muc_actor(occupant);
            tracing::warn!(room=%occupant.room_jid, nick=%occupant.nick,
                incarnation=%occupant.cluster_epoch,
                "removed local MUC actor that lost PostgreSQL occupancy authority");
        }
    }
    context.locals.record_muc_reconciliation();
    Ok(())
}

pub(crate) async fn run(
    context: Arc<StandaloneMucMaintenanceContext>,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(RENEW_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let remaining = {
                    let last = *context.last_complete_pass.lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    remaining_lease(last, Instant::now())
                };
                if remaining.is_zero() {
                    // The lease has already elapsed, so fence before making
                    // any further database call. A later healthy pass may
                    // admit fresh occupancies, never resurrect these actors.
                    fence_local_actors(&context);
                }
                let budget = if remaining.is_zero() {
                    PASS_BUDGET
                } else {
                    remaining.min(PASS_BUDGET)
                };
                let outcome = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    result = within_pass_budget(budget, renew_once(&context)) => result,
                };
                match outcome {
                    Ok(()) => {
                        *context.last_complete_pass.lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
                        heartbeat.ok();
                    }
                    Err(error) => {
                        context.locals.record_background_failure();
                        heartbeat.error(&error);
                        let last = *context.last_complete_pass.lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        if remaining_lease(last, Instant::now()).is_zero() {
                            fence_local_actors(&context);
                            tracing::error!(?error,
                                "PostgreSQL MUC occupancy authority expired; fenced local actors");
                        } else {
                            tracing::warn!(?error,
                                "PostgreSQL MUC occupancy renewal failed; retrying within lease");
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_passes_cannot_extend_the_lease_deadline() {
        let verified = Instant::now();
        assert_eq!(remaining_lease(verified, verified), OCCUPANCY_LEASE);
        assert_eq!(
            remaining_lease(verified, verified + Duration::from_secs(60)),
            Duration::from_secs(30)
        );
        assert!(remaining_lease(verified, verified + OCCUPANCY_LEASE).is_zero());
        assert!(remaining_lease(
            verified,
            verified + OCCUPANCY_LEASE + Duration::from_secs(1)
        )
        .is_zero());
    }

    #[test]
    fn renewal_batches_fit_the_repository_limit() {
        let targets = [(); MAX_MUC_OCCUPANCY_RENEW_BATCH * 2 + 1];
        let sizes = targets
            .chunks(MAX_MUC_OCCUPANCY_RENEW_BATCH)
            .map(<[_]>::len)
            .collect::<Vec<_>>();
        assert_eq!(sizes, vec![128, 128, 1]);
        assert!(PASS_BUDGET < OCCUPANCY_LEASE);
        assert!(RENEW_INTERVAL < PASS_BUDGET);
    }

    #[test]
    fn resolved_target_must_match_the_room_and_local_actor() {
        let lookup = MucOccupancyLookup {
            room_localpart: "lobby".to_owned(),
            full_jid: "alice@example.test/phone".to_owned(),
            nick: "Alice".to_owned(),
            occupant_incarnation: Uuid::new_v4(),
            connection_uuid: Uuid::new_v4(),
        };
        let mut resolved = MucResolvedOccupancy {
            room_localpart: lookup.room_localpart.clone(),
            target: ClusterMucOccupancyTarget {
                room_id: Uuid::new_v4(),
                room_epoch: Uuid::new_v4(),
                occupant_incarnation: lookup.occupant_incarnation,
                occupancy_epoch: 1,
                full_jid: lookup.full_jid.clone(),
                nick: lookup.nick.clone(),
                connection_uuid: lookup.connection_uuid,
                connection_epoch: 1,
            },
        };
        assert!(exact_local_target(&lookup, &resolved));
        resolved.room_localpart = "other-room".to_owned();
        assert!(!exact_local_target(&lookup, &resolved));
        resolved.room_localpart = lookup.room_localpart.clone();
        resolved.target.nick = "Replacement".to_owned();
        assert!(!exact_local_target(&lookup, &resolved));
        assert!(room_in_configured_domain(
            "lobby@conference.example.test",
            "conference.example.test"
        ));
        assert!(!room_in_configured_domain(
            "lobby@conference.other.test",
            "conference.example.test"
        ));
    }

    #[tokio::test]
    async fn blocked_pass_stops_at_the_remaining_lease_budget() {
        let last_complete = Instant::now() - OCCUPANCY_LEASE + Duration::from_millis(75);
        let remaining = remaining_lease(last_complete, Instant::now());
        assert!(remaining <= Duration::from_millis(75));
        let began = Instant::now();
        let result: Result<()> = within_pass_budget(remaining, std::future::pending()).await;
        assert!(result.is_err());
        assert!(began.elapsed() < Duration::from_secs(1));
    }
}
