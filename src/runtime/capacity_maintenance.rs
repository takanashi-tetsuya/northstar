//! Supervised local lease renewal and deployment-wide expiry maintenance.
use crate::{
    state::{CapacityLeaseReaperContext, CapacityLeaseRenewalContext},
    workers::WorkerHeartbeat,
};
use anyhow::Result;
use tokio_util::sync::CancellationToken;

pub(crate) async fn serve_renewal(
    context: CapacityLeaseRenewalContext,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(context.heartbeat_interval());
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                if !context.renew_once(&cancel).await? {
                    return Ok(());
                }
                heartbeat.ok();
            }
        }
    }
}

pub(crate) async fn serve_reaper(
    context: CapacityLeaseReaperContext,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(context.heartbeat_interval());
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                if !context.reap_once(&cancel).await? {
                    return Ok(());
                }
                heartbeat.ok();
            }
        }
    }
}
