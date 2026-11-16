//! Crash-safe completion of XEP-0077 account removal.
//!
//! The client path and the supervised recovery worker share this coordinator,
//! so resumable-session teardown, deletion and post-commit notifications cannot
//! silently drift into two implementations.

mod context;

use anyhow::{Context, Result};
pub use context::{AccountDeletionRecoveryContext, AccountDeletionRecoveryPorts};
use northstar_auth_application::account::AccountRepository;
use northstar_auth_application::account_teardown::FinalizeAccountDeletion;
use northstar_runtime::workers::WorkerHeartbeat;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Recovery outcomes share the process counters without granting the worker
/// access to unrelated observability state.
pub struct AccountDeletionRecoveryTelemetry<'a> {
    success: &'a AtomicU64,
    failure: &'a AtomicU64,
    lease_loss: &'a AtomicU64,
}

impl<'a> AccountDeletionRecoveryTelemetry<'a> {
    pub fn new(success: &'a AtomicU64, failure: &'a AtomicU64, lease_loss: &'a AtomicU64) -> Self {
        Self {
            success,
            failure,
            lease_loss,
        }
    }

    pub fn succeeded(&self) {
        self.success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn failed(&self) {
        self.failure.fetch_add(1, Ordering::Relaxed);
    }

    pub fn lease_lost(&self) {
        self.lease_loss.fetch_add(1, Ordering::Relaxed);
    }
}

pub async fn finalize<R: AccountRepository, P: AccountDeletionRecoveryPorts>(
    context: &AccountDeletionRecoveryContext<R, P>,
    user_id: Uuid,
    username: &str,
) -> Result<FinalizeAccountDeletion> {
    finalize_with(context, user_id, username).await
}

async fn finalize_with<R: AccountRepository, P: AccountDeletionRecoveryPorts>(
    context: &AccountDeletionRecoveryContext<R, P>,
    user_id: Uuid,
    username: &str,
) -> Result<FinalizeAccountDeletion> {
    // Durable SM teardown records must be consumed while the user row still
    // exists; deleting first would cascade the only retry authority.
    context
        .revoke_sm(user_id)
        .await
        .context("could not quiesce durable stream-management sessions")?;

    let Some(removed) = context
        .delete_quiesced(user_id)
        .await
        .context("could not delete quiesced account")?
    else {
        return Ok(FinalizeAccountDeletion::Missing);
    };
    let account = format!("{}@{}", username, context.local_domain());

    // Deletion is already committed. Notification failures are observable but
    // cannot truthfully turn the successful mutation into an IQ failure.
    for (contact_id, contact_username, change) in &removed.reverse_roster_changes {
        if let Err(error) = context
            .deliver_roster_change(*contact_id, contact_username, change)
            .await
        {
            tracing::warn!(
                contact = %contact_username,
                version = change.version,
                ?error,
                "failed to deliver post-deletion reverse roster push"
            );
        }
    }
    for (contact, _, subscription, _) in removed.roster {
        if matches!(subscription.as_str(), "to" | "both") {
            context
                .route_presence(&account, &contact, "unsubscribe")
                .await;
        }
        if matches!(subscription.as_str(), "from" | "both") {
            context
                .route_presence(&account, &contact, "unsubscribed")
                .await;
        }
    }

    context.disconnect_account(user_id, &account).await;
    Ok(FinalizeAccountDeletion::Deleted)
}

pub async fn serve<R: AccountRepository + 'static, P: AccountDeletionRecoveryPorts>(
    context: Arc<AccountDeletionRecoveryContext<R, P>>,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let jobs = context.claim().await?;
                let mut failed = false;
                for job in jobs {
                    heartbeat.pulse();
                    match finalize_with(&context, job.user_id, &job.username).await {
                        Ok(FinalizeAccountDeletion::Deleted) => {
                            context.telemetry().succeeded();
                            tracing::info!(user_id = %job.user_id, "recovered interrupted account deletion");
                        }
                        Ok(FinalizeAccountDeletion::Missing) => {
                            // The FK should already have cascaded the request.
                            // Treat the stale claim as benign and observable.
                            tracing::info!(user_id = %job.user_id, "account deletion recovery found an already removed account");
                        }
                        Err(error) => {
                            failed = true;
                            context.telemetry().failed();
                            tracing::error!(user_id = %job.user_id, ?error, "account deletion recovery failed");
                            if !context.release(&job).await?
                            {
                                context.telemetry().lease_lost();
                                tracing::warn!(user_id = %job.user_id, "account deletion recovery lease was lost before release");
                            }
                        }
                    }
                }
                if failed {
                    heartbeat.error("one or more durable account deletions failed");
                } else {
                    heartbeat.ok();
                }
            }
        }
    }
}
