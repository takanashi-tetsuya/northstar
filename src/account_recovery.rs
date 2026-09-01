//! Crash-safe completion of XEP-0077 account removal.
//!
//! The client path and the supervised recovery worker share this coordinator,
//! so resumable-session teardown, deletion and post-commit notifications cannot
//! silently drift into two implementations.

use crate::{
    state::AppState,
    workers::WorkerHeartbeat,
    xmpp::{protocol::roster::deliver_roster_change, xml_builder::XmlElement},
};
use anyhow::{Context, Result};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FinalizeAccountDeletion {
    Deleted,
    Missing,
}

pub(crate) async fn finalize(
    state: &AppState,
    user_id: Uuid,
    username: &str,
) -> Result<FinalizeAccountDeletion> {
    // Durable SM teardown records must be consumed while the user row still
    // exists; deleting first would cascade the only retry authority.
    state
        .revoke_user_sm_sessions_with_teardown(user_id)
        .await
        .context("could not quiesce durable stream-management sessions")?;

    let Some(removed) = state
        .account_service()
        .delete_quiesced(user_id)
        .await
        .context("could not delete quiesced account")?
    else {
        return Ok(FinalizeAccountDeletion::Missing);
    };
    let account = format!("{}@{}", username, state.config.domain);

    // Deletion is already committed. Notification failures are observable but
    // cannot truthfully turn the successful mutation into an IQ failure.
    for (contact_id, contact_username, change) in &removed.reverse_roster_changes {
        if let Err(error) =
            deliver_roster_change(state, *contact_id, contact_username, change, None).await
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
            route_account_removal_presence(state, &account, &contact, "unsubscribe").await;
        }
        if matches!(subscription.as_str(), "from" | "both") {
            route_account_removal_presence(state, &account, &contact, "unsubscribed").await;
        }
    }

    state.disconnect_account(user_id, &account).await;
    Ok(FinalizeAccountDeletion::Deleted)
}

async fn route_account_removal_presence(state: &AppState, from: &str, to: &str, kind: &str) {
    let stanza = XmlElement::namespaced("presence", "jabber:client")
        .attr("from", from)
        .attr("to", to)
        .attr("type", kind)
        .finish();
    let Ok(target) = crate::jid::CanonicalJid::parse(to) else {
        return;
    };
    let domain = target.domainpart();
    if domain == state.config.domain {
        for (_, session) in state.session_entries_for(to) {
            let _ = session.sender.try_send(stanza.clone());
        }
        if let Ok(nodes) = state.cluster.lookup_nodes(to).await {
            for node_id in nodes {
                if node_id != state.cluster.node_id {
                    let _ = state
                        .cluster
                        .send_to_node(&node_id, to, &stanza, false, None)
                        .await;
                }
            }
        }
    } else if state.federation_domain_allowed(domain) {
        let _ = state
            .federation
            .send(domain, stanza, Some(from.to_owned()))
            .await;
    }
}

pub(crate) async fn serve(
    state: Arc<AppState>,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let jobs = state.account_service().claim_deletion_recovery(16, 900).await?;
                let mut failed = false;
                for job in jobs {
                    heartbeat.pulse();
                    match finalize(&state, job.user_id, &job.username).await {
                        Ok(FinalizeAccountDeletion::Deleted) => {
                            state
                                .metrics
                                .account_deletion_recovery_success_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tracing::info!(user_id = %job.user_id, "recovered interrupted account deletion");
                        }
                        Ok(FinalizeAccountDeletion::Missing) => {
                            // The FK should already have cascaded the request.
                            // Treat the stale claim as benign and observable.
                            tracing::info!(user_id = %job.user_id, "account deletion recovery found an already removed account");
                        }
                        Err(error) => {
                            failed = true;
                            state
                                .metrics
                                .account_deletion_recovery_failures_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tracing::error!(user_id = %job.user_id, ?error, "account deletion recovery failed");
                            if !state.account_service().release_deletion_recovery(
                                &job,
                                "finalization-failed",
                            )
                            .await?
                            {
                                state
                                    .metrics
                                    .account_deletion_recovery_lease_losses_total
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
