//! Shared PostgreSQL wake transport for SM, MIX and account revocation workers.
use crate::{
    config::SM_AUTHORITY_LISTENER_MAX_CONNECTIONS,
    services::{
        mix::{MixDeliveryWakeBroker, MIX_DELIVERY_WAKE_NOTIFICATION_CHANNEL},
        sm::SmAuthorityBroker,
    },
};
use anyhow::{Context, Result};
use sqlx::postgres::{PgConnectOptions, PgListener, PgPoolOptions};
use std::{sync::Arc, time::Duration};
const SM_AUTHORITY_NOTIFICATION_CHANNEL: &str = "northstar_sm_authority_v1";

/// Run the one reserved PostgreSQL notification connection shared by the
/// XEP-0198, MIX delivery and account revocation workers.
///
/// AppState composes these independent services here; neither protocol layer
/// reaches into the other's broker.  This deliberately reuses the existing
/// reserved listener connection instead of consuming a primary-pool slot or
/// adding a new runtime-role connection.
async fn run_database_authority_listener(
    connect_options: PgConnectOptions,
    authority: Arc<SmAuthorityBroker>,
    mix_delivery_wake: Arc<MixDeliveryWakeBroker>,
    account_revocations: Arc<tokio::sync::Notify>,
    cancel: tokio_util::sync::CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> Result<()> {
    // PgListener internally retains this one-connection pool solely to rebuild
    // its socket after a PostgreSQL failover. It is deliberately unrelated to
    // the application PgPool, so a blocked LISTEN cannot consume one of the
    // request/transaction connections.
    let listener_pool = PgPoolOptions::new()
        .min_connections(0)
        .max_connections(SM_AUTHORITY_LISTENER_MAX_CONNECTIONS)
        .max_lifetime(None)
        .idle_timeout(None)
        .connect_with(connect_options)
        .await
        .context("could not establish the dedicated SM authority listener connection")?;
    let actual_schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&listener_pool)
        .await
        .context("could not attest the SM authority listener schema")?;
    anyhow::ensure!(
        actual_schema == authority.schema(),
        "SM authority listener connected to an unexpected PostgreSQL schema"
    );
    let mut listener = PgListener::connect_with(&listener_pool)
        .await
        .context("could not acquire the dedicated SM authority LISTEN connection")?;
    listener
        .listen_all([
            SM_AUTHORITY_NOTIFICATION_CHANNEL,
            MIX_DELIVERY_WAKE_NOTIFICATION_CHANNEL,
            "northstar_account_revocations",
        ])
        .await
        .context("could not subscribe to PostgreSQL authority notifications")?;
    // Publish only after all channels are installed. A reconnect or startup
    // can have a gap before LISTEN becomes active; each broker's retained
    // generation makes its workers run an authoritative database probe.
    authority.publish_listener_transition();
    mix_delivery_wake.publish_listener_transition();
    account_revocations.notify_one();
    heartbeat.ok();
    let mut liveness = tokio::time::interval(Duration::from_secs(5));
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                authority.publish_listener_transition();
                mix_delivery_wake.publish_listener_transition();
                account_revocations.notify_one();
                return Ok(());
            }
            _ = liveness.tick() => {
                // LISTEN is legitimately quiet when no SM authority changes
                // occur. A periodic supervisor heartbeat proves that this
                // task is still schedulable without turning notification
                // silence into a false failure.
                heartbeat.ok();
            }
            notification = listener.try_recv() => {
                match notification {
                    Ok(Some(notification)) => {
                        match notification.channel() {
                            SM_AUTHORITY_NOTIFICATION_CHANNEL => {
                                if !authority.accept_notification(notification.payload()) {
                                    tracing::warn!(channel = notification.channel(), "discarded malformed or mismatched SM authority notification");
                                    continue;
                                }
                            }
                            MIX_DELIVERY_WAKE_NOTIFICATION_CHANNEL => {
                                // Migration 0133 emits only TG_TABLE_SCHEMA
                                // (max 63 bytes). The payload is a wake hint,
                                // never a delivery capability: MIX workers
                                // still claim the exact fenced recipient row.
                                if notification.payload().len() > 63
                                    || !mix_delivery_wake
                                        .accept_committed_notification(notification.payload())
                                {
                                    tracing::warn!(
                                        channel = notification.channel(),
                                        "discarded mismatched MIX delivery wake notification"
                                    );
                                    continue;
                                }
                            }
                            "northstar_account_revocations" => {
                                if notification.payload() != authority.schema() {
                                    continue;
                                }
                                                    account_revocations.notify_one();
                            }
                            _ => continue,
                        }
                        heartbeat.ok();
                    }
                    Ok(None) => {
                        // PgListener has already re-established LISTEN before
                        // returning None. Notifications in the disconnect gap
                        // are unknowable, so generation is the loss marker and
                        // every current waiter performs a fresh authority read.
                        authority.publish_listener_transition();
                        mix_delivery_wake.publish_listener_transition();
                        account_revocations.notify_one();
                        heartbeat.ok();
                    }
                    Err(error) => {
                        authority.publish_listener_transition();
                        mix_delivery_wake.publish_listener_transition();
                        account_revocations.notify_one();
                        return Err(error).context("SM authority notification listener failed");
                    }
                }
            }
        }
    }
}

/// Start the one database authority listener after AppState has composed the
/// independent SM and MIX service brokers.  The listener is a wake transport,
/// not a source of protocol authority; each recipient/session path still
/// reads its fenced PostgreSQL record before acting.
pub(crate) fn start_database_authority_listener(
    authority: Arc<SmAuthorityBroker>,
    mix_delivery_wake: Arc<MixDeliveryWakeBroker>,
    account_revocations: Arc<tokio::sync::Notify>,
    connect_options: PgConnectOptions,
    registry: Arc<crate::workers::WorkerRegistry>,
    cancel: tokio_util::sync::CancellationToken,
) {
    registry.supervise(
        "sm-authority-listener",
        crate::workers::WorkerCriticality::Restartable,
        crate::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(15)),
        cancel.clone(),
        move |heartbeat| {
            let authority = Arc::clone(&authority);
            let mix_delivery_wake = Arc::clone(&mix_delivery_wake);
            let account_revocations = Arc::clone(&account_revocations);
            let connect_options = connect_options.clone();
            let cancel = cancel.clone();
            async move {
                run_database_authority_listener(
                    connect_options,
                    authority,
                    mix_delivery_wake,
                    account_revocations,
                    cancel,
                    heartbeat,
                )
                .await
            }
        },
    );
}
