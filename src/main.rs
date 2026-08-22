mod abuse;
mod api;
mod auth;
mod config;
mod db;
mod error;
mod metrics;
mod s2s;
mod state;
mod storage;
mod tls;
mod xmpp;

use anyhow::{Context, Result};
use config::Config;
use sqlx::postgres::PgPoolOptions;
use state::AppState;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let config = Config::from_env()?;
    let _log_guard = init_logging(&config)?;
    tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("could not install the rustls AWS-LC crypto provider"))?;
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .min_connections(config.database_min_connections)
        .connect(&config.database_url)
        .await
        .context("could not connect to PostgreSQL")?;
    db::migrate(&pool).await?;
    db::ensure_bootstrap_admin(&pool, &config).await?;
    let (federation, federation_rx) = s2s::FederationRouter::channel();
    let state = AppState::new(config, pool, federation)?;

    let cancel = CancellationToken::new();

    let bg_state = state.clone();
    let bg_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = bg_cancel.cancelled() => break,
                _ = interval.tick() => {
                    bg_state.abuse.cleanup_challenges();
                    if let Err(e) = db::cleanup_expired_sessions(&bg_state.pool).await {
                        tracing::error!("failed to cleanup expired sessions: {e}");
                        bg_state.metrics.background_maintenance_failures_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    if let Err(e) = db::cleanup_expired_upload_slots(&bg_state.pool).await {
                        tracing::error!("failed to cleanup expired upload slots: {e}");
                        bg_state.metrics.background_maintenance_failures_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    if let Err(e) = db::cleanup_expired_offline_messages(
                        &bg_state.pool,
                        bg_state.config.offline_message_ttl_days,
                    ).await {
                        tracing::error!("failed to cleanup expired offline messages: {e}");
                        bg_state.metrics.background_maintenance_failures_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    let now = std::time::Instant::now();
                    bg_state
                        .resumable_sessions
                        .retain(|_, session| session.expires_at > now);
                }
            }
        }
    });

    let xmpp = tokio::spawn(xmpp::serve_tcp(state.clone(), cancel.clone()));
    let s2s = tokio::spawn(s2s::serve(state.clone(), federation_rx, cancel.clone()));
    let http = tokio::spawn(api::serve(state, cancel.clone()));

    tokio::select! {
        _ = cancel.cancelled() => {},
        _ = api::shutdown_signal() => { tracing::info!("shutdown signal received; stopping listeners and draining HTTP requests"); },
        result = xmpp => result.context("XMPP task panicked")??,
        result = s2s => result.context("S2S task panicked")??,
        result = http => result.context("HTTP task panicked")??,
    }

    cancel.cancel();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    tracing::info!("shutdown complete");

    Ok(())
}

fn init_logging(config: &Config) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let rotation = match config.log_rotation.to_lowercase().as_str() {
        "hourly" => tracing_appender::rolling::Rotation::HOURLY,
        "minutely" => tracing_appender::rolling::Rotation::MINUTELY,
        "never" => tracing_appender::rolling::Rotation::NEVER,
        _ => tracing_appender::rolling::Rotation::DAILY,
    };

    let file_appender = tracing_appender::rolling::Builder::new()
        .rotation(rotation)
        .filename_prefix("server.log")
        .max_log_files(config.log_retention_files)
        .build(&config.log_dir)
        .context("failed to build rolling file appender")?;

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    if config.log_format.eq_ignore_ascii_case("json") {
        let file_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(non_blocking)
            .with_ansi(false);
        let console_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(std::io::stderr)
            .with_ansi(false);
        tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .with(console_layer)
            .init();
    } else {
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(non_blocking)
            .with_ansi(false);
        let console_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
        tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .with(console_layer)
            .init();
    }

    Ok(Some(guard))
}
