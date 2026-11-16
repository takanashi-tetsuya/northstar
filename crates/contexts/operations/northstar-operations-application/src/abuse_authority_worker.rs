//! Fail-closed anti-abuse deployment authority guard.

use crate::readiness::{AbuseKeyAuthorityProbe, ReadinessRepository};
use anyhow::{Context, Result};
use northstar_abuse_policy::model::AbuseKeyDeploymentIdentity;
use northstar_runtime::workers::WorkerHeartbeat;
use std::{future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

pub const ABUSE_KEY_AUTHORITY_POLL_INTERVAL: Duration = Duration::from_secs(5);
pub const ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// One validation of this process's anti-abuse key generation against durable authority.
pub trait AbuseKeyAuthorityCheck: Send + Sync {
    fn validate(
        &self,
        identity: &AbuseKeyDeploymentIdentity,
    ) -> impl Future<Output = Result<()>> + Send;
}

impl<R: ReadinessRepository> AbuseKeyAuthorityCheck for AbuseKeyAuthorityProbe<R> {
    async fn validate(&self, identity: &AbuseKeyDeploymentIdentity) -> Result<()> {
        AbuseKeyAuthorityProbe::validate(self, identity).await
    }
}

pub async fn serve_abuse_key_authority(
    authority_probe: &impl AbuseKeyAuthorityCheck,
    authority_identity: AbuseKeyDeploymentIdentity,
    authority_cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(ABUSE_KEY_AUTHORITY_POLL_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = authority_cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let validation = tokio::time::timeout(
                    ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT,
                    authority_probe.validate(&authority_identity),
                ).await;
                match validation {
                    Ok(Ok(())) => heartbeat.ok(),
                    Ok(Err(error)) => {
                        heartbeat.error(&error);
                        tracing::error!(
                            ?error,
                            poll_seconds = ABUSE_KEY_AUTHORITY_POLL_INTERVAL.as_secs(),
                            "anti-abuse key authority diverged; cancelling every listener"
                        );
                        return Err(error).context(
                            "PostgreSQL rejected this process's anti-abuse key generation",
                        );
                    }
                    Err(error) => {
                        heartbeat.error(&error);
                        tracing::error!(
                            ?error,
                            query_timeout_seconds = ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT.as_secs(),
                            "anti-abuse key authority could not be verified in time; cancelling every listener"
                        );
                        anyhow::bail!(
                            "PostgreSQL anti-abuse key authority validation exceeded the {} second fail-closed timeout",
                            ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT.as_secs(),
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_runtime::workers::{WorkerCriticality, WorkerMode, WorkerRegistry};
    use std::{
        pin::Pin,
        sync::{Arc, Mutex},
        task::Poll,
    };

    struct RecordingCheck {
        identities: Mutex<Vec<AbuseKeyDeploymentIdentity>>,
        reject: bool,
        stall: bool,
    }

    impl AbuseKeyAuthorityCheck for RecordingCheck {
        async fn validate(&self, identity: &AbuseKeyDeploymentIdentity) -> Result<()> {
            self.identities.lock().unwrap().push(identity.clone());
            if self.stall {
                std::future::pending::<()>().await;
            }
            if self.reject {
                anyhow::bail!("authority rejected");
            }
            Ok(())
        }
    }

    fn identity() -> AbuseKeyDeploymentIdentity {
        AbuseKeyDeploymentIdentity {
            xmpp_domain: "example.test".into(),
            epoch: 3,
            current_key_id: "current".into(),
            previous_key_id: None,
            retire_previous: false,
            minimum_overlap: Duration::from_secs(30),
        }
    }

    async fn worker_heartbeat() -> (Arc<WorkerRegistry>, CancellationToken, WorkerHeartbeat) {
        let registry = WorkerRegistry::new();
        let cancel = CancellationToken::new();
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        registry.supervise(
            "test-abuse-authority-heartbeat",
            WorkerCriticality::Critical,
            WorkerMode::Continuous,
            None,
            cancel.clone(),
            move |heartbeat| {
                assert!(sender.send(heartbeat).is_ok());
                std::future::pending::<Result<()>>()
            },
        );
        let heartbeat = receiver.recv().await.unwrap();
        (registry, cancel, heartbeat)
    }

    async fn poll_worker(
        mut worker: Pin<&mut impl Future<Output = Result<()>>>,
    ) -> Poll<Result<()>> {
        std::future::poll_fn(|cx| Poll::Ready(worker.as_mut().poll(cx))).await
    }

    #[tokio::test(start_paused = true)]
    async fn abuse_authority_ok_reports_healthy_and_cancel_returns_ok() {
        let (registry, registry_cancel, heartbeat) = worker_heartbeat().await;
        let probe = RecordingCheck {
            identities: Mutex::new(Vec::new()),
            reject: false,
            stall: false,
        };
        let identity = identity();
        let cancel = CancellationToken::new();
        // A successful pass must clear these two prior errors before another
        // error would reach the registry's three-error failure threshold.
        heartbeat.error("prior failure");
        heartbeat.error("prior failure");
        let worker =
            serve_abuse_key_authority(&probe, identity.clone(), cancel.clone(), heartbeat.clone());
        tokio::pin!(worker);
        assert!(poll_worker(worker.as_mut()).await.is_pending());
        assert_eq!(
            probe.identities.lock().unwrap().as_slice(),
            std::slice::from_ref(&identity)
        );
        heartbeat.error("health check");
        assert!(registry.readiness_error().is_none());

        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(poll_worker(worker.as_mut()).await.is_pending());
        assert_eq!(probe.identities.lock().unwrap().len(), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(poll_worker(worker.as_mut()).await.is_pending());
        assert_eq!(
            *probe.identities.lock().unwrap(),
            [identity.clone(), identity.clone()]
        );
        heartbeat.error("health check");
        heartbeat.error("health check");
        assert!(registry.readiness_error().is_none());

        cancel.cancel();
        worker.await.unwrap();
        assert!(registry
            .shutdown_and_join(&registry_cancel, Duration::from_secs(1))
            .await
            .is_clean());
    }

    #[tokio::test(start_paused = true)]
    async fn abuse_authority_rejection_returns_the_contextual_error() {
        let (registry, registry_cancel, heartbeat) = worker_heartbeat().await;
        let probe = RecordingCheck {
            identities: Mutex::new(Vec::new()),
            reject: true,
            stall: false,
        };
        heartbeat.error("prior failure");
        heartbeat.error("prior failure");
        let error =
            serve_abuse_key_authority(&probe, identity(), CancellationToken::new(), heartbeat)
                .await
                .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "PostgreSQL rejected this process's anti-abuse key generation: authority rejected"
        );
        assert_eq!(probe.identities.lock().unwrap().len(), 1);
        assert!(registry
            .readiness_error()
            .unwrap()
            .contains("authority rejected"));
        assert!(registry
            .shutdown_and_join(&registry_cancel, Duration::from_secs(1))
            .await
            .is_clean());
    }

    #[tokio::test(start_paused = true)]
    async fn abuse_authority_timeout_bails_after_the_query_timeout() {
        let (registry, registry_cancel, heartbeat) = worker_heartbeat().await;
        let probe = RecordingCheck {
            identities: Mutex::new(Vec::new()),
            reject: false,
            stall: true,
        };
        heartbeat.error("prior failure");
        heartbeat.error("prior failure");
        let worker =
            serve_abuse_key_authority(&probe, identity(), CancellationToken::new(), heartbeat);
        tokio::pin!(worker);
        let started = tokio::time::Instant::now();
        assert!(poll_worker(worker.as_mut()).await.is_pending());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(poll_worker(worker.as_mut()).await.is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        let error = worker.await.unwrap_err();
        assert_eq!(started.elapsed(), ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT);
        assert_eq!(
            error.to_string(),
            "PostgreSQL anti-abuse key authority validation exceeded the 3 second fail-closed timeout"
        );
        assert_eq!(probe.identities.lock().unwrap().len(), 1);
        assert!(registry.readiness_error().is_some());
        assert!(registry
            .shutdown_and_join(&registry_cancel, Duration::from_secs(1))
            .await
            .is_clean());
    }
}
