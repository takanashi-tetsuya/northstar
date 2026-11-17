//! Durable capacity audits and recovery of work left by the previous process.

use anyhow::{Context, Result};
use std::future::Future;

/// The durable capacity audits that must pass before any runtime state is built.
pub trait DurableCapacityAuditPorts {
    fn audit_mix_delivery_capacity(&self) -> impl Future<Output = Result<()>> + Send;
    fn audit_mix_pam_operation_capacity(&self) -> impl Future<Output = Result<()>> + Send;
}

pub async fn audit_durable_capacity<P: DurableCapacityAuditPorts>(ports: &P) -> Result<()> {
    let startup_phase =
        northstar_telemetry::logging::StartupPhase::begin("mix_delivery_capacity_audit");
    ports
        .audit_mix_delivery_capacity()
        .await
        .context("MIX delivery capacity ledger failed startup reconciliation")?;
    startup_phase.complete();
    let startup_phase = northstar_telemetry::logging::StartupPhase::begin("mix_pam_capacity_audit");
    ports
        .audit_mix_pam_operation_capacity()
        .await
        .context("MIX-PAM operation capacity authority failed startup audit")?;
    startup_phase.complete();
    Ok(())
}

/// Recovery of durable federation and presence work left by the previous process.
pub trait RestartRecoveryPorts {
    type MixPresenceRecovery;
    type AbuseKeyDeployment;

    fn recover_remote_pam(&self) -> impl Future<Output = Result<()>> + Send;
    fn prepare_mix_presence(
        &self,
    ) -> impl Future<Output = Result<Self::MixPresenceRecovery>> + Send;
    fn reconcile_mix_muc_mirrors(&self) -> impl Future<Output = Result<u64>> + Send;
    fn reconcile_abuse_key_deployment(
        &self,
        identity: &Self::AbuseKeyDeployment,
    ) -> impl Future<Output = Result<()>> + Send;
}

pub async fn recover_after_restart<P: RestartRecoveryPorts>(
    ports: &P,
    mix_muc_mirror_enabled: bool,
    abuse_key_deployment: Option<&P::AbuseKeyDeployment>,
) -> Result<P::MixPresenceRecovery> {
    ports
        .recover_remote_pam()
        .await
        .context("failed to recover pending MIX-PAM federation operations")?;
    let mix_presence_recovery = ports
        .prepare_mix_presence()
        .await
        .context("failed to prepare XEP-0403 presence recovery")?;
    if mix_muc_mirror_enabled {
        let linked = ports
            .reconcile_mix_muc_mirrors()
            .await
            .context("failed to reconcile XEP-0408 MIX/MUC mirror associations")?;
        tracing::info!(linked, "XEP-0408 partial MIX/MUC mirror mode enabled");
    }

    if let Some(identity) = abuse_key_deployment {
        ports
            .reconcile_abuse_key_deployment(identity)
            .await
            .context("anti-abuse HMAC deployment consistency check failed")?;
    }

    Ok(mix_presence_recovery)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingPorts {
        events: Mutex<Vec<String>>,
        fail_at: Option<&'static str>,
    }

    impl RecordingPorts {
        fn record(&self, event: &str) -> Result<()> {
            self.events.lock().unwrap().push(event.to_owned());
            anyhow::ensure!(self.fail_at != Some(event), "{event} failed");
            Ok(())
        }
    }

    impl DurableCapacityAuditPorts for RecordingPorts {
        async fn audit_mix_delivery_capacity(&self) -> Result<()> {
            self.record("delivery")
        }

        async fn audit_mix_pam_operation_capacity(&self) -> Result<()> {
            self.record("pam")
        }
    }

    impl RestartRecoveryPorts for RecordingPorts {
        type MixPresenceRecovery = (u64, Vec<String>);
        type AbuseKeyDeployment = u64;

        async fn recover_remote_pam(&self) -> Result<()> {
            self.record("recover")
        }

        async fn prepare_mix_presence(&self) -> Result<Self::MixPresenceRecovery> {
            self.record("prepare")?;
            Ok((42, vec!["presence target".to_owned()]))
        }

        async fn reconcile_mix_muc_mirrors(&self) -> Result<u64> {
            self.record("mirror")?;
            Ok(7)
        }

        async fn reconcile_abuse_key_deployment(
            &self,
            identity: &Self::AbuseKeyDeployment,
        ) -> Result<()> {
            self.record(&format!("abuse:{identity}"))
        }
    }

    #[tokio::test]
    async fn capacity_audits_run_delivery_then_pam() {
        let ports = RecordingPorts::default();
        audit_durable_capacity(&ports).await.unwrap();
        assert_eq!(*ports.events.lock().unwrap(), vec!["delivery", "pam"]);
    }

    #[tokio::test]
    async fn capacity_audit_failure_stops_and_keeps_context() {
        for (step, expected_events, expected_message) in [
            (
                "delivery",
                vec!["delivery"],
                "MIX delivery capacity ledger failed startup reconciliation",
            ),
            (
                "pam",
                vec!["delivery", "pam"],
                "MIX-PAM operation capacity authority failed startup audit",
            ),
        ] {
            let ports = RecordingPorts {
                fail_at: Some(step),
                ..RecordingPorts::default()
            };
            let error = audit_durable_capacity(&ports).await.unwrap_err();
            assert_eq!(error.to_string(), expected_message);
            assert_eq!(error.root_cause().to_string(), format!("{step} failed"));
            assert_eq!(*ports.events.lock().unwrap(), expected_events);
        }
    }

    #[tokio::test]
    async fn restart_recovery_runs_in_order_and_returns_the_presence_recovery() {
        let ports = RecordingPorts::default();
        let recovery = recover_after_restart(&ports, true, Some(&9)).await.unwrap();
        assert_eq!(recovery, (42, vec!["presence target".to_owned()]));
        assert_eq!(
            *ports.events.lock().unwrap(),
            vec!["recover", "prepare", "mirror", "abuse:9"]
        );
    }

    #[tokio::test]
    async fn restart_recovery_skips_disabled_mirror_and_absent_abuse_deployment() {
        let ports = RecordingPorts::default();
        let recovery = recover_after_restart(&ports, false, None).await.unwrap();
        assert_eq!(recovery, (42, vec!["presence target".to_owned()]));
        assert_eq!(*ports.events.lock().unwrap(), vec!["recover", "prepare"]);
    }

    #[tokio::test]
    async fn restart_recovery_failure_stops_later_steps_and_keeps_context() {
        for (step, expected_events, expected_message) in [
            (
                "recover",
                vec!["recover"],
                "failed to recover pending MIX-PAM federation operations",
            ),
            (
                "prepare",
                vec!["recover", "prepare"],
                "failed to prepare XEP-0403 presence recovery",
            ),
            (
                "mirror",
                vec!["recover", "prepare", "mirror"],
                "failed to reconcile XEP-0408 MIX/MUC mirror associations",
            ),
            (
                "abuse:9",
                vec!["recover", "prepare", "mirror", "abuse:9"],
                "anti-abuse HMAC deployment consistency check failed",
            ),
        ] {
            let ports = RecordingPorts {
                fail_at: Some(step),
                ..RecordingPorts::default()
            };
            let error = recover_after_restart(&ports, true, Some(&9))
                .await
                .unwrap_err();
            assert_eq!(error.to_string(), expected_message);
            assert_eq!(error.root_cause().to_string(), format!("{step} failed"));
            assert_eq!(*ports.events.lock().unwrap(), expected_events);
        }
    }
}
