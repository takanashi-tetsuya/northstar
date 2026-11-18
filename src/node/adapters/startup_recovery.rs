//! Root bindings for durable startup audits and restart recovery.

use anyhow::Result;
use northstar_abuse_policy::model::AbuseKeyDeploymentIdentity;
use northstar_operations_application::startup_recovery::{
    DurableCapacityAuditPorts, RestartRecoveryPorts,
};
use northstar_room_postgres::mix::MixPresenceProbeTarget;
use northstar_time::{DateTime, Utc};
use sqlx::PgPool;

pub(in crate::node) struct StartupRecoveryAdapters<'a> {
    pub(in crate::node) pool: &'a PgPool,
    pub(in crate::node) domain: &'a str,
}

impl DurableCapacityAuditPorts for StartupRecoveryAdapters<'_> {
    async fn audit_mix_delivery_capacity(&self) -> Result<()> {
        northstar_room_postgres::mix::audit_mix_delivery_capacity_ledger(self.pool).await
    }

    async fn audit_mix_pam_operation_capacity(&self) -> Result<()> {
        northstar_room_postgres::mix::audit_mix_pam_operation_capacity(self.pool).await
    }
}

impl RestartRecoveryPorts for StartupRecoveryAdapters<'_> {
    type MixPresenceRecovery = (DateTime<Utc>, Vec<MixPresenceProbeTarget>);
    type AbuseKeyDeployment = AbuseKeyDeploymentIdentity;

    async fn recover_remote_pam(&self) -> Result<()> {
        northstar_room_postgres::mix::recover_remote_pam_after_restart(self.pool).await
    }

    async fn prepare_mix_presence(&self) -> Result<Self::MixPresenceRecovery> {
        northstar_room_postgres::mix::prepare_mix_presence_after_restart(self.pool, self.domain)
            .await
    }

    async fn reconcile_mix_muc_mirrors(&self) -> Result<u64> {
        let mix_domain = format!("mix.{}", self.domain);
        northstar_room_postgres::mix_muc::reconcile_mix_muc_mirrors(
            self.pool,
            &mix_domain,
            self.domain,
        )
        .await
    }

    async fn reconcile_abuse_key_deployment(
        &self,
        identity: &Self::AbuseKeyDeployment,
    ) -> Result<()> {
        northstar_abuse_postgres::keys::reconcile_abuse_key_deployment(
            self.pool,
            identity,
            &northstar_workflows::abuse_effects::WorkflowAbuseEffects,
        )
        .await
    }
}
