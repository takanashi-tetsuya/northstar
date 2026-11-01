//! PostgreSQL adapter for committed local direct-spool revision wakes.

use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use northstar_message_application::direct_spool_wake::{
    ClaimedDirectSpoolWake, DirectSpoolWakeRepository, DirectSpoolWakeRoute,
};
use northstar_security::cluster_keys::ClusterReadinessAuthority;
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresDirectSpoolWakeRepository {
    pool: PgPool,
}

impl PostgresDirectSpoolWakeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// The caller holds the shared node-claim advisory lock from transaction
/// start. This write shares the message's commit or rollback fate.
pub async fn record_direct_spool_wake_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    domain: &str,
    recipient_id: Uuid,
) -> Result<()> {
    let _: i64 = sqlx::query_scalar("SELECT northstar_record_direct_spool_wake($1,$2)")
        .bind(domain)
        .bind(recipient_id)
        .fetch_one(&mut **transaction)
        .await?;
    Ok(())
}

impl DirectSpoolWakeRepository for PostgresDirectSpoolWakeRepository {
    async fn cleanup(&self, limit: i32) -> Result<i64> {
        ensure!(
            (1..=256).contains(&limit),
            "invalid direct spool wake cleanup page"
        );
        Ok(
            sqlx::query_scalar("SELECT northstar_cleanup_direct_spool_wakes($1)")
                .bind(limit)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    async fn claim(
        &self,
        authority: &ClusterReadinessAuthority,
        limit: i32,
    ) -> Result<Vec<ClaimedDirectSpoolWake>> {
        ensure!(
            (1..=256).contains(&limit),
            "invalid direct spool wake claim page"
        );
        let rows: Vec<(Uuid, Uuid, Uuid, DateTime<Utc>)> = sqlx::query_as(
            "SELECT recipient_id,revision,claim_token,replay_cutoff FROM northstar_claim_direct_spool_wakes($1,$2,$3,$4,$5)",
        )
        .bind(&authority.key_identity.xmpp_domain)
        .bind(&authority.instance_node_id)
        .bind(authority.instance_uuid)
        .bind(authority.instance_epoch)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(recipient_id, revision, claim_token, cutoff)| ClaimedDirectSpoolWake {
                    recipient_id,
                    revision,
                    claim_token,
                    cutoff,
                },
            )
            .collect())
    }

    async fn routes_page(
        &self,
        authority: &ClusterReadinessAuthority,
        recipient_id: Uuid,
        after: Option<&str>,
        limit: i32,
    ) -> Result<Vec<DirectSpoolWakeRoute>> {
        ensure!(
            (1..=256).contains(&limit),
            "invalid direct spool route page"
        );
        let rows: Vec<(String, Uuid)> = sqlx::query_as(
            "SELECT full_jid,connection_id FROM northstar_direct_spool_routes_page($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(&authority.key_identity.xmpp_domain)
        .bind(&authority.instance_node_id)
        .bind(authority.instance_uuid)
        .bind(authority.instance_epoch)
        .bind(recipient_id)
        .bind(after)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(full_jid, connection_id)| DirectSpoolWakeRoute {
                full_jid,
                connection_id,
            })
            .collect())
    }

    async fn acknowledge_if_empty(
        &self,
        authority: &ClusterReadinessAuthority,
        recipient_id: Uuid,
        revision: Uuid,
        claim_token: Uuid,
    ) -> Result<bool> {
        Ok(sqlx::query_scalar(
            "SELECT northstar_ack_direct_spool_wake_if_empty($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(&authority.key_identity.xmpp_domain)
        .bind(&authority.instance_node_id)
        .bind(authority.instance_uuid)
        .bind(authority.instance_epoch)
        .bind(recipient_id)
        .bind(revision)
        .bind(claim_token)
        .fetch_one(&self.pool)
        .await?)
    }

    async fn defer(
        &self,
        authority: &ClusterReadinessAuthority,
        recipient_id: Uuid,
        revision: Uuid,
        claim_token: Uuid,
        delay: Duration,
    ) -> Result<bool> {
        ensure!(
            (1..=300).contains(&delay.as_secs()) && delay.subsec_nanos() == 0,
            "invalid direct spool wake retry delay"
        );
        Ok(
            sqlx::query_scalar("SELECT northstar_defer_direct_spool_wake($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(&authority.key_identity.xmpp_domain)
                .bind(&authority.instance_node_id)
                .bind(authority.instance_uuid)
                .bind(authority.instance_epoch)
                .bind(recipient_id)
                .bind(revision)
                .bind(claim_token)
                .bind(delay.as_secs() as i32)
                .fetch_one(&self.pool)
                .await?,
        )
    }
}
