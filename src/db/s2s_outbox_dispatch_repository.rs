//! PostgreSQL adapter for fenced outbound federation delivery.
use crate::{
    db,
    services::s2s_outbox_dispatch::{
        OutboxFailureDisposition, RouteRecoveryHead, S2sOutboxDispatchRepository,
    },
};
use anyhow::Result;
use northstar_federation_core::{ExpiredS2sOutboxItem, S2sOutboxItem};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresS2sOutboxDispatchRepository {
    pool: PgPool,
}

impl PostgresS2sOutboxDispatchRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl S2sOutboxDispatchRepository for PostgresS2sOutboxDispatchRepository {
    async fn renew(&self, id: Uuid, token: Uuid, lease_seconds: u64) -> Result<bool> {
        db::renew_s2s_outbox_lease(&self.pool, id, token, lease_seconds).await
    }

    async fn complete(&self, id: Uuid, token: Uuid) -> Result<bool> {
        db::complete_s2s_outbox(&self.pool, id, token).await
    }

    async fn fail(
        &self,
        item: &S2sOutboxItem,
        error: &str,
        retry_base_seconds: u64,
        retry_max_seconds: u64,
        max_attempts: i32,
        permanent: bool,
    ) -> Result<OutboxFailureDisposition> {
        let disposition = db::fail_s2s_outbox(
            &self.pool,
            item,
            error,
            retry_base_seconds,
            retry_max_seconds,
            max_attempts,
            permanent,
        )
        .await?;
        Ok(match disposition {
            db::S2sFailureDisposition::RetryScheduled => OutboxFailureDisposition::RetryScheduled,
            db::S2sFailureDisposition::Expired => OutboxFailureDisposition::Expired,
            db::S2sFailureDisposition::Dropped => OutboxFailureDisposition::Dropped,
            db::S2sFailureDisposition::LeaseLost => OutboxFailureDisposition::LeaseLost,
        })
    }

    async fn expire(&self, limit: i64) -> Result<Vec<ExpiredS2sOutboxItem>> {
        db::expire_s2s_outbox(&self.pool, limit).await
    }

    async fn claim_excluding_domains(
        &self,
        limit: i64,
        lease_seconds: u64,
        excluded_domains: &[String],
    ) -> Result<Vec<S2sOutboxItem>> {
        db::claim_due_s2s_outbox_excluding_domains(
            &self.pool,
            limit,
            lease_seconds,
            excluded_domains,
        )
        .await
    }

    async fn claim_for_domains(
        &self,
        limit: i64,
        lease_seconds: u64,
        domains: &[String],
    ) -> Result<Vec<S2sOutboxItem>> {
        db::claim_due_s2s_outbox_for_domains(&self.pool, limit, lease_seconds, domains).await
    }

    async fn route_head(&self, domain: &str) -> Result<Option<RouteRecoveryHead>> {
        Ok(db::s2s_route_recovery_head(&self.pool, domain)
            .await?
            .map(|head| RouteRecoveryHead {
                id: head.id,
                target_domain: head.target_domain,
                stanza: head.stanza,
                attempt_count: head.attempt_count,
                retry_due: head.retry_due,
                claim_in_flight: head.claim_in_flight,
            }))
    }

    async fn wake_route_head(&self, id: Uuid, domain: &str, attempt_count: i32) -> Result<bool> {
        db::wake_s2s_route_recovery_head(&self.pool, id, domain, attempt_count).await
    }
}
