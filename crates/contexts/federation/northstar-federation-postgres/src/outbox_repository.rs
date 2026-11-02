//! PostgreSQL implementation of durable federation admission.
use northstar_federation_application::outbox::FederationOutboxRepository;
use northstar_federation_core::S2sOutboxPolicy;
use sqlx::PgPool;

#[derive(Clone)]
pub struct PostgresFederationOutboxRepository {
    pool: PgPool,
}

impl PostgresFederationOutboxRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl FederationOutboxRepository for PostgresFederationOutboxRepository {
    async fn enqueue<'a>(
        &'a self,
        target_domain: &'a str,
        stanza: &'a str,
        bounce_to: Option<&'a str>,
        policy: S2sOutboxPolicy,
    ) -> anyhow::Result<()> {
        crate::enqueue_s2s_outbox(
            &self.pool,
            target_domain,
            stanza,
            bounce_to,
            policy.ttl_seconds,
            policy.max_rows,
            policy.max_bytes,
            policy.max_per_domain,
        )
        .await?;
        Ok(())
    }
}
