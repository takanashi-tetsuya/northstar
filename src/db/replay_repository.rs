//! PostgreSQL ownership and claim transitions for offline and BOSH replay.
use crate::{db, services::replay::*};
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresReplayRepository {
    pool: PgPool,
}
impl PostgresReplayRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl ReplayLeaseRepository for PostgresReplayRepository {
    async fn username(&self, recipient_id: Uuid) -> Result<Option<String>> {
        sqlx::query_scalar("SELECT username FROM users WHERE id=$1")
            .bind(recipient_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }
    async fn acquire_lease(
        &self,
        recipient_id: Uuid,
        resource: &str,
        owner_token: Uuid,
        cutoff: Option<DateTime<Utc>>,
        lease_seconds: i64,
    ) -> Result<OfflineReplayLeaseAcquire> {
        db::replay::acquire_offline_replay_lease(
            &self.pool,
            recipient_id,
            resource,
            owner_token,
            cutoff,
            lease_seconds,
        )
        .await
    }
}

impl ReplayRepository for PostgresReplayRepository {
    async fn claim_page(
        &self,
        session: &ReplaySession,
        active_privacy_list: Option<&str>,
        bind2_mam_catchup: bool,
        offline_ttl_days: i64,
    ) -> Result<ReplayPageOutcome> {
        Ok(
            match db::replay::claim_offline_replay_page(
                &self.pool,
                session.lease(),
                offline_ttl_days,
                session.owner_bare_jid(),
                session.owner_full_jid(),
                active_privacy_list,
                bind2_mam_catchup,
                db::replay::REPLAY_OWNER_LEASE_SECONDS,
            )
            .await?
            {
                db::replay::OfflineReplayPageOutcome::Claimed(page) => {
                    ReplayPageOutcome::Claimed(ReplayPage {
                        claim_token: page.claim_token,
                        messages: page
                            .messages
                            .into_iter()
                            .map(|message| ReplayMessage {
                                id: message.id,
                                stanza: message.stanza,
                            })
                            .collect(),
                    })
                }
                db::replay::OfflineReplayPageOutcome::Empty => ReplayPageOutcome::Empty,
                db::replay::OfflineReplayPageOutcome::LeaseLost => ReplayPageOutcome::LeaseLost,
            },
        )
    }

    async fn renew_before_send(
        &self,
        session: &ReplaySession,
        page_claim_token: Uuid,
        pending_ids: &[Uuid],
    ) -> Result<bool> {
        db::replay::renew_offline_replay_before_send(
            &self.pool,
            session.lease(),
            page_claim_token,
            pending_ids,
            db::replay::REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
    }

    async fn release_unsent(
        &self,
        session: &ReplaySession,
        page_claim_token: Uuid,
        message_ids: &[Uuid],
    ) -> Result<u64> {
        db::replay::release_untransferred_offline_claims(
            &self.pool,
            session.recipient_id(),
            page_claim_token,
            message_ids,
        )
        .await
    }

    async fn finish(&self, session: &ReplaySession) -> Result<bool> {
        db::replay::release_offline_replay_lease(&self.pool, session.lease()).await
    }

    async fn pending_presence_page(
        &self,
        recipient_id: Uuid,
        owner_bare_jid: &str,
        active_privacy_list: Option<&str>,
        after: Option<&PendingPresenceCursor>,
        domain: &str,
    ) -> Result<PendingPresencePage> {
        db::replay::pending_presence_replay_page_filtered(
            &self.pool,
            recipient_id,
            owner_bare_jid,
            domain,
            active_privacy_list,
            after,
        )
        .await
    }

    async fn fence_socket_write(
        &self,
        delivery: crate::outbound::DurableDelivery,
    ) -> Result<crate::outbound::DurableDelivery> {
        db::replay::fence_durable_socket_write(&self.pool, delivery).await
    }

    async fn acknowledge_socket_write(
        &self,
        delivery: crate::outbound::DurableDelivery,
    ) -> Result<()> {
        db::replay::acknowledge_durable_delivery(&self.pool, delivery).await
    }

    async fn renew_bosh_fences(
        &self,
        session_id: Uuid,
        expected_response: Option<(u64, &crate::outbound::BoshResponseOwnership)>,
        ttl_seconds: u64,
    ) -> Result<()> {
        db::replay::renew_bosh_transport_fences(
            &self.pool,
            session_id,
            expected_response,
            ttl_seconds,
        )
        .await
    }

    async fn acknowledge_bosh_responses(
        &self,
        session_id: Uuid,
        acknowledged_rid: u64,
    ) -> Result<()> {
        let acknowledged = db::replay::acknowledge_bosh_transport_responses(
            &self.pool,
            session_id,
            acknowledged_rid,
        )
        .await?;
        tracing::debug!(
            %session_id,
            acknowledged_rid,
            acknowledged,
            "acknowledged durable BOSH transport sources"
        );
        Ok(())
    }

    async fn bind_bosh_response_sources(
        &self,
        session_id: Uuid,
        rid: u64,
        sources: &[crate::outbound::TransportOwnershipSource],
        ttl_seconds: u64,
    ) -> Result<crate::outbound::BoshResponseOwnership> {
        db::replay::bind_bosh_transport_response(&self.pool, session_id, rid, sources, ttl_seconds)
            .await
    }

    async fn release_bosh_fences(&self, session_id: Uuid) -> Result<()> {
        db::replay::release_bosh_transport_fences(&self.pool, session_id).await
    }
}

#[cfg(test)]
impl ReplayService<PostgresReplayRepository> {
    pub(crate) async fn busy_retry_test_fixture(
        database_url: &str,
    ) -> Result<(Self, Uuid, String, Uuid)> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(database_url)
            .await?;
        crate::db::migrate(&pool).await?;
        let recipient = Uuid::new_v4();
        let username = format!("busyretry{}", &recipient.simple().to_string()[..12]);
        let full_jid = format!("{username}@example.test/Phone");
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(recipient)
            .bind(&username)
            .execute(&pool)
            .await?;
        let message_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO offline_messages(
                 id,recipient_id,sender_jid,stanza,target_resource,encrypted,mam_backed
             ) VALUES($1,$2,'sender@remote.test/Phone',$3,'Phone',FALSE,FALSE)",
        )
        .bind(message_id)
        .bind(recipient)
        .bind("<message id='busy-resource-retry'/>")
        .execute(&pool)
        .await?;
        Ok((
            Self::new(PostgresReplayRepository::new(pool), "example.test", 30),
            recipient,
            full_jid,
            message_id,
        ))
    }
    pub(crate) async fn remove_test_recipient(&self, recipient_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(recipient_id)
            .execute(&self.repository_for_tests().pool)
            .await?;
        Ok(())
    }
}
