//! Durable XEP-0160 replay application boundary.
//!
//! Transport code owns ordering and socket backpressure. This service owns
//! every PostgreSQL capability needed to acquire resource replay ownership,
//! claim an authorized page, renew its exact unsent suffix, and release only
//! work which never crossed the transport queue boundary.

use crate::db;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

const OWNER_LEASE_SECONDS: i64 = db::replay::REPLAY_OWNER_LEASE_SECONDS;

pub(crate) type PendingPresenceCursor = db::replay::PendingPresenceCursor;
pub(crate) type PendingPresencePage = db::replay::PendingPresenceReplayPage;

#[derive(Clone, Debug)]
pub(crate) struct ReplaySession {
    lease: db::replay::OfflineReplayLease,
    owner_bare_jid: String,
    owner_full_jid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplayBusyUntil {
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) retry_after: std::time::Duration,
}

#[derive(Clone, Debug)]
pub(crate) enum ReplayStartOutcome {
    Acquired(ReplaySession),
    BusyUntil(ReplayBusyUntil),
}

impl ReplaySession {
    pub(crate) fn recipient_id(&self) -> Uuid {
        self.lease.recipient_id
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ReplayMessage {
    pub(crate) id: Uuid,
    pub(crate) stanza: String,
}

#[derive(Debug)]
pub(crate) struct ReplayPage {
    pub(crate) claim_token: Uuid,
    pub(crate) messages: Vec<ReplayMessage>,
}

#[derive(Debug)]
pub(crate) enum ReplayPageOutcome {
    Claimed(ReplayPage),
    Empty,
    LeaseLost,
}

#[derive(Clone)]
pub(crate) struct ReplayService {
    pool: PgPool,
    domain: String,
    offline_ttl_days: i64,
}

impl ReplayService {
    pub(crate) fn new(pool: PgPool, domain: &str, offline_ttl_days: i64) -> Self {
        Self {
            pool,
            domain: domain.to_owned(),
            offline_ttl_days,
        }
    }

    #[cfg(test)]
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
            Self::new(pool, "example.test", 30),
            recipient,
            full_jid,
            message_id,
        ))
    }

    #[cfg(test)]
    pub(crate) async fn remove_test_recipient(&self, recipient_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(recipient_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Start one resource replay epoch. The database clock is authoritative
    /// unless the availability transition already captured an earlier cutoff.
    pub(crate) async fn start(
        &self,
        recipient_id: Uuid,
        current_full_jid: &str,
        explicit_cutoff: Option<DateTime<Utc>>,
    ) -> Result<ReplayStartOutcome> {
        let username = sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE id=$1")
            .bind(recipient_id)
            .fetch_optional(&self.pool)
            .await?
            .context("offline replay account disappeared")?;
        let owner_bare_jid = crate::jid::canonicalize_bare(&format!("{username}@{}", self.domain))?;
        let owner_full_jid = crate::jid::canonical_session_key(current_full_jid)?;
        anyhow::ensure!(
            crate::jid::canonical_bare_key(&owner_full_jid)? == owner_bare_jid,
            "offline replay resource does not belong to recipient account"
        );
        let parsed = crate::jid::CanonicalJid::parse(&owner_full_jid)?;
        let owner_resource = parsed
            .resourcepart()
            .expect("canonical_session_key requires a resourcepart");
        anyhow::ensure!(
            (1..=1023).contains(&owner_resource.len()),
            "offline replay resource must be between 1 and 1023 bytes"
        );
        let owner_token = Uuid::new_v4();
        Ok(
            match db::replay::acquire_offline_replay_lease(
                &self.pool,
                recipient_id,
                owner_resource,
                owner_token,
                explicit_cutoff,
                OWNER_LEASE_SECONDS,
            )
            .await?
            {
                db::replay::OfflineReplayLeaseAcquire::Acquired(lease) => {
                    ReplayStartOutcome::Acquired(ReplaySession {
                        lease,
                        owner_bare_jid,
                        owner_full_jid,
                    })
                }
                db::replay::OfflineReplayLeaseAcquire::BusyUntil(busy) => {
                    ReplayStartOutcome::BusyUntil(ReplayBusyUntil {
                        expires_at: busy.expires_at,
                        retry_after: busy.retry_after,
                    })
                }
            },
        )
    }

    pub(crate) async fn claim_page(
        &self,
        session: &ReplaySession,
        active_privacy_list: Option<&str>,
        bind2_mam_catchup: bool,
    ) -> Result<ReplayPageOutcome> {
        Ok(
            match db::replay::claim_offline_replay_page(
                &self.pool,
                &session.lease,
                self.offline_ttl_days,
                &session.owner_bare_jid,
                &session.owner_full_jid,
                active_privacy_list,
                bind2_mam_catchup,
                OWNER_LEASE_SECONDS,
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

    pub(crate) async fn renew_before_send(
        &self,
        session: &ReplaySession,
        page_claim_token: Uuid,
        pending_ids: &[Uuid],
    ) -> Result<bool> {
        db::replay::renew_offline_replay_before_send(
            &self.pool,
            &session.lease,
            page_claim_token,
            pending_ids,
            OWNER_LEASE_SECONDS,
        )
        .await
    }

    pub(crate) async fn release_unsent(
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

    pub(crate) async fn finish(&self, session: &ReplaySession) -> Result<bool> {
        db::replay::release_offline_replay_lease(&self.pool, &session.lease).await
    }

    pub(crate) async fn pending_presence_page(
        &self,
        recipient_id: Uuid,
        owner_bare_jid: &str,
        active_privacy_list: Option<&str>,
        after: Option<&PendingPresenceCursor>,
    ) -> Result<PendingPresencePage> {
        db::replay::pending_presence_replay_page_filtered(
            &self.pool,
            recipient_id,
            owner_bare_jid,
            &self.domain,
            active_privacy_list,
            after,
        )
        .await
    }

    /// Acquire the exact short-lived non-SM socket ownership fence. Transport
    /// code never receives PostgreSQL authority directly.
    pub(crate) async fn fence_socket_write(
        &self,
        delivery: crate::outbound::DurableDelivery,
    ) -> Result<crate::outbound::DurableDelivery> {
        db::replay::fence_durable_socket_write(&self.pool, delivery).await
    }

    pub(crate) async fn acknowledge_socket_write(
        &self,
        delivery: crate::outbound::DurableDelivery,
    ) -> Result<()> {
        db::replay::acknowledge_durable_delivery(&self.pool, delivery).await
    }

    pub(crate) async fn renew_bosh_fences(
        &self,
        session_id: Uuid,
        expected_response: Option<(u64, &[Uuid])>,
        ttl_seconds: u64,
    ) -> Result<()> {
        db::replay::renew_bosh_delivery_fences(
            &self.pool,
            session_id,
            expected_response,
            ttl_seconds,
        )
        .await
    }

    pub(crate) async fn acknowledge_bosh_responses(
        &self,
        session_id: Uuid,
        acknowledged_rid: u64,
    ) -> Result<()> {
        let acknowledged = db::replay::acknowledge_bosh_delivery_responses(
            &self.pool,
            session_id,
            acknowledged_rid,
        )
        .await?;
        tracing::debug!(
            %session_id,
            acknowledged_rid,
            acknowledged,
            "acknowledged durable BOSH response fences"
        );
        Ok(())
    }

    pub(crate) async fn bind_bosh_response(
        &self,
        session_id: Uuid,
        rid: u64,
        deliveries: &[crate::outbound::DurableDelivery],
        ttl_seconds: u64,
    ) -> Result<()> {
        db::replay::bind_bosh_delivery_response(
            &self.pool,
            session_id,
            rid,
            deliveries,
            ttl_seconds,
        )
        .await
    }

    pub(crate) async fn release_bosh_fences(&self, session_id: Uuid) -> Result<()> {
        db::replay::release_bosh_delivery_fences(&self.pool, session_id).await
    }
}
