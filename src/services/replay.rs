//! Durable XEP-0160 replay application boundary.
//!
//! Applies resource ownership and replay policy through repository operations.
//! Transport code owns ordering and socket backpressure; only the unsent suffix
//! can be released for another attempt.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub(crate) const OWNER_LEASE_SECONDS: i64 = 90;

pub(crate) type PendingPresencePage = PendingPresenceReplayPage;

#[derive(Clone, Debug)]
pub(crate) struct ReplaySession {
    lease: OfflineReplayLease,
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
    pub(crate) fn lease(&self) -> &OfflineReplayLease {
        &self.lease
    }
    pub(crate) fn owner_bare_jid(&self) -> &str {
        &self.owner_bare_jid
    }
    pub(crate) fn owner_full_jid(&self) -> &str {
        &self.owner_full_jid
    }

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

#[derive(Clone, Debug)]
pub struct PendingPresenceCursor {
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) source: i16,
    pub(crate) key: String,
}

#[derive(Clone, Debug)]
pub struct PendingPresenceReplay {
    pub requester: String,
    pub stanza: Option<String>,
    pub cursor: PendingPresenceCursor,
}

#[derive(Debug)]
pub struct PendingPresenceReplayPage {
    pub items: Vec<PendingPresenceReplay>,
    pub next_cursor: Option<PendingPresenceCursor>,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineReplayLease {
    pub recipient_id: Uuid,
    pub resource: String,
    pub owner_token: Uuid,
    pub replay_started_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineReplayBusyUntil {
    pub expires_at: DateTime<Utc>,
    /// Remaining lease time measured by PostgreSQL in the same query which
    /// returned `expires_at`. Callers must use this monotonic duration rather
    /// than subtracting an application-wall-clock value.
    pub retry_after: std::time::Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OfflineReplayLeaseAcquire {
    Acquired(OfflineReplayLease),
    BusyUntil(OfflineReplayBusyUntil),
}

pub(crate) trait ReplayLeaseRepository: Send + Sync {
    fn username(
        &self,
        recipient_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn acquire_lease(
        &self,
        recipient_id: Uuid,
        resource: &str,
        owner_token: Uuid,
        cutoff: Option<DateTime<Utc>>,
        lease_seconds: i64,
    ) -> impl std::future::Future<Output = Result<OfflineReplayLeaseAcquire>> + Send;
}

pub(crate) trait ReplayRepository: ReplayLeaseRepository {
    fn claim_page(
        &self,
        session: &ReplaySession,
        active_privacy_list: Option<&str>,
        bind2_mam_catchup: bool,
        offline_ttl_days: i64,
    ) -> impl std::future::Future<Output = Result<ReplayPageOutcome>> + Send;
    fn renew_before_send(
        &self,
        session: &ReplaySession,
        page_claim_token: Uuid,
        pending_ids: &[Uuid],
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn release_unsent(
        &self,
        session: &ReplaySession,
        page_claim_token: Uuid,
        message_ids: &[Uuid],
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
    fn finish(
        &self,
        session: &ReplaySession,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn pending_presence_page(
        &self,
        recipient_id: Uuid,
        owner_bare_jid: &str,
        active_privacy_list: Option<&str>,
        after: Option<&PendingPresenceCursor>,
        domain: &str,
    ) -> impl std::future::Future<Output = Result<PendingPresencePage>> + Send;
    fn fence_socket_write(
        &self,
        delivery: crate::outbound::DurableDelivery,
    ) -> impl std::future::Future<Output = Result<crate::outbound::DurableDelivery>> + Send;
    fn acknowledge_socket_write(
        &self,
        delivery: crate::outbound::DurableDelivery,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn renew_bosh_fences(
        &self,
        session_id: Uuid,
        expected_response: Option<(u64, &crate::outbound::BoshResponseOwnership)>,
        ttl_seconds: u64,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn acknowledge_bosh_responses(
        &self,
        session_id: Uuid,
        acknowledged_rid: u64,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn bind_bosh_response_sources(
        &self,
        session_id: Uuid,
        rid: u64,
        sources: &[crate::outbound::TransportOwnershipSource],
        ttl_seconds: u64,
    ) -> impl std::future::Future<Output = Result<crate::outbound::BoshResponseOwnership>> + Send;
    fn release_bosh_fences(
        &self,
        session_id: Uuid,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

#[derive(Clone)]
pub(crate) struct ReplayService<R> {
    repository: R,
    domain: String,
    offline_ttl_days: i64,
}
impl<R: ReplayLeaseRepository> ReplayService<R> {
    pub(crate) fn new(repository: R, domain: &str, offline_ttl_days: i64) -> Self {
        Self {
            repository,
            domain: domain.to_owned(),
            offline_ttl_days,
        }
    }
    #[cfg(test)]
    pub(crate) fn repository_for_tests(&self) -> &R {
        &self.repository
    }
    pub(crate) async fn start(
        &self,
        recipient_id: Uuid,
        current_full_jid: &str,
        explicit_cutoff: Option<DateTime<Utc>>,
    ) -> Result<ReplayStartOutcome> {
        let username = self
            .repository
            .username(recipient_id)
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
            match self
                .repository
                .acquire_lease(
                    recipient_id,
                    owner_resource,
                    owner_token,
                    explicit_cutoff,
                    OWNER_LEASE_SECONDS,
                )
                .await?
            {
                OfflineReplayLeaseAcquire::Acquired(lease) => {
                    ReplayStartOutcome::Acquired(ReplaySession {
                        lease,
                        owner_bare_jid,
                        owner_full_jid,
                    })
                }
                OfflineReplayLeaseAcquire::BusyUntil(busy) => {
                    ReplayStartOutcome::BusyUntil(ReplayBusyUntil {
                        expires_at: busy.expires_at,
                        retry_after: busy.retry_after,
                    })
                }
            },
        )
    }
}

impl<R: ReplayRepository> ReplayService<R> {
    pub(crate) async fn claim_page(
        &self,
        session: &ReplaySession,
        active_privacy_list: Option<&str>,
        bind2_mam_catchup: bool,
    ) -> Result<ReplayPageOutcome> {
        self.repository
            .claim_page(
                session,
                active_privacy_list,
                bind2_mam_catchup,
                self.offline_ttl_days,
            )
            .await
    }

    pub(crate) async fn renew_before_send(
        &self,
        session: &ReplaySession,
        page_claim_token: Uuid,
        pending_ids: &[Uuid],
    ) -> Result<bool> {
        self.repository
            .renew_before_send(session, page_claim_token, pending_ids)
            .await
    }

    pub(crate) async fn release_unsent(
        &self,
        session: &ReplaySession,
        page_claim_token: Uuid,
        message_ids: &[Uuid],
    ) -> Result<u64> {
        self.repository
            .release_unsent(session, page_claim_token, message_ids)
            .await
    }

    pub(crate) async fn finish(&self, session: &ReplaySession) -> Result<bool> {
        self.repository.finish(session).await
    }

    pub(crate) async fn pending_presence_page(
        &self,
        recipient_id: Uuid,
        owner_bare_jid: &str,
        active_privacy_list: Option<&str>,
        after: Option<&PendingPresenceCursor>,
    ) -> Result<PendingPresencePage> {
        self.repository
            .pending_presence_page(
                recipient_id,
                owner_bare_jid,
                active_privacy_list,
                after,
                &self.domain,
            )
            .await
    }

    pub(crate) async fn fence_socket_write(
        &self,
        delivery: crate::outbound::DurableDelivery,
    ) -> Result<crate::outbound::DurableDelivery> {
        self.repository.fence_socket_write(delivery).await
    }

    pub(crate) async fn acknowledge_socket_write(
        &self,
        delivery: crate::outbound::DurableDelivery,
    ) -> Result<()> {
        self.repository.acknowledge_socket_write(delivery).await
    }

    pub(crate) async fn renew_bosh_fences(
        &self,
        session_id: Uuid,
        expected_response: Option<(u64, &crate::outbound::BoshResponseOwnership)>,
        ttl_seconds: u64,
    ) -> Result<()> {
        self.repository
            .renew_bosh_fences(session_id, expected_response, ttl_seconds)
            .await
    }

    pub(crate) async fn acknowledge_bosh_responses(
        &self,
        session_id: Uuid,
        acknowledged_rid: u64,
    ) -> Result<()> {
        self.repository
            .acknowledge_bosh_responses(session_id, acknowledged_rid)
            .await
    }

    pub(crate) async fn bind_bosh_response_sources(
        &self,
        session_id: Uuid,
        rid: u64,
        sources: &[crate::outbound::TransportOwnershipSource],
        ttl_seconds: u64,
    ) -> Result<crate::outbound::BoshResponseOwnership> {
        self.repository
            .bind_bosh_response_sources(session_id, rid, sources, ttl_seconds)
            .await
    }

    pub(crate) async fn release_bosh_fences(&self, session_id: Uuid) -> Result<()> {
        self.repository.release_bosh_fences(session_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    struct LeaseRepository {
        username: Option<&'static str>,
        fail_lookup: bool,
        fail_lease: bool,
        lease_calls: AtomicUsize,
    }
    impl ReplayLeaseRepository for LeaseRepository {
        async fn username(&self, _: Uuid) -> Result<Option<String>> {
            anyhow::ensure!(!self.fail_lookup, "lookup unavailable");
            Ok(self.username.map(str::to_owned))
        }
        async fn acquire_lease(
            &self,
            _: Uuid,
            resource: &str,
            owner_token: Uuid,
            cutoff: Option<DateTime<Utc>>,
            lease_seconds: i64,
        ) -> Result<OfflineReplayLeaseAcquire> {
            self.lease_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(resource, "Phone");
            assert!(!owner_token.is_nil());
            assert_eq!(cutoff, None);
            assert_eq!(lease_seconds, 90);
            anyhow::ensure!(!self.fail_lease, "lease unavailable");
            Ok(OfflineReplayLeaseAcquire::BusyUntil(
                OfflineReplayBusyUntil {
                    // An unrelated application clock must not change the delay.
                    expires_at: DateTime::from_timestamp(1, 0).unwrap(),
                    retry_after: Duration::from_millis(137),
                },
            ))
        }
    }
    fn service(
        username: Option<&'static str>,
        fail_lookup: bool,
        fail_lease: bool,
    ) -> ReplayService<LeaseRepository> {
        ReplayService::new(
            LeaseRepository {
                username,
                fail_lookup,
                fail_lease,
                lease_calls: AtomicUsize::new(0),
            },
            "example.test",
            30,
        )
    }

    #[tokio::test]
    async fn rejects_foreign_resources_before_claiming_and_preserves_database_retry_delay() {
        let service = service(Some("alice"), false, false);
        let user = Uuid::new_v4();
        for jid in [
            "bob@example.test/Phone",
            "alice@elsewhere.test/Phone",
            "alice@example.test",
        ] {
            assert!(service.start(user, jid, None).await.is_err());
        }
        assert_eq!(service.repository.lease_calls.load(Ordering::SeqCst), 0);
        let ReplayStartOutcome::BusyUntil(busy) = service
            .start(user, "Alice@EXAMPLE.test/Phone", None)
            .await
            .unwrap()
        else {
            panic!("busy lease must not grant ownership")
        };
        assert_eq!(busy.expires_at, DateTime::from_timestamp(1, 0).unwrap());
        assert_eq!(busy.retry_after, Duration::from_millis(137));
        assert_eq!(service.repository.lease_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn missing_account_and_repository_failures_never_grant_replay_ownership() {
        for (username, fail_lookup, fail_lease, calls) in [
            (None, false, false, 0),
            (Some("alice"), true, false, 0),
            (Some("alice"), false, true, 1),
        ] {
            let service = service(username, fail_lookup, fail_lease);
            assert!(service
                .start(Uuid::new_v4(), "alice@example.test/Phone", None)
                .await
                .is_err());
            assert_eq!(service.repository.lease_calls.load(Ordering::SeqCst), calls);
        }
    }
}
