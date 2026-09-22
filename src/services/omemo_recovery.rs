//! One-time OMEMO transfer lifecycle and source completion capabilities.
use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OmemoRecoveryTransfer {
    pub id: Uuid,
    pub user_id: Uuid,
    pub generation: i64,
    pub source_device_id: i64,
    pub package_sha256: Option<[u8; 32]>,
    pub state: String,
    pub consumer_commitment: Option<[u8; 32]>,
    pub consumed_auth_generation: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub prepared_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub expired: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OmemoRecoveryAuthority {
    pub next_generation: i64,
    pub latest_consumed_generation: i64,
    pub latest_consumed_transfer_id: Option<Uuid>,
    pub latest_consumer_commitment: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OmemoRecoveryPollStatus {
    pub generation: i64,
    pub state: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrepareOmemoRecovery {
    Prepared(OmemoRecoveryTransfer),
    Replay(OmemoRecoveryTransfer),
    Conflict,
    Unauthorized,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SealOmemoRecovery {
    Sealed(OmemoRecoveryTransfer),
    Replay(OmemoRecoveryTransfer),
    Missing,
    Expired,
    Conflict,
    Unauthorized,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsumeOmemoRecovery {
    Consumed(OmemoRecoveryTransfer),
    Replay(OmemoRecoveryTransfer),
    Missing,
    Expired,
    Conflict,
    Unauthorized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevokeOmemoRecovery {
    Revoked,
    Replay,
    Missing,
    Conflict,
    Unauthorized,
}

pub struct PrepareOmemoRecoveryRequest<'a> {
    pub user_id: Uuid,
    pub canonical_account: &'a str,
    pub expected_auth_generation: i64,
    pub presented_session: &'a str,
    pub transfer_id: Uuid,
    pub source_device_id: i64,
    pub poll_secret: &'a [u8; 32],
}

pub struct ConsumeOmemoRecoveryRequest<'a> {
    pub user_id: Uuid,
    pub canonical_account: &'a str,
    pub expected_auth_generation: i64,
    pub presented_session: &'a str,
    pub transfer_id: Uuid,
    pub consumer_secret: &'a [u8; 32],
    pub package_sha256: &'a [u8; 32],
}

pub(crate) struct OmemoRecoveryActor<'a> {
    pub(crate) user_id: Uuid,
    pub(crate) auth_generation: i64,
    pub(crate) session_token: &'a str,
}

pub(crate) enum OmemoRecoveryRead<T> {
    Authorized(T),
    Unauthorized,
}

pub(crate) trait OmemoRecoveryRepository: Send + Sync {
    fn prepare(
        &self,
        request: PrepareOmemoRecoveryRequest<'_>,
    ) -> impl std::future::Future<Output = Result<PrepareOmemoRecovery>> + Send;
    fn seal(
        &self,
        actor: OmemoRecoveryActor<'_>,
        transfer_id: Uuid,
        digest: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<SealOmemoRecovery>> + Send;
    fn consume(
        &self,
        request: ConsumeOmemoRecoveryRequest<'_>,
    ) -> impl std::future::Future<Output = Result<ConsumeOmemoRecovery>> + Send;
    fn revoke(
        &self,
        actor: OmemoRecoveryActor<'_>,
        transfer_id: Uuid,
    ) -> impl std::future::Future<Output = Result<RevokeOmemoRecovery>> + Send;
    fn transfer(
        &self,
        actor: OmemoRecoveryActor<'_>,
        transfer_id: Uuid,
    ) -> impl std::future::Future<Output = Result<OmemoRecoveryRead<Option<OmemoRecoveryTransfer>>>> + Send;
    fn authority(
        &self,
        actor: OmemoRecoveryActor<'_>,
    ) -> impl std::future::Future<Output = Result<OmemoRecoveryRead<OmemoRecoveryAuthority>>> + Send;
}

#[derive(Clone)]
pub(crate) struct OmemoRecoveryService<R> {
    repository: R,
}
impl<R: OmemoRecoveryRepository> OmemoRecoveryService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }
    pub(crate) async fn prepare(
        &self,
        request: PrepareOmemoRecoveryRequest<'_>,
    ) -> Result<PrepareOmemoRecovery> {
        self.repository.prepare(request).await
    }
    pub(crate) async fn seal(
        &self,
        actor: OmemoRecoveryActor<'_>,
        transfer_id: Uuid,
        digest: &[u8; 32],
    ) -> Result<SealOmemoRecovery> {
        self.repository.seal(actor, transfer_id, digest).await
    }
    pub(crate) async fn consume(
        &self,
        request: ConsumeOmemoRecoveryRequest<'_>,
    ) -> Result<ConsumeOmemoRecovery> {
        self.repository.consume(request).await
    }
    pub(crate) async fn revoke(
        &self,
        actor: OmemoRecoveryActor<'_>,
        transfer_id: Uuid,
    ) -> Result<RevokeOmemoRecovery> {
        self.repository.revoke(actor, transfer_id).await
    }
    pub(crate) async fn transfer(
        &self,
        actor: OmemoRecoveryActor<'_>,
        transfer_id: Uuid,
    ) -> Result<OmemoRecoveryRead<Option<OmemoRecoveryTransfer>>> {
        self.repository.transfer(actor, transfer_id).await
    }
    pub(crate) async fn authority(
        &self,
        actor: OmemoRecoveryActor<'_>,
    ) -> Result<OmemoRecoveryRead<OmemoRecoveryAuthority>> {
        self.repository.authority(actor).await
    }
}

pub(crate) trait OmemoRecoveryPollRepository: Send + Sync {
    fn poll(
        &self,
        domain: &str,
        transfer_id: Uuid,
        poll_secret: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<Option<OmemoRecoveryPollStatus>>> + Send;
}
#[derive(Clone)]
pub(crate) struct OmemoRecoveryPollService<R> {
    repository: R,
}
impl<R: OmemoRecoveryPollRepository> OmemoRecoveryPollService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }
    pub(crate) async fn poll(
        &self,
        domain: &str,
        transfer_id: Uuid,
        poll_secret: &[u8; 32],
    ) -> Result<Option<OmemoRecoveryPollStatus>> {
        self.repository.poll(domain, transfer_id, poll_secret).await
    }
}
