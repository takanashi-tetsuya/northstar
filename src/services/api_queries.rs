//! Authorized REST projections and complete repeatable-read queries.
pub(crate) use crate::services::mam::{ArchivePage, MamArchiveQuery};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::{Uuid, Variant};
use zeroize::Zeroizing;

/// Verifier-free identity/status projection for REST bearer authorization.
/// Password and SCRAM material is structurally absent, so ordinary API
/// requests cannot accidentally retain reusable credential verifiers.
#[derive(Clone, Debug)]
pub struct ApiPrincipal {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_admin: bool,
    pub auth_generation: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageBoundary {
    pub created_at: DateTime<Utc>,
    pub id: Uuid,
}

#[derive(Debug)]
pub struct KeysetPage<T> {
    pub rows: Vec<T>,
    pub next: Option<PageBoundary>,
    /// PostgreSQL time captured for this page. Routes must use this value when
    /// issuing the continuation cursor, never a web node's wall clock.
    pub database_now: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ReportPageRow {
    pub id: Uuid,
    pub reporter_id: Uuid,
    pub reporter_username: String,
    pub reported_jid: String,
    pub category: String,
    pub description: String,
    pub status: String,
    pub resolution: Option<String>,
    pub assigned_admin: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub evidence: serde_json::Value,
    pub appeal: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct UserPageRow {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_admin: bool,
    pub is_disabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct InvitationPageRow {
    pub id: Uuid,
    pub label: String,
    pub created_by: Option<String>,
    pub max_uses: i32,
    pub use_count: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct MucRoomPageRow {
    pub id: Uuid,
    pub localpart: String,
    pub title: Option<String>,
    pub public: bool,
    pub persistent: bool,
    pub members_only: bool,
    pub moderated: bool,
    pub non_anonymous: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadDeadLetterKind {
    StorageJob,
    Cleanup,
}

impl UploadDeadLetterKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StorageJob => "storage_job",
            Self::Cleanup => "cleanup",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "storage_job" => Some(Self::StorageJob),
            "cleanup" => Some(Self::Cleanup),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UploadDeadLetterId {
    StorageJob(i64),
    /// Random administrator-facing recovery handle. This is deliberately not
    /// `upload_cleanup_queue.object_id`, which is also the local object key.
    Cleanup(Uuid),
}

impl UploadDeadLetterId {
    pub fn parse(kind: UploadDeadLetterKind, value: &str) -> Option<Self> {
        match kind {
            UploadDeadLetterKind::StorageJob => value
                .parse::<i64>()
                .ok()
                .filter(|id| *id > 0 && id.to_string() == value)
                .map(Self::StorageJob),
            UploadDeadLetterKind::Cleanup => Uuid::parse_str(value)
                .ok()
                .filter(|id| {
                    !id.is_nil()
                        && id.get_version_num() == 4
                        && id.get_variant() == Variant::RFC4122
                        && id.hyphenated().to_string() == value
                })
                .map(Self::Cleanup),
        }
    }

    pub fn as_api_string(self) -> String {
        match self {
            Self::StorageJob(id) => id.to_string(),
            Self::Cleanup(id) => id.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadDeadLetterBoundary {
    StorageJob(i64),
    Cleanup(Uuid),
}

pub struct UploadDeadLetterRecord {
    pub id: UploadDeadLetterId,
    pub operation: String,
    pub attempts: i64,
    pub dead_lettered_at: DateTime<Utc>,
    pub available_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    /// Never serialize this field directly. The HTTP boundary emits only a
    /// scrubbed, bounded categorical summary.
    pub(crate) last_error: Option<Zeroizing<String>>,
}

pub struct UploadDeadLetterPage {
    pub rows: Vec<UploadDeadLetterRecord>,
    pub next: Option<UploadDeadLetterBoundary>,
    pub database_now: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct SessionView {
    pub connection_id: uuid::Uuid,
    pub node: String,
    pub jid: String,
    pub ip: Option<String>,
    pub resource: String,
    /// XEP-0280 is negotiated per resource. Exposing this non-secret runtime
    /// flag makes a successful control IQ distinguishable from a fanout or
    /// transport problem during production diagnosis.
    pub carbons_enabled: bool,
    pub connected_duration_seconds: u64,
}

#[derive(Serialize)]
pub struct OfflineMessagesStats {
    pub total_messages: i64,
    pub estimated_bytes: i64,
}

#[derive(Serialize)]
pub struct MucRoomView {
    pub id: uuid::Uuid,
    pub localpart: String,
    pub title: Option<String>,
    pub created_at: DateTime<Utc>,
    pub public: bool,
    pub persistent: bool,
    pub members_only: bool,
    pub moderated: bool,
    pub non_anonymous: bool,
    pub current_occupants: usize,
}

/// Revalidated under the same database locks as the requested projection.
/// Never include the bearer in diagnostics.
pub(crate) struct ApiReadAuthority<'a> {
    pub(crate) user_id: Uuid,
    pub(crate) auth_generation: i64,
    pub(crate) session_token: &'a str,
}

pub(crate) struct TimedRead<T> {
    pub(crate) value: T,
    pub(crate) database_now: DateTime<Utc>,
}

pub(crate) struct SessionPage {
    pub(crate) rows: Vec<SessionView>,
    pub(crate) next: Option<Uuid>,
    pub(crate) database_now: DateTime<Utc>,
}

pub(crate) struct LiveAdminStats {
    pub(crate) island_mode: bool,
    pub(crate) registration_open: bool,
    pub(crate) online_sessions: usize,
    pub(crate) room_occupants: usize,
}

pub(crate) struct AdminStatistics {
    pub(crate) users: i64,
    pub(crate) archived: i64,
    pub(crate) offline: i64,
    pub(crate) rooms: i64,
    pub(crate) uploads: i64,
    pub(crate) push_subscriptions: i64,
    pub(crate) pending_reports: i64,
    pub(crate) pending_appeals: i64,
    pub(crate) active_invitations: i64,
    pub(crate) live: LiveAdminStats,
}

/// An absent authorized result means that the bearer or its generation/role
/// was rejected. Empty collections and missing archive cursors are separate
/// values. Runtime projections are synchronous and execute under the same
/// authorization locks; SQL transactions never cross this port.
pub(crate) trait ApiQueryRepository: Send + Sync {
    fn principal(
        &self,
        token: &str,
    ) -> impl std::future::Future<Output = Result<Option<ApiPrincipal>>> + Send;
    fn cursor_clock(&self) -> impl std::future::Future<Output = Result<DateTime<Utc>>> + Send;
    fn users(
        &self,
        actor: ApiReadAuthority<'_>,
        after: Option<PageBoundary>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Option<KeysetPage<UserPageRow>>>> + Send;
    fn admin_reports(
        &self,
        actor: ApiReadAuthority<'_>,
        status: Option<&str>,
        after: Option<PageBoundary>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Option<KeysetPage<ReportPageRow>>>> + Send;
    fn own_reports(
        &self,
        actor: ApiReadAuthority<'_>,
        status: Option<&str>,
        after: Option<PageBoundary>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Option<KeysetPage<ReportPageRow>>>> + Send;
    fn invitations(
        &self,
        actor: ApiReadAuthority<'_>,
        after: Option<PageBoundary>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Option<KeysetPage<InvitationPageRow>>>> + Send;
    fn upload_dead_letters(
        &self,
        actor: ApiReadAuthority<'_>,
        kind: UploadDeadLetterKind,
        after: Option<UploadDeadLetterBoundary>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Option<UploadDeadLetterPage>>> + Send;
    fn history(
        &self,
        actor: ApiReadAuthority<'_>,
        query: &MamArchiveQuery,
    ) -> impl std::future::Future<Output = Result<Option<TimedRead<Option<ArchivePage>>>>> + Send;
    fn offline_statistics(
        &self,
        actor: ApiReadAuthority<'_>,
    ) -> impl std::future::Future<Output = Result<Option<OfflineMessagesStats>>> + Send;
    fn statistics<F>(
        &self,
        actor: ApiReadAuthority<'_>,
        snapshot: F,
    ) -> impl std::future::Future<Output = Result<Option<AdminStatistics>>> + Send
    where
        F: FnOnce() -> LiveAdminStats + Send;
    fn sessions<F>(
        &self,
        actor: ApiReadAuthority<'_>,
        snapshot: F,
    ) -> impl std::future::Future<Output = Result<Option<SessionPage>>> + Send
    where
        F: FnOnce() -> (Vec<SessionView>, Option<Uuid>) + Send;
    fn muc_rooms<F>(
        &self,
        actor: ApiReadAuthority<'_>,
        after: Option<PageBoundary>,
        limit: i64,
        snapshot: F,
    ) -> impl std::future::Future<Output = Result<Option<KeysetPage<MucRoomView>>>> + Send
    where
        F: FnOnce(Vec<MucRoomPageRow>) -> Vec<MucRoomView> + Send;
}

#[derive(Clone)]
pub(crate) struct ApiQueryService<R> {
    repository: R,
}
impl<R: ApiQueryRepository> ApiQueryService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }
    pub(crate) async fn principal(&self, token: &str) -> Result<Option<ApiPrincipal>> {
        self.repository.principal(token).await
    }
    pub(crate) async fn cursor_clock(&self) -> Result<DateTime<Utc>> {
        self.repository.cursor_clock().await
    }
    pub(crate) async fn users(
        &self,
        actor: ApiReadAuthority<'_>,
        after: Option<PageBoundary>,
        limit: i64,
    ) -> Result<Option<KeysetPage<UserPageRow>>> {
        self.repository.users(actor, after, limit).await
    }
    pub(crate) async fn admin_reports(
        &self,
        actor: ApiReadAuthority<'_>,
        status: Option<&str>,
        after: Option<PageBoundary>,
        limit: i64,
    ) -> Result<Option<KeysetPage<ReportPageRow>>> {
        self.repository
            .admin_reports(actor, status, after, limit)
            .await
    }
    pub(crate) async fn own_reports(
        &self,
        actor: ApiReadAuthority<'_>,
        status: Option<&str>,
        after: Option<PageBoundary>,
        limit: i64,
    ) -> Result<Option<KeysetPage<ReportPageRow>>> {
        self.repository
            .own_reports(actor, status, after, limit)
            .await
    }
    pub(crate) async fn invitations(
        &self,
        actor: ApiReadAuthority<'_>,
        after: Option<PageBoundary>,
        limit: i64,
    ) -> Result<Option<KeysetPage<InvitationPageRow>>> {
        self.repository.invitations(actor, after, limit).await
    }
    pub(crate) async fn upload_dead_letters(
        &self,
        actor: ApiReadAuthority<'_>,
        kind: UploadDeadLetterKind,
        after: Option<UploadDeadLetterBoundary>,
        limit: i64,
    ) -> Result<Option<UploadDeadLetterPage>> {
        self.repository
            .upload_dead_letters(actor, kind, after, limit)
            .await
    }
    pub(crate) async fn history(
        &self,
        actor: ApiReadAuthority<'_>,
        query: &MamArchiveQuery,
    ) -> Result<Option<TimedRead<Option<ArchivePage>>>> {
        self.repository.history(actor, query).await
    }
    pub(crate) async fn offline_statistics(
        &self,
        actor: ApiReadAuthority<'_>,
    ) -> Result<Option<OfflineMessagesStats>> {
        self.repository.offline_statistics(actor).await
    }
    pub(crate) async fn statistics<F>(
        &self,
        actor: ApiReadAuthority<'_>,
        snapshot: F,
    ) -> Result<Option<AdminStatistics>>
    where
        F: FnOnce() -> LiveAdminStats + Send,
    {
        self.repository.statistics(actor, snapshot).await
    }
    pub(crate) async fn sessions<F>(
        &self,
        actor: ApiReadAuthority<'_>,
        snapshot: F,
    ) -> Result<Option<SessionPage>>
    where
        F: FnOnce() -> (Vec<SessionView>, Option<Uuid>) + Send,
    {
        self.repository.sessions(actor, snapshot).await
    }
    pub(crate) async fn muc_rooms<F>(
        &self,
        actor: ApiReadAuthority<'_>,
        after: Option<PageBoundary>,
        limit: i64,
        snapshot: F,
    ) -> Result<Option<KeysetPage<MucRoomView>>>
    where
        F: FnOnce(Vec<MucRoomPageRow>) -> Vec<MucRoomView> + Send,
    {
        self.repository
            .muc_rooms(actor, after, limit, snapshot)
            .await
    }
}
