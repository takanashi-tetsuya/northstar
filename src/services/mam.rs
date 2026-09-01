//! Application boundary for XEP-0313 archive preferences, authorization and
//! visibility-aware paging.
//!
//! Protocol code parses XMPP forms and renders forwarded stanzas.  This
//! service owns PostgreSQL access and exposes only an authorized room handle,
//! preventing stanza handlers from composing room and affiliation reads.

use crate::db;
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) use crate::db::{
    ArchiveBoundary, ArchivePage, ArchiveRow, MamArchiveQuery, MamPreferences, MamRsmPage,
};

#[derive(Clone, Debug)]
pub(crate) struct MamRoomAccess {
    localpart: String,
    occupant_id_secret: Vec<u8>,
    reveal_real_jid: bool,
}

impl MamRoomAccess {
    pub(crate) fn localpart(&self) -> &str {
        &self.localpart
    }

    pub(crate) fn occupant_id_secret(&self) -> &[u8] {
        &self.occupant_id_secret
    }

    pub(crate) fn reveal_real_jid(&self) -> bool {
        self.reveal_real_jid
    }
}

#[derive(Clone, Debug)]
pub(crate) enum MamRoomAccessOutcome {
    Allowed(MamRoomAccess),
    Missing,
    Forbidden,
}

#[derive(Debug)]
pub(crate) enum MamRoomReadOutcome<T> {
    Allowed { access: MamRoomAccess, value: T },
    Missing,
    Forbidden,
}

/// Minimal protocol-facing row for a federated MAM response stream. Database
/// storage flags and client-origin identifiers intentionally stay behind the
/// service boundary.
#[derive(Clone, Debug)]
pub(crate) struct FederatedMamStreamRow {
    id: Uuid,
    peer_jid: String,
    stanza: String,
    created_at: DateTime<Utc>,
}

impl FederatedMamStreamRow {
    pub(crate) fn id(&self) -> Uuid {
        self.id
    }

    pub(crate) fn peer_jid(&self) -> &str {
        &self.peer_jid
    }

    pub(crate) fn stanza(&self) -> &str {
        &self.stanza
    }

    pub(crate) fn created_at(&self) -> &DateTime<Utc> {
        &self.created_at
    }
}

#[derive(Debug)]
pub(crate) struct FederatedMamStreamPage {
    access: MamRoomAccess,
    rows: Vec<FederatedMamStreamRow>,
    total: i64,
    first_index: i64,
    complete: bool,
}

impl FederatedMamStreamPage {
    pub(crate) fn access(&self) -> &MamRoomAccess {
        &self.access
    }

    pub(crate) fn rows(&self) -> &[FederatedMamStreamRow] {
        &self.rows
    }

    pub(crate) fn total(&self) -> i64 {
        self.total
    }

    pub(crate) fn first_index(&self) -> i64 {
        self.first_index
    }

    pub(crate) fn complete(&self) -> bool {
        self.complete
    }
}

/// Authorization and paging context for one atomic federated room archive
/// response. The federation router remains a separate delivery capability;
/// these fields are the room-read authority that must share one transaction.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FederatedMamStreamRequest<'a> {
    target_domain: &'a str,
    localpart: &'a str,
    viewer_bare_jid: &'a str,
    currently_joined: bool,
    query: &'a MamArchiveQuery,
}

impl<'a> FederatedMamStreamRequest<'a> {
    pub(crate) fn new(
        target_domain: &'a str,
        localpart: &'a str,
        viewer_bare_jid: &'a str,
        currently_joined: bool,
        query: &'a MamArchiveQuery,
    ) -> Self {
        Self {
            target_domain,
            localpart,
            viewer_bare_jid,
            currently_joined,
            query,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FederatedMamAdmissionOutcome {
    Queued,
    Missing,
    Forbidden,
    PageMissing,
    OutboxRejected,
}

#[derive(Clone)]
pub(crate) struct MamService {
    pool: PgPool,
}

impl MamService {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub(crate) async fn preferences(&self, owner_id: Uuid) -> Result<MamPreferences> {
        db::mam_preferences(&self.pool, owner_id).await
    }

    pub(crate) async fn set_preferences(
        &self,
        owner_id: Uuid,
        preferences: &MamPreferences,
    ) -> Result<()> {
        db::set_mam_preferences(&self.pool, owner_id, preferences).await
    }

    /// Resolve room policy and affiliation in one repository snapshot, then
    /// return a capability that can be used for MAM reads.
    pub(crate) async fn authorize_room(
        &self,
        localpart: &str,
        viewer_id: Uuid,
        currently_joined: bool,
    ) -> Result<MamRoomAccessOutcome> {
        Ok(
            match db::authorize_mam_room(&self.pool, localpart, viewer_id, currently_joined).await?
            {
                db::MamRoomReadOutcome::Allowed { access, .. } => {
                    MamRoomAccessOutcome::Allowed(map_room_access(access))
                }
                db::MamRoomReadOutcome::Missing => MamRoomAccessOutcome::Missing,
                db::MamRoomReadOutcome::Forbidden => MamRoomAccessOutcome::Forbidden,
            },
        )
    }

    pub(crate) async fn authorize_federated_room(
        &self,
        localpart: &str,
        viewer_bare_jid: &str,
        currently_joined: bool,
    ) -> Result<MamRoomAccessOutcome> {
        Ok(
            match db::authorize_federated_mam_room(
                &self.pool,
                localpart,
                viewer_bare_jid,
                currently_joined,
            )
            .await?
            {
                db::MamRoomReadOutcome::Allowed { access, .. } => {
                    MamRoomAccessOutcome::Allowed(map_room_access(access))
                }
                db::MamRoomReadOutcome::Missing => MamRoomAccessOutcome::Missing,
                db::MamRoomReadOutcome::Forbidden => MamRoomAccessOutcome::Forbidden,
            },
        )
    }

    pub(crate) async fn personal_boundaries(
        &self,
        owner_id: Uuid,
    ) -> Result<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
        db::archive_boundaries_visible(&self.pool, owner_id).await
    }

    pub(crate) async fn authorized_room_boundaries(
        &self,
        localpart: &str,
        viewer_id: Uuid,
        currently_joined: bool,
    ) -> Result<MamRoomReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
        map_room_read(
            db::mam_room_archive_boundaries_authorized(
                &self.pool,
                localpart,
                viewer_id,
                currently_joined,
            )
            .await?,
        )
    }

    pub(crate) async fn personal_page(
        &self,
        owner_id: Uuid,
        query: &MamArchiveQuery,
    ) -> Result<Option<ArchivePage>> {
        db::mam_user_archive_page(&self.pool, owner_id, query).await
    }

    pub(crate) async fn authorized_room_page(
        &self,
        localpart: &str,
        viewer_id: Uuid,
        currently_joined: bool,
        query: &MamArchiveQuery,
    ) -> Result<MamRoomReadOutcome<Option<ArchivePage>>> {
        map_room_read(
            db::mam_room_archive_page_authorized(
                &self.pool,
                localpart,
                viewer_id,
                currently_joined,
                query,
            )
            .await?,
        )
    }

    pub(crate) async fn authorized_federated_room_boundaries(
        &self,
        localpart: &str,
        viewer_bare_jid: &str,
        currently_joined: bool,
    ) -> Result<MamRoomReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
        map_room_read(
            db::mam_federated_room_archive_boundaries_authorized(
                &self.pool,
                localpart,
                viewer_bare_jid,
                currently_joined,
            )
            .await?,
        )
    }

    /// Authorize a federated room archive read, render its complete wire
    /// response, and admit every result plus the terminal IQ to the durable
    /// S2S outbox in one PostgreSQL transaction. Room identity/policy and the
    /// external affiliation remain locked until the outbox projection commits.
    pub(crate) async fn admit_federated_room_stream<F>(
        &self,
        federation: &crate::s2s::FederationRouter,
        request: FederatedMamStreamRequest<'_>,
        render: F,
    ) -> Result<FederatedMamAdmissionOutcome>
    where
        F: FnOnce(&FederatedMamStreamPage) -> Result<Vec<String>>,
    {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *transaction)
            .await?;
        let page = match db::mam_federated_room_archive_page_authorized_in_transaction(
            &mut transaction,
            request.localpart,
            request.viewer_bare_jid,
            request.currently_joined,
            request.query,
        )
        .await?
        {
            db::MamRoomReadOutcome::Allowed {
                access,
                value: Some(page),
            } => map_federated_stream_page(access, page),
            db::MamRoomReadOutcome::Allowed { value: None, .. } => {
                transaction.commit().await?;
                return Ok(FederatedMamAdmissionOutcome::PageMissing);
            }
            db::MamRoomReadOutcome::Missing => {
                transaction.commit().await?;
                return Ok(FederatedMamAdmissionOutcome::Missing);
            }
            db::MamRoomReadOutcome::Forbidden => {
                transaction.commit().await?;
                return Ok(FederatedMamAdmissionOutcome::Forbidden);
            }
        };

        let responses = match render(&page) {
            Ok(responses) => responses,
            Err(error) => {
                transaction.rollback().await?;
                return Err(error);
            }
        };
        if responses.is_empty() {
            transaction.rollback().await?;
            anyhow::bail!("federated MAM renderer omitted the terminal response");
        }
        let policy = federation.outbox_policy();
        for response in &responses {
            if let Err(error) = db::enqueue_s2s_outbox_in_transaction(
                &mut transaction,
                request.target_domain,
                response,
                None,
                policy,
            )
            .await
            {
                transaction.rollback().await?;
                tracing::warn!(
                    domain = request.target_domain,
                    room = request.localpart,
                    ?error,
                    "federated MAM response stream was rejected atomically"
                );
                return Ok(FederatedMamAdmissionOutcome::OutboxRejected);
            }
        }
        transaction.commit().await?;
        federation.wake_outbox();
        Ok(FederatedMamAdmissionOutcome::Queued)
    }
}

fn map_room_access(access: db::MamRoomArchiveAccess) -> MamRoomAccess {
    MamRoomAccess {
        localpart: access.localpart,
        occupant_id_secret: access.occupant_id_secret,
        reveal_real_jid: access.reveal_real_jid,
    }
}

fn map_room_read<T>(outcome: db::MamRoomReadOutcome<T>) -> Result<MamRoomReadOutcome<T>> {
    Ok(match outcome {
        db::MamRoomReadOutcome::Allowed { access, value } => MamRoomReadOutcome::Allowed {
            access: map_room_access(access),
            value,
        },
        db::MamRoomReadOutcome::Missing => MamRoomReadOutcome::Missing,
        db::MamRoomReadOutcome::Forbidden => MamRoomReadOutcome::Forbidden,
    })
}

fn map_federated_stream_page(
    access: db::MamRoomArchiveAccess,
    page: db::ArchivePage,
) -> FederatedMamStreamPage {
    FederatedMamStreamPage {
        access: map_room_access(access),
        rows: page
            .rows
            .into_iter()
            .map(|row| FederatedMamStreamRow {
                id: row.id,
                peer_jid: row.peer_jid,
                stanza: row.stanza,
                created_at: row.created_at,
            })
            .collect(),
        total: page.total,
        first_index: page.first_index,
        complete: page.complete,
    }
}
