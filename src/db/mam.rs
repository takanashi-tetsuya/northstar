//! Archive snapshots and atomic federation response admission.

use crate::{db, services::mam::*};
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresMamRepository {
    pool: PgPool,
}

impl PostgresMamRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    async fn personal_boundaries(
        &self,
        owner_id: Uuid,
    ) -> Result<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
        db::archive_boundaries_visible(&self.pool, owner_id).await
    }

    async fn authorized_room_boundaries(
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

    async fn personal_page(
        &self,
        owner_id: Uuid,
        query: &MamArchiveQuery,
    ) -> Result<Option<ArchivePage>> {
        db::mam_user_archive_page(&self.pool, owner_id, query).await
    }

    async fn authorized_room_page(
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
}

impl MamQueryRepository for PostgresMamRepository {
    type Error = anyhow::Error;
    async fn query_archive(&self, command: MamQueryCommand) -> Result<MamQueryResult> {
        match command.scope {
            MamQueryScope::Personal { owner_id } => {
                match self.personal_page(owner_id, &command.query).await? {
                    Some(page) => Ok(MamQueryResult::Page { room: None, page }),
                    None => Ok(MamQueryResult::ItemNotFound),
                }
            }
            MamQueryScope::Room {
                localpart,
                viewer_id,
                currently_joined,
            } => {
                match self
                    .authorized_room_page(&localpart, viewer_id, currently_joined, &command.query)
                    .await?
                {
                    MamRoomReadOutcome::Allowed {
                        access,
                        value: Some(page),
                    } => Ok(MamQueryResult::Page {
                        room: Some(access),
                        page,
                    }),
                    MamRoomReadOutcome::Allowed { value: None, .. }
                    | MamRoomReadOutcome::Missing => Ok(MamQueryResult::ItemNotFound),
                    MamRoomReadOutcome::Forbidden => Ok(MamQueryResult::Forbidden),
                }
            }
            MamQueryScope::FederatedRoom { .. } => Ok(MamQueryResult::Forbidden),
        }
    }

    async fn get_boundaries(&self, command: MamMetadataCommand) -> Result<MamMetadataResult> {
        match command.scope {
            MamQueryScope::Personal { owner_id } => {
                let (start, end) = self.personal_boundaries(owner_id).await?;
                Ok(MamMetadataResult::Boundaries {
                    room: None,
                    start,
                    end,
                })
            }
            MamQueryScope::Room {
                localpart,
                viewer_id,
                currently_joined,
            } => {
                match self
                    .authorized_room_boundaries(&localpart, viewer_id, currently_joined)
                    .await?
                {
                    MamRoomReadOutcome::Allowed { access, value } => {
                        Ok(MamMetadataResult::Boundaries {
                            room: Some(access),
                            start: value.0,
                            end: value.1,
                        })
                    }
                    MamRoomReadOutcome::Missing => Ok(MamMetadataResult::ItemNotFound),
                    MamRoomReadOutcome::Forbidden => Ok(MamMetadataResult::Forbidden),
                }
            }
            MamQueryScope::FederatedRoom { .. } => Ok(MamMetadataResult::Forbidden),
        }
    }

    async fn get_preferences(&self, command: MamPreferencesGetCommand) -> Result<MamPreferences> {
        db::mam_preferences(&self.pool, command.owner_id).await
    }
    /// Resolve room policy and affiliation in one repository snapshot, then
    /// return a capability that can be used for MAM reads.
    async fn authorize_room(
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

    async fn authorize_federated_room(
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

    async fn authorized_federated_room_boundaries(
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
}

impl MamPreferencesWriter for PostgresMamRepository {
    type Error = anyhow::Error;

    async fn set_preferences(&self, command: MamPreferencesSetCommand) -> Result<()> {
        db::set_mam_preferences(&self.pool, command.owner_id, &command.preferences).await
    }
}

impl FederatedMamStreamWriter for PostgresMamRepository {
    type Error = anyhow::Error;

    /// Authorize a federated room archive read, render its complete wire
    /// response, and admit every result plus the terminal IQ to the durable
    /// S2S outbox in one PostgreSQL transaction. Room identity/policy and the
    /// external affiliation remain locked until the outbox projection commits.
    async fn admit_federated_room_stream<F>(
        &self,
        limits: FederatedMamOutboxLimits,
        request: FederatedMamStreamRequest<'_>,
        render: F,
    ) -> Result<FederatedMamAdmissionOutcome>
    where
        F: FnOnce(&FederatedMamStreamPage) -> Result<Vec<String>> + Send,
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
        let policy = db::S2sOutboxPolicy {
            ttl_seconds: limits.ttl_seconds,
            max_rows: limits.max_rows,
            max_bytes: limits.max_bytes,
            max_per_domain: limits.max_per_domain,
        };
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
