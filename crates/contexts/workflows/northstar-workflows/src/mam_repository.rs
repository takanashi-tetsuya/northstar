//! Archive snapshots and atomic federation response admission.

use crate::mam_room;
use anyhow::Result;
use northstar_archive_application::*;
use northstar_archive_postgres as archive;
use northstar_room_postgres::mam_authorization::FederatedMamRoomGuard;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresMamRepository {
    pool: PgPool,
}

impl PostgresMamRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    async fn personal_boundaries(
        &self,
        owner_id: Uuid,
    ) -> Result<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
        archive::archive_boundaries_visible(&self.pool, owner_id).await
    }

    async fn authorized_room_boundaries(
        &self,
        localpart: &str,
        viewer_id: Uuid,
        currently_joined: bool,
    ) -> Result<MamRoomReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
        map_room_read(
            mam_room::mam_room_archive_boundaries_authorized(
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
        archive::mam_user_archive_page(&self.pool, owner_id, query).await
    }

    async fn authorized_room_page(
        &self,
        localpart: &str,
        viewer_id: Uuid,
        currently_joined: bool,
        query: &MamArchiveQuery,
    ) -> Result<MamRoomReadOutcome<Option<ArchivePage>>> {
        map_room_read(
            mam_room::mam_room_archive_page_authorized(
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
                let read = self
                    .authorized_room_page(&localpart, viewer_id, currently_joined, &command.query)
                    .await?;
                Ok(MamQueryResult::from_room_read(read))
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
                let read = self
                    .authorized_room_boundaries(&localpart, viewer_id, currently_joined)
                    .await?;
                Ok(MamMetadataResult::from_room_read(read))
            }
            MamQueryScope::FederatedRoom { .. } => Ok(MamMetadataResult::Forbidden),
        }
    }

    async fn get_federated_boundaries(
        &self,
        command: FederatedMamMetadataCommand,
    ) -> Result<MamMetadataResult> {
        let read = map_room_read(
            mam_room::mam_federated_room_archive_boundaries_authorized(
                &self.pool,
                command.localpart(),
                command.viewer_bare_jid(),
                command.currently_joined(),
            )
            .await?,
        )?;
        Ok(MamMetadataResult::from_room_read(read))
    }

    async fn get_preferences(&self, command: MamPreferencesGetCommand) -> Result<MamPreferences> {
        archive::mam_preferences(&self.pool, command.owner_id).await
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
            match northstar_room_postgres::mam_authorization::authorize_mam_room(
                &self.pool,
                localpart,
                viewer_id,
                currently_joined,
            )
            .await?
            {
                archive::MamRoomReadOutcome::Allowed { access, .. } => {
                    MamRoomAccessOutcome::Allowed(map_room_access(access))
                }
                archive::MamRoomReadOutcome::Missing => MamRoomAccessOutcome::Missing,
                archive::MamRoomReadOutcome::Forbidden => MamRoomAccessOutcome::Forbidden,
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
            match northstar_room_postgres::mam_authorization::authorize_federated_mam_room(
                &self.pool,
                localpart,
                viewer_bare_jid,
                currently_joined,
            )
            .await?
            {
                archive::MamRoomReadOutcome::Allowed { access, .. } => {
                    MamRoomAccessOutcome::Allowed(map_room_access(access))
                }
                archive::MamRoomReadOutcome::Missing => MamRoomAccessOutcome::Missing,
                archive::MamRoomReadOutcome::Forbidden => MamRoomAccessOutcome::Forbidden,
            },
        )
    }
}

impl MamPreferencesWriter for PostgresMamRepository {
    type Error = anyhow::Error;

    async fn set_preferences(&self, command: MamPreferencesSetCommand) -> Result<()> {
        archive::set_mam_preferences(&self.pool, command.owner_id, &command.preferences).await
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
        let Some(mut guard) = FederatedMamRoomGuard::acquire(&self.pool, request.localpart).await?
        else {
            return Ok(FederatedMamAdmissionOutcome::Missing);
        };
        let room_id = guard.room_id();
        let mut transaction = guard.begin_snapshot().await?;
        let page = match mam_room::mam_federated_room_archive_page_authorized_in_transaction(
            &mut transaction,
            room_id,
            request.localpart,
            request.viewer_bare_jid,
            request.currently_joined,
            request.query,
        )
        .await?
        {
            archive::MamRoomReadOutcome::Allowed {
                access,
                value: Some(page),
            } => map_federated_stream_page(access, page),
            archive::MamRoomReadOutcome::Allowed { value: None, .. } => {
                transaction.commit().await?;
                guard.release().await;
                return Ok(FederatedMamAdmissionOutcome::PageMissing);
            }
            archive::MamRoomReadOutcome::Missing => {
                transaction.commit().await?;
                guard.release().await;
                return Ok(FederatedMamAdmissionOutcome::Missing);
            }
            archive::MamRoomReadOutcome::Forbidden => {
                transaction.commit().await?;
                guard.release().await;
                return Ok(FederatedMamAdmissionOutcome::Forbidden);
            }
        };

        let responses = match render(&page) {
            Ok(responses) => responses,
            Err(error) => {
                transaction.rollback().await?;
                guard.release().await;
                return Err(error);
            }
        };
        if responses.is_empty() {
            transaction.rollback().await?;
            guard.release().await;
            anyhow::bail!("federated MAM renderer omitted the terminal response");
        }
        let policy = northstar_federation_core::S2sOutboxPolicy {
            ttl_seconds: limits.ttl_seconds,
            max_rows: limits.max_rows,
            max_bytes: limits.max_bytes,
            max_per_domain: limits.max_per_domain,
        };
        for response in &responses {
            if let Err(error) = northstar_federation_postgres::enqueue_s2s_outbox_in_transaction(
                &mut transaction,
                request.target_domain,
                response,
                None,
                policy,
            )
            .await
            {
                transaction.rollback().await?;
                guard.release().await;
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
        guard.release().await;
        Ok(FederatedMamAdmissionOutcome::Queued)
    }
}

fn map_room_access(access: archive::MamRoomArchiveAccess) -> MamRoomAccess {
    MamRoomAccess {
        localpart: access.localpart,
        occupant_id_secret: access.occupant_id_secret,
        reveal_real_jid: access.reveal_real_jid,
    }
}

fn map_room_read<T>(outcome: archive::MamRoomReadOutcome<T>) -> Result<MamRoomReadOutcome<T>> {
    Ok(match outcome {
        archive::MamRoomReadOutcome::Allowed { access, value } => MamRoomReadOutcome::Allowed {
            access: map_room_access(access),
            value,
        },
        archive::MamRoomReadOutcome::Missing => MamRoomReadOutcome::Missing,
        archive::MamRoomReadOutcome::Forbidden => MamRoomReadOutcome::Forbidden,
    })
}

fn map_federated_stream_page(
    access: archive::MamRoomArchiveAccess,
    page: archive::ArchivePage,
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
