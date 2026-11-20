//! Archive snapshots and atomic federation response admission.

use crate::mam_room;
use anyhow::Result;
use northstar_archive_application::*;
use northstar_archive_postgres as archive;
use northstar_room_postgres::mam_authorization::FederatedMamRoomGuard;
use sqlx::{Acquire, PgPool};

#[derive(Clone)]
pub struct PostgresMamRepository {
    pool: PgPool,
}

impl PostgresMamRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl MamQueryRepository for PostgresMamRepository {
    type Error = anyhow::Error;
    async fn query_archive(&self, command: MamQueryCommand) -> Result<MamQueryResult> {
        match command.scope {
            MamQueryScope::Personal { authority } => Ok(
                match archive::mam_personal_page(&self.pool, &authority, &command.query).await? {
                    MamAccountOutcome::Authorized(Some(page)) => {
                        MamQueryResult::Page { room: None, page }
                    }
                    MamAccountOutcome::Authorized(None) => MamQueryResult::ItemNotFound,
                    MamAccountOutcome::StaleAccount => MamQueryResult::StaleAccount,
                },
            ),
            MamQueryScope::Room {
                localpart,
                account,
                authority,
            } => {
                let read = mam_room::mam_room_archive_page_authorized(
                    &self.pool,
                    &localpart,
                    &account,
                    &authority,
                    &command.query,
                )
                .await?;
                Ok(MamQueryResult::from_room_read(map_room_read(read)))
            }
            MamQueryScope::FederatedRoom { .. } => Ok(MamQueryResult::Forbidden),
        }
    }

    async fn get_boundaries(&self, command: MamMetadataCommand) -> Result<MamMetadataResult> {
        match command.scope {
            MamQueryScope::Personal { authority } => Ok(
                match archive::mam_personal_boundaries(&self.pool, &authority).await? {
                    MamAccountOutcome::Authorized((start, end)) => MamMetadataResult::Boundaries {
                        room: None,
                        start,
                        end,
                    },
                    MamAccountOutcome::StaleAccount => MamMetadataResult::StaleAccount,
                },
            ),
            MamQueryScope::Room {
                localpart,
                account,
                authority,
            } => {
                let read = mam_room::mam_room_archive_boundaries_authorized(
                    &self.pool, &localpart, &account, &authority,
                )
                .await?;
                Ok(MamMetadataResult::from_room_read(map_room_read(read)))
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
                command.authority(),
            )
            .await?,
        );
        Ok(MamMetadataResult::from_room_read(read))
    }

    async fn authorize_personal(
        &self,
        authority: &MamLocalAuthority,
    ) -> Result<MamAccountOutcome<()>> {
        archive::authorize_mam_account(&self.pool, authority).await
    }

    async fn get_preferences(
        &self,
        command: MamPreferencesGetCommand,
    ) -> Result<MamAccountOutcome<MamPreferences>> {
        archive::mam_preferences(&self.pool, &command.authority).await
    }

    /// Resolve room policy and affiliation in one repository snapshot, then
    /// return a capability that can be used for MAM reads.
    async fn authorize_room(
        &self,
        localpart: &str,
        account: &MamLocalAuthority,
        authority: &MamRoomReadAuthority,
    ) -> Result<MamRoomAccessOutcome> {
        let outcome =
            mam_room::authorize_mam_room(&self.pool, localpart, account, authority).await?;
        Ok(map_room_access_outcome(outcome))
    }

    async fn federated_room_visible(&self, localpart: &str, viewer_full_jid: &str) -> Result<bool> {
        northstar_room_postgres::mam_authorization::federated_mam_room_visible(
            &self.pool,
            localpart,
            viewer_full_jid,
        )
        .await
    }

    async fn authorize_federated_room(
        &self,
        localpart: &str,
        authority: &MamRoomReadAuthority,
    ) -> Result<MamRoomAccessOutcome> {
        let outcome = northstar_room_postgres::mam_authorization::authorize_federated_mam_room(
            &self.pool, localpart, authority,
        )
        .await?;
        Ok(map_room_access_outcome(outcome))
    }
}

impl MamPreferencesWriter for PostgresMamRepository {
    type Error = anyhow::Error;

    async fn set_preferences(
        &self,
        command: MamPreferencesSetCommand,
    ) -> Result<MamAccountOutcome<()>> {
        archive::set_mam_preferences(&self.pool, &command.authority, &command.preferences).await
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
            request.authority,
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
            archive::MamRoomReadOutcome::Forbidden | archive::MamRoomReadOutcome::StaleAccount => {
                transaction.commit().await?;
                guard.release().await;
                return Ok(FederatedMamAdmissionOutcome::Forbidden);
            }
        };

        let responses = match render(&page) {
            Ok(responses) => responses,
            Err(error) => {
                transaction.commit().await?;
                guard.release().await;
                return Err(error);
            }
        };
        if responses.is_empty() {
            transaction.commit().await?;
            guard.release().await;
            anyhow::bail!("federated MAM renderer omitted the terminal response");
        }
        let policy = northstar_federation_core::S2sOutboxPolicy {
            ttl_seconds: limits.ttl_seconds,
            max_rows: limits.max_rows,
            max_bytes: limits.max_bytes,
            max_per_domain: limits.max_per_domain,
        };
        // Keep the response batch atomic while preserving the historical
        // one-time room repair if response admission is rejected.
        let mut outbox = transaction.begin().await?;
        for response in &responses {
            if let Err(error) = northstar_federation_postgres::enqueue_s2s_outbox_in_transaction(
                &mut outbox,
                request.target_domain,
                response,
                None,
                policy,
            )
            .await
            {
                outbox.rollback().await?;
                transaction.commit().await?;
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
        outbox.commit().await?;
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

fn map_room_access_outcome(outcome: archive::MamRoomReadOutcome<()>) -> MamRoomAccessOutcome {
    match map_room_read(outcome) {
        MamRoomReadOutcome::Allowed { access, .. } => MamRoomAccessOutcome::Allowed(access),
        MamRoomReadOutcome::Missing => MamRoomAccessOutcome::Missing,
        MamRoomReadOutcome::Forbidden => MamRoomAccessOutcome::Forbidden,
        MamRoomReadOutcome::StaleAccount => MamRoomAccessOutcome::StaleAccount,
    }
}

fn map_room_read<T>(outcome: archive::MamRoomReadOutcome<T>) -> MamRoomReadOutcome<T> {
    match outcome {
        archive::MamRoomReadOutcome::Allowed { access, value } => MamRoomReadOutcome::Allowed {
            access: map_room_access(access),
            value,
        },
        archive::MamRoomReadOutcome::Missing => MamRoomReadOutcome::Missing,
        archive::MamRoomReadOutcome::Forbidden => MamRoomReadOutcome::Forbidden,
        archive::MamRoomReadOutcome::StaleAccount => MamRoomReadOutcome::StaleAccount,
    }
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
