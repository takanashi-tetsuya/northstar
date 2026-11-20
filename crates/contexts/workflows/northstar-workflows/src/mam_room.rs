//! MUC MAM room archive reads under the room authorization, local and federated.

use anyhow::Result;
use northstar_archive_core::{MamLocalAuthority, MamRoomReadAuthority};
use northstar_archive_postgres::*;
use northstar_room_postgres::mam_authorization::{
    authorize_federated_mam_room_in_transaction, authorize_mam_room_in_transaction,
    FederatedMamRoomGuard,
};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

async fn begin_local_mam_snapshot(pool: &PgPool) -> Result<Transaction<'_, Postgres>> {
    let mut transaction = pool.begin().await?;
    // Read-write for the room's one-time legacy occupant-ID secret repair.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

async fn authorize_local_room_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    localpart: &str,
    account: &MamLocalAuthority,
    authority: &MamRoomReadAuthority,
    has_peer_filter: bool,
) -> Result<MamRoomReadOutcome<()>> {
    if !mam_account_is_current(transaction, account).await? {
        return Ok(MamRoomReadOutcome::StaleAccount);
    }
    authorize_mam_room_in_transaction(
        transaction,
        localpart,
        account.id,
        authority,
        has_peer_filter,
    )
    .await
}

pub async fn authorize_mam_room(
    pool: &PgPool,
    localpart: &str,
    account: &MamLocalAuthority,
    authority: &MamRoomReadAuthority,
) -> Result<MamRoomReadOutcome<()>> {
    let mut transaction = begin_local_mam_snapshot(pool).await?;
    let outcome =
        authorize_local_room_in_transaction(&mut transaction, localpart, account, authority, false)
            .await?;
    transaction.commit().await?;
    Ok(outcome)
}

pub async fn mam_room_archive_boundaries_authorized(
    pool: &PgPool,
    localpart: &str,
    account: &MamLocalAuthority,
    authority: &MamRoomReadAuthority,
) -> Result<MamRoomReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
    let mut transaction = begin_local_mam_snapshot(pool).await?;
    let access = match authorize_local_room_in_transaction(
        &mut transaction,
        localpart,
        account,
        authority,
        false,
    )
    .await?
    {
        MamRoomReadOutcome::Allowed { access, .. } => access,
        MamRoomReadOutcome::Missing => {
            transaction.commit().await?;
            return Ok(MamRoomReadOutcome::Missing);
        }
        MamRoomReadOutcome::Forbidden => {
            transaction.commit().await?;
            return Ok(MamRoomReadOutcome::Forbidden);
        }
        MamRoomReadOutcome::StaleAccount => return Ok(MamRoomReadOutcome::StaleAccount),
    };
    let value = archive_boundaries_for_in_transaction(
        &mut transaction,
        MamArchiveSource::Muc(access.room_id),
        Some(account.id),
    )
    .await?;
    transaction.commit().await?;
    Ok(MamRoomReadOutcome::Allowed { access, value })
}

pub async fn mam_room_archive_page_authorized(
    pool: &PgPool,
    localpart: &str,
    account: &MamLocalAuthority,
    authority: &MamRoomReadAuthority,
    query: &MamArchiveQuery,
) -> Result<MamRoomReadOutcome<Option<ArchivePage>>> {
    let mut transaction = begin_local_mam_snapshot(pool).await?;
    let access = match authorize_local_room_in_transaction(
        &mut transaction,
        localpart,
        account,
        authority,
        query.with_jid.is_some(),
    )
    .await?
    {
        MamRoomReadOutcome::Allowed { access, .. } => access,
        MamRoomReadOutcome::Missing => {
            transaction.commit().await?;
            return Ok(MamRoomReadOutcome::Missing);
        }
        MamRoomReadOutcome::Forbidden => {
            transaction.commit().await?;
            return Ok(MamRoomReadOutcome::Forbidden);
        }
        MamRoomReadOutcome::StaleAccount => return Ok(MamRoomReadOutcome::StaleAccount),
    };
    let value = mam_archive_page_for_in_transaction(
        &mut transaction,
        MamArchiveSource::Muc(access.room_id),
        Some(account.id),
        query,
    )
    .await?;
    transaction.commit().await?;
    Ok(MamRoomReadOutcome::Allowed { access, value })
}

pub async fn mam_federated_room_archive_boundaries_authorized(
    pool: &PgPool,
    localpart: &str,
    authority: &MamRoomReadAuthority,
) -> Result<MamRoomReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
    let Some(mut guard) = FederatedMamRoomGuard::acquire(pool, localpart).await? else {
        return Ok(MamRoomReadOutcome::Missing);
    };
    let room_id = guard.room_id();
    let mut transaction = guard.begin_snapshot().await?;
    let outcome = match authorize_federated_mam_room_in_transaction(
        &mut transaction,
        room_id,
        localpart,
        authority,
        false,
    )
    .await?
    {
        MamRoomReadOutcome::Allowed { access, .. } => {
            let value = archive_boundaries_for_in_transaction(
                &mut transaction,
                MamArchiveSource::Muc(access.room_id),
                None,
            )
            .await?;
            MamRoomReadOutcome::Allowed { access, value }
        }
        MamRoomReadOutcome::Missing => MamRoomReadOutcome::Missing,
        MamRoomReadOutcome::Forbidden => MamRoomReadOutcome::Forbidden,
        MamRoomReadOutcome::StaleAccount => MamRoomReadOutcome::StaleAccount,
    };
    transaction.commit().await?;
    guard.release().await;
    Ok(outcome)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn mam_federated_room_archive_page_authorized(
    pool: &PgPool,
    localpart: &str,
    authority: &MamRoomReadAuthority,
    query: &MamArchiveQuery,
) -> Result<MamRoomReadOutcome<Option<ArchivePage>>> {
    let Some(mut guard) = FederatedMamRoomGuard::acquire(pool, localpart).await? else {
        return Ok(MamRoomReadOutcome::Missing);
    };
    let room_id = guard.room_id();
    let mut transaction = guard.begin_snapshot().await?;
    let outcome = mam_federated_room_archive_page_authorized_in_transaction(
        &mut transaction,
        room_id,
        localpart,
        authority,
        query,
    )
    .await?;
    transaction.commit().await?;
    guard.release().await;
    Ok(outcome)
}

/// Resolve federated room authority and page its archive inside a transaction
/// owned by the application service.  The caller may append a durable
/// response projection before commit without reopening a TOCTOU window. The
/// transaction must come from `FederatedMamRoomGuard::begin_snapshot` on the
/// same connection, and `expected_room_id` must come from that guard.
pub async fn mam_federated_room_archive_page_authorized_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    expected_room_id: Uuid,
    localpart: &str,
    authority: &MamRoomReadAuthority,
    query: &MamArchiveQuery,
) -> Result<MamRoomReadOutcome<Option<ArchivePage>>> {
    let access = match authorize_federated_mam_room_in_transaction(
        transaction,
        expected_room_id,
        localpart,
        authority,
        query.with_jid.is_some(),
    )
    .await?
    {
        MamRoomReadOutcome::Allowed { access, .. } => access,
        MamRoomReadOutcome::Missing => return Ok(MamRoomReadOutcome::Missing),
        MamRoomReadOutcome::Forbidden => return Ok(MamRoomReadOutcome::Forbidden),
        MamRoomReadOutcome::StaleAccount => return Ok(MamRoomReadOutcome::StaleAccount),
    };
    let value = mam_archive_page_for_in_transaction(
        transaction,
        MamArchiveSource::Muc(access.room_id),
        None,
        query,
    )
    .await?;
    Ok(MamRoomReadOutcome::Allowed { access, value })
}
