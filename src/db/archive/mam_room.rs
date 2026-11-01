//! MUC MAM room archive reads under the room authorization, local and federated.

use super::*;
use northstar_room_postgres::mam_authorization::{
    authorize_federated_mam_room_in_transaction, authorize_mam_room_in_transaction,
    FederatedMamRoomGuard,
};

pub async fn mam_room_archive_boundaries_authorized(
    pool: &PgPool,
    localpart: &str,
    viewer_id: Uuid,
    currently_joined: bool,
) -> Result<MamRoomReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let access = match authorize_mam_room_in_transaction(
        &mut transaction,
        localpart,
        viewer_id,
        currently_joined,
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
    };
    let value = archive_boundaries_for_in_transaction(
        &mut transaction,
        MamArchiveSource::Muc(access.room_id),
        Some(viewer_id),
    )
    .await?;
    transaction.commit().await?;
    Ok(MamRoomReadOutcome::Allowed { access, value })
}

pub async fn mam_room_archive_page_authorized(
    pool: &PgPool,
    localpart: &str,
    viewer_id: Uuid,
    currently_joined: bool,
    query: &MamArchiveQuery,
) -> Result<MamRoomReadOutcome<Option<ArchivePage>>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let access = match authorize_mam_room_in_transaction(
        &mut transaction,
        localpart,
        viewer_id,
        currently_joined,
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
    };
    let value = mam_archive_page_for_in_transaction(
        &mut transaction,
        MamArchiveSource::Muc(access.room_id),
        Some(viewer_id),
        query,
    )
    .await?;
    transaction.commit().await?;
    Ok(MamRoomReadOutcome::Allowed { access, value })
}

pub async fn mam_federated_room_archive_boundaries_authorized(
    pool: &PgPool,
    localpart: &str,
    viewer_bare_jid: &str,
    currently_joined: bool,
) -> Result<MamRoomReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
    let viewer_bare_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(viewer_bare_jid)?;
    anyhow::ensure!(
        viewer_bare_jid.localpart().is_some(),
        "federated MAM viewer must be a user bare JID"
    );
    let Some(mut guard) = FederatedMamRoomGuard::acquire(pool, localpart).await? else {
        return Ok(MamRoomReadOutcome::Missing);
    };
    let room_id = guard.room_id();
    let mut transaction = guard.begin_snapshot().await?;
    let outcome = match authorize_federated_mam_room_in_transaction(
        &mut transaction,
        room_id,
        localpart,
        &viewer_bare_jid.to_string(),
        currently_joined,
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
    };
    transaction.commit().await?;
    guard.release().await;
    Ok(outcome)
}

#[cfg(test)]
pub async fn mam_federated_room_archive_page_authorized(
    pool: &PgPool,
    localpart: &str,
    viewer_bare_jid: &str,
    currently_joined: bool,
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
        viewer_bare_jid,
        currently_joined,
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
pub(crate) async fn mam_federated_room_archive_page_authorized_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    expected_room_id: Uuid,
    localpart: &str,
    viewer_bare_jid: &str,
    currently_joined: bool,
    query: &MamArchiveQuery,
) -> Result<MamRoomReadOutcome<Option<ArchivePage>>> {
    let viewer_bare_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(viewer_bare_jid)?;
    anyhow::ensure!(
        viewer_bare_jid.localpart().is_some(),
        "federated MAM viewer must be a user bare JID"
    );
    let access = match authorize_federated_mam_room_in_transaction(
        transaction,
        expected_room_id,
        localpart,
        &viewer_bare_jid.to_string(),
        currently_joined,
        query.with_jid.is_some(),
    )
    .await?
    {
        MamRoomReadOutcome::Allowed { access, .. } => access,
        MamRoomReadOutcome::Missing => return Ok(MamRoomReadOutcome::Missing),
        MamRoomReadOutcome::Forbidden => return Ok(MamRoomReadOutcome::Forbidden),
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
