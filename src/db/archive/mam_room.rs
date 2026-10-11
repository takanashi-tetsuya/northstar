//! MUC MAM room authorization and room archive reads, local and federated.

use super::*;

pub(super) async fn mam_room_occupant_id_secret_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    existing: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    if let Some(secret) = existing.filter(|secret| !secret.is_empty()) {
        return Ok(secret);
    }
    // Older rooms lack the XEP-0421 secret. Keep the one-time repair in the
    // same snapshot that produces the authorized archive capability.
    let mut secret = vec![0_u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let updated = sqlx::query(
        "UPDATE muc_rooms SET occupant_id_secret=$2
          WHERE id=$1 AND occupant_id_secret IS NULL",
    )
    .bind(room_id)
    .bind(&secret)
    .execute(&mut **transaction)
    .await?;
    anyhow::ensure!(
        updated.rows_affected() == 1,
        "MAM room occupant-id secret changed during snapshot authorization"
    );
    Ok(secret)
}

pub(super) async fn authorize_mam_room_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    localpart: &str,
    viewer_id: Uuid,
    currently_joined: bool,
    has_peer_filter: bool,
) -> Result<MamRoomReadOutcome<()>> {
    let row = sqlx::query(
        "SELECT r.id,r.localpart,r.members_only,r.non_anonymous,r.password_hash,
                r.occupant_id_secret,a.affiliation
           FROM muc_rooms r
           LEFT JOIN muc_affiliations a
             ON a.room_id=r.id AND a.user_id=$2
          WHERE r.localpart=$1 AND r.destroyed_at IS NULL",
    )
    .bind(localpart)
    .bind(viewer_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(MamRoomReadOutcome::Missing);
    };
    let affiliation: Option<String> = row.try_get("affiliation")?;
    let reveal_real_jid = match decide_mam_room_read(
        row.try_get("members_only")?,
        row.try_get("non_anonymous")?,
        row.try_get::<Option<String>, _>("password_hash")?.is_some(),
        affiliation.as_deref(),
        currently_joined,
        has_peer_filter,
    ) {
        MamRoomReadDecision::Forbidden => return Ok(MamRoomReadOutcome::Forbidden),
        MamRoomReadDecision::Allowed { reveal_real_jid } => reveal_real_jid,
    };
    let room_id: Uuid = row.try_get("id")?;
    let occupant_id_secret = mam_room_occupant_id_secret_in_transaction(
        transaction,
        room_id,
        row.try_get("occupant_id_secret")?,
    )
    .await?;
    Ok(MamRoomReadOutcome::Allowed {
        access: MamRoomArchiveAccess {
            room_id,
            localpart: row.try_get("localpart")?,
            occupant_id_secret,
            reveal_real_jid,
        },
        value: (),
    })
}

/// Hold the MUC affiliation lock before opening the repeatable-read snapshot.
/// MUC writers acquire namespace 29 before room rows, so taking a room row
/// first here can deadlock. The lookup only selects the lock key; authorization
/// rechecks the exact room identity after the lock has been acquired.
pub(crate) struct FederatedMamRoomGuard {
    pub(super) connection: PoolConnection<Postgres>,
    pub(super) room_id: Uuid,
    pub(super) maybe_held: bool,
}

impl FederatedMamRoomGuard {
    pub(crate) async fn acquire(pool: &PgPool, localpart: &str) -> Result<Option<Self>> {
        let mut connection = pool.acquire().await?;
        let room_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM muc_rooms WHERE localpart=$1 AND destroyed_at IS NULL",
        )
        .bind(localpart)
        .fetch_optional(&mut *connection)
        .await?;
        let Some(room_id) = room_id else {
            return Ok(None);
        };
        // A cancelled lock request can have completed on the server. Mark the
        // connection before awaiting it so Drop never returns that session to
        // the pool with an advisory lock still held.
        let mut guard = Self {
            connection,
            room_id,
            maybe_held: true,
        };
        sqlx::query("SELECT pg_advisory_lock(hashtextextended($1::TEXT, 29))")
            .bind(room_id.to_string())
            .execute(&mut *guard.connection)
            .await?;
        Ok(Some(guard))
    }

    pub(crate) fn room_id(&self) -> Uuid {
        self.room_id
    }

    pub(crate) async fn begin_snapshot(&mut self) -> Result<Transaction<'_, Postgres>> {
        let mut transaction = self.connection.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *transaction)
            .await?;
        Ok(transaction)
    }

    pub(crate) async fn release(mut self) {
        let unlocked = sqlx::query_scalar::<_, bool>(
            "SELECT pg_advisory_unlock(hashtextextended($1::TEXT, 29))",
        )
        .bind(self.room_id.to_string())
        .fetch_one(&mut *self.connection)
        .await;
        match unlocked {
            Ok(true) => self.maybe_held = false,
            Ok(false) => {
                tracing::warn!(room_id = %self.room_id, "federated MAM room lock was not held at release")
            }
            Err(error) => {
                tracing::warn!(room_id = %self.room_id, ?error, "federated MAM room lock release failed")
            }
        }
        // On failure Drop closes the session. Once the transaction committed,
        // an unlock failure must not report a failed read or outbox admission.
    }
}

impl Drop for FederatedMamRoomGuard {
    fn drop(&mut self) {
        if self.maybe_held {
            self.connection.close_on_drop();
        }
    }
}

pub(super) async fn authorize_federated_mam_room_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    expected_room_id: Uuid,
    localpart: &str,
    viewer_bare_jid: &str,
    currently_joined: bool,
    has_peer_filter: bool,
) -> Result<MamRoomReadOutcome<()>> {
    // The room row is the durable identity fence for this authorization.  A
    // shared lock prevents destroy/recreate and room-policy changes from
    // committing between the policy decision and the caller's durable
    // projection (for example, an S2S outbox stream).
    let row = sqlx::query(
        "SELECT id,localpart,members_only,non_anonymous,password_hash,
                occupant_id_secret
           FROM muc_rooms
          WHERE localpart=$1 AND id=$2 AND destroyed_at IS NULL
          FOR SHARE",
    )
    .bind(localpart)
    .bind(expected_room_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(MamRoomReadOutcome::Missing);
    };
    let room_id: Uuid = row.try_get("id")?;

    // The caller already holds namespace 29 on this same session. Its fresh
    // transaction snapshot sees affiliation changes committed while it waited.
    let affiliation: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM muc_external_affiliations
          WHERE room_id=$1 AND jid=$2 FOR SHARE",
    )
    .bind(room_id)
    .bind(viewer_bare_jid)
    .fetch_optional(&mut **transaction)
    .await?;
    let reveal_real_jid = match decide_mam_room_read(
        row.try_get("members_only")?,
        row.try_get("non_anonymous")?,
        row.try_get::<Option<String>, _>("password_hash")?.is_some(),
        affiliation.as_deref(),
        currently_joined,
        has_peer_filter,
    ) {
        MamRoomReadDecision::Forbidden => return Ok(MamRoomReadOutcome::Forbidden),
        MamRoomReadDecision::Allowed { reveal_real_jid } => reveal_real_jid,
    };
    let occupant_id_secret = mam_room_occupant_id_secret_in_transaction(
        transaction,
        room_id,
        row.try_get("occupant_id_secret")?,
    )
    .await?;
    Ok(MamRoomReadOutcome::Allowed {
        access: MamRoomArchiveAccess {
            room_id,
            localpart: row.try_get("localpart")?,
            occupant_id_secret,
            reveal_real_jid,
        },
        value: (),
    })
}

pub async fn authorize_mam_room(
    pool: &PgPool,
    localpart: &str,
    viewer_id: Uuid,
    currently_joined: bool,
) -> Result<MamRoomReadOutcome<()>> {
    let mut transaction = pool.begin().await?;
    // This is intentionally read-write only for the one-time legacy
    // occupant-id-secret repair above. All policy and returned identity are
    // still derived from one repeatable-read snapshot.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let outcome = authorize_mam_room_in_transaction(
        &mut transaction,
        localpart,
        viewer_id,
        currently_joined,
        false,
    )
    .await?;
    transaction.commit().await?;
    Ok(outcome)
}

pub async fn authorize_federated_mam_room(
    pool: &PgPool,
    localpart: &str,
    viewer_bare_jid: &str,
    currently_joined: bool,
) -> Result<MamRoomReadOutcome<()>> {
    let viewer_bare_jid = crate::jid::CanonicalJid::parse_bare(viewer_bare_jid)?;
    anyhow::ensure!(
        viewer_bare_jid.localpart().is_some(),
        "federated MAM viewer must be a user bare JID"
    );
    let Some(mut guard) = FederatedMamRoomGuard::acquire(pool, localpart).await? else {
        return Ok(MamRoomReadOutcome::Missing);
    };
    let room_id = guard.room_id();
    let mut transaction = guard.begin_snapshot().await?;
    let outcome = authorize_federated_mam_room_in_transaction(
        &mut transaction,
        room_id,
        localpart,
        &viewer_bare_jid.to_string(),
        currently_joined,
        false,
    )
    .await?;
    transaction.commit().await?;
    guard.release().await;
    Ok(outcome)
}

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
    let viewer_bare_jid = crate::jid::CanonicalJid::parse_bare(viewer_bare_jid)?;
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
    let viewer_bare_jid = crate::jid::CanonicalJid::parse_bare(viewer_bare_jid)?;
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
