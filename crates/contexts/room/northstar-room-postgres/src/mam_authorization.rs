//! MUC MAM room authorization: the room snapshot, the federated room lock and
//! the occupant-id secret repair. Archive page and boundary reads under this
//! authorization belong to the archive context.

use crate::cluster_muc::exact_cluster_muc_occupancy;
use anyhow::Result;
use northstar_archive_core::{
    decide_mam_room_read, MamDbRoomReadOutcome as MamRoomReadOutcome, MamRoomArchiveAccess,
    MamRoomReadAuthority, MamRoomReadDecision,
};
use rand::RngCore;
use sqlx::{pool::PoolConnection, postgres::PgRow, Acquire, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

const MAM_CONFIGURATION_VISIBLE: &str = "(r.configuration_state <> 'locked'
    OR (r.configuration_owner_jid=$2 AND r.configuration_expires_at>clock_timestamp()))";

async fn mam_occupancy_matches(
    transaction: &mut Transaction<'_, Postgres>,
    room: &PgRow,
    authority: &MamRoomReadAuthority,
    federated: bool,
) -> Result<bool> {
    let Some(proof) = authority.occupancy else {
        return Ok(false);
    };
    let Some(occupancy) = exact_cluster_muc_occupancy(
        transaction,
        room.try_get("id")?,
        proof.occupant_incarnation,
        proof.connection_uuid,
    )
    .await?
    else {
        return Ok(false);
    };
    if occupancy.try_get::<Uuid, _>("room_epoch")? != room.try_get::<Uuid, _>("room_epoch")? {
        return Ok(false);
    }
    let full_jid: &str = occupancy.try_get("full_jid")?;
    Ok(if federated {
        authority.matches_remote_actor(full_jid)
    } else {
        full_jid == authority.full_jid
    })
}

/// Check room visibility and preserve the one-time repair for the disabled
/// MAM extension's existing room lookup.
pub async fn federated_mam_room_visible(
    pool: &PgPool,
    localpart: &str,
    viewer_full_jid: &str,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let statement = format!(
        "SELECT r.id,r.occupant_id_secret FROM muc_rooms r
          WHERE r.localpart=$1 AND r.destroyed_at IS NULL AND {MAM_CONFIGURATION_VISIBLE}"
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(localpart)
        .bind(viewer_full_jid)
        .fetch_optional(&mut *transaction)
        .await?;
    if let Some(row) = &row {
        mam_room_occupant_id_secret_in_transaction(
            &mut transaction,
            row.try_get("id")?,
            row.try_get("occupant_id_secret")?,
        )
        .await?;
    }
    transaction.commit().await?;
    Ok(row.is_some())
}

pub async fn mam_room_occupant_id_secret_in_transaction(
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

pub async fn authorize_mam_room_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    localpart: &str,
    viewer_id: Uuid,
    authority: &MamRoomReadAuthority,
    has_peer_filter: bool,
) -> Result<MamRoomReadOutcome<()>> {
    let statement = format!(
        "SELECT r.id,r.room_epoch,r.localpart,r.members_only,r.non_anonymous,r.password_hash,
                r.occupant_id_secret,a.affiliation
           FROM muc_rooms r
           LEFT JOIN muc_affiliations a
             ON a.room_id=r.id AND a.user_id=$3
          WHERE r.localpart=$1 AND r.destroyed_at IS NULL AND {MAM_CONFIGURATION_VISIBLE}"
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(localpart)
        .bind(&authority.full_jid)
        .bind(viewer_id)
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(row) = row else {
        return Ok(MamRoomReadOutcome::Missing);
    };
    let affiliation: Option<String> = row.try_get("affiliation")?;
    let currently_joined = mam_occupancy_matches(transaction, &row, authority, false).await?;
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
pub struct FederatedMamRoomGuard {
    connection: PoolConnection<Postgres>,
    room_id: Uuid,
    maybe_held: bool,
}

impl FederatedMamRoomGuard {
    pub async fn acquire(pool: &PgPool, localpart: &str) -> Result<Option<Self>> {
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

    pub fn room_id(&self) -> Uuid {
        self.room_id
    }

    pub async fn begin_snapshot(&mut self) -> Result<Transaction<'_, Postgres>> {
        let mut transaction = self.connection.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *transaction)
            .await?;
        Ok(transaction)
    }

    /// Return whether the advisory unlock was confirmed. Otherwise discard the session.
    pub async fn release(mut self) -> bool {
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
        !self.maybe_held
    }
}

impl Drop for FederatedMamRoomGuard {
    fn drop(&mut self) {
        if self.maybe_held {
            self.connection.close_on_drop();
        }
    }
}

pub async fn authorize_federated_mam_room_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    expected_room_id: Uuid,
    localpart: &str,
    authority: &MamRoomReadAuthority,
    has_peer_filter: bool,
) -> Result<MamRoomReadOutcome<()>> {
    // The room row is the durable identity fence for this authorization.  A
    // shared lock prevents destroy/recreate and room-policy changes from
    // committing between the policy decision and the caller's durable
    // projection (for example, an S2S outbox stream).
    let viewer = northstar_xmpp_types::CanonicalJid::parse(&authority.full_jid)?;
    anyhow::ensure!(
        viewer.localpart().is_some() && viewer.resourcepart().is_some(),
        "federated MAM viewer must be a user full JID"
    );
    let statement = format!(
        "SELECT r.id,r.room_epoch,r.localpart,r.members_only,r.non_anonymous,r.password_hash,
                r.occupant_id_secret
           FROM muc_rooms r
          WHERE r.localpart=$1 AND r.id=$3 AND r.destroyed_at IS NULL
            AND {MAM_CONFIGURATION_VISIBLE}
          FOR SHARE"
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(localpart)
        .bind(&authority.full_jid)
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
    .bind(viewer.bare())
    .fetch_optional(&mut **transaction)
    .await?;
    let currently_joined = mam_occupancy_matches(transaction, &row, authority, true).await?;
    // The old federated room lookup repaired visible legacy rooms even if
    // their archive policy denied the request. Keep that repair behind the
    // configuration visibility check in this snapshot.
    let occupant_id_secret = mam_room_occupant_id_secret_in_transaction(
        transaction,
        room_id,
        row.try_get("occupant_id_secret")?,
    )
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

pub async fn authorize_federated_mam_room(
    pool: &PgPool,
    localpart: &str,
    authority: &MamRoomReadAuthority,
) -> Result<MamRoomReadOutcome<()>> {
    let Some(mut guard) = FederatedMamRoomGuard::acquire(pool, localpart).await? else {
        return Ok(MamRoomReadOutcome::Missing);
    };
    let room_id = guard.room_id();
    let mut transaction = guard.begin_snapshot().await?;
    let outcome = authorize_federated_mam_room_in_transaction(
        &mut transaction,
        room_id,
        localpart,
        authority,
        false,
    )
    .await?;
    transaction.commit().await?;
    guard.release().await;
    Ok(outcome)
}
