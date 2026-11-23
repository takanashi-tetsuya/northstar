use anyhow::Result;
use northstar_room_application::muc_service::MucRoomIncarnation;
use northstar_room_core::occupancy::MucOccupantRoute;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub async fn muc_departed_room(
    pool: &PgPool,
    localpart: &str,
    route: &MucOccupantRoute,
    sm_session_id: Option<Uuid>,
) -> Result<Option<MucRoomIncarnation>> {
    let session_scoped = route.connection_id.is_nil()
        && sm_session_id.is_some_and(|session_id| !session_id.is_nil());
    if !route.is_exact() && !session_scoped {
        return Ok(None);
    }
    let rows = sqlx::query(
        "SELECT o.room_id,o.room_epoch
           FROM cluster_muc_occupancies o
           JOIN muc_rooms r ON r.id=o.room_id AND r.room_epoch=o.room_epoch
          WHERE r.localpart=$1 AND o.nick=$2 AND o.full_jid=$3
            AND ($7 OR (o.occupant_incarnation=$4 AND o.connection_uuid=$5))
            AND ($6::uuid IS NULL OR o.sm_session_id=$6)
          LIMIT 2",
    )
    .bind(localpart)
    .bind(&route.nick)
    .bind(&route.full_jid)
    .bind(route.cluster_epoch)
    .bind(route.connection_id)
    .bind(sm_session_id)
    .bind(session_scoped)
    .fetch_all(pool)
    .await?;
    Ok(match rows.as_slice() {
        [row] => Some(MucRoomIncarnation {
            room_id: row.get("room_id"),
            room_epoch: row.get("room_epoch"),
        }),
        _ => None,
    })
}

pub(super) async fn lock_temporary_room_occupancies(
    tx: &mut Transaction<'_, Postgres>,
    room: MucRoomIncarnation,
) -> Result<()> {
    sqlx::query(
        "SELECT occupant_incarnation FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND state IN ('active','suspended')
          ORDER BY occupant_incarnation FOR UPDATE",
    )
    .bind(room.room_id)
    .bind(room.room_epoch)
    .fetch_all(&mut **tx)
    .await?;
    Ok(())
}

pub async fn sm_teardown_muc_observers(
    pool: &PgPool,
    room: MucRoomIncarnation,
    departed_nick: &str,
) -> Result<Vec<MucOccupantRoute>> {
    let rows = sqlx::query(
        "SELECT o.nick,o.full_jid,o.connection_uuid,o.occupant_incarnation
           FROM cluster_muc_occupancies o
           JOIN muc_rooms r ON r.id=o.room_id AND r.room_epoch=o.room_epoch
          WHERE o.room_id=$1 AND o.room_epoch=$2 AND o.nick<>$3
            AND r.destroyed_at IS NULL AND o.state IN ('active','suspended')",
    )
    .bind(room.room_id)
    .bind(room.room_epoch)
    .bind(departed_nick)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| MucOccupantRoute {
            nick: row.get("nick"),
            full_jid: row.get("full_jid"),
            connection_id: row.get("connection_uuid"),
            cluster_epoch: row.get("occupant_incarnation"),
        })
        .collect())
}
