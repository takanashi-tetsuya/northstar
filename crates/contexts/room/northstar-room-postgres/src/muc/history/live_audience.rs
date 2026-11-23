use super::*;
use northstar_room_core::occupancy::MucOccupantRoute;

pub(super) async fn capture(
    transaction: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    authority: &MucActorAuthority<'_>,
) -> Result<Option<LiveAudience>> {
    if !authority.clustered {
        return Ok(None);
    }
    let rows = sqlx::query_as::<_, (String, String, String, Uuid, Uuid)>(
        "SELECT owner_node_id,nick,full_jid,connection_uuid,occupant_incarnation
           FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND state IN ('active','suspended')
          ORDER BY occupancy_epoch
          LIMIT $3",
    )
    .bind(room_id)
    .bind(authority.expected_room_epoch)
    .bind(LiveAudience::LIMIT as i64 + 1)
    .fetch_all(&mut **transaction)
    .await?;
    LiveAudience::new(
        rows.into_iter()
            .map(|(node, nick, full_jid, connection_id, cluster_epoch)| {
                (
                    node,
                    MucOccupantRoute {
                        nick,
                        full_jid,
                        connection_id,
                        cluster_epoch,
                    },
                )
            })
            .collect(),
    )
    .map(Some)
}
