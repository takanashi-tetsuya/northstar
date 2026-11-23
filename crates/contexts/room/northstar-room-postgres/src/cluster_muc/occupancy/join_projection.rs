use super::*;
use northstar_room_application::muc_service::{MucJoinProjection, SerializableMucOccupant};
use northstar_room_core::stanza::muc_occupant_id;

pub(super) async fn password_matches(
    tx: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    verified_hash: Option<&str>,
) -> Result<bool> {
    let hash: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM muc_rooms WHERE id=$1")
            .bind(room_id)
            .fetch_one(&mut **tx)
            .await?;
    Ok(hash.as_deref() == verified_hash)
}

pub(super) async fn read(
    tx: &mut Transaction<'_, Postgres>,
    request: MucJoinProjectionRequest<'_>,
    room: &RoomAuthority,
    actor: ClusterMucOccupancy,
    audience: &[ClusterMucAudienceSnapshot],
) -> Result<MucJoinProjection> {
    let room_id = actor.room_id;
    let row = sqlx::query(
        "SELECT subject,subject_changed_at,occupant_id_secret FROM muc_rooms WHERE id=$1",
    )
    .bind(room_id)
    .fetch_one(&mut **tx)
    .await?;
    let secret = row
        .get::<Option<Vec<u8>>, _>("occupant_id_secret")
        .context("projected MUC join requires an initialized occupant ID secret")?;
    let history = if request.include_history && room.logging_enabled {
        crate::muc::muc_history_since_on(&mut **tx, room_id, 100, request.history_since)
            .await?
            .into_iter()
            .map(Into::into)
            .collect()
    } else {
        Vec::new()
    };
    let epochs: Vec<_> = audience
        .iter()
        .filter(|entry| entry.occupant_incarnation != actor.occupant_incarnation)
        .map(|entry| entry.occupancy_epoch)
        .collect();
    let mut roster = Vec::with_capacity(epochs.len());
    if !epochs.is_empty() {
        let payloads: std::collections::HashMap<_, _> = sqlx::query_as::<_, (i64, String)>(
            "SELECT occupancy_epoch,presence_payload FROM cluster_muc_occupancies
              WHERE room_id=$1 AND occupancy_epoch=ANY($2)",
        )
        .bind(room_id)
        .bind(&epochs)
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .collect();
        for entry in audience {
            if let Some(payload) = payloads.get(&entry.occupancy_epoch) {
                roster.push(SerializableMucOccupant {
                    full_jid: entry.full_jid.clone(),
                    room_jid: request.room_jid.to_owned(),
                    nick: entry.nick.clone(),
                    affiliation: entry.affiliation.clone(),
                    role: entry.role.clone(),
                    room_non_anonymous: room.non_anonymous,
                    occupant_id: muc_occupant_id(&secret, &entry.bare_jid),
                    cluster_epoch: entry.occupant_incarnation,
                    connection_id: entry.connection_uuid,
                    federated_domain: entry.authenticated_domain.clone(),
                    sm_session_id: entry.sm_session_id,
                    payload: payload.clone(),
                });
            }
        }
    }
    Ok(MucJoinProjection {
        occupant_id: muc_occupant_id(&secret, &actor.bare_jid),
        actor,
        non_anonymous: room.non_anonymous,
        logging_enabled: room.logging_enabled,
        max_occupants: room.max_occupants,
        subject: row.get("subject"),
        subject_changed_at: row.get("subject_changed_at"),
        occupant_id_secret: secret,
        roster,
        history,
    })
}
