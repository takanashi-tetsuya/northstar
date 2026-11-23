use super::{OperationRecord, Postgres, Result, Transaction, Uuid, Value};
use northstar_room_application::cluster_muc_delivery_read::EventRenderPolicy;
use std::borrow::Cow;

pub(super) async fn operation_render_details<'a>(
    tx: &mut Transaction<'_, Postgres>,
    record: &OperationRecord<'a>,
) -> Result<Cow<'a, Value>> {
    if !matches!(
        record.kind,
        "join"
            | "resume"
            | "role"
            | "affiliation"
            | "rename"
            | "kick"
            | "ban"
            | "leave"
            | "expire"
            | "account_delete"
            | "destroy"
            | "locked_expiry"
            | "config"
            | "admin_batch"
    ) {
        return Ok(Cow::Borrowed(record.details));
    }
    let actor_nick = if matches!(record.kind, "kick" | "ban") {
        let actor_incarnation = record.authorization_snapshot["actor_incarnation"]
            .as_str()
            .map(str::parse::<Uuid>)
            .transpose()?;
        sqlx::query_scalar::<_, String>(
            "SELECT nick FROM cluster_muc_occupancies
              WHERE room_id=$1 AND room_epoch=$2 AND full_jid=$3
                AND occupant_incarnation=$4 AND occupancy_epoch=$5",
        )
        .bind(record.room_id)
        .bind(record.room_epoch)
        .bind(record.actor_full_jid)
        .bind(actor_incarnation)
        .bind(record.authorization_snapshot["actor_occupancy_epoch"].as_i64())
        .fetch_optional(&mut **tx)
        .await?
    } else {
        None
    };
    let non_anonymous = match record.details["non_anonymous"].as_bool() {
        Some(committed) => committed,
        None => {
            sqlx::query_scalar("SELECT non_anonymous FROM muc_rooms WHERE id=$1 AND room_epoch=$2")
                .bind(record.room_id)
                .bind(record.room_epoch)
                .fetch_one(&mut **tx)
                .await?
        }
    };
    let mut details = record.details.clone();
    details["render_policy"] = serde_json::to_value(EventRenderPolicy {
        non_anonymous,
        actor_nick,
    })?;
    Ok(Cow::Owned(details))
}
