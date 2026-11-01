//! The administrator MUC-destroy effect's complete PostgreSQL transaction.

use anyhow::{Context, Result};
use northstar_operations_application::operation_muc_destroy::{
    MucDestroyAudience, MucDestroyCommit, MucDestroyRepository, ValidatedMucDestroy,
};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresMucDestroyRepository {
    pool: PgPool,
}

impl PostgresMucDestroyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl MucDestroyRepository for PostgresMucDestroyRepository {
    async fn commit(&self, command: ValidatedMucDestroy<'_>) -> Result<MucDestroyCommit> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("northstar:muc-room:{}", command.localpart))
            .execute(&mut *tx)
            .await?;
        let intent_matches = sqlx::query_scalar::<_, Uuid>(
            "SELECT operation_id FROM api_muc_destroy_intents WHERE room_jid=$1 AND localpart=$2 AND operation_id=$3 FOR UPDATE",
        )
        .bind(command.room_jid)
        .bind(command.localpart)
        .bind(command.operation_id)
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        anyhow::ensure!(intent_matches, "durable MUC destroy intent is absent");
        let room_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM muc_rooms
              WHERE localpart=$1 AND destroyed_at IS NULL FOR UPDATE",
        )
        .bind(command.localpart)
        .fetch_optional(&mut *tx)
        .await?;
        let actor_label = command.actor_id.to_string();
        let committed_audience = if let Some(room_id) = room_id {
            northstar_room_postgres::cluster_muc::admin_destroy_cluster_muc_room_in_tx(
                &mut tx,
                command.operation_id,
                room_id,
                command.actor_id,
                &actor_label,
                command.alternate_jid,
                command.reason,
            )
            .await?
        } else {
            None
        };
        let destroyed = committed_audience.is_some();
        let audience = committed_audience
            .unwrap_or_default()
            .into_iter()
            .map(|occupant| MucDestroyAudience {
                full_jid: occupant.full_jid,
                nick: occupant.nick,
                occupant_incarnation: occupant.occupant_incarnation,
                connection_id: occupant.connection_uuid,
            })
            .collect();
        sqlx::query("DELETE FROM api_muc_destroy_intents WHERE operation_id=$1")
            .bind(command.operation_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO audit_log(actor_id,action,target,details,request_id,operation_id) VALUES($1,'admin.muc_room.destroy',$2,$3,$4,$5)")
            .bind(Some(command.actor_id))
            .bind(command.room_jid)
            .bind(serde_json::json!({"destroyed":destroyed}))
            .bind(command.request_id)
            .bind(command.operation_id)
            .execute(&mut *tx)
            .await?;
        tx.commit()
            .await
            .context("could not commit administrator MUC destroy effect")?;
        Ok(MucDestroyCommit {
            room_jid: command.room_jid.to_owned(),
            destroyed,
            audience,
        })
    }
}
