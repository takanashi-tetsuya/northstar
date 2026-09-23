//! The administrator MUC-destroy effect's complete PostgreSQL transaction.

use crate::{
    db,
    services::operation_muc_destroy::{
        MucDestroyCommit, MucDestroyRepository, ValidatedMucDestroy,
    },
};
use anyhow::{Context, Result};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresMucDestroyRepository {
    pool: PgPool,
}

impl PostgresMucDestroyRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
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
        let destroyed = if let Some(room_id) = room_id {
            db::admin_destroy_cluster_muc_room_in_tx(
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
            false
        };
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at an isolated PostgreSQL database"]
    async fn missing_exact_destroy_intent_rolls_back_without_audit_or_room_mutation() {
        let url = std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let operation_id = Uuid::new_v4();
        let room_jid = "absent-room@conference.example.test";
        let before: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE operation_id=$1")
                .bind(operation_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let result = PostgresMucDestroyRepository::new(pool.clone())
            .commit(ValidatedMucDestroy {
                operation_id,
                request_id: Uuid::new_v4(),
                actor_id: Uuid::new_v4(),
                room_jid,
                localpart: "absent-room",
                alternate_jid: None,
                reason: None,
            })
            .await;
        let error = result.err().expect("missing intent must refuse the effect");
        assert!(error
            .to_string()
            .contains("durable MUC destroy intent is absent"));
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE operation_id=$1")
            .bind(operation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(after, before);
        pool.close().await;
    }
}
