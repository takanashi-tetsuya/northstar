//! PostgreSQL adapter for SM-owned MUC teardown projections and exact cleanup.

use crate::{db, services::sm_teardown_muc::*};
use anyhow::Result;
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresSmTeardownMucRepository {
    pool: PgPool,
}

impl PostgresSmTeardownMucRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SmTeardownMucRepository for PostgresSmTeardownMucRepository {
    async fn room(&self, localpart: &str) -> Result<Option<SmTeardownMucRoom>> {
        Ok(db::muc_room(&self.pool, localpart)
            .await?
            .map(|room| SmTeardownMucRoom {
                id: room.id,
                room_epoch: room.room_epoch,
                config_version: room.config_version,
                non_anonymous: room.non_anonymous,
                occupant_id_secret: room.occupant_id_secret,
            }))
    }

    async fn affiliation(&self, room_id: Uuid, user_id: Uuid) -> Result<Option<String>> {
        db::muc_affiliation(&self.pool, room_id, user_id).await
    }

    async fn blocked_local_audience(
        &self,
        local_domain: &str,
        occupant_jids: &[String],
        stanza_senders: &[String],
    ) -> Result<HashSet<String>> {
        db::blocked_local_accounts_for_candidates(
            &self.pool,
            local_domain,
            occupant_jids,
            stanza_senders,
        )
        .await
    }

    async fn delete_temporary_room(
        &self,
        room_id: Uuid,
        room_epoch: Uuid,
        config_version: i64,
    ) -> Result<bool> {
        db::delete_temporary_muc_room(&self.pool, room_id, room_epoch, config_version).await
    }
}
