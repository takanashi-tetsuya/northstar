use super::{lock_room, Postgres, Result, Transaction, Uuid};

pub(super) struct CapacityPlan(Vec<i16>);

impl CapacityPlan {
    pub(super) fn new(shards: impl IntoIterator<Item = i16>) -> Self {
        let mut shards: Vec<i16> = shards.into_iter().collect();
        shards.sort_unstable();
        shards.dedup();
        Self(shards)
    }

    pub(super) fn all() -> Self {
        Self::new(0..64)
    }

    pub(super) async fn lock_outbox_if_multiple(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<()> {
        if self.0.len() > 1 {
            self.lock_outbox(tx).await?;
        }
        Ok(())
    }

    pub(super) async fn lock_outbox(&self, tx: &mut Transaction<'_, Postgres>) -> Result<()> {
        sqlx::query(
            "SELECT shard FROM cluster_muc_outbox_capacity
              WHERE shard=ANY($1) ORDER BY shard FOR UPDATE",
        )
        .bind(&self.0)
        .fetch_all(&mut **tx)
        .await?;
        Ok(())
    }

    pub(super) async fn lock_dead_letters_if_multiple(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<()> {
        if self.0.len() > 1 {
            sqlx::query(
                "SELECT shard FROM cluster_muc_dead_letter_capacity
                  WHERE shard=ANY($1) ORDER BY shard FOR UPDATE",
            )
            .bind(&self.0)
            .fetch_all(&mut **tx)
            .await?;
        }
        Ok(())
    }
}

pub(crate) async fn lock_room_event_capacity(
    tx: &mut Transaction<'_, Postgres>,
    room_ids: &[Uuid],
    local_user_id: Option<Uuid>,
) -> Result<()> {
    if room_ids.is_empty() || (room_ids.len() == 1 && local_user_id.is_none()) {
        return Ok(());
    }
    if local_user_id.is_some() {
        for room_id in room_ids {
            lock_room(tx, *room_id).await?;
        }
    }
    sqlx::query(
        "SELECT room_id FROM cluster_muc_occupancies
          WHERE room_id=ANY($1) AND ($2::uuid IS NULL OR local_user_id=$2)
            AND state IN ('active','suspended')
          ORDER BY room_id,occupancy_epoch FOR UPDATE",
    )
    .bind(room_ids)
    .bind(local_user_id)
    .fetch_all(&mut **tx)
    .await?;
    CapacityPlan::all().lock_outbox(tx).await
}

#[cfg(test)]
mod tests;
