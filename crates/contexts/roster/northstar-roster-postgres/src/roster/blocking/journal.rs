use anyhow::Result;
use northstar_roster_application::blocklist_revisions::{
    BlocklistAction, BlocklistChange, BlocklistJournal, BlocklistRevisionRepository,
    BlocklistSnapshot,
};
use northstar_roster_core::RosterActor;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::super::PostgresBlockingRepository;

pub(super) async fn append(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    action: &str,
    changed: &[String],
) -> Result<()> {
    if changed.is_empty() {
        return Ok(());
    }
    let revision: i64 = sqlx::query_scalar(
        "INSERT INTO blocklist_revisions AS counter (owner_id, revision) VALUES ($1, 1)
         ON CONFLICT (owner_id) DO UPDATE SET revision = counter.revision + 1
         RETURNING revision",
    )
    .bind(owner_id)
    .fetch_one(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO blocklist_change_log (owner_id, revision, action, patterns) VALUES ($1, $2, $3, $4)",
    )
    .bind(owner_id)
    .bind(revision)
    .bind(action)
    .bind(changed)
    .execute(&mut **transaction)
    .await?;
    sqlx::query("DELETE FROM blocklist_change_log WHERE owner_id = $1 AND revision <= $2 - 10000")
        .bind(owner_id)
        .bind(revision)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

impl BlocklistRevisionRepository for PostgresBlockingRepository {
    async fn blocklist_snapshot(&self, actor: &RosterActor) -> Result<Option<BlocklistSnapshot>> {
        let row = sqlx::query_as::<_, (i64, Vec<String>)>(
            "SELECT COALESCE(counter.revision, 0), ARRAY(
                 SELECT blocked_jid FROM blocked_jids WHERE owner_id = account.id ORDER BY blocked_jid
             )
             FROM users account LEFT JOIN blocklist_revisions counter ON counter.owner_id = account.id
             WHERE account.id = $1 AND account.auth_generation = $2 AND NOT account.is_disabled",
        )
        .bind(actor.account_id)
        .bind(actor.auth_generation)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(revision, patterns)| BlocklistSnapshot { revision, patterns }))
    }

    async fn blocklist_journal(
        &self,
        actor: &RosterActor,
        after: Option<i64>,
    ) -> Result<Option<BlocklistJournal>> {
        let rows = sqlx::query(
            "SELECT COALESCE(counter.revision, 0) AS head, entry.revision, entry.action, entry.patterns
             FROM users account LEFT JOIN blocklist_revisions counter ON counter.owner_id = account.id
             LEFT JOIN LATERAL (
                 SELECT revision, action, patterns FROM blocklist_change_log
                 WHERE owner_id = account.id AND revision > COALESCE($3, counter.revision - 1)
                 ORDER BY revision LIMIT 128
             ) entry ON TRUE
             WHERE account.id = $1 AND account.auth_generation = $2 AND NOT account.is_disabled
             ORDER BY entry.revision",
        )
        .bind(actor.account_id)
        .bind(actor.auth_generation)
        .bind(after)
        .fetch_all(&self.pool)
        .await?;
        let Some(first) = rows.first() else {
            return Ok(None);
        };
        let revision = first.try_get("head")?;
        let mut changes = Vec::new();
        for row in &rows {
            let Some(revision) = row.try_get::<Option<i64>, _>("revision")? else {
                continue;
            };
            let action = match row.try_get::<&str, _>("action")? {
                "block" => BlocklistAction::Block,
                "unblock" => BlocklistAction::Unblock,
                "unblock-all" => BlocklistAction::UnblockAll,
                action => anyhow::bail!("invalid blocklist journal action: {action}"),
            };
            changes.push(BlocklistChange {
                revision,
                action,
                patterns: row.try_get("patterns")?,
            });
        }
        Ok(Some(BlocklistJournal { revision, changes }))
    }
}
