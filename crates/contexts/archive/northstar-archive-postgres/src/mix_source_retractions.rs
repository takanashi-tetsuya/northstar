//! Transaction-scoped, append-only MIX source authority.

use anyhow::{ensure, Result};
use northstar_time::{DateTime, Utc};
use northstar_xmpp_types::jid::CanonicalJid;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub struct MixSourceRetraction {
    pub action_stanza_id: Uuid,
    pub retracted_at: DateTime<Utc>,
}

pub async fn lock_sources_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    source_by: &str,
    source_ids: &[Uuid],
    exclusive: bool,
) -> Result<()> {
    let channel = CanonicalJid::parse_bare(source_by)?;
    ensure!(
        channel.localpart().is_some() && channel.to_string() == source_by,
        "MIX channel authority must be a canonical bare channel JID"
    );
    let keys = sqlx::query_scalar::<_, i32>(
        "SELECT DISTINCT pg_catalog.hashtext($1::text || ':' || source_id::text) AS lock_key
         FROM pg_catalog.unnest($2::uuid[]) AS ids(source_id)
         ORDER BY lock_key",
    )
    .bind(source_by)
    .bind(source_ids)
    .fetch_all(&mut **tx)
    .await?;
    let lock = if exclusive {
        "SELECT pg_catalog.pg_advisory_xact_lock(('mix_source_retractions'::regclass)::oid::int4, $1::int4)"
    } else {
        "SELECT pg_catalog.pg_advisory_xact_lock_shared(('mix_source_retractions'::regclass)::oid::int4, $1::int4)"
    };
    for key in keys {
        sqlx::query(lock).bind(key).execute(&mut **tx).await?;
    }
    Ok(())
}

/// Requires exclusive locks on both source IDs. False means a conflicting binding.
pub async fn record_locked_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    source_by: &str,
    target: Uuid,
    action: Uuid,
    participant: &str,
) -> Result<bool> {
    let inserted = sqlx::query_as::<_, (Uuid, String)>(
        "INSERT INTO mix_source_retractions
             (source_by, target_stanza_id, action_stanza_id, source_participant, first_for_target)
         SELECT $1, $2, $3, $4, NOT EXISTS (
             SELECT 1 FROM mix_source_retractions
             WHERE source_by=$1 AND target_stanza_id=$2 AND first_for_target
         )
         ON CONFLICT (source_by, action_stanza_id) DO NOTHING
         RETURNING target_stanza_id, source_participant",
    )
    .bind(source_by)
    .bind(target)
    .bind(action)
    .bind(participant)
    .fetch_optional(&mut **tx)
    .await?;
    let binding = match inserted {
        Some(binding) => Some(binding),
        None => action_binding_in_tx(tx, source_by, action).await?,
    };
    Ok(binding.is_some_and(|(bound_target, actor)| bound_target == target && actor == participant))
}

pub async fn action_binding_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    source_by: &str,
    action: Uuid,
) -> Result<Option<(Uuid, String)>> {
    Ok(sqlx::query_as(
        "SELECT target_stanza_id, source_participant FROM mix_source_retractions
         WHERE source_by=$1 AND action_stanza_id=$2",
    )
    .bind(source_by)
    .bind(action)
    .fetch_optional(&mut **tx)
    .await?)
}

pub async fn primary_retraction_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    source_by: &str,
    target: Uuid,
) -> Result<Option<MixSourceRetraction>> {
    let fact = sqlx::query_as::<_, (Uuid, DateTime<Utc>)>(
        "SELECT action_stanza_id, retracted_at FROM mix_source_retractions
         WHERE source_by=$1 AND target_stanza_id=$2 AND first_for_target",
    )
    .bind(source_by)
    .bind(target)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(
        fact.map(|(action_stanza_id, retracted_at)| MixSourceRetraction {
            action_stanza_id,
            retracted_at,
        }),
    )
}
