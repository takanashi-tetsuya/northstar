//! Atomic selection and cancellation of personal retraction originals.

use anyhow::Result;
use northstar_message_application::retractions::NormalizedOwner;
use northstar_xmpp_types::jid::canonical_bare_key;
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
#[error("offline original is locked: {message_id}")]
pub(super) struct BusySpoolOriginal {
    recipient_id: Uuid,
    message_id: Uuid,
}

impl BusySpoolOriginal {
    pub(super) async fn wait(&self, pool: &PgPool) -> Result<()> {
        sqlx::query("SELECT id FROM offline_messages WHERE recipient_id=$1 AND id=$2 FOR UPDATE")
            .bind(self.recipient_id)
            .bind(self.message_id)
            .fetch_optional(pool)
            .await?;
        Ok(())
    }
}

pub(super) async fn fence_spool_cancellation(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(5645368709120102)")
        .execute(&mut **tx)
        .await?;
    sqlx::query("LOCK TABLE offline_messages IN ROW EXCLUSIVE MODE")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(super) async fn lock_originals(
    tx: &mut Transaction<'_, Postgres>,
    owners: &[NormalizedOwner],
    target_id: &str,
) -> Result<Vec<(Uuid, Uuid)>> {
    let (owner_ids, peers): (Vec<_>, Vec<_>) = owners
        .iter()
        .map(|owner| (owner.owner_id, owner.peer_bare_jid.clone()))
        .unzip();
    Ok(sqlx::query_as(
        "WITH candidates AS MATERIALIZED (
             SELECT candidate.id
               FROM unnest($1::UUID[], $2::TEXT[]) AS owner(owner_id, peer)
               CROSS JOIN LATERAL (
                   SELECT original.id FROM message_archive original
                    WHERE original.owner_id=owner.owner_id
                      AND pg_catalog.md5(original.peer_jid)=pg_catalog.md5(owner.peer)
                      AND pg_catalog.md5(original.stanza_id)=pg_catalog.md5($3::TEXT)
                      AND original.peer_jid=owner.peer AND original.stanza_id=$3
                      AND original.source_stanza_id IS NULL
                    ORDER BY original.created_at DESC,original.id DESC LIMIT 3
               ) candidate
         )
         SELECT archive.owner_id,archive.id FROM candidates
           JOIN message_archive archive ON archive.id=candidates.id
          ORDER BY archive.owner_id,archive.id FOR UPDATE OF archive",
    )
    .bind(&owner_ids)
    .bind(&peers)
    .bind(target_id)
    .fetch_all(&mut **tx)
    .await?)
}

pub(super) async fn cancel_unowned_original(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    archive_id: Uuid,
    account_bares: &HashMap<Uuid, String>,
    sender_bare: &str,
    original: &str,
) -> Result<()> {
    let document = roxmltree::Document::parse(original)?;
    let to = document
        .root_element()
        .attribute("to")
        .unwrap_or(sender_bare);
    let Ok(recipient_bare) = canonical_bare_key(to) else {
        return Ok(());
    };
    let Some(recipient_id) = account_bares
        .iter()
        .find_map(|(id, bare)| (bare == &recipient_bare).then_some(*id))
    else {
        return Ok(());
    };
    let message_id = if recipient_id == owner_id {
        archive_id
    } else {
        let candidate_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT offline_message_id FROM personal_message_admissions
              WHERE sender_archive_id=$1 AND identity_kind='local-origin'
                AND actor_scope=$2 AND target_scope=$3
                AND recipient_archive_id IS NULL AND offline_message_id IS NOT NULL
              LIMIT 2",
        )
        .bind(archive_id)
        .bind(sender_bare)
        .bind(&recipient_bare)
        .fetch_all(&mut **tx)
        .await?;
        let [message_id] = candidate_ids.as_slice() else {
            return Ok(());
        };
        *message_id
    };
    let sender = sqlx::query_scalar::<_, String>(
        "SELECT sender_jid FROM offline_messages WHERE recipient_id=$1 AND id=$2 FOR UPDATE NOWAIT",
    )
    .bind(recipient_id)
    .bind(message_id)
    .fetch_optional(&mut **tx)
    .await;
    let sender = match sender {
        Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("55P03") => {
            return Err(BusySpoolOriginal {
                recipient_id,
                message_id,
            }
            .into());
        }
        result => result?,
    };
    if sender
        .and_then(|jid| canonical_bare_key(&jid).ok())
        .as_deref()
        != Some(sender_bare)
    {
        return Ok(());
    }
    sqlx::query(
        "DELETE FROM offline_messages message
          WHERE message.recipient_id=$1 AND message.id=$2
            AND message.delivery_claim_id IS NULL
            AND NOT EXISTS (
                SELECT 1 FROM sm_resume_stanzas sm WHERE sm.delivery_message_id=message.id
            )
            AND NOT EXISTS (
                SELECT 1 FROM bosh_delivery_fences bosh WHERE bosh.message_id=message.id
            )
            AND NOT EXISTS (
                SELECT 1 FROM legal_holds hold
                 WHERE hold.released_at IS NULL AND (
                     EXISTS (SELECT 1 FROM legal_hold_offline_messages link
                              WHERE link.hold_id=hold.id AND link.message_id=message.id)
                     OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                WHERE scope_link.hold_id=hold.id
                                  AND scope_link.scope_type='offline_message_recipient'
                                  AND scope_link.subject_id=message.recipient_id)
                 )
            )",
    )
    .bind(recipient_id)
    .bind(message_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
