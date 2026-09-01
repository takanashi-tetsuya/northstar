//! RFC 7622 migration for durable identity metadata outside keyed subsystems.
//!
//! Raw stanza/evidence payloads are intentionally immutable.  The columns
//! handled here are the canonical identity metadata used for authorization,
//! routing, archive filtering and replay admission.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeMap;
use uuid::Uuid;

const MIGRATION: &str = "remaining-identity-metadata-rfc7622-ulabel-v2";
const VERSION: i32 = 2;

fn full(value: &str, field: &str, row: impl std::fmt::Display) -> Result<String> {
    crate::jid::canonicalize(value).with_context(|| {
        format!("RFC 7622 migration rejected invalid {field} in row {row}: {value:?}")
    })
}

fn bare(value: &str, field: &str, row: impl std::fmt::Display) -> Result<String> {
    crate::jid::canonicalize_bare(value).with_context(|| {
        format!("RFC 7622 migration rejected invalid {field} in row {row}: {value:?}")
    })
}

fn domain(value: &str, field: &str, row: impl std::fmt::Display) -> Result<String> {
    crate::jid::prepare_domainpart(value).with_context(|| {
        format!("RFC 7622 migration rejected invalid {field} in row {row}: {value:?}")
    })
}

fn muc_origin_digest(actor_scope: &str, origin_id: &str) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"northstar:muc-origin-id:v1\0");
    digest.update((actor_scope.len() as u32).to_be_bytes());
    digest.update(actor_scope.as_bytes());
    digest.update((origin_id.len() as u32).to_be_bytes());
    digest.update(origin_id.as_bytes());
    digest.finalize().to_vec()
}

pub(crate) async fn canonicalize_remaining_identity_storage_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,7622))")
        .bind(MIGRATION)
        .execute(&mut **transaction)
        .await?;
    let complete: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration=$1 AND canonicalizer_version=$2)",
    )
    .bind(MIGRATION)
    .bind(VERSION)
    .fetch_one(&mut **transaction)
    .await?;
    if complete {
        return Ok(());
    }

    sqlx::query("SET LOCAL lock_timeout='30s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "LOCK TABLE offline_messages, message_archive, personal_message_admissions,
         muc_rooms, muc_messages, muc_origin_admissions, abuse_reports,
         abuse_report_evidence, s2s_outbox, privacy_list_items,
         mix_events, mix_muc_mirrors IN ACCESS EXCLUSIVE MODE",
    )
    .execute(&mut **transaction)
    .await
    .context(
        "timed out waiting to lock remaining RFC 7622 identity metadata; stop other Northstar nodes using this database, then restart",
    )?;

    let mut transformed = 0_i64;
    transformed += canonicalize_offline(transaction).await?;
    transformed += canonicalize_personal_archive(transaction).await?;
    transformed += canonicalize_personal_admissions(transaction).await?;
    transformed += canonicalize_muc(transaction).await?;
    transformed += canonicalize_reports(transaction).await?;
    transformed += canonicalize_s2s_outbox(transaction).await?;
    transformed += canonicalize_privacy(transaction).await?;
    transformed += canonicalize_mix_metadata(transaction).await?;

    sqlx::query(
        "INSERT INTO jid_identity_migrations(migration,canonicalizer_version,transformed_rows) VALUES($1,$2,$3)",
    )
    .bind(MIGRATION)
    .bind(VERSION)
    .bind(transformed)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn canonicalize_offline(transaction: &mut Transaction<'_, Postgres>) -> Result<i64> {
    let rows = sqlx::query("SELECT id,sender_jid FROM offline_messages ORDER BY id")
        .fetch_all(&mut **transaction)
        .await?;
    let mut changed = 0_i64;
    for row in rows {
        let id: Uuid = row.get("id");
        let original: String = row.get("sender_jid");
        let canonical = full(&original, "offline_messages.sender_jid", id)?;
        if canonical != original {
            changed += sqlx::query("UPDATE offline_messages SET sender_jid=$2 WHERE id=$1")
                .bind(id)
                .bind(canonical)
                .execute(&mut **transaction)
                .await?
                .rows_affected() as i64;
        }
    }
    Ok(changed)
}

async fn canonicalize_personal_archive(transaction: &mut Transaction<'_, Postgres>) -> Result<i64> {
    struct ArchiveRow {
        id: Uuid,
        owner: Uuid,
        peer: String,
        peer_full: String,
        source: Option<String>,
        source_id: Option<Uuid>,
    }
    let rows = sqlx::query(
        "SELECT id,owner_id,peer_jid,peer_full_jid,source_by,source_stanza_id FROM message_archive ORDER BY id",
    )
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| ArchiveRow {
        id: row.get("id"),
        owner: row.get("owner_id"),
        peer: row.get("peer_jid"),
        peer_full: row.get("peer_full_jid"),
        source: row.get("source_by"),
        source_id: row.get("source_stanza_id"),
    })
    .collect::<Vec<_>>();
    let mut source_keys = BTreeMap::new();
    let mut prepared = Vec::with_capacity(rows.len());
    for row in rows {
        let canonical_full = full(&row.peer_full, "message_archive.peer_full_jid", row.id)?;
        let canonical_peer = crate::jid::canonical_bare_key(&canonical_full)?;
        anyhow::ensure!(
            crate::jid::canonical_bare_key(&row.peer)? == canonical_peer,
            "message_archive row {} has inconsistent peer_jid and peer_full_jid",
            row.id
        );
        let canonical_source = row
            .source
            .as_deref()
            .map(|value| bare(value, "message_archive.source_by", row.id))
            .transpose()?;
        if let (Some(source), Some(source_id)) = (&canonical_source, row.source_id) {
            let key = (row.owner, source.clone(), source_id);
            if let Some(previous) = source_keys.insert(key, row.id) {
                anyhow::bail!(
                    "RFC 7622 migration found a message_archive source collision between rows {previous} and {}",
                    row.id
                );
            }
        }
        prepared.push((row, canonical_peer, canonical_full, canonical_source));
    }
    let mut changed = 0_i64;
    for (row, peer, peer_full, source) in prepared {
        if row.peer != peer || row.peer_full != peer_full || row.source != source {
            changed += sqlx::query(
                "UPDATE message_archive SET peer_jid=$2,peer_full_jid=$3,source_by=$4 WHERE id=$1",
            )
            .bind(row.id)
            .bind(peer)
            .bind(peer_full)
            .bind(source)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
        }
    }
    Ok(changed)
}

async fn canonicalize_personal_admissions(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64> {
    let rows = sqlx::query(
        "SELECT id,identity_kind,actor_scope,target_scope,identity_digest FROM personal_message_admissions ORDER BY id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut keys = BTreeMap::new();
    let mut prepared = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row.get("id");
        let kind: String = row.get("identity_kind");
        let actor: String = row.get("actor_scope");
        let target: String = row.get("target_scope");
        let digest: Vec<u8> = row.get("identity_digest");
        let canonical_actor = full(&actor, "personal_message_admissions.actor_scope", id)?;
        let canonical_target = full(&target, "personal_message_admissions.target_scope", id)?;
        let key = (
            kind,
            canonical_actor.clone(),
            canonical_target.clone(),
            digest,
        );
        if let Some(previous) = keys.insert(key, id) {
            anyhow::bail!(
                "RFC 7622 migration found a personal-message admission collision between rows {previous} and {id}"
            );
        }
        prepared.push((id, actor, target, canonical_actor, canonical_target));
    }
    let mut changed = 0_i64;
    for (id, actor, target, canonical_actor, canonical_target) in prepared {
        if actor != canonical_actor || target != canonical_target {
            changed += sqlx::query(
                "UPDATE personal_message_admissions SET actor_scope=$2,target_scope=$3 WHERE id=$1",
            )
            .bind(id)
            .bind(canonical_actor)
            .bind(canonical_target)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
        }
    }
    Ok(changed)
}

async fn canonicalize_muc(transaction: &mut Transaction<'_, Postgres>) -> Result<i64> {
    struct Admission {
        room: Uuid,
        digest: Vec<u8>,
        actor: String,
        origin: String,
        stanza: Uuid,
        canonical_actor: String,
        canonical_digest: Vec<u8>,
    }
    let admissions = sqlx::query(
        "SELECT room_id,origin_digest,actor_scope,origin_id,stanza_id FROM muc_origin_admissions ORDER BY room_id,origin_digest",
    )
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| -> Result<Admission> {
        let room: Uuid = row.get("room_id");
        let digest: Vec<u8> = row.get("origin_digest");
        let actor: String = row.get("actor_scope");
        let origin: String = row.get("origin_id");
        let stanza: Uuid = row.get("stanza_id");
        let canonical_actor = bare(&actor, "muc_origin_admissions.actor_scope", stanza)?;
        let canonical_digest = muc_origin_digest(&canonical_actor, &origin);
        Ok(Admission { room, digest, actor, origin, stanza, canonical_actor, canonical_digest })
    })
    .collect::<Result<Vec<_>>>()?;
    let mut keys = BTreeMap::new();
    for admission in &admissions {
        if let Some(previous) = keys.insert(
            (admission.room, admission.canonical_digest.clone()),
            admission.stanza,
        ) {
            anyhow::bail!(
                "RFC 7622 migration found a MUC origin-id collision between stanzas {previous} and {}",
                admission.stanza
            );
        }
    }

    let rooms =
        sqlx::query("SELECT id,subject_set_by,configuration_owner_jid FROM muc_rooms ORDER BY id")
            .fetch_all(&mut **transaction)
            .await?;
    let messages = sqlx::query(
        "SELECT id,room_id,sender_jid,actor_scope,origin_id,origin_digest FROM muc_messages ORDER BY id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut changed = 0_i64;
    for admission in &admissions {
        if admission.actor != admission.canonical_actor
            || admission.digest != admission.canonical_digest
        {
            changed += sqlx::query(
                "UPDATE muc_origin_admissions SET origin_digest=$3,actor_scope=$4 WHERE room_id=$1 AND origin_digest=$2",
            )
            .bind(admission.room)
            .bind(&admission.digest)
            .bind(&admission.canonical_digest)
            .bind(&admission.canonical_actor)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
        }
    }
    for row in rooms {
        let id: Uuid = row.get("id");
        let subject: Option<String> = row.get("subject_set_by");
        let owner: Option<String> = row.get("configuration_owner_jid");
        let canonical_subject = subject
            .as_deref()
            .map(|value| bare(value, "muc_rooms.subject_set_by", id))
            .transpose()?;
        let canonical_owner = owner
            .as_deref()
            .map(|value| full(value, "muc_rooms.configuration_owner_jid", id))
            .transpose()?;
        if subject != canonical_subject || owner != canonical_owner {
            changed += sqlx::query(
                "UPDATE muc_rooms SET subject_set_by=$2,configuration_owner_jid=$3 WHERE id=$1",
            )
            .bind(id)
            .bind(canonical_subject)
            .bind(canonical_owner)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
        }
    }
    for row in messages {
        let id: Uuid = row.get("id");
        let room: Uuid = row.get("room_id");
        let sender: String = row.get("sender_jid");
        let actor: Option<String> = row.get("actor_scope");
        let origin: Option<String> = row.get("origin_id");
        let digest: Option<Vec<u8>> = row.get("origin_digest");
        let canonical_sender = full(&sender, "muc_messages.sender_jid", id)?;
        let canonical_actor = actor
            .as_deref()
            .map(|value| bare(value, "muc_messages.actor_scope", id))
            .transpose()?;
        let canonical_digest = match (&canonical_actor, &origin, &digest) {
            (Some(actor), Some(origin), Some(_)) => {
                let value = muc_origin_digest(actor, origin);
                anyhow::ensure!(
                    admissions.iter().any(|admission| admission.room == room
                        && admission.stanza == id
                        && admission.origin == *origin
                        && admission.canonical_actor == *actor
                        && admission.canonical_digest == value),
                    "muc_messages row {id} has no matching durable origin admission"
                );
                Some(value)
            }
            (Some(_), None, None) | (None, None, None) => None,
            _ => anyhow::bail!("muc_messages row {id} has incomplete origin identity metadata"),
        };
        if sender != canonical_sender || actor != canonical_actor || digest != canonical_digest {
            changed += sqlx::query(
                "UPDATE muc_messages SET sender_jid=$2,actor_scope=$3,origin_digest=$4 WHERE id=$1",
            )
            .bind(id)
            .bind(canonical_sender)
            .bind(canonical_actor)
            .bind(canonical_digest)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
        }
    }
    Ok(changed)
}

async fn canonicalize_reports(transaction: &mut Transaction<'_, Postgres>) -> Result<i64> {
    let reports = sqlx::query("SELECT id,reported_jid FROM abuse_reports ORDER BY id")
        .fetch_all(&mut **transaction)
        .await?;
    let evidence = sqlx::query("SELECT id,sender_jid FROM abuse_report_evidence ORDER BY id")
        .fetch_all(&mut **transaction)
        .await?;
    let mut changed = 0_i64;
    for row in reports {
        let id: Uuid = row.get("id");
        let original: String = row.get("reported_jid");
        let canonical = crate::jid::canonical_bare_key(&original)?;
        if original != canonical {
            changed += sqlx::query("UPDATE abuse_reports SET reported_jid=$2 WHERE id=$1")
                .bind(id)
                .bind(canonical)
                .execute(&mut **transaction)
                .await?
                .rows_affected() as i64;
        }
    }
    for row in evidence {
        let id: Uuid = row.get("id");
        let original: String = row.get("sender_jid");
        let canonical = full(&original, "abuse_report_evidence.sender_jid", id)?;
        if original != canonical {
            changed += sqlx::query("UPDATE abuse_report_evidence SET sender_jid=$2 WHERE id=$1")
                .bind(id)
                .bind(canonical)
                .execute(&mut **transaction)
                .await?
                .rows_affected() as i64;
        }
    }
    Ok(changed)
}

async fn canonicalize_s2s_outbox(transaction: &mut Transaction<'_, Postgres>) -> Result<i64> {
    let rows =
        sqlx::query("SELECT id,target_domain,bounce_to,dedupe_hash FROM s2s_outbox ORDER BY id")
            .fetch_all(&mut **transaction)
            .await?;
    let mut keys = BTreeMap::new();
    let mut prepared = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row.get("id");
        let target: String = row.get("target_domain");
        let bounce: Option<String> = row.get("bounce_to");
        let digest: Vec<u8> = row.get("dedupe_hash");
        let canonical_target = domain(&target, "s2s_outbox.target_domain", id)?;
        let canonical_bounce = bounce
            .as_deref()
            .map(|value| full(value, "s2s_outbox.bounce_to", id))
            .transpose()?;
        if let Some(previous) = keys.insert((canonical_target.clone(), digest), id) {
            anyhow::bail!(
                "RFC 7622 migration found an S2S outbox identity collision between rows {previous} and {id}"
            );
        }
        prepared.push((id, target, bounce, canonical_target, canonical_bounce));
    }
    let mut changed = 0_i64;
    for (id, target, bounce, canonical_target, canonical_bounce) in prepared {
        if target != canonical_target || bounce != canonical_bounce {
            changed +=
                sqlx::query("UPDATE s2s_outbox SET target_domain=$2,bounce_to=$3 WHERE id=$1")
                    .bind(id)
                    .bind(canonical_target)
                    .bind(canonical_bounce)
                    .execute(&mut **transaction)
                    .await?
                    .rows_affected() as i64;
        }
    }
    Ok(changed)
}

async fn canonicalize_privacy(transaction: &mut Transaction<'_, Postgres>) -> Result<i64> {
    let rows = sqlx::query(
        "SELECT owner_id,list_name,item_order,match_value FROM privacy_list_items WHERE match_type='jid' ORDER BY owner_id,list_name,item_order",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut changed = 0_i64;
    for row in rows {
        let owner: Uuid = row.get("owner_id");
        let list: String = row.get("list_name");
        let order: i64 = row.get("item_order");
        let original: String = row.get("match_value");
        let canonical = full(
            &original,
            "privacy_list_items.match_value",
            format_args!("{owner}/{list}/{order}"),
        )?;
        if original != canonical {
            changed += sqlx::query(
                "UPDATE privacy_list_items SET match_value=$4 WHERE owner_id=$1 AND list_name=$2 AND item_order=$3",
            )
            .bind(owner)
            .bind(list)
            .bind(order)
            .bind(canonical)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
        }
    }
    Ok(changed)
}

async fn canonicalize_mix_metadata(transaction: &mut Transaction<'_, Postgres>) -> Result<i64> {
    let events = sqlx::query(
        "SELECT id,channel_id,node,item_id,publisher_jid,payload FROM mix_events ORDER BY id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mirrors = sqlx::query(
        "SELECT mix_channel_id,created_by FROM mix_muc_mirrors ORDER BY mix_channel_id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut item_keys = BTreeMap::new();
    let mut prepared_events = Vec::with_capacity(events.len());
    for row in events {
        let id: Uuid = row.get("id");
        let channel: Uuid = row.get("channel_id");
        let node: String = row.get("node");
        let item: String = row.get("item_id");
        let publisher: Option<String> = row.get("publisher_jid");
        let payload: String = row.get("payload");
        let canonical_publisher = publisher
            .as_deref()
            .map(|value| bare(value, "mix_events.publisher_jid", id))
            .transpose()?;
        let (canonical_item, canonical_payload) = match node.as_str() {
            crate::db::NODE_ALLOWED | crate::db::NODE_BANNED => {
                let pattern = if item.contains('@') {
                    bare(&item, "mix_events access ItemID", id)?
                } else {
                    domain(&item, "mix_events access ItemID", id)?
                };
                (
                    pattern.clone(),
                    format!(
                        "<jid xmlns='urn:xmpp:mix:admin:0'>{}</jid>",
                        crate::state::xml_escape(&pattern)
                    ),
                )
            }
            crate::db::NODE_PRESENCE => (
                full(&item, "mix_events presence ItemID", id)?,
                payload.clone(),
            ),
            _ => (item.clone(), payload.clone()),
        };
        if let Some(previous) =
            item_keys.insert((channel, node.clone(), canonical_item.clone()), id)
        {
            anyhow::bail!(
                "RFC 7622 migration found a MIX event ItemID collision between rows {previous} and {id}"
            );
        }
        prepared_events.push((
            id,
            item,
            publisher,
            payload,
            canonical_item,
            canonical_publisher,
            canonical_payload,
        ));
    }
    let mut changed = 0_i64;
    for (id, item, publisher, payload, canonical_item, canonical_publisher, canonical_payload) in
        prepared_events
    {
        if item != canonical_item
            || publisher != canonical_publisher
            || payload != canonical_payload
        {
            changed += sqlx::query(
                "UPDATE mix_events SET item_id=$2,publisher_jid=$3,payload=$4 WHERE id=$1",
            )
            .bind(id)
            .bind(canonical_item)
            .bind(canonical_publisher)
            .bind(canonical_payload)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
        }
    }
    for row in mirrors {
        let id: Uuid = row.get("mix_channel_id");
        let original: String = row.get("created_by");
        let canonical = bare(&original, "mix_muc_mirrors.created_by", id)?;
        if original != canonical {
            changed +=
                sqlx::query("UPDATE mix_muc_mirrors SET created_by=$2 WHERE mix_channel_id=$1")
                    .bind(id)
                    .bind(canonical)
                    .execute(&mut **transaction)
                    .await?
                    .rows_affected() as i64;
        }
    }
    Ok(changed)
}
