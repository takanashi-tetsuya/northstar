//! PostgreSQL persistence for the offline XEP-0227 import.
//!
//! Import keeps account staging, dependent rows and the operator audit record
//! in one serializable transaction. A dry run follows the same write path and
//! rolls the complete transaction back.

use crate::{
    jid,
    pie::{ConflictPolicy, PieUser, PreparedUser},
};
use anyhow::{bail, Context, Result};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

struct StagedUser {
    id: Uuid,
    data: PieUser,
}

pub(crate) async fn persist_import(
    pool: &PgPool,
    domain: &str,
    source: &str,
    prepared: Vec<PreparedUser>,
    conflict: ConflictPolicy,
    dry_run: bool,
    warning_count: usize,
) -> Result<(u64, u64)> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await?;
    if conflict == ConflictPolicy::Replace {
        // Replacement cascades through upload_slots. Match online account
        // deletion's global-capacity -> domain/user lock order. The typed
        // SQL capability performs a NOWAIT capacity admission, so this does
        // not impose an arbitrary timeout on the rest of the replacement.
        sqlx::query("SELECT northstar_upload_capacity_lock()")
            .fetch_one(&mut *tx)
            .await
            .context("upload storage capacity busy; retry PIE replacement")?;
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 227))")
        .bind(domain)
        .execute(&mut *tx)
        .await?;
    let mut staged = Vec::with_capacity(prepared.len());
    let mut skipped = 0_u64;
    for user in prepared {
        match stage_user_identity(&mut tx, user, conflict).await? {
            Some(user) => staged.push(user),
            None => skipped += 1,
        }
    }
    // Every identity exists before dependent state is restored. This makes
    // local pending-presence restoration independent of username sort order.
    for user in &mut staged {
        import_user_data(&mut tx, domain, user).await?;
    }
    let imported = staged.len() as u64;
    sqlx::query("INSERT INTO audit_log(actor_id,action,target,details) VALUES(NULL,'operator.pie.import',$1,$2)")
        .bind(domain)
        .bind(serde_json::json!({
            "source":source,
            "dry_run":dry_run,
            "conflict":format!("{:?}", conflict).to_ascii_lowercase(),
            "imported":imported,
            "skipped":skipped,
            "warnings":warning_count
        }))
        .execute(&mut *tx).await?;
    if dry_run {
        tx.rollback().await?;
    } else {
        tx.commit().await?;
    }
    Ok((imported, skipped))
}

async fn stage_user_identity(
    tx: &mut Transaction<'_, Postgres>,
    user: PreparedUser,
    conflict: ConflictPolicy,
) -> Result<Option<StagedUser>> {
    let existing = sqlx::query("SELECT id,is_admin FROM users WHERE username=$1 FOR UPDATE")
        .bind(&user.data.username)
        .fetch_optional(&mut **tx)
        .await?;
    if let Some(existing) = existing {
        let existing_id: Uuid = existing.get("id");
        match conflict {
            ConflictPolicy::Fail => bail!("PIE user {:?} already exists", user.data.username),
            ConflictPolicy::Skip => return Ok(None),
            ConflictPolicy::Replace => {
                if existing.get::<bool, _>("is_admin") {
                    bail!(
                        "PIE refuses to replace administrator {:?}; server roles are outside XEP-0227",
                        user.data.username
                    );
                }
                sqlx::query("DELETE FROM users WHERE id=$1")
                    .bind(existing_id)
                    .execute(&mut **tx)
                    .await?;
            }
        }
    }
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash,scram_sha256_salt,scram_sha256_iterations,scram_sha256_stored_key,scram_sha256_server_key) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(user_id).bind(&user.data.username).bind(user.password_hash)
        .bind(user.scram.salt).bind(user.scram.iterations as i32)
        .bind(user.scram.stored_key).bind(user.scram.server_key)
        .execute(&mut **tx).await?;
    Ok(Some(StagedUser {
        id: user_id,
        data: user.data,
    }))
}

async fn import_user_data(
    tx: &mut Transaction<'_, Postgres>,
    domain: &str,
    user: &mut StagedUser,
) -> Result<()> {
    let user_id = user.id;
    for item in std::mem::take(&mut user.data.roster) {
        sqlx::query("INSERT INTO roster_items(owner_id,contact_jid,display_name,subscription,ask,groups,approved) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(user_id).bind(item.jid).bind(item.name).bind(item.subscription).bind(item.ask)
            .bind(serde_json::to_value(item.groups)?).bind(item.approved).execute(&mut **tx).await?;
    }
    if !user.data.offline.is_empty() {
        // Share the same queue-snapshot gate as live C2S/MUC delivery. The
        // administrator's exclusive clear operation must have a precise
        // before/after boundary even while an XEP-0227 import is committing.
        sqlx::query("SELECT pg_advisory_xact_lock_shared(5645368709120102)")
            .execute(&mut **tx)
            .await?;
    }
    for message in std::mem::take(&mut user.data.offline) {
        sqlx::query("INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,target_resource,encrypted,created_at) VALUES($1,$2,$3,$4,$5,$6,COALESCE($7,clock_timestamp()))")
            .bind(Uuid::new_v4()).bind(user_id).bind(message.sender).bind(message.stanza)
            .bind(message.target_resource).bind(message.encrypted).bind(message.created_at)
            .execute(&mut **tx).await?;
    }
    for private in std::mem::take(&mut user.data.private_xml) {
        sqlx::query(
            "INSERT INTO private_xml(user_id,element_name,element_ns,xml_data) VALUES($1,$2,$3,$4)",
        )
        .bind(user_id)
        .bind(private.name)
        .bind(private.namespace)
        .bind(private.xml)
        .execute(&mut **tx)
        .await?;
    }
    if let Some(vcard) = user.data.vcard.take() {
        sqlx::query("INSERT INTO vcards(user_id,payload) VALUES($1,$2)")
            .bind(user_id)
            .bind(vcard)
            .execute(&mut **tx)
            .await?;
    }
    for blocked in std::mem::take(&mut user.data.blocked) {
        sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)")
            .bind(user_id)
            .bind(blocked)
            .execute(&mut **tx)
            .await?;
    }
    for pending in std::mem::take(&mut user.data.pending) {
        let parsed = jid::CanonicalJid::parse(&pending.from)?;
        if parsed.domainpart() == domain {
            let requester = parsed
                .localpart()
                .context("local pending subscription has no localpart")?;
            let requester_id: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM users WHERE username=$1")
                    .bind(requester)
                    .fetch_optional(&mut **tx)
                    .await?;
            if let Some(requester_id) = requester_id {
                if requester_id != user_id {
                    sqlx::query("INSERT INTO pending_presence_subscriptions(requester_id,recipient_id,stanza) VALUES($1,$2,$3) ON CONFLICT(requester_id,recipient_id) DO UPDATE SET stanza=EXCLUDED.stanza")
                        .bind(requester_id).bind(user_id).bind(pending.stanza).execute(&mut **tx).await?;
                }
            } else {
                sqlx::query("INSERT INTO federated_presence_pending(recipient_id,from_jid,stanza) VALUES($1,$2,$3) ON CONFLICT(recipient_id,from_jid) DO UPDATE SET stanza=EXCLUDED.stanza")
                    .bind(user_id).bind(pending.from).bind(pending.stanza).execute(&mut **tx).await?;
            }
        } else {
            sqlx::query("INSERT INTO federated_presence_pending(recipient_id,from_jid,stanza) VALUES($1,$2,$3) ON CONFLICT(recipient_id,from_jid) DO UPDATE SET stanza=EXCLUDED.stanza")
                .bind(user_id).bind(pending.from).bind(pending.stanza).execute(&mut **tx).await?;
        }
    }
    for (node_name, node) in std::mem::take(&mut user.data.pep_nodes) {
        sqlx::query("INSERT INTO pep_nodes(owner_id,node,access_model,max_items,persist_items,send_last_published_item,deliver_notifications,roster_groups_allowed,access_whitelist) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(user_id).bind(&node_name).bind(node.access_model).bind(node.max_items)
            .bind(node.persist_items).bind(node.send_last).bind(node.deliver_notifications)
            .bind(node.roster_groups_allowed).bind(node.access_whitelist).execute(&mut **tx).await?;
        for subscription in node.subscriptions {
            sqlx::query("INSERT INTO pep_subscriptions(owner_id,node,subscriber_jid,subid,state) VALUES($1,$2,$3,$4,$5)")
                .bind(user_id).bind(&node_name).bind(subscription.jid).bind(subscription.subid).bind(subscription.state).execute(&mut **tx).await?;
        }
        for item in node.items {
            sqlx::query("INSERT INTO pep_items(owner_id,node,item_id,payload) VALUES($1,$2,$3,$4)")
                .bind(user_id)
                .bind(&node_name)
                .bind(item.id)
                .bind(item.payload)
                .execute(&mut **tx)
                .await?;
        }
    }
    for item in std::mem::take(&mut user.data.archive) {
        sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(Uuid::new_v4()).bind(user_id).bind(item.peer_jid).bind(item.peer_full_jid)
            .bind(item.stanza).bind(item.encrypted).bind(item.result_id).bind(item.created_at).execute(&mut **tx).await?;
    }
    Ok(())
}
