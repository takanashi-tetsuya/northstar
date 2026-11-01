use anyhow::{Context, Result};
use northstar_operations_postgres::admin_commands::*;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use uuid::Uuid;

mod accounts;

pub use self::accounts::*;

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::too_many_arguments)]
pub async fn mutate_admin_accounts_authorized_with_failure_after<
    E: crate::account_lifecycle::AccountDeletionEffects,
>(
    effects: &E,
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    targets: &[AdminAccountMutationTarget],
    action: AdminAccountMutationAction,
    domain: &str,
    fail_after: usize,
) -> Result<AdminBatchAccountWriteOutcome> {
    mutate_admin_accounts_authorized_inner(
        effects,
        pool,
        fence,
        targets,
        action,
        domain,
        Some(fail_after),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn mutate_admin_accounts_authorized_inner<
    E: crate::account_lifecycle::AccountDeletionEffects,
>(
    effects: &E,
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    targets: &[AdminAccountMutationTarget],
    action: AdminAccountMutationAction,
    domain: &str,
    fail_after: Option<usize>,
) -> Result<AdminBatchAccountWriteOutcome> {
    anyhow::ensure!(!targets.is_empty(), "account mutation target list is empty");
    anyhow::ensure!(targets.len() <= 200, "too many account mutation targets");
    let domain = northstar_xmpp_types::jid::prepare_domainpart(domain)?;
    let mut target_ids = targets.iter().map(|target| target.id).collect::<Vec<_>>();
    target_ids.sort_unstable();
    target_ids.dedup();
    if target_ids.len() != targets.len() {
        return Ok(AdminBatchAccountWriteOutcome::TargetChanged);
    }
    let mut usernames = targets
        .iter()
        .map(|target| target.username.as_str())
        .collect::<Vec<_>>();
    usernames.sort_unstable();
    usernames.dedup();
    if usernames.len() != targets.len() {
        return Ok(AdminBatchAccountWriteOutcome::TargetChanged);
    }
    for target in targets {
        if let Some(full_jid) = target.exact_full_jid.as_deref() {
            let full_jid = northstar_xmpp_types::jid::CanonicalJid::parse(full_jid)?;
            anyhow::ensure!(
                full_jid.localpart() == Some(target.username.as_str())
                    && full_jid.domainpart() == domain
                    && full_jid.resourcepart().is_some(),
                "exact session JID does not match its account incarnation"
            );
        }
    }

    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *tx)
        .await?;
    // Account deletion cascades update the shared upload ledger. Preserve the
    // system-wide lock order used by self-service deletion: ledger, then
    // command session/actor authority, then the account-authority gate and
    // UUID-ordered target rows.
    if action == AdminAccountMutationAction::Delete {
        sqlx::query("SELECT northstar_upload_capacity_lock()")
            .fetch_one(&mut *tx)
            .await
            .context("upload storage capacity busy; retry administrative account deletion")?;
    }
    let claim_session: Option<Uuid> =
        sqlx::query_scalar("SELECT northstar_admin_command_authorize_claim($1,$2,$3,$4,$5,$6)")
            .bind(fence.claim_token)
            .bind(fence.actor_id)
            .bind(fence.actor_username)
            .bind(fence.actor_generation)
            .bind(fence.node)
            .bind(fence.target_digest)
            .fetch_one(&mut *tx)
            .await?;
    if claim_session.is_none() {
        tx.rollback().await?;
        return Ok(AdminBatchAccountWriteOutcome::Unauthorized);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(5645368709120101)")
        .execute(&mut *tx)
        .await?;

    let mut local_contacts: HashMap<Uuid, HashMap<String, (Uuid, String)>> = HashMap::new();
    let mut lock_ids = target_ids.clone();
    lock_ids.push(fence.actor_id);
    if action == AdminAccountMutationAction::Delete {
        for row in sqlx::query(
            "SELECT r.owner_id,r.contact_jid,u.id,u.username
               FROM roster_items r
               JOIN users u ON u.username=split_part(r.contact_jid,'@',1)
              WHERE r.owner_id=ANY($1)
                AND split_part(r.contact_jid,'@',2)=$2
                AND position('/' in r.contact_jid)=0",
        )
        .bind(&target_ids)
        .bind(&domain)
        .fetch_all(&mut *tx)
        .await?
        {
            let owner_id: Uuid = row.get("owner_id");
            let contact_id: Uuid = row.get("id");
            if contact_id != owner_id {
                lock_ids.push(contact_id);
                local_contacts
                    .entry(owner_id)
                    .or_default()
                    .insert(row.get("contact_jid"), (contact_id, row.get("username")));
            }
        }
    }
    lock_ids.sort_unstable();
    lock_ids.dedup();
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(&lock_ids)
        .fetch_all(&mut *tx)
        .await?;
    if !admin_authorized_in_tx(
        &mut tx,
        fence.actor_id,
        fence.actor_username,
        fence.actor_generation,
    )
    .await?
    {
        tx.rollback().await?;
        return Ok(AdminBatchAccountWriteOutcome::Unauthorized);
    }
    let rows = sqlx::query(
        "SELECT id,username,is_admin,is_disabled FROM users
         WHERE id=ANY($1) ORDER BY id",
    )
    .bind(&target_ids)
    .fetch_all(&mut *tx)
    .await?;
    if rows.len() != targets.len() {
        tx.rollback().await?;
        return Ok(AdminBatchAccountWriteOutcome::TargetChanged);
    }
    let target_rows = rows
        .into_iter()
        .map(|row| {
            (
                row.get::<Uuid, _>("id"),
                (
                    row.get::<String, _>("username"),
                    row.get::<bool, _>("is_admin"),
                    row.get::<bool, _>("is_disabled"),
                ),
            )
        })
        .collect::<HashMap<_, _>>();
    if targets.iter().any(|target| {
        target_rows
            .get(&target.id)
            .is_none_or(|(username, _, _)| username != &target.username)
    }) {
        tx.rollback().await?;
        return Ok(AdminBatchAccountWriteOutcome::TargetChanged);
    }
    if matches!(
        action,
        AdminAccountMutationAction::Delete | AdminAccountMutationAction::Disable
    ) && target_ids.contains(&fence.actor_id)
    {
        tx.rollback().await?;
        return Ok(AdminBatchAccountWriteOutcome::SelfMutation);
    }
    if matches!(
        action,
        AdminAccountMutationAction::Delete | AdminAccountMutationAction::Disable
    ) {
        let removes_enabled_admin = targets.iter().any(|target| {
            target_rows
                .get(&target.id)
                .is_some_and(|(_, is_admin, disabled)| *is_admin && !*disabled)
        });
        if removes_enabled_admin {
            let remaining: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM users
                 WHERE is_admin AND NOT is_disabled AND NOT (id=ANY($1))",
            )
            .bind(&target_ids)
            .fetch_one(&mut *tx)
            .await?;
            if remaining == 0 {
                tx.rollback().await?;
                return Ok(AdminBatchAccountWriteOutcome::LastAdministrator);
            }
        }
    }

    let mut ordered = targets.to_vec();
    ordered.sort_by_key(|target| target.id);
    for (index, target) in ordered.iter().enumerate() {
        let bare_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&format!(
            "{}@{}",
            target.username, domain
        ))?;
        anyhow::ensure!(
            bare_jid.localpart() == Some(target.username.as_str())
                && bare_jid.domainpart() == domain,
            "administrator target identity changed during JID preparation"
        );
        let bare_jid = bare_jid.to_string();
        match action {
            AdminAccountMutationAction::Delete => {
                let cleanup_issued: bool = sqlx::query_scalar(
                    "SELECT northstar_admin_command_issue_delete_cleanup(
                      $1,$2,$3,$4,$5,$6,$7,$8,$9)",
                )
                .bind(fence.claim_token)
                .bind(fence.actor_id)
                .bind(fence.actor_username)
                .bind(fence.actor_generation)
                .bind(fence.node)
                .bind(fence.target_digest)
                .bind(target.id)
                .bind(&target.username)
                .bind(&bare_jid)
                .fetch_one(&mut *tx)
                .await?;
                if !cleanup_issued {
                    tx.rollback().await?;
                    return Ok(AdminBatchAccountWriteOutcome::TargetChanged);
                }
                crate::account_lifecycle::delete_user_with_roster_locked_in_transaction(
                    effects,
                    &mut tx,
                    target.id,
                    &domain,
                    local_contacts.remove(&target.id).unwrap_or_default(),
                    Some((
                        fence.actor_id,
                        "admin.user.delete",
                        serde_json::json!({"source":"xep-0133","username":target.username}),
                    )),
                    Some(crate::account_lifecycle::AdminDeletionFence {
                        actor_id: fence.actor_id,
                        actor_username: fence.actor_username,
                        actor_generation: fence.actor_generation,
                        claim_token: fence.claim_token,
                        node: fence.node,
                        target_digest: fence.target_digest,
                        complete_command: index + 1 == ordered.len(),
                        result_payload: fence.result_payload,
                    }),
                )
                .await?;
            }
            AdminAccountMutationAction::Disable | AdminAccountMutationAction::Reenable => {
                let lifecycle = if action == AdminAccountMutationAction::Disable {
                    "disable"
                } else {
                    "reenable"
                };
                let outcome: String = sqlx::query_scalar(
                    "SELECT northstar_admin_command_user_lifecycle(
                      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,$11,$12)",
                )
                .bind(fence.claim_token)
                .bind(fence.actor_id)
                .bind(fence.actor_username)
                .bind(fence.actor_generation)
                .bind(fence.node)
                .bind(fence.target_digest)
                .bind(target.id)
                .bind(&target.username)
                .bind(lifecycle)
                .bind(&bare_jid)
                .bind(index + 1 == ordered.len())
                .bind(fence.result_payload)
                .fetch_one(&mut *tx)
                .await?;
                match outcome.as_str() {
                    "applied" => {}
                    "unauthorized" => {
                        tx.rollback().await?;
                        return Ok(AdminBatchAccountWriteOutcome::Unauthorized);
                    }
                    "target_changed" => {
                        tx.rollback().await?;
                        return Ok(AdminBatchAccountWriteOutcome::TargetChanged);
                    }
                    "self_mutation" => {
                        tx.rollback().await?;
                        return Ok(AdminBatchAccountWriteOutcome::SelfMutation);
                    }
                    "last_administrator" => {
                        tx.rollback().await?;
                        return Ok(AdminBatchAccountWriteOutcome::LastAdministrator);
                    }
                    other => anyhow::bail!("admin lifecycle capability returned {other:?}"),
                }
            }
            AdminAccountMutationAction::EndSessions => {
                let outcome: String = sqlx::query_scalar(
                    "SELECT northstar_admin_command_user_lifecycle(
                      $1,$2,$3,$4,$5,$6,$7,$8,'end_sessions',$9,$10,$11,$12)",
                )
                .bind(fence.claim_token)
                .bind(fence.actor_id)
                .bind(fence.actor_username)
                .bind(fence.actor_generation)
                .bind(fence.node)
                .bind(fence.target_digest)
                .bind(target.id)
                .bind(&target.username)
                .bind(&bare_jid)
                .bind(target.exact_full_jid.as_deref())
                .bind(index + 1 == ordered.len())
                .bind(fence.result_payload)
                .fetch_one(&mut *tx)
                .await?;
                if outcome != "applied" {
                    tx.rollback().await?;
                    return Ok(match outcome.as_str() {
                        "unauthorized" => AdminBatchAccountWriteOutcome::Unauthorized,
                        "target_changed" => AdminBatchAccountWriteOutcome::TargetChanged,
                        "self_mutation" => AdminBatchAccountWriteOutcome::SelfMutation,
                        "last_administrator" => AdminBatchAccountWriteOutcome::LastAdministrator,
                        other => {
                            anyhow::bail!("admin session lifecycle capability returned {other:?}")
                        }
                    });
                }
            }
        }
        if fail_after == Some(index + 1) {
            anyhow::bail!("test-only administrative batch failure");
        }
    }
    tx.commit().await?;
    Ok(AdminBatchAccountWriteOutcome::Applied(targets.to_vec()))
}

/// A generic offline-queue clear cannot revoke a delivery that is already
/// owned by a live or recoverable transport. Callers may map this typed
/// outcome to a conflict without exposing unrelated database diagnostics.
#[derive(Debug, thiserror::Error)]
#[error("offline queue contains transport-owned deliveries; end those sessions before clearing")]
pub struct OfflineMessagesTransportOwned;

pub async fn clear_offline_messages_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_id: Uuid,
    request_id: Option<Uuid>,
) -> Result<u64> {
    // Exclusive against the shared gate held by every production enqueue.
    // Rows committed before this lock are deleted; enqueue transactions that
    // start after it survive. This is one atomic queue snapshot.
    sqlx::query("SELECT pg_advisory_xact_lock(5645368709120102)")
        .execute(&mut **tx)
        .await?;
    // This destructive operator action is deliberately rejected while any
    // transport owns a row. The table lock closes the check/delete race with
    // SM/BOSH binders, both of which update the offline row before publishing
    // their fence. Account deletion has its own session-quiesce workflow; a
    // generic queue clear must not silently revoke live delivery semantics.
    sqlx::query("LOCK TABLE offline_messages IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut **tx)
        .await?;
    let occupied: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM offline_messages message
              WHERE message.delivery_claim_id IS NOT NULL
                 OR EXISTS (
                     SELECT 1 FROM sm_resume_stanzas sm
                      WHERE sm.delivery_message_id=message.id
                 )
                 OR EXISTS (
                     SELECT 1 FROM bosh_delivery_fences bosh
                      WHERE bosh.message_id=message.id
                 )
         )",
    )
    .fetch_one(&mut **tx)
    .await?;
    if occupied {
        return Err(OfflineMessagesTransportOwned.into());
    }
    let removed = sqlx::query("DELETE FROM offline_messages")
        .execute(&mut **tx)
        .await?
        .rows_affected();
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id)
         VALUES($1,'admin.offline_messages.clear',NULL,$2,$3)",
    )
    .bind(actor_id)
    .bind(serde_json::json!({"removed":removed}))
    .bind(request_id)
    .execute(&mut **tx)
    .await?;
    Ok(removed)
}
