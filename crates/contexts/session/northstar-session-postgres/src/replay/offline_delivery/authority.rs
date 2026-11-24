use super::*;
use northstar_delivery_core::{recipient_delivery_identity, RecipientDeliveryIdentity};
use northstar_session_application::replay::{ReplayPreparation, ReplayRoute};

pub(super) async fn lock_account(
    transaction: &mut Transaction<'_, Postgres>,
    recipient_id: Uuid,
    auth_generation: i64,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_lock_auth_generation($1,$2)")
            .bind(recipient_id)
            .bind(auth_generation)
            .fetch_one(&mut **transaction)
            .await?,
    )
}

/// Read the effective policy inputs without locks or lease refreshes. Roster
/// writes bump the account's durable version; blocks, lists and selections
/// have no common revision, so compare their ordered facts instead.
pub(super) async fn policy_version(
    transaction: &mut Transaction<'_, Postgres>,
    route: &ReplayRoute,
    selected: Option<&str>,
) -> Result<Option<ReplayPolicyVersion>> {
    let version: Option<String> = sqlx::query_scalar(
        "SELECT jsonb_build_array(
             account.roster_version,
             (SELECT jsonb_agg(blocked_jid ORDER BY blocked_jid)
                FROM blocked_jids WHERE owner_id=account.id),
             (SELECT jsonb_agg(jsonb_build_array(name,updated_at) ORDER BY name)
                FROM privacy_lists WHERE owner_id=account.id),
             (SELECT jsonb_agg(to_jsonb(item) ORDER BY list_name,item_order)
                FROM privacy_list_items item WHERE owner_id=account.id),
             (SELECT list_name FROM privacy_default_lists WHERE owner_id=account.id),
             active.list_name
         )::TEXT
           FROM users account
           LEFT JOIN privacy_active_sessions active
             ON active.owner_id=account.id AND active.connection_id=$2
          WHERE account.id=$1 AND NOT account.is_disabled AND account.auth_generation=$4
            AND active.list_name IS NOT DISTINCT FROM $3::TEXT
            AND (active.list_name IS NULL OR active.expires_at>clock_timestamp())",
    )
    .bind(route.recipient_id)
    .bind(route.connection_id)
    .bind(selected)
    .bind(route.auth_generation)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(version.map(ReplayPolicyVersion))
}

const MAM_PROOF_SQL: &str = "SELECT message.id,archive.id
       FROM unnest($2::UUID[],$3::BOOLEAN[]) AS candidate(message_id,wire_proven)
       JOIN offline_messages message ON message.id=candidate.message_id
       LEFT JOIN personal_message_admissions admission ON admission.offline_message_id=message.id
       JOIN message_archive archive ON archive.owner_id=message.recipient_id
        AND ((candidate.wire_proven AND archive.id=message.id)
             OR archive.id=admission.recipient_archive_id)
      WHERE message.recipient_id=$1 AND message.mam_backed
        AND ($4::UUID IS NULL OR archive.id=$4)
        AND NOT EXISTS (SELECT 1 FROM personal_retraction_action_projections action
                         WHERE action.archive_id=archive.id)
        AND NOT EXISTS (
            SELECT 1 FROM blocked_jids block WHERE block.owner_id=archive.owner_id
              AND block.blocked_jid IN (archive.peer_full_jid,archive.peer_jid,
                  CASE WHEN position('@' in archive.peer_jid)>0
                       THEN split_part(archive.peer_jid,'@',2) ELSE archive.peer_jid END)
        )
      ORDER BY archive.id";

pub(super) async fn mam_proofs(
    transaction: &mut Transaction<'_, Postgres>,
    recipient_id: Uuid,
    owner_bare_jid: &str,
    candidates: &[ClaimedOfflineCandidate],
    lock_projection: bool,
) -> Result<HashMap<Uuid, Uuid>> {
    let (messages, wire_projections): (Vec<_>, Vec<_>) = candidates
        .iter()
        .filter(|row| row.mam_backed)
        .map(|row| {
            (
                row.message.id,
                wire_matches_projection(&row.message.stanza, owner_bare_jid, row.message.id),
            )
        })
        .unzip();
    if messages.is_empty() {
        return Ok(HashMap::new());
    }
    Ok(read_mam_proofs(
        transaction,
        recipient_id,
        &messages,
        &wire_projections,
        None,
        lock_projection,
    )
    .await?
    .into_iter()
    .collect())
}

fn wire_matches_projection(stanza: &str, owner: &str, id: Uuid) -> bool {
    recipient_delivery_identity(stanza, owner) == RecipientDeliveryIdentity::Exact(id)
}

async fn read_mam_proofs(
    transaction: &mut Transaction<'_, Postgres>,
    recipient_id: Uuid,
    messages: &[Uuid],
    wire_projections: &[bool],
    exact_archive: Option<Uuid>,
    lock_projection: bool,
) -> Result<Vec<(Uuid, Uuid)>> {
    let sql = if lock_projection {
        format!("{MAM_PROOF_SQL} FOR SHARE OF archive SKIP LOCKED")
    } else {
        MAM_PROOF_SQL.to_owned()
    };
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(recipient_id)
        .bind(messages)
        .bind(wire_projections)
        .bind(exact_archive)
        .fetch_all(&mut **transaction)
        .await?)
}

pub(super) async fn delete_exact_claims(
    transaction: &mut Transaction<'_, Postgres>,
    recipient_id: Uuid,
    claim_token: Uuid,
    message_ids: &[Uuid],
) -> Result<()> {
    let removed = sqlx::query(
        "DELETE FROM offline_messages
          WHERE recipient_id=$1 AND delivery_claim_id=$2 AND id=ANY($3::UUID[])",
    )
    .bind(recipient_id)
    .bind(claim_token)
    .bind(message_ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        removed == message_ids.len() as u64,
        "offline suppression lost its exact page claim"
    );
    Ok(())
}

pub(crate) async fn prepare_current_message(
    pool: &PgPool,
    session: &ReplaySession,
    message: ReplayMessageAuthority<'_>,
) -> Result<ReplayPreparation> {
    let route = session.route();
    let current = message.route.is_current;
    if !current() {
        return Ok(ReplayPreparation::RetryPage);
    }
    let mut transaction = pool.begin().await?;
    let authorized: Option<bool> = sqlx::query_scalar(
        "SELECT TRUE FROM northstar_lock_user_rows_update(ARRAY[$1::uuid]) locked
          WHERE locked.auth_generation=$2 AND NOT locked.is_disabled",
    )
    .bind(route.recipient_id)
    .bind(route.auth_generation)
    .fetch_optional(&mut *transaction)
    .await?;
    if authorized.is_none() {
        transaction.rollback().await?;
        return Ok(ReplayPreparation::StaleRoute);
    }
    if !current() {
        transaction.rollback().await?;
        return Ok(ReplayPreparation::RetryPage);
    }
    if let Some(selected) = message.route.active_privacy_list {
        let selection: Option<bool> = sqlx::query_scalar(
            "SELECT TRUE FROM privacy_active_sessions
              WHERE owner_id=$1 AND connection_id=$2 AND list_name=$3
                AND expires_at>clock_timestamp()
              FOR SHARE",
        )
        .bind(route.recipient_id)
        .bind(route.connection_id)
        .bind(selected)
        .fetch_optional(&mut *transaction)
        .await?;
        if selection.is_none() {
            transaction.rollback().await?;
            return Ok(ReplayPreparation::RetryPage);
        }
    }
    let exact: Option<String> = sqlx::query_scalar(
        "SELECT stanza FROM offline_messages
          WHERE recipient_id=$1 AND delivery_claim_id=$2 AND id=$3
            AND delivery_claim_expires_at>clock_timestamp()
          FOR UPDATE",
    )
    .bind(route.recipient_id)
    .bind(message.claim_token)
    .bind(message.message_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let stanza = exact.context("offline replay lost its renewed message claim")?;
    let version =
        policy_version(&mut transaction, route, message.route.active_privacy_list).await?;
    if !current() || version.as_ref() != Some(message.policy_version) {
        transaction.rollback().await?;
        return Ok(ReplayPreparation::RetryPage);
    }
    let suppress = match message.disposition {
        ReplayDisposition::Deliver => false,
        ReplayDisposition::Denied => true,
        ReplayDisposition::MamProjection(archive_id) => {
            let wire_proven = archive_id == message.message_id
                && wire_matches_projection(&stanza, session.owner_bare_jid(), archive_id);
            !read_mam_proofs(
                &mut transaction,
                route.recipient_id,
                &[message.message_id],
                &[wire_proven],
                Some(archive_id),
                true,
            )
            .await?
            .is_empty()
        }
    };
    if !current() {
        transaction.rollback().await?;
        return Ok(ReplayPreparation::RetryPage);
    }
    if !suppress {
        return Ok(ReplayPreparation::Ready(
            northstar_session_application::replay::RecoveryReplayAuthorizationGuard::new(
                RecoveryReplayAuthorizationGuard { transaction },
            ),
        ));
    }
    delete_exact_claims(
        &mut transaction,
        route.recipient_id,
        message.claim_token,
        &[message.message_id],
    )
    .await?;
    let version =
        policy_version(&mut transaction, route, message.route.active_privacy_list).await?;
    if !current() || version.as_ref() != Some(message.policy_version) {
        transaction.rollback().await?;
        return Ok(ReplayPreparation::RetryPage);
    }
    transaction.commit().await?;
    Ok(ReplayPreparation::Suppressed)
}

#[cfg(test)]
mod tests;
