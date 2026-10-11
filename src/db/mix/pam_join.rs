//! Remote MIX-PAM operations: admission, replay and remote join.

use super::*;

pub struct BeginRemotePamJoin<'a> {
    pub user_id: Uuid,
    pub actor_jid: &'a str,
    pub channel_jid: &'a str,
    pub nick: Option<&'a str>,
    pub nodes: &'a [String],
    pub request_id: &'a str,
    pub client_request_id: &'a str,
    pub requester_full_jid: &'a str,
    pub request_digest: &'a [u8; 32],
    pub remote_domain: &'a str,
    pub outbound_stanza: &'a str,
    pub policy: super::super::S2sOutboxPolicy,
}

pub struct BeginRemotePamLeave<'a> {
    pub user_id: Uuid,
    pub actor_jid: &'a str,
    pub channel_jid: &'a str,
    pub request_id: &'a str,
    pub client_request_id: &'a str,
    pub requester_full_jid: &'a str,
    pub request_digest: &'a [u8; 32],
    pub remote_domain: &'a str,
    pub outbound_stanza: &'a str,
    pub policy: super::super::S2sOutboxPolicy,
}

#[derive(Clone, Copy)]
pub struct RemotePamJoin<'a> {
    pub participant_id: &'a str,
    pub subscriptions: &'a [String],
    pub nick: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub enum RemotePamCompletionOutcome {
    Applied(RemotePamCompletion),
    Replay(RemotePamCompletion),
    Conflict,
    Missing,
}

pub(super) const MIX_PAM_RESULT_LEASE_SECONDS: i64 = 90;
pub(super) const MIX_PAM_RESULT_MAX_ATTEMPTS: i32 = 20;

pub(super) struct MixPamCapacityReconciliationCommitted(pub(super) ());

pub(super) async fn reconcile_mix_pam_capacity_committed(
    pool: &PgPool,
) -> Result<MixPamCapacityReconciliationCommitted> {
    let mut transaction = pool.begin().await?;
    // The owner-held capability takes the global counter as its first lock and
    // reclaims the complete hard-bounded eligible set. Commit before opening
    // the producer transaction so a later capacity rejection cannot roll the
    // same cleanup back and depend on worker cadence for forward progress.
    let _: i64 = sqlx::query_scalar("SELECT northstar_mix_pam_capacity_reconcile()")
        .fetch_one(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(MixPamCapacityReconciliationCommitted(()))
}

pub(super) fn pam_operation_replay(
    row: &sqlx::postgres::PgRow,
    digest: &[u8; 32],
) -> PamOperationReplay {
    if row.get::<Vec<u8>, _>("request_digest").as_slice() != digest {
        PamOperationReplay::Conflict
    } else if let Some(response) = row.get::<Option<String>, _>("response_xml") {
        PamOperationReplay::Replay(response)
    } else {
        PamOperationReplay::Pending
    }
}

pub async fn lookup_remote_pam_operation(
    pool: &PgPool,
    user_id: Uuid,
    requester_full_jid: &str,
    client_request_id: &str,
    request_digest: &[u8; 32],
) -> Result<PamOperationReplay> {
    let requester = crate::jid::canonical_session_key(requester_full_jid)?;
    anyhow::ensure!(
        !client_request_id.is_empty() && client_request_id.len() <= 1_024,
        "invalid PAM client request id"
    );
    let row = sqlx::query(
        "SELECT request_digest,response_xml FROM mix_pam_operations
          WHERE user_id=$1 AND requester_full_jid=$2 AND client_request_id=$3",
    )
    .bind(user_id)
    .bind(requester)
    .bind(client_request_id)
    .fetch_optional(pool)
    .await?;
    Ok(row
        .as_ref()
        .map(|row| pam_operation_replay(row, request_digest))
        .unwrap_or(PamOperationReplay::Miss))
}

pub(super) async fn lock_pam_admission_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    channel_jid: &str,
    requester_full_jid: &str,
    client_request_id: &str,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("pam-membership:{user_id}:{channel_jid}"))
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!(
            "pam-client:{user_id}:{requester_full_jid}:{client_request_id}"
        ))
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

/// Lock the authenticated account against deletion, disable or rename, then
/// acquire the durable global PAM capacity authority before any membership,
/// client-id or operation lock. The service's clone-shared FIFO gate is held
/// before this function may check out its transaction, so each process
/// contributes at most one database waiter. Database triggers subsequently
/// lock global -> exact user counter.
pub(super) async fn remote_pam_account_matches_actor_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    actor_jid: &str,
) -> Result<bool> {
    let actor_username = crate::jid::CanonicalJid::parse_bare(actor_jid)?
        .localpart()
        .context("MIX-PAM actor requires a localpart")?
        .to_owned();
    sqlx::query_scalar("SELECT northstar_mix_pam_account_capacity_lock($1,$2)")
        .bind(user_id)
        .bind(actor_username)
        .fetch_one(&mut **transaction)
        .await
        .map_err(Into::into)
}

pub(super) fn validate_pam_outbound(
    outbound: &str,
    request_id: &str,
    actor: &str,
    channel: &str,
) -> Result<()> {
    anyhow::ensure!(
        !outbound.is_empty() && outbound.len() <= super::super::MAX_S2S_STANZA_BYTES,
        "invalid remote PAM stanza size"
    );
    let document = roxmltree::Document::parse(outbound).context("invalid remote PAM stanza")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "iq"
            && root.attribute("type") == Some("set")
            && root.attribute("id") == Some(request_id)
            && root.attribute("from") == Some(actor)
            && root.attribute("to") == Some(channel),
        "remote PAM stanza does not match its durable operation"
    );
    Ok(())
}

pub(super) async fn existing_pam_operation_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    requester_full_jid: &str,
    client_request_id: &str,
    request_digest: &[u8; 32],
) -> Result<Option<PamOperationReplay>> {
    let row = sqlx::query(
        "SELECT request_digest,response_xml FROM mix_pam_operations
          WHERE user_id=$1 AND requester_full_jid=$2 AND client_request_id=$3
          FOR SHARE",
    )
    .bind(user_id)
    .bind(requester_full_jid)
    .bind(client_request_id)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row
        .as_ref()
        .map(|row| pam_operation_replay(row, request_digest)))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_pam_operation_and_outbox_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    channel_jid: &str,
    remote_domain: &str,
    operation: &str,
    remote_request_id: &str,
    client_request_id: &str,
    requester_full_jid: &str,
    request_digest: &[u8; 32],
    outbound_stanza: &str,
    prior_participant_id: Option<&str>,
    prior_nick: Option<&str>,
    prior_subscriptions: &[String],
    policy: super::super::S2sOutboxPolicy,
) -> Result<()> {
    let expected_username = crate::jid::CanonicalJid::parse(requester_full_jid)?
        .localpart()
        .context("MIX-PAM requester requires a localpart")?
        .to_owned();
    let operation_id = Uuid::new_v4();
    let request_outbox_id = Uuid::new_v4();
    super::super::enqueue_s2s_outbox_with_id_in_transaction(
        transaction,
        request_outbox_id,
        remote_domain,
        outbound_stanza,
        None,
        policy,
    )
    .await?;
    let deadline_seconds = i64::try_from(policy.ttl_seconds.clamp(30, 86_400))
        .context("remote PAM timeout is too large")?;
    sqlx::query(
        "SELECT northstar_mix_pam_operation_insert(
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
         )",
    )
    .bind(operation_id)
    .bind(user_id)
    .bind(channel_jid)
    .bind(remote_domain)
    .bind(operation)
    .bind(remote_request_id)
    .bind(client_request_id)
    .bind(requester_full_jid)
    .bind(request_digest.as_slice())
    .bind(request_outbox_id)
    .bind(prior_participant_id.is_some())
    .bind(prior_participant_id)
    .bind(prior_nick)
    .bind(prior_subscriptions)
    .bind(deadline_seconds)
    .bind(expected_username)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub async fn begin_remote_pam_join(
    pool: &PgPool,
    request: BeginRemotePamJoin<'_>,
) -> Result<PamOperationReplay> {
    let actor_jid = canonical_user_bare(request.actor_jid)?;
    let channel_jid = crate::jid::canonicalize_bare(request.channel_jid)?;
    let nodes = valid_join_nodes(request.nodes)?;
    let nick = request.nick.map(prepare_mix_nick).transpose()?;
    anyhow::ensure!(
        !request.request_id.is_empty() && request.request_id.len() <= 128,
        "invalid PAM request id"
    );
    anyhow::ensure!(
        !request.client_request_id.is_empty() && request.client_request_id.len() <= 1_024,
        "invalid PAM client request id"
    );
    let requester_full_jid = crate::jid::canonical_session_key(request.requester_full_jid)?;
    let remote_domain = crate::jid::prepare_domainpart(request.remote_domain)?;
    anyhow::ensure!(
        crate::jid::canonical_bare_key(&requester_full_jid)? == actor_jid,
        "MIX-PAM requester resource does not belong to authenticated actor"
    );
    anyhow::ensure!(
        crate::jid::CanonicalJid::parse_bare(&channel_jid)?.domainpart() == remote_domain,
        "MIX-PAM remote domain does not own the channel"
    );
    validate_pam_outbound(
        request.outbound_stanza,
        request.request_id,
        &actor_jid,
        &channel_jid,
    )?;
    let _reconciled = reconcile_mix_pam_capacity_committed(pool).await?;
    let mut transaction = pool.begin().await?;
    anyhow::ensure!(
        remote_pam_account_matches_actor_tx(&mut transaction, request.user_id, &actor_jid).await?,
        "MIX-PAM account UUID does not belong to authenticated actor"
    );
    lock_pam_admission_tx(
        &mut transaction,
        request.user_id,
        &channel_jid,
        &requester_full_jid,
        request.client_request_id,
    )
    .await?;
    if let Some(replay) = existing_pam_operation_tx(
        &mut transaction,
        request.user_id,
        &requester_full_jid,
        request.client_request_id,
        request.request_digest,
    )
    .await?
    {
        transaction.rollback().await?;
        return Ok(replay);
    }
    let previous =
        locked_pam_membership_tx(&mut transaction, request.user_id, &channel_jid).await?;
    if previous
        .as_ref()
        .is_some_and(|membership| membership.state != "joined")
    {
        transaction.rollback().await?;
        // This request has no operation/result journal of its own. Returning
        // `Pending` would make the protocol wait for a result that can only be
        // correlated to the older IQ. Report a miss so the caller emits its
        // bounded resource-constraint response instead.
        return Ok(PamOperationReplay::Miss);
    }
    let prior_participant_id = previous
        .as_ref()
        .and_then(|membership| membership.participant_id.clone());
    anyhow::ensure!(
        previous.is_none() || prior_participant_id.is_some(),
        "joined PAM membership has no stable participant id"
    );
    let prior_nick: Option<String> = if let Some(previous) = previous.as_ref() {
        sqlx::query_scalar("SELECT nick FROM mix_pam_memberships WHERE id=$1")
            .bind(previous.id)
            .fetch_one(&mut *transaction)
            .await?
    } else {
        None
    };
    let prior_subscriptions = previous
        .as_ref()
        .map(|membership| membership.subscriptions.clone())
        .unwrap_or_default();
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mix_pam_memberships (id, user_id, channel_jid, nick, state, request_id, client_request_id, requester_full_jid) VALUES ($1, $2, $3, $4, 'pending_join', $5, $6, $7) ON CONFLICT (user_id, channel_jid) DO UPDATE SET nick = EXCLUDED.nick, state = 'pending_join', request_id = EXCLUDED.request_id, client_request_id = EXCLUDED.client_request_id, requester_full_jid = EXCLUDED.requester_full_jid, updated_at = NOW()",
    )
    .bind(id)
    .bind(request.user_id)
    .bind(&channel_jid)
    .bind(nick.as_deref())
    .bind(request.request_id)
    .bind(request.client_request_id)
    .bind(&requester_full_jid)
    .execute(&mut *transaction)
    .await?;
    let membership_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM mix_pam_memberships WHERE user_id = $1 AND channel_jid = $2",
    )
    .bind(request.user_id)
    .bind(&channel_jid)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM mix_pam_subscriptions WHERE membership_id = $1")
        .bind(membership_id)
        .execute(&mut *transaction)
        .await?;
    for node in nodes {
        sqlx::query("INSERT INTO mix_pam_subscriptions (membership_id, node) VALUES ($1, $2)")
            .bind(membership_id)
            .bind(node)
            .execute(&mut *transaction)
            .await?;
    }
    insert_pam_operation_and_outbox_tx(
        &mut transaction,
        request.user_id,
        &channel_jid,
        &remote_domain,
        "join",
        request.request_id,
        request.client_request_id,
        &requester_full_jid,
        request.request_digest,
        request.outbound_stanza,
        prior_participant_id.as_deref(),
        prior_nick.as_deref(),
        &prior_subscriptions,
        request.policy,
    )
    .await?;
    transaction.commit().await?;
    Ok(PamOperationReplay::Pending)
}

/// Durable PAM correlation and its S2S outbox survive restart. Startup must
/// never guess that an unanswered remote mutation failed and roll back only
/// the local half.
pub async fn recover_remote_pam_after_restart(pool: &PgPool) -> Result<()> {
    let _ = prune_expired_pam_results(pool, 512).await?;
    Ok(())
}

pub(super) async fn locked_pam_membership_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    channel_jid: &str,
) -> Result<Option<PamMembership>> {
    let row = sqlx::query(
        "SELECT id,user_id,channel_jid,participant_id,state,request_id,
                client_request_id,requester_full_jid
           FROM mix_pam_memberships
          WHERE user_id=$1 AND channel_jid=$2 FOR UPDATE",
    )
    .bind(user_id)
    .bind(channel_jid)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let id: Uuid = row.get("id");
    let subscriptions = sqlx::query_scalar(
        "SELECT node FROM mix_pam_subscriptions WHERE membership_id=$1 ORDER BY node",
    )
    .bind(id)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(Some(PamMembership {
        id,
        user_id: row.get("user_id"),
        channel_jid: row.get("channel_jid"),
        participant_id: row.get("participant_id"),
        state: row.get("state"),
        request_id: row.get("request_id"),
        client_request_id: row.get("client_request_id"),
        requester_full_jid: row.get("requester_full_jid"),
        subscriptions,
    }))
}

pub(super) fn terminal_pam_completion(
    row: &sqlx::postgres::PgRow,
    response_digest: &[u8; 32],
) -> RemotePamCompletionOutcome {
    let exact = row
        .get::<Option<Vec<u8>>, _>("remote_response_digest")
        .is_some_and(|digest| digest.as_slice() == response_digest);
    if !exact {
        return RemotePamCompletionOutcome::Conflict;
    }
    RemotePamCompletionOutcome::Replay(RemotePamCompletion {
        response_xml: row
            .get::<Option<String>, _>("response_xml")
            .expect("terminal PAM row has a response"),
        membership: None,
        applied: false,
        roster_removed: None,
    })
}
