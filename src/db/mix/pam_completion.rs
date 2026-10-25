//! Remote MIX-PAM completion, memberships, leave, recovery and result leases.

use super::*;

#[allow(clippy::too_many_arguments)]
pub async fn complete_remote_pam_success(
    pool: &PgPool,
    authenticated_domain: &str,
    channel_jid: &str,
    recipient_bare: &str,
    request_id: &str,
    response_digest: &[u8; 32],
    join: Option<RemotePamJoin<'_>>,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<RemotePamCompletionOutcome> {
    let authenticated_domain = northstar_xmpp_types::jid::prepare_domainpart(authenticated_domain)?;
    let channel_jid = northstar_xmpp_types::jid::canonicalize_bare(channel_jid)?;
    let recipient_bare = northstar_xmpp_types::jid::canonicalize_bare(recipient_bare)?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT operation_id,user_id,channel_jid,remote_domain,operation,
                request_outbox_id,
                client_request_id,requester_full_jid,state,
                remote_response_digest,response_xml
           FROM mix_pam_operations WHERE remote_request_id=$1 FOR UPDATE",
    )
    .bind(request_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Ok(RemotePamCompletionOutcome::Missing);
    };
    if row.get::<String, _>("remote_domain") != authenticated_domain
        || row.get::<String, _>("channel_jid") != channel_jid
    {
        transaction.rollback().await?;
        return Ok(RemotePamCompletionOutcome::Conflict);
    }
    let operation_state: String = row.get("state");
    if operation_state == "terminal" {
        let outcome = terminal_pam_completion(&row, response_digest);
        transaction.rollback().await?;
        return Ok(outcome);
    }
    anyhow::ensure!(
        matches!(operation_state.as_str(), "pending" | "reconciliation"),
        "invalid remote PAM operation state"
    );
    let reconciliation_response = (operation_state == "reconciliation")
        .then(|| row.get::<Option<String>, _>("response_xml"))
        .flatten();
    let user_id: Uuid = row.get("user_id");
    let operation: String = row.get("operation");
    let requester: String = row.get("requester_full_jid");
    let actor = northstar_xmpp_types::jid::canonical_bare_key(&requester)?;
    if actor != recipient_bare {
        transaction.rollback().await?;
        return Ok(RemotePamCompletionOutcome::Conflict);
    }
    let client_request_id: String = row.get("client_request_id");
    let Some(mut membership) =
        locked_pam_membership_tx(&mut transaction, user_id, &channel_jid).await?
    else {
        anyhow::bail!("remote PAM operation lost its membership authority")
    };
    let response = match (operation.as_str(), join) {
        ("join", Some(join)) if membership.state == "pending_join" => {
            anyhow::ensure!(
                valid_stable_participant_id(join.participant_id),
                "invalid remote MIX participant id"
            );
            let subscriptions = valid_join_nodes(join.subscriptions)?;
            anyhow::ensure!(
                subscriptions
                    .iter()
                    .all(|node| membership.subscriptions.contains(node))
                    && (membership.subscriptions.is_empty() || !subscriptions.is_empty()),
                "remote MIX service returned unrequested subscriptions"
            );
            let nick = join.nick.map(prepare_mix_nick).transpose()?;
            sqlx::query(
                "UPDATE mix_pam_memberships
                    SET participant_id=$2,nick=COALESCE($3,nick),state='joined',
                        request_id=NULL,client_request_id=NULL,requester_full_jid=NULL,
                        updated_at=clock_timestamp()
                  WHERE id=$1",
            )
            .bind(membership.id)
            .bind(join.participant_id)
            .bind(nick.as_deref())
            .execute(&mut *transaction)
            .await?;
            sqlx::query("DELETE FROM mix_pam_subscriptions WHERE membership_id=$1")
                .bind(membership.id)
                .execute(&mut *transaction)
                .await?;
            for node in &subscriptions {
                sqlx::query("INSERT INTO mix_pam_subscriptions(membership_id,node) VALUES($1,$2)")
                    .bind(membership.id)
                    .bind(node)
                    .execute(&mut *transaction)
                    .await?;
            }
            membership.participant_id = Some(join.participant_id.to_owned());
            membership.state = "joined".to_owned();
            membership.request_id = None;
            membership.client_request_id = None;
            membership.requester_full_jid = None;
            membership.subscriptions = subscriptions.clone();
            upsert_mix_roster_tx(&mut transaction, user_id, &channel_jid, None, true).await?;
            match reconciliation_response.as_ref() {
                Some(response) => response.clone(),
                None => payloads.pam_join_result(PamJoinResult {
                    client_request_id: &client_request_id,
                    actor_bare: &actor,
                    requester_full_jid: &requester,
                    channel_jid: &channel_jid,
                    participant_id: join.participant_id,
                    subscriptions: &subscriptions,
                    nick: nick.as_deref(),
                })?,
            }
        }
        ("leave", None) if membership.state == "pending_leave" => {
            let response = match reconciliation_response.as_ref() {
                Some(response) => response.clone(),
                None => payloads.pam_leave_result(
                    &client_request_id,
                    &actor,
                    &requester,
                    &channel_jid,
                )?,
            };
            delete_mix_roster_tx(&mut transaction, user_id, &channel_jid).await?;
            sqlx::query("DELETE FROM mix_pam_memberships WHERE id=$1")
                .bind(membership.id)
                .execute(&mut *transaction)
                .await?;
            response
        }
        _ => anyhow::bail!("remote PAM result does not match the pending operation"),
    };
    // An authenticated terminal response proves that this exact request was
    // accepted remotely. Remove any crash-recovered request row in the same
    // transaction so the ordinary S2S worker cannot retransmit it after the
    // business operation has become terminal.
    sqlx::query("DELETE FROM s2s_outbox WHERE id=$1")
        .bind(row.get::<Uuid, _>("request_outbox_id"))
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE mix_pam_operations
            SET state='terminal',remote_response_digest=$2,response_xml=$3,
                next_delivery_at=clock_timestamp(),updated_at=clock_timestamp()
          WHERE operation_id=$1 AND state IN ('pending','reconciliation')",
    )
    .bind(row.get::<Uuid, _>("operation_id"))
    .bind(response_digest.as_slice())
    .bind(&response)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(RemotePamCompletionOutcome::Applied(RemotePamCompletion {
        response_xml: response,
        membership: Some(membership),
        applied: true,
        roster_removed: Some(operation == "leave"),
    }))
}

pub(super) async fn pam_membership_from_row(
    pool: &PgPool,
    row: sqlx::postgres::PgRow,
) -> Result<PamMembership> {
    let id: Uuid = row.get("id");
    let subscriptions = sqlx::query_scalar(
        "SELECT node FROM mix_pam_subscriptions WHERE membership_id = $1 ORDER BY node",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    Ok(PamMembership {
        id,
        user_id: row.get("user_id"),
        channel_jid: row.get("channel_jid"),
        participant_id: row.get("participant_id"),
        state: row.get("state"),
        request_id: row.get("request_id"),
        client_request_id: row.get("client_request_id"),
        requester_full_jid: row.get("requester_full_jid"),
        subscriptions,
    })
}

pub async fn pam_memberships(pool: &PgPool, user_id: Uuid) -> Result<Vec<PamMembership>> {
    let rows = sqlx::query(
        "SELECT id, user_id, channel_jid, participant_id, state, request_id, client_request_id, requester_full_jid FROM mix_pam_memberships WHERE user_id = $1 ORDER BY channel_jid",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    let mut memberships = Vec::with_capacity(rows.len());
    for row in rows {
        memberships.push(pam_membership_from_row(pool, row).await?);
    }
    Ok(memberships)
}

pub async fn pam_membership(
    pool: &PgPool,
    user_id: Uuid,
    channel_jid: &str,
) -> Result<Option<PamMembership>> {
    let channel_jid = northstar_xmpp_types::jid::canonicalize_bare(channel_jid)?;
    let row = sqlx::query(
        "SELECT id, user_id, channel_jid, participant_id, state, request_id, client_request_id, requester_full_jid FROM mix_pam_memberships WHERE user_id = $1 AND channel_jid = $2",
    )
    .bind(user_id)
    .bind(channel_jid)
    .fetch_optional(pool)
    .await?;
    match row {
        Some(row) => pam_membership_from_row(pool, row).await.map(Some),
        None => Ok(None),
    }
}

pub async fn local_pam_users_for_channel(pool: &PgPool, channel_jid: &str) -> Result<Vec<Uuid>> {
    let channel_jid = northstar_xmpp_types::jid::canonicalize_bare(channel_jid)?;
    sqlx::query_scalar(
        "SELECT user_id FROM mix_pam_memberships WHERE channel_jid = $1 ORDER BY user_id",
    )
    .bind(channel_jid)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub async fn begin_remote_pam_leave(
    pool: &PgPool,
    request: BeginRemotePamLeave<'_>,
) -> Result<PamOperationReplay> {
    let actor_jid = canonical_user_bare(request.actor_jid)?;
    let channel_jid = northstar_xmpp_types::jid::canonicalize_bare(request.channel_jid)?;
    let requester_full_jid =
        northstar_xmpp_types::jid::canonical_session_key(request.requester_full_jid)?;
    let remote_domain = northstar_xmpp_types::jid::prepare_domainpart(request.remote_domain)?;
    anyhow::ensure!(
        northstar_xmpp_types::jid::canonical_bare_key(&requester_full_jid)? == actor_jid,
        "MIX-PAM requester resource does not belong to authenticated actor"
    );
    anyhow::ensure!(
        !request.request_id.is_empty() && request.request_id.len() <= 128,
        "invalid PAM request id"
    );
    anyhow::ensure!(
        !request.client_request_id.is_empty() && request.client_request_id.len() <= 1_024,
        "invalid PAM client request id"
    );
    anyhow::ensure!(
        northstar_xmpp_types::jid::CanonicalJid::parse_bare(&channel_jid)?.domainpart()
            == remote_domain,
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
    let updated = sqlx::query(
        "UPDATE mix_pam_memberships SET state = 'pending_leave', request_id = $3, client_request_id = $4, requester_full_jid = $5, updated_at = NOW() WHERE user_id = $1 AND channel_jid = $2 AND state = 'joined'",
    )
    .bind(request.user_id)
    .bind(&channel_jid)
    .bind(request.request_id)
    .bind(request.client_request_id)
    .bind(&requester_full_jid)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        == 1;
    if !updated {
        transaction.rollback().await?;
        return Ok(PamOperationReplay::Miss);
    }
    insert_pam_operation_and_outbox_tx(
        &mut transaction,
        request.user_id,
        &channel_jid,
        &remote_domain,
        "leave",
        request.request_id,
        request.client_request_id,
        &requester_full_jid,
        request.request_digest,
        request.outbound_stanza,
        None,
        None,
        &[],
        request.policy,
    )
    .await?;
    transaction.commit().await?;
    Ok(PamOperationReplay::Pending)
}

#[allow(clippy::too_many_arguments)]
pub async fn complete_remote_pam_error(
    pool: &PgPool,
    authenticated_domain: &str,
    channel_jid: &str,
    recipient_bare: &str,
    request_id: &str,
    response_digest: &[u8; 32],
    error_type: &str,
    condition: &str,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<RemotePamCompletionOutcome> {
    let authenticated_domain = northstar_xmpp_types::jid::prepare_domainpart(authenticated_domain)?;
    let channel_jid = northstar_xmpp_types::jid::canonicalize_bare(channel_jid)?;
    let recipient_bare = northstar_xmpp_types::jid::canonicalize_bare(recipient_bare)?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT operation_id,user_id,channel_jid,remote_domain,operation,
                request_outbox_id,prior_joined,prior_participant_id,
                prior_nick,prior_subscriptions,
                client_request_id,requester_full_jid,state,
                remote_response_digest,response_xml
           FROM mix_pam_operations WHERE remote_request_id=$1 FOR UPDATE",
    )
    .bind(request_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Ok(RemotePamCompletionOutcome::Missing);
    };
    if row.get::<String, _>("remote_domain") != authenticated_domain
        || row.get::<String, _>("channel_jid") != channel_jid
    {
        transaction.rollback().await?;
        return Ok(RemotePamCompletionOutcome::Conflict);
    }
    let operation_state: String = row.get("state");
    if operation_state == "terminal" {
        let outcome = terminal_pam_completion(&row, response_digest);
        transaction.rollback().await?;
        return Ok(outcome);
    }
    anyhow::ensure!(
        matches!(operation_state.as_str(), "pending" | "reconciliation"),
        "invalid remote PAM operation state"
    );
    let user_id: Uuid = row.get("user_id");
    let requester: String = row.get("requester_full_jid");
    let actor = northstar_xmpp_types::jid::canonical_bare_key(&requester)?;
    if actor != recipient_bare {
        transaction.rollback().await?;
        return Ok(RemotePamCompletionOutcome::Conflict);
    }
    let response = match row.get::<Option<String>, _>("response_xml") {
        Some(response) => response,
        None => payloads.pam_error_result(
            row.get::<String, _>("client_request_id").as_str(),
            &actor,
            &requester,
            error_type,
            condition,
        )?,
    };
    let membership = locked_pam_membership_tx(&mut transaction, user_id, &channel_jid).await?;
    let Some(mut membership) = membership else {
        anyhow::bail!("remote PAM error lost its membership authority")
    };
    match (
        row.get::<String, _>("operation").as_str(),
        membership.state.as_str(),
    ) {
        ("join", "pending_join") => {
            if row.get::<bool, _>("prior_joined") {
                let prior_participant_id: String = row.get("prior_participant_id");
                let prior_nick: Option<String> = row.get("prior_nick");
                let prior_subscriptions: Vec<String> = row.get("prior_subscriptions");
                sqlx::query(
                    "UPDATE mix_pam_memberships
                        SET participant_id=$2,nick=$3,state='joined',request_id=NULL,
                            client_request_id=NULL,requester_full_jid=NULL,
                            updated_at=clock_timestamp()
                      WHERE id=$1",
                )
                .bind(membership.id)
                .bind(&prior_participant_id)
                .bind(prior_nick.as_deref())
                .execute(&mut *transaction)
                .await?;
                sqlx::query("DELETE FROM mix_pam_subscriptions WHERE membership_id=$1")
                    .bind(membership.id)
                    .execute(&mut *transaction)
                    .await?;
                for node in &prior_subscriptions {
                    sqlx::query(
                        "INSERT INTO mix_pam_subscriptions(membership_id,node) VALUES($1,$2)",
                    )
                    .bind(membership.id)
                    .bind(node)
                    .execute(&mut *transaction)
                    .await?;
                }
                membership.participant_id = Some(prior_participant_id);
                membership.state = "joined".to_owned();
                membership.request_id = None;
                membership.client_request_id = None;
                membership.requester_full_jid = None;
                membership.subscriptions = prior_subscriptions;
            } else {
                sqlx::query("DELETE FROM mix_pam_memberships WHERE id=$1")
                    .bind(membership.id)
                    .execute(&mut *transaction)
                    .await?;
            }
        }
        ("leave", "pending_leave") => {
            sqlx::query(
                "UPDATE mix_pam_memberships
                    SET state='joined',request_id=NULL,client_request_id=NULL,
                        requester_full_jid=NULL,updated_at=clock_timestamp()
                  WHERE id=$1",
            )
            .bind(membership.id)
            .execute(&mut *transaction)
            .await?;
            membership.state = "joined".to_owned();
            membership.request_id = None;
            membership.client_request_id = None;
            membership.requester_full_jid = None;
        }
        _ => anyhow::bail!("remote PAM error does not match the pending membership"),
    }
    sqlx::query("DELETE FROM s2s_outbox WHERE id=$1")
        .bind(row.get::<Uuid, _>("request_outbox_id"))
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE mix_pam_operations
            SET state='terminal',remote_response_digest=$2,response_xml=$3,
                next_delivery_at=clock_timestamp(),updated_at=clock_timestamp()
          WHERE operation_id=$1 AND state IN ('pending','reconciliation')",
    )
    .bind(row.get::<Uuid, _>("operation_id"))
    .bind(response_digest.as_slice())
    .bind(&response)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(RemotePamCompletionOutcome::Applied(RemotePamCompletion {
        response_xml: response,
        membership: Some(membership),
        applied: true,
        roster_removed: None,
    }))
}

pub async fn reconcile_expired_remote_pam(
    pool: &PgPool,
    limit: i64,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<u64> {
    let mut transaction = pool.begin().await?;
    let rows = sqlx::query(
        "SELECT operation_id,user_id,channel_jid,client_request_id,requester_full_jid
           FROM mix_pam_operations
          WHERE state='pending' AND deadline_at<=clock_timestamp()
          ORDER BY deadline_at,operation_id LIMIT $1 FOR UPDATE SKIP LOCKED",
    )
    .bind(limit.clamp(1, 256))
    .fetch_all(&mut *transaction)
    .await?;
    for row in &rows {
        let requester: String = row.get("requester_full_jid");
        let actor = northstar_xmpp_types::jid::canonical_bare_key(&requester)?;
        let response = payloads.pam_error_result(
            row.get::<String, _>("client_request_id").as_str(),
            &actor,
            &requester,
            "wait",
            "remote-server-timeout",
        )?;
        // Reconciliation deliberately leaves the membership pending. The
        // server reports uncertainty; it never invents a remote rollback.
        sqlx::query(
            "UPDATE mix_pam_operations
                SET state='reconciliation',response_xml=$2,
                    next_delivery_at=clock_timestamp(),updated_at=clock_timestamp()
              WHERE operation_id=$1 AND state='pending'",
        )
        .bind(row.get::<Uuid, _>("operation_id"))
        .bind(response)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(u64::try_from(rows.len()).unwrap_or(u64::MAX))
}

pub async fn claim_pam_results(pool: &PgPool, limit: i64) -> Result<Vec<ClaimedPamResult>> {
    // Keep the ordered statements in separate autocommit transactions while
    // avoiding a second pool checkout between expiry cleanup and claiming.
    let mut connection = pool.acquire().await?;
    sqlx::query(
        "WITH expired AS (
             SELECT operation_id FROM mix_pam_operations
              WHERE state IN ('terminal','reconciliation') AND response_xml IS NOT NULL
                AND delivered_at IS NULL AND dead_lettered_at IS NULL
                AND expires_at<=clock_timestamp()
                AND (lease_until IS NULL OR lease_until<=clock_timestamp())
              ORDER BY expires_at,operation_id
              LIMIT 256 FOR UPDATE SKIP LOCKED
         )
         UPDATE mix_pam_operations operation
            SET dead_lettered_at=clock_timestamp(),last_error='result retention expired',
                lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp()
           FROM expired WHERE operation.operation_id=expired.operation_id",
    )
    .execute(&mut *connection)
    .await?;
    let rows = sqlx::query(
        "WITH candidates AS (
             SELECT operation_id FROM mix_pam_operations
              WHERE state IN ('terminal','reconciliation')
                AND response_xml IS NOT NULL
                AND delivered_at IS NULL AND dead_lettered_at IS NULL
                AND (state='reconciliation' OR expires_at>clock_timestamp())
                AND next_delivery_at<=clock_timestamp()
                AND (lease_until IS NULL OR lease_until<=clock_timestamp())
                AND NOT EXISTS(
                    SELECT 1 FROM mix_pam_operations earlier
                     WHERE earlier.requester_full_jid=mix_pam_operations.requester_full_jid
                       AND earlier.response_xml IS NOT NULL
                       AND earlier.delivered_at IS NULL
                       AND earlier.dead_lettered_at IS NULL
                       AND (earlier.created_at,earlier.operation_id)
                           < (mix_pam_operations.created_at,mix_pam_operations.operation_id)
                )
              ORDER BY next_delivery_at,created_at,operation_id
              LIMIT $1 FOR UPDATE SKIP LOCKED
         ), claimed AS (
             UPDATE mix_pam_operations operation
                SET lease_token=gen_random_uuid(),
                    lease_until=clock_timestamp()+make_interval(secs=>$2)
               FROM candidates
              WHERE operation.operation_id=candidates.operation_id
             RETURNING operation.*
         )
         SELECT operation_id,user_id,requester_full_jid,response_xml,
                delivery_attempt_count,lease_token FROM claimed
          ORDER BY next_delivery_at,created_at,operation_id",
    )
    .bind(limit.clamp(1, 64))
    .bind(MIX_PAM_RESULT_LEASE_SECONDS)
    .fetch_all(&mut *connection)
    .await?;
    drop(connection);
    Ok(rows
        .into_iter()
        .map(|row| ClaimedPamResult {
            operation_id: row.get("operation_id"),
            user_id: row.get("user_id"),
            requester_full_jid: row.get("requester_full_jid"),
            response_xml: row.get("response_xml"),
            attempt_count: row.get("delivery_attempt_count"),
            lease_token: row.get("lease_token"),
        })
        .collect())
}

pub async fn renew_pam_result_lease(
    pool: &PgPool,
    operation_id: Uuid,
    lease_token: Uuid,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE mix_pam_operations
            SET lease_until=clock_timestamp()+make_interval(secs=>$3),updated_at=clock_timestamp()
          WHERE operation_id=$1 AND lease_token=$2 AND lease_until>clock_timestamp()
            AND delivered_at IS NULL AND dead_lettered_at IS NULL",
    )
    .bind(operation_id)
    .bind(lease_token)
    .bind(MIX_PAM_RESULT_LEASE_SECONDS)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn acknowledge_pam_result(
    pool: &PgPool,
    operation_id: Uuid,
    lease_token: Uuid,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE mix_pam_operations
            SET delivered_at=clock_timestamp(),lease_token=NULL,lease_until=NULL,
                updated_at=clock_timestamp()
          WHERE operation_id=$1 AND lease_token=$2 AND delivered_at IS NULL
            AND dead_lettered_at IS NULL",
    )
    .bind(operation_id)
    .bind(lease_token)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn defer_pam_result(
    pool: &PgPool,
    operation_id: Uuid,
    lease_token: Uuid,
    delay_seconds: i64,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE mix_pam_operations
            SET next_delivery_at=clock_timestamp()+make_interval(secs=>$3),
                lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp()
          WHERE operation_id=$1 AND lease_token=$2 AND delivered_at IS NULL
            AND dead_lettered_at IS NULL",
    )
    .bind(operation_id)
    .bind(lease_token)
    .bind(delay_seconds.clamp(1, 300))
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn retry_pam_result(
    pool: &PgPool,
    operation_id: Uuid,
    lease_token: Uuid,
    attempt_count: i32,
    error: &str,
) -> Result<bool> {
    let next = attempt_count.saturating_add(1);
    if next >= MIX_PAM_RESULT_MAX_ATTEMPTS {
        return Ok(sqlx::query(
            "UPDATE mix_pam_operations
                SET delivery_attempt_count=$3,dead_lettered_at=clock_timestamp(),
                    lease_token=NULL,lease_until=NULL,last_error=left($4,2048),
                    updated_at=clock_timestamp()
              WHERE operation_id=$1 AND lease_token=$2 AND delivered_at IS NULL
                AND dead_lettered_at IS NULL",
        )
        .bind(operation_id)
        .bind(lease_token)
        .bind(next)
        .bind(error)
        .execute(pool)
        .await?
        .rows_affected()
            == 1);
    }
    let delay = 1_i64 << u32::try_from(next.clamp(0, 8)).unwrap_or(8);
    Ok(sqlx::query(
        "UPDATE mix_pam_operations
            SET delivery_attempt_count=$3,
                next_delivery_at=clock_timestamp()+make_interval(secs=>$4),
                lease_token=NULL,lease_until=NULL,last_error=left($5,2048),
                updated_at=clock_timestamp()
          WHERE operation_id=$1 AND lease_token=$2 AND delivered_at IS NULL
            AND dead_lettered_at IS NULL",
    )
    .bind(operation_id)
    .bind(lease_token)
    .bind(next)
    .bind(delay)
    .bind(error)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn prune_expired_pam_results(pool: &PgPool, limit: i64) -> Result<u64> {
    // A reconciliation row is still the only correlation authority for a
    // late authenticated remote result. It may stop automatic client
    // delivery at its retention deadline, but must not be deleted merely
    // because its timeout response was delivered or dead-lettered.
    let mut transaction = pool.begin().await?;
    // The owner-held capability takes the singleton before selecting/deleting
    // any operation. The service gate is held before PgPool checkout, so one
    // process contributes at most one database waiter.
    let removed: i64 = sqlx::query_scalar("SELECT northstar_mix_pam_operation_prune($1)")
        .bind(limit.clamp(1, 2_048))
        .fetch_one(&mut *transaction)
        .await?;
    transaction.commit().await?;
    u64::try_from(removed).context("negative MIX-PAM prune count")
}
