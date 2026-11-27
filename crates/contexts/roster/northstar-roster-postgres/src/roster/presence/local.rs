use super::*;

/// Client-authorized local transition. Account lookup, credential-generation
/// validation, deterministic two-account locking and both roster mutations
/// share one transaction. Captured target evidence is checked, not trusted.
#[allow(clippy::too_many_arguments)]
pub async fn transition_local_presence_subscription_authorized<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    actor_domain: &str,
    target_username: &str,
    kind: &str,
    stamped_stanza: &str,
    expected_target: &PresenceAccount,
) -> Result<AuthorizedLocalPresenceTransition> {
    transition_local_presence_subscription_authorized_with_hook(
        effects,
        pool,
        actor_id,
        expected_auth_generation,
        connection_id,
        actor_domain,
        target_username,
        kind,
        stamped_stanza,
        Some(expected_target),
        || async {},
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn transition_local_presence_subscription_authorized_with_hook<
    E: RosterTransactionEffects,
    F,
    Fut,
>(
    effects: &E,
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    actor_domain: &str,
    target_username: &str,
    kind: &str,
    stamped_stanza: &str,
    expected_target: Option<&PresenceAccount>,
    after_target_resolution: F,
) -> Result<AuthorizedLocalPresenceTransition>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if SubscriptionAction::parse(kind).is_none() {
        return Ok(AuthorizedLocalPresenceTransition::Missing);
    }
    let actor_domain = northstar_xmpp_types::jid::prepare_domainpart(actor_domain)?;
    let target_username = northstar_roster_application::normalize_username(target_username)?;
    let mut transaction = pool.begin().await?;

    // Lock both UUIDs in one deterministic statement. When the caller
    // captured target evidence, do not resolve the name a second time.
    let target_id = match expected_target {
        Some(target) => Some(target.id),
        None => {
            sqlx::query_scalar("SELECT id FROM users WHERE username=$1")
                .bind(&target_username)
                .fetch_optional(&mut *transaction)
                .await?
        }
    };
    let Some(target_id) = target_id else {
        transaction.rollback().await?;
        return Ok(AuthorizedLocalPresenceTransition::Missing);
    };
    // Production uses a no-op. The deterministic test hook proves that an
    // account deleted and recreated after resolution cannot inherit the
    // in-flight mutation intended for the previous UUID.
    after_target_resolution().await;
    let mut lock_ids = vec![actor_id];
    if target_id != actor_id {
        lock_ids.push(target_id);
        lock_ids.sort_unstable();
    }
    // The runtime role has no UPDATE on users; the reviewed row-lock
    // capability locks both accounts in id order and returns the locked rows.
    let locked = sqlx::query(
        "SELECT id,username,auth_generation,is_disabled
           FROM northstar_lock_user_rows_update($1)",
    )
    .bind(&lock_ids)
    .fetch_all(&mut *transaction)
    .await?;
    let actor = locked.iter().find_map(|row| {
        (row.get::<Uuid, _>("id") == actor_id).then(|| PresenceAccount {
            id: actor_id,
            username: row.get("username"),
            auth_generation: row.get("auth_generation"),
        })
    });
    let actor_authorized = locked.iter().any(|row| {
        row.get::<Uuid, _>("id") == actor_id
            && row.get::<i64, _>("auth_generation") == expected_auth_generation
            && !row.get::<bool, _>("is_disabled")
    });
    if !actor_authorized {
        transaction.rollback().await?;
        return Ok(AuthorizedLocalPresenceTransition::Unauthorized);
    }
    let actor = actor.expect("authorized actor row was locked");
    let target = locked.iter().find_map(|row| {
        (row.get::<Uuid, _>("id") == target_id
            && row.get::<String, _>("username") == target_username
            && expected_target.is_none_or(|expected| {
                row.get::<i64, _>("auth_generation") == expected.auth_generation
            })
            && !row.get::<bool, _>("is_disabled"))
        .then(|| PresenceAccount {
            id: target_id,
            username: target_username.clone(),
            auth_generation: row.get("auth_generation"),
        })
    });
    let Some(target) = target else {
        transaction.rollback().await?;
        return Ok(AuthorizedLocalPresenceTransition::Missing);
    };
    let actor_jid = format!("{}@{actor_domain}", actor.username);
    let target_jid = format!("{}@{actor_domain}", target.username);
    // Match ProfileService's roster-row -> seed-0 block-policy order. This
    // prevents both an authorization race with XEP-0191 and a lock inversion
    // with profile audience snapshots.
    sqlx::query(
        "SELECT owner_id FROM roster_items
          WHERE (owner_id=$1 AND contact_jid=$2)
             OR (owner_id=$3 AND contact_jid=$4)
          ORDER BY owner_id FOR UPDATE",
    )
    .bind(actor.id)
    .bind(&target_jid)
    .bind(target.id)
    .bind(&actor_jid)
    .fetch_all(&mut *transaction)
    .await?;
    let mut block_owners = vec![actor.id, target.id];
    block_owners.sort_unstable();
    block_owners.dedup();
    for owner_id in block_owners {
        lock_block_policy_in_transaction(&mut transaction, owner_id).await?;
    }
    if is_blocked_for_account_in_transaction(&mut transaction, actor.id, &actor_jid, &target_jid)
        .await?
        || is_blocked_for_account_in_transaction(
            &mut transaction,
            target.id,
            &target_jid,
            &actor_jid,
        )
        .await?
    {
        transaction.rollback().await?;
        return Ok(AuthorizedLocalPresenceTransition::PolicyDenied(
            PresencePolicyDenial::Blocking,
        ));
    }
    if crate::privacy::privacy_denies_in_transaction(
        &mut transaction,
        actor.id,
        Some(connection_id),
        &target_jid,
        crate::privacy::PrivacyStanzaKind::PresenceOut,
    )
    .await?
    {
        transaction.rollback().await?;
        return Ok(AuthorizedLocalPresenceTransition::PolicyDenied(
            PresencePolicyDenial::Privacy,
        ));
    }
    let transition = if actor.id == target.id {
        suppressed_local_presence_transition()
    } else {
        transition_local_presence_subscription_in_transaction(
            effects,
            &mut transaction,
            actor.id,
            &actor_jid,
            target.id,
            &target_jid,
            kind,
            stamped_stanza,
        )
        .await?
    };
    transaction.commit().await?;
    Ok(AuthorizedLocalPresenceTransition::Transition(Box::new(
        AuthorizedLocalPresence {
            actor,
            target,
            transition,
        },
    )))
}

pub fn suppressed_local_presence_transition() -> LocalPresenceTransition {
    LocalPresenceTransition {
        effect: LocalPresenceEffect::Suppressed,
        actor_subscription: "none".to_owned(),
        actor_changed: false,
        target_changed: false,
        actor_change: None,
        target_change: None,
        pending_created_at_micros: None,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn transition_local_presence_subscription_in_transaction<E: RosterTransactionEffects>(
    effects: &E,
    transaction: &mut Transaction<'_, Postgres>,
    actor_id: Uuid,
    actor_jid: &str,
    target_id: Uuid,
    target_jid: &str,
    kind: &str,
    stamped_stanza: &str,
) -> Result<LocalPresenceTransition> {
    let actor_row = sqlx::query(
        "SELECT subscription,ask,approved FROM roster_items WHERE owner_id=$1 AND contact_jid=$2 FOR UPDATE",
    )
    .bind(actor_id)
    .bind(target_jid)
    .fetch_optional(&mut **transaction)
    .await?;
    let target_row = sqlx::query(
        "SELECT subscription,ask,approved FROM roster_items WHERE owner_id=$1 AND contact_jid=$2 FOR UPDATE",
    )
    .bind(target_id)
    .bind(actor_jid)
    .fetch_optional(&mut **transaction)
    .await?;
    let actor_facts = subscription_facts(actor_row.as_ref());
    let target_facts = subscription_facts(target_row.as_ref());
    let pending_inbound = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2 FOR UPDATE",
    )
    .bind(target_id)
    .bind(actor_id)
    .fetch_optional(&mut **transaction)
    .await?
    .is_some();
    let pending_outbound = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2 FOR UPDATE",
    )
    .bind(actor_id)
    .bind(target_id)
    .fetch_optional(&mut **transaction)
    .await?
    .is_some();

    let decision = local_subscription_transition(
        actor_facts,
        target_facts,
        pending_outbound,
        pending_inbound,
        SubscriptionAction::parse(kind).expect("presence kind validated before transaction"),
    );
    let pending_created_at_micros = if decision.pending_outbound
        == PendingSubscriptionChange::Insert
    {
        if stamped_stanza.is_empty() || stamped_stanza.len() > 65_536 {
            anyhow::bail!("presence subscription stanza exceeds the persistence limit");
        }
        sqlx::query_scalar("INSERT INTO pending_presence_subscriptions(requester_id,recipient_id,stanza) VALUES($1,$2,$3) ON CONFLICT(requester_id,recipient_id) DO NOTHING RETURNING (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint")
            .bind(actor_id)
            .bind(target_id)
            .bind(stamped_stanza)
            .fetch_optional(&mut **transaction)
            .await?
    } else {
        None
    };
    if decision.pending_outbound == PendingSubscriptionChange::Delete {
        sqlx::query(
            "DELETE FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2",
        )
        .bind(actor_id)
        .bind(target_id)
        .execute(&mut **transaction)
        .await?;
    }
    if decision.pending_inbound == PendingSubscriptionChange::Delete {
        sqlx::query(
            "DELETE FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2",
        )
        .bind(target_id)
        .bind(actor_id)
        .execute(&mut **transaction)
        .await?;
    }

    let actor_change = if decision.journal_actor {
        Some(
            update_subscription_in_transaction(
                effects,
                transaction,
                actor_id,
                target_jid,
                decision.actor.subscription(),
                decision.actor.ask(),
                Some(decision.actor.approved()),
            )
            .await?,
        )
    } else {
        None
    };
    let target_change = if decision.journal_target {
        Some(
            update_subscription_in_transaction(
                effects,
                transaction,
                target_id,
                actor_jid,
                decision.target.subscription(),
                decision.target.ask(),
                Some(decision.target.approved()),
            )
            .await?,
        )
    } else {
        None
    };
    Ok(LocalPresenceTransition {
        effect: decision.effect,
        actor_subscription: decision.actor.subscription().to_owned(),
        actor_changed: decision.journal_actor,
        target_changed: decision.journal_target,
        actor_change,
        target_change,
        pending_created_at_micros,
    })
}
