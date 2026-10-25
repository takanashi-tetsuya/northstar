//! Implement local and remote presence-subscription transitions, pending-state queries, and transactional outbox admission.

use super::*;

/// Client-authorized local transition. Account lookup, credential-generation
/// validation, deterministic two-account locking and both roster mutations
/// share one transaction. A username resolved by the protocol layer never
/// crosses this authority boundary as a reusable UUID.
#[allow(clippy::too_many_arguments)]
pub async fn transition_local_presence_subscription_authorized(
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    actor_domain: &str,
    target_username: &str,
    kind: &str,
    stamped_stanza: &str,
) -> Result<AuthorizedLocalPresenceTransition> {
    transition_local_presence_subscription_authorized_with_hook(
        pool,
        actor_id,
        expected_auth_generation,
        connection_id,
        actor_domain,
        target_username,
        kind,
        stamped_stanza,
        || async {},
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn transition_local_presence_subscription_authorized_with_hook<F, Fut>(
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    actor_domain: &str,
    target_username: &str,
    kind: &str,
    stamped_stanza: &str,
    after_target_resolution: F,
) -> Result<AuthorizedLocalPresenceTransition>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if !matches!(
        kind,
        "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
    ) {
        return Ok(AuthorizedLocalPresenceTransition::Missing);
    }
    let actor_domain = northstar_xmpp_types::jid::prepare_domainpart(actor_domain)?;
    let target_username = northstar_auth_core::normalize_username(target_username)?;
    let mut transaction = pool.begin().await?;

    // Resolve the target incarnation inside this transaction, then lock the
    // two UUIDs in one deterministic statement. A concurrent delete/recreate
    // can therefore only yield Missing or the fully locked new incarnation;
    // it can never redirect a mutation accepted for the old UUID.
    let target_candidate = sqlx::query("SELECT id,username FROM users WHERE username=$1")
        .bind(&target_username)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(target_candidate) = target_candidate else {
        transaction.rollback().await?;
        return Ok(AuthorizedLocalPresenceTransition::Missing);
    };
    let target_id: Uuid = target_candidate.try_get("id")?;
    // Production uses a no-op. The deterministic test hook proves that an
    // account deleted and recreated after resolution cannot inherit the
    // in-flight mutation intended for the previous UUID.
    after_target_resolution().await;
    let mut lock_ids = vec![actor_id];
    if target_id != actor_id {
        lock_ids.push(target_id);
        lock_ids.sort_unstable();
    }
    let locked = sqlx::query(
        "SELECT id,username,auth_generation,is_disabled
           FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE",
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
    if super::super::privacy::privacy_denies_in_transaction(
        &mut transaction,
        actor.id,
        Some(connection_id),
        &target_jid,
        super::super::PrivacyStanzaKind::PresenceOut,
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

pub(super) fn suppressed_local_presence_transition() -> LocalPresenceTransition {
    LocalPresenceTransition {
        effect: LocalPresenceEffect::Suppressed,
        actor_subscription: "none".to_owned(),
        actor_changed: false,
        target_changed: false,
        actor_change: None,
        target_change: None,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn transition_local_presence_subscription_in_transaction(
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
    let actor_subscription = actor_row
        .as_ref()
        .map(|row| row.get::<String, _>("subscription"))
        .unwrap_or_else(|| "none".to_owned());
    let target_subscription = target_row
        .as_ref()
        .map(|row| row.get::<String, _>("subscription"))
        .unwrap_or_else(|| "none".to_owned());
    let actor_ask = actor_row
        .as_ref()
        .and_then(|row| row.get::<Option<String>, _>("ask"));
    let target_ask = target_row
        .as_ref()
        .and_then(|row| row.get::<Option<String>, _>("ask"));
    let actor_approved = actor_row
        .as_ref()
        .is_some_and(|row| row.get::<bool, _>("approved"));
    let target_approved = target_row
        .as_ref()
        .is_some_and(|row| row.get::<bool, _>("approved"));
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

    let mut next_actor_subscription = actor_subscription.clone();
    let mut next_actor_ask = actor_ask.clone();
    let mut next_actor_approved = actor_approved;
    let mut next_target_subscription = target_subscription.clone();
    let mut next_target_ask = target_ask.clone();
    let mut next_target_approved = target_approved;
    let effect;
    let mut insert_outbound_pending = false;
    let mut delete_outbound_pending = false;
    let mut delete_inbound_pending = false;

    match kind {
        "subscribe" if target_approved => {
            next_actor_subscription =
                add_subscription_direction(&actor_subscription, "to").to_owned();
            next_actor_ask = None;
            next_target_subscription =
                add_subscription_direction(&target_subscription, "from").to_owned();
            next_target_approved = false;
            delete_outbound_pending = true;
            effect = LocalPresenceEffect::AutoApproved;
        }
        "subscribe" if matches!(actor_subscription.as_str(), "to" | "both") => {
            effect = LocalPresenceEffect::Suppressed;
        }
        "subscribe" if pending_outbound => {
            effect = LocalPresenceEffect::Suppressed;
        }
        "subscribe" => {
            if stamped_stanza.is_empty() || stamped_stanza.len() > 65_536 {
                anyhow::bail!("presence subscription stanza exceeds the persistence limit");
            }
            next_actor_ask = Some("subscribe".to_owned());
            insert_outbound_pending = true;
            effect = LocalPresenceEffect::Forward;
        }
        "subscribed" if pending_inbound => {
            next_actor_subscription =
                add_subscription_direction(&actor_subscription, "from").to_owned();
            next_actor_approved = false;
            next_target_subscription =
                add_subscription_direction(&target_subscription, "to").to_owned();
            next_target_ask = None;
            delete_inbound_pending = true;
            effect = LocalPresenceEffect::Forward;
        }
        "subscribed" if matches!(actor_subscription.as_str(), "from" | "both") => {
            effect = LocalPresenceEffect::Suppressed;
        }
        "subscribed" => {
            next_actor_approved = true;
            effect = LocalPresenceEffect::Suppressed;
        }
        "unsubscribe" => {
            next_actor_subscription =
                remove_subscription_direction(&actor_subscription, "to").to_owned();
            next_actor_ask = None;
            next_target_subscription =
                remove_subscription_direction(&target_subscription, "from").to_owned();
            delete_outbound_pending = true;
            effect = LocalPresenceEffect::Forward;
        }
        "unsubscribed" => {
            let routed = pending_inbound || matches!(actor_subscription.as_str(), "from" | "both");
            next_actor_subscription =
                remove_subscription_direction(&actor_subscription, "from").to_owned();
            next_actor_approved = false;
            if routed {
                next_target_subscription =
                    remove_subscription_direction(&target_subscription, "to").to_owned();
                next_target_ask = None;
            }
            delete_inbound_pending = true;
            effect = if routed {
                LocalPresenceEffect::Forward
            } else {
                LocalPresenceEffect::Suppressed
            };
        }
        _ => unreachable!("presence kind validated before transaction"),
    }

    if insert_outbound_pending {
        sqlx::query("INSERT INTO pending_presence_subscriptions(requester_id,recipient_id,stanza) VALUES($1,$2,$3) ON CONFLICT(requester_id,recipient_id) DO NOTHING")
            .bind(actor_id)
            .bind(target_id)
            .bind(stamped_stanza)
            .execute(&mut **transaction)
            .await?;
    }
    if delete_outbound_pending {
        sqlx::query(
            "DELETE FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2",
        )
        .bind(actor_id)
        .bind(target_id)
        .execute(&mut **transaction)
        .await?;
    }
    if delete_inbound_pending {
        sqlx::query(
            "DELETE FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2",
        )
        .bind(target_id)
        .bind(actor_id)
        .execute(&mut **transaction)
        .await?;
    }

    let actor_changed = actor_row.as_ref().is_some_and(|_| {
        next_actor_subscription != actor_subscription
            || next_actor_ask != actor_ask
            || next_actor_approved != actor_approved
    }) || (actor_row.is_none()
        && (next_actor_subscription != "none" || next_actor_ask.is_some() || next_actor_approved));
    let target_changed = target_row.as_ref().is_some_and(|_| {
        next_target_subscription != target_subscription
            || next_target_ask != target_ask
            || next_target_approved != target_approved
    }) || (target_row.is_none()
        && (next_target_subscription != "none"
            || next_target_ask.is_some()
            || next_target_approved));
    let actor_change = if actor_changed {
        Some(
            update_subscription_in_transaction(
                transaction,
                actor_id,
                target_jid,
                &next_actor_subscription,
                next_actor_ask.as_deref(),
                Some(next_actor_approved),
            )
            .await?,
        )
    } else {
        None
    };
    let target_change = if target_changed {
        Some(
            update_subscription_in_transaction(
                transaction,
                target_id,
                actor_jid,
                &next_target_subscription,
                next_target_ask.as_deref(),
                Some(next_target_approved),
            )
            .await?,
        )
    } else {
        None
    };
    Ok(LocalPresenceTransition {
        effect,
        actor_subscription: next_actor_subscription,
        actor_changed,
        target_changed,
        actor_change,
        target_change,
    })
}

pub(super) fn add_subscription_direction(current: &str, direction: &str) -> &'static str {
    match (current, direction) {
        ("none", "to") => "to",
        ("none", "from") => "from",
        ("to", "from") | ("from", "to") | ("both", _) => "both",
        ("to", "to") => "to",
        ("from", "from") => "from",
        _ => "none",
    }
}

pub(super) fn remove_subscription_direction(current: &str, direction: &str) -> &'static str {
    match (current, direction) {
        ("both", "to") => "from",
        ("both", "from") => "to",
        ("to", "to") | ("from", "from") => "none",
        ("to", "from") => "to",
        ("from", "to") => "from",
        _ => "none",
    }
}

pub async fn pending_presence_subscription_count(pool: &PgPool, recipient_id: Uuid) -> Result<i64> {
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM pending_presence_subscriptions WHERE recipient_id = $1) + (SELECT COUNT(*) FROM federated_presence_pending WHERE recipient_id = $1)",
    )
    .bind(recipient_id)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

/// Applies the local side of an inbound RFC 6121 federated subscription
/// transition.  The roster row, version journal and durable pending request
/// are committed together, so a process/database failure cannot expose a
/// roster authorization with stale pending state (or consume the request
/// without the corresponding roster change).
pub async fn transition_inbound_remote_presence_subscription(
    pool: &PgPool,
    recipient_id: Uuid,
    recipient_domain: &str,
    from_jid: &str,
    kind: &str,
    stamped_stanza: &str,
) -> Result<AuthorizedInboundRemotePresenceTransition> {
    if !matches!(
        kind,
        "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
    ) {
        return Ok(AuthorizedInboundRemotePresenceTransition::Missing);
    }
    let recipient_domain = northstar_xmpp_types::jid::prepare_domainpart(recipient_domain)?;
    let from_jid = northstar_xmpp_types::jid::canonicalize_bare(from_jid)?;
    if kind == "subscribe" && (stamped_stanza.is_empty() || stamped_stanza.len() > 65_536) {
        anyhow::bail!("federated presence subscription stanza exceeds the persistence limit");
    }

    let mut transaction = pool.begin().await?;
    // The recipient is a locally hosted authority, not an authenticated C2S
    // actor.  Lock its exact UUID and disabled state, but deliberately do not
    // apply a client auth-generation check to an inbound federated stanza.
    let recipient = sqlx::query(
        "SELECT id,username,auth_generation FROM users
          WHERE id=$1 AND NOT is_disabled FOR UPDATE",
    )
    .bind(recipient_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(recipient) = recipient else {
        transaction.rollback().await?;
        return Ok(AuthorizedInboundRemotePresenceTransition::Missing);
    };
    let recipient = PresenceAccount {
        id: recipient.try_get("id")?,
        username: recipient.try_get("username")?,
        auth_generation: recipient.try_get("auth_generation")?,
    };
    let recipient_bare = format!("{}@{recipient_domain}", recipient.username);
    let existing = sqlx::query(
        "SELECT subscription, ask, approved FROM roster_items WHERE owner_id=$1 AND contact_jid=$2 FOR UPDATE",
    )
    .bind(recipient_id)
    .bind(&from_jid)
    .fetch_optional(&mut *transaction)
    .await?;
    // Inbound federation has no local C2S credential generation. Its
    // authority is the exact enabled local recipient incarnation plus that
    // account's XEP-0191 and durable default XEP-0016 inbound policy.
    lock_block_policy_in_transaction(&mut transaction, recipient.id).await?;
    if is_blocked_for_account_in_transaction(
        &mut transaction,
        recipient.id,
        &recipient_bare,
        &from_jid,
    )
    .await?
    {
        transaction.rollback().await?;
        return Ok(AuthorizedInboundRemotePresenceTransition::PolicyDenied(
            PresencePolicyDenial::Blocking,
        ));
    }
    if super::super::privacy::privacy_denies_in_transaction(
        &mut transaction,
        recipient.id,
        None,
        &from_jid,
        super::super::PrivacyStanzaKind::PresenceIn,
    )
    .await?
    {
        transaction.rollback().await?;
        return Ok(AuthorizedInboundRemotePresenceTransition::PolicyDenied(
            PresencePolicyDenial::Privacy,
        ));
    }
    let subscription = existing
        .as_ref()
        .map(|row| row.get::<String, _>("subscription"))
        .unwrap_or_else(|| "none".to_owned());
    let ask = existing
        .as_ref()
        .and_then(|row| row.get::<Option<String>, _>("ask"));
    let approved = existing
        .as_ref()
        .is_some_and(|row| row.get::<bool, _>("approved"));
    let pending = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM federated_presence_pending WHERE recipient_id=$1 AND from_jid=$2 FOR UPDATE",
    )
    .bind(recipient_id)
    .bind(&from_jid)
    .fetch_optional(&mut *transaction)
    .await?
    .is_some();

    let mut next_subscription = subscription.clone();
    let mut next_ask = ask.clone();
    let mut next_approved = approved;
    let mut effect = InboundRemotePresenceEffect::Suppressed;
    let mut auto_reply = None;
    let mut send_unavailable = false;
    let mut delete_pending = false;
    let mut insert_pending = false;

    match kind {
        "subscribe" if approved => {
            next_subscription = add_subscription_direction(&subscription, "from").to_owned();
            next_approved = false;
            delete_pending = true;
            // Replaying the acknowledgement is safe and lets a duplicate
            // request recover a response lost after the prior COMMIT.
            auto_reply = Some("subscribed");
        }
        "subscribe" if matches!(subscription.as_str(), "from" | "both") => {
            auto_reply = Some("subscribed");
        }
        "subscribe" if pending => {}
        "subscribe" => {
            insert_pending = true;
            effect = InboundRemotePresenceEffect::Forward;
        }
        "subscribed"
            if ask.as_deref() == Some("subscribe")
                && matches!(subscription.as_str(), "none" | "from") =>
        {
            next_subscription = add_subscription_direction(&subscription, "to").to_owned();
            next_ask = None;
            effect = InboundRemotePresenceEffect::Forward;
        }
        "subscribed" => {}
        "unsubscribe" if pending || matches!(subscription.as_str(), "from" | "both") => {
            send_unavailable = matches!(subscription.as_str(), "from" | "both");
            next_subscription = remove_subscription_direction(&subscription, "from").to_owned();
            next_approved = false;
            delete_pending = true;
            effect = InboundRemotePresenceEffect::Forward;
            auto_reply = Some("unsubscribed");
        }
        "unsubscribe" => {
            // RFC 6121 recommends acknowledging even a harmless duplicate;
            // this also closes the crash window after the first transition.
            auto_reply = Some("unsubscribed");
        }
        "unsubscribed"
            if ask.as_deref() == Some("subscribe")
                || matches!(subscription.as_str(), "to" | "both") =>
        {
            next_subscription = remove_subscription_direction(&subscription, "to").to_owned();
            next_ask = None;
            effect = InboundRemotePresenceEffect::Forward;
        }
        "unsubscribed" => {}
        _ => unreachable!("presence kind validated above"),
    }

    if insert_pending {
        sqlx::query(
            "INSERT INTO federated_presence_pending (recipient_id, from_jid, stanza) VALUES ($1, $2, $3) ON CONFLICT (recipient_id, from_jid) DO NOTHING",
        )
        .bind(recipient_id)
        .bind(&from_jid)
        .bind(stamped_stanza)
        .execute(&mut *transaction)
        .await?;
    }
    if delete_pending {
        sqlx::query("DELETE FROM federated_presence_pending WHERE recipient_id=$1 AND from_jid=$2")
            .bind(recipient_id)
            .bind(&from_jid)
            .execute(&mut *transaction)
            .await?;
    }

    let changed = existing.as_ref().is_some_and(|_| {
        next_subscription != subscription || next_ask != ask || next_approved != approved
    }) || (existing.is_none()
        && (next_subscription != "none" || next_ask.is_some() || next_approved));
    let change = if changed {
        Some(
            update_subscription_in_transaction(
                &mut transaction,
                recipient_id,
                &from_jid,
                &next_subscription,
                next_ask.as_deref(),
                Some(next_approved),
            )
            .await?,
        )
    } else {
        None
    };
    transaction.commit().await?;
    Ok(AuthorizedInboundRemotePresenceTransition::Transition(
        Box::new(AuthorizedInboundRemotePresence {
            recipient,
            transition: InboundRemotePresenceTransition {
                effect,
                subscription: next_subscription,
                change,
                auto_reply,
                send_unavailable,
            },
        }),
    ))
}

/// Client-authorized federated/component transition without an S2S outbox.
/// This is intentionally distinct from the inbound-federation path: the
/// latter authenticates a remote domain and has no C2S credential generation.
pub async fn transition_remote_presence_subscription_authorized(
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    actor_domain: &str,
    contact: &str,
    kind: &str,
) -> Result<AuthorizedRemotePresenceTransition> {
    transition_remote_presence_subscription_authorized_inner(
        pool,
        actor_id,
        expected_auth_generation,
        connection_id,
        actor_domain,
        contact,
        kind,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn transition_remote_presence_subscription_with_outbox_authorized(
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    actor_domain: &str,
    contact: &str,
    kind: &str,
    target_domain: &str,
    stanza: &str,
    bounce_to: Option<&str>,
    policy: super::super::S2sOutboxPolicy,
) -> Result<AuthorizedRemotePresenceTransition> {
    transition_remote_presence_subscription_authorized_inner(
        pool,
        actor_id,
        expected_auth_generation,
        connection_id,
        actor_domain,
        contact,
        kind,
        Some((target_domain, stanza, bounce_to, policy)),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn transition_remote_presence_subscription_authorized_inner(
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    actor_domain: &str,
    contact: &str,
    kind: &str,
    outbox: Option<(&str, &str, Option<&str>, super::super::S2sOutboxPolicy)>,
) -> Result<AuthorizedRemotePresenceTransition> {
    anyhow::ensure!(
        matches!(
            kind,
            "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
        ),
        "invalid presence subscription transition"
    );
    let mut transaction = pool.begin().await?;
    let actor_domain = northstar_xmpp_types::jid::prepare_domainpart(actor_domain)?;
    let contact = northstar_xmpp_types::jid::canonicalize_bare(contact)?;
    let actor = sqlx::query(
        "SELECT id,username,auth_generation FROM users
          WHERE id=$1 AND auth_generation=$2 AND NOT is_disabled
          FOR UPDATE",
    )
    .bind(actor_id)
    .bind(expected_auth_generation)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(actor) = actor else {
        transaction.rollback().await?;
        return Ok(AuthorizedRemotePresenceTransition::Unauthorized);
    };
    let actor = PresenceAccount {
        id: actor.try_get("id")?,
        username: actor.try_get("username")?,
        auth_generation: actor.try_get("auth_generation")?,
    };
    // See the local path for the shared lock order. A block committed after
    // the protocol's preliminary policy check must still suppress both the
    // roster mutation and durable federation admission.
    sqlx::query(
        "SELECT owner_id FROM roster_items
          WHERE owner_id=$1 AND contact_jid=$2 FOR UPDATE",
    )
    .bind(actor.id)
    .bind(&contact)
    .fetch_all(&mut *transaction)
    .await?;
    lock_block_policy_in_transaction(&mut transaction, actor.id).await?;
    let actor_bare = format!("{}@{actor_domain}", actor.username);
    if is_blocked_for_account_in_transaction(&mut transaction, actor.id, &actor_bare, &contact)
        .await?
    {
        transaction.rollback().await?;
        return Ok(AuthorizedRemotePresenceTransition::PolicyDenied(
            PresencePolicyDenial::Blocking,
        ));
    }
    if super::super::privacy::privacy_denies_in_transaction(
        &mut transaction,
        actor.id,
        Some(connection_id),
        &contact,
        super::super::PrivacyStanzaKind::PresenceOut,
    )
    .await?
    {
        transaction.rollback().await?;
        return Ok(AuthorizedRemotePresenceTransition::PolicyDenied(
            PresencePolicyDenial::Privacy,
        ));
    }
    let transition = transition_remote_presence_subscription_in_transaction(
        &mut transaction,
        actor.id,
        &contact,
        kind,
        outbox,
    )
    .await?
    .expect("presence kind validated before transaction");
    transaction.commit().await?;
    Ok(AuthorizedRemotePresenceTransition::Transition(Box::new(
        AuthorizedRemotePresence { actor, transition },
    )))
}

pub(super) async fn transition_remote_presence_subscription_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    recipient_id: Uuid,
    from_jid: &str,
    kind: &str,
    outbox: Option<(&str, &str, Option<&str>, super::super::S2sOutboxPolicy)>,
) -> Result<Option<RemotePresenceTransition>> {
    let from_jid = northstar_xmpp_types::jid::canonicalize_bare(from_jid)?;
    let existing = sqlx::query(
        "SELECT subscription, ask, approved FROM roster_items WHERE owner_id=$1 AND contact_jid=$2 FOR UPDATE",
    )
    .bind(recipient_id)
    .bind(&from_jid)
    .fetch_optional(&mut **transaction)
    .await?;
    let subscription = existing
        .as_ref()
        .map(|row| row.get::<String, _>("subscription"))
        .unwrap_or_else(|| "none".to_owned());
    let ask = existing
        .as_ref()
        .and_then(|row| row.get::<Option<String>, _>("ask"));
    let approved = existing
        .as_ref()
        .is_some_and(|row| row.get::<bool, _>("approved"));
    let pending = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM federated_presence_pending WHERE recipient_id=$1 AND from_jid=$2 FOR UPDATE",
    )
    .bind(recipient_id)
    .bind(&from_jid)
    .fetch_optional(&mut **transaction)
    .await?
    .is_some();
    let (next_subscription, next_ask, next_approved, routed) = match kind {
        "subscribe" => (
            subscription.clone(),
            if matches!(subscription.as_str(), "none" | "from") {
                Some("subscribe".to_owned())
            } else {
                ask.clone()
            },
            approved,
            true,
        ),
        "subscribed" if pending => (
            add_subscription_direction(&subscription, "from").to_owned(),
            ask.clone(),
            false,
            true,
        ),
        "subscribed" if !matches!(subscription.as_str(), "from" | "both") => {
            (subscription.clone(), ask.clone(), true, false)
        }
        "subscribed" => (subscription.clone(), ask.clone(), approved, false),
        "unsubscribe" => (
            remove_subscription_direction(&subscription, "to").to_owned(),
            None,
            approved,
            true,
        ),
        "unsubscribed" => (
            remove_subscription_direction(&subscription, "from").to_owned(),
            ask.clone(),
            false,
            pending || matches!(subscription.as_str(), "from" | "both"),
        ),
        _ => return Ok(None),
    };
    // A no-op cancellation must not materialize an empty roster item merely
    // because no row existed.  Initial subscribe/pre-approval transitions do
    // need a row because `ask`/`approved` carries protocol state.
    let changed = existing.as_ref().is_some_and(|_| {
        next_subscription != subscription || next_ask != ask || next_approved != approved
    }) || (existing.is_none()
        && (next_subscription != "none" || next_ask.is_some() || next_approved));
    let change = if changed {
        Some(
            update_subscription_in_transaction(
                transaction,
                recipient_id,
                &from_jid,
                &next_subscription,
                next_ask.as_deref(),
                Some(next_approved),
            )
            .await?,
        )
    } else {
        None
    };
    if (kind == "subscribed" && pending) || kind == "unsubscribed" {
        sqlx::query("DELETE FROM federated_presence_pending WHERE recipient_id=$1 AND from_jid=$2")
            .bind(recipient_id)
            .bind(&from_jid)
            .execute(&mut **transaction)
            .await?;
    }
    if routed {
        if let Some((target_domain, stanza, bounce_to, policy)) = outbox {
            super::super::enqueue_s2s_outbox_in_transaction(
                transaction,
                target_domain,
                stanza,
                bounce_to,
                policy,
            )
            .await?;
        }
    }
    Ok(Some(RemotePresenceTransition {
        subscription: next_subscription,
        change,
        routed,
    }))
}
