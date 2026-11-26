use super::*;

/// Client-authorized federated/component transition without an S2S outbox.
/// This is intentionally distinct from the inbound-federation path: the
/// latter authenticates a remote domain and has no C2S credential generation.
#[allow(clippy::too_many_arguments)]
pub async fn transition_remote_presence_subscription_authorized<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    actor_domain: &str,
    contact: &str,
    kind: &str,
) -> Result<AuthorizedRemotePresenceTransition> {
    transition_remote_presence_subscription_authorized_inner(
        effects,
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
pub async fn transition_remote_presence_subscription_with_outbox_authorized<
    E: RosterTransactionEffects,
>(
    effects: &E,
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
    policy: S2sOutboxPolicy,
) -> Result<AuthorizedRemotePresenceTransition> {
    transition_remote_presence_subscription_authorized_inner(
        effects,
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
pub async fn transition_remote_presence_subscription_authorized_inner<
    E: RosterTransactionEffects,
>(
    effects: &E,
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    actor_domain: &str,
    contact: &str,
    kind: &str,
    outbox: Option<(&str, &str, Option<&str>, S2sOutboxPolicy)>,
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
        "SELECT locked.id,locked.username,locked.auth_generation
           FROM northstar_lock_user_rows_update(ARRAY[$1::uuid]) locked
          WHERE locked.auth_generation=$2 AND NOT locked.is_disabled",
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
    if crate::privacy::privacy_denies_in_transaction(
        &mut transaction,
        actor.id,
        Some(connection_id),
        &contact,
        crate::privacy::PrivacyStanzaKind::PresenceOut,
    )
    .await?
    {
        transaction.rollback().await?;
        return Ok(AuthorizedRemotePresenceTransition::PolicyDenied(
            PresencePolicyDenial::Privacy,
        ));
    }
    let transition = transition_remote_presence_subscription_in_transaction(
        effects,
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

pub async fn transition_remote_presence_subscription_in_transaction<E: RosterTransactionEffects>(
    effects: &E,
    transaction: &mut Transaction<'_, Postgres>,
    recipient_id: Uuid,
    from_jid: &str,
    kind: &str,
    outbox: Option<(&str, &str, Option<&str>, S2sOutboxPolicy)>,
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
                effects,
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
            effects
                .enqueue_federated_stanza(transaction, target_domain, stanza, bounce_to, policy)
                .await?;
        }
    }
    Ok(Some(RemotePresenceTransition {
        subscription: next_subscription,
        change,
        routed,
    }))
}
