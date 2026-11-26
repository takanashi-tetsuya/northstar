use super::*;

/// Applies the local side of an inbound RFC 6121 federated subscription
/// transition.  The roster row, version journal and durable pending request
/// are committed together, so a process/database failure cannot expose a
/// roster authorization with stale pending state (or consume the request
/// without the corresponding roster change).
pub async fn transition_inbound_remote_presence_subscription<E: RosterTransactionEffects>(
    effects: &E,
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
        "SELECT locked.id,locked.username,locked.auth_generation
           FROM northstar_lock_user_rows_update(ARRAY[$1::uuid]) locked
          WHERE NOT locked.is_disabled",
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
    if crate::privacy::privacy_denies_in_transaction(
        &mut transaction,
        recipient.id,
        None,
        &from_jid,
        crate::privacy::PrivacyStanzaKind::PresenceIn,
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
                effects,
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
