use super::*;
use anyhow::Context;
use northstar_roster_application::presence::{
    InboundSubscriptionRequest, SubscriptionOutboxAdmissionError,
};

/// Applies the local side of an inbound RFC 6121 federated subscription
/// transition.  The roster row, version journal and durable pending request
/// are committed together, so a process/database failure cannot expose a
/// roster authorization with stale pending state (or consume the request
/// without the corresponding roster change).
pub async fn transition_inbound_remote_presence_subscription<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    request: InboundSubscriptionRequest<'_>,
) -> Result<AuthorizedInboundRemotePresenceTransition> {
    let InboundSubscriptionRequest {
        recipient: expected_recipient,
        local_domain,
        contact,
        action,
        stanza: stamped_stanza,
        verified_peer,
        subscribed_reply,
        unsubscribed_reply,
        outbox_policy,
    } = request;
    let recipient_id = expected_recipient.id;
    let recipient_domain = northstar_xmpp_types::jid::prepare_domainpart(local_domain)?;
    let verified_peer = northstar_xmpp_types::jid::prepare_domainpart(verified_peer)?;
    let from = northstar_xmpp_types::jid::CanonicalJid::parse_bare(contact)?;
    if from.domainpart() != verified_peer.as_str() {
        return Ok(AuthorizedInboundRemotePresenceTransition::Missing);
    }
    let from_jid = from.to_string();
    if action == SubscriptionAction::Subscribe
        && (stamped_stanza.is_empty() || stamped_stanza.len() > 65_536)
    {
        anyhow::bail!("federated presence subscription stanza exceeds the persistence limit");
    }

    let mut transaction = pool.begin().await?;
    let recipient = sqlx::query(
        "SELECT locked.id,locked.username,locked.auth_generation
           FROM northstar_lock_user_rows_update(ARRAY[$1::uuid]) locked
          WHERE NOT locked.is_disabled AND locked.auth_generation=$2 AND locked.username=$3",
    )
    .bind(recipient_id)
    .bind(expected_recipient.auth_generation)
    .bind(&expected_recipient.username)
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
    let pending = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM federated_presence_pending WHERE recipient_id=$1 AND from_jid=$2 FOR UPDATE",
    )
    .bind(recipient_id)
    .bind(&from_jid)
    .fetch_optional(&mut *transaction)
    .await?
    .is_some();

    let decision =
        inbound_subscription_transition(subscription_facts(existing.as_ref()), pending, action);
    let mut forward = decision.forward;
    let pending_created_at_micros = if decision.pending == PendingSubscriptionChange::Insert {
        let created_at = sqlx::query_scalar(
            "INSERT INTO federated_presence_pending (recipient_id, from_jid, stanza) VALUES ($1, $2, $3) ON CONFLICT (recipient_id, from_jid) DO NOTHING RETURNING (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint",
        )
        .bind(recipient_id)
        .bind(&from_jid)
        .bind(stamped_stanza)
        .fetch_optional(&mut *transaction)
        .await?;
        if created_at.is_none() {
            forward = false;
        }
        created_at
    } else {
        None
    };
    if decision.pending == PendingSubscriptionChange::Delete {
        sqlx::query("DELETE FROM federated_presence_pending WHERE recipient_id=$1 AND from_jid=$2")
            .bind(recipient_id)
            .bind(&from_jid)
            .execute(&mut *transaction)
            .await?;
    }

    let change = if decision.journal {
        Some(
            update_subscription_in_transaction(
                effects,
                &mut transaction,
                recipient_id,
                &from_jid,
                decision.facts.subscription(),
                decision.facts.ask(),
                Some(decision.facts.approved()),
            )
            .await?,
        )
    } else {
        None
    };
    if let Some(reply) = decision.auto_reply {
        let stanza = match reply {
            SubscriptionReply::Subscribed => subscribed_reply,
            SubscriptionReply::Unsubscribed => unsubscribed_reply,
        };
        effects
            .enqueue_federated_stanza(
                &mut transaction,
                &verified_peer,
                stanza,
                None,
                outbox_policy,
            )
            .await
            .context(SubscriptionOutboxAdmissionError)?;
    }
    transaction.commit().await?;
    Ok(AuthorizedInboundRemotePresenceTransition::Transition(
        Box::new(AuthorizedInboundRemotePresence {
            recipient,
            transition: InboundRemotePresenceTransition {
                effect: if forward {
                    InboundRemotePresenceEffect::Forward
                } else {
                    InboundRemotePresenceEffect::Suppressed
                },
                subscription: decision.facts.subscription().to_owned(),
                change,
                auto_reply: decision.auto_reply,
                send_unavailable: decision.send_unavailable,
                pending_created_at_micros,
            },
        }),
    ))
}
