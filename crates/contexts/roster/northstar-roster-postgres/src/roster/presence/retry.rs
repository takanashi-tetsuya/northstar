use super::*;
use northstar_roster_application::subscription_retry::{
    SubscriptionRetryAdmission, SubscriptionRetryIdentity, SubscriptionRetryRequest,
    SubscriptionRetryTarget,
};
use northstar_xmpp_types::jid::CanonicalJid;

pub async fn pending_retry_identity(
    pool: &PgPool,
    request: SubscriptionRetryRequest<'_>,
) -> Result<Option<SubscriptionRetryIdentity>> {
    pending_identity_on(pool, request).await
}

async fn pending_identity_on<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    request: SubscriptionRetryRequest<'_>,
) -> Result<Option<SubscriptionRetryIdentity>> {
    let recipient_id = match request.target {
        SubscriptionRetryTarget::Local(target) => Some(target.id),
        SubscriptionRetryTarget::Federated { .. } => None,
    };
    let row = sqlx::query_as::<_, (i64, Option<i64>, Option<i64>)>(
        "SELECT (EXTRACT(EPOCH FROM r.updated_at) * 1000000)::bigint,
                (SELECT version FROM roster_change_log log
                  WHERE log.owner_id=r.owner_id AND log.contact_jid=r.contact_jid
                  ORDER BY version DESC LIMIT 1),
                (EXTRACT(EPOCH FROM p.created_at) * 1000000)::bigint
           FROM roster_items r
           LEFT JOIN pending_presence_subscriptions p
             ON p.requester_id=r.owner_id AND p.recipient_id=$3
          WHERE r.owner_id=$1 AND r.contact_jid=$2 AND r.ask='subscribe'
            AND ($3::uuid IS NULL OR p.created_at IS NOT NULL)",
    )
    .bind(request.actor.account_id)
    .bind(request.contact)
    .bind(recipient_id)
    .fetch_optional(executor)
    .await?;
    Ok(row.map(
        |(roster_updated_at_micros, roster_version, local_created_at_micros)| {
            SubscriptionRetryIdentity {
                roster_updated_at_micros,
                roster_version,
                local_created_at_micros,
            }
        },
    ))
}

pub async fn retry_outbound_subscription<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    request: SubscriptionRetryRequest<'_>,
    expected: SubscriptionRetryIdentity,
    minimal_stanza: &str,
) -> Result<SubscriptionRetryAdmission> {
    let actor = request.actor;
    let from = CanonicalJid::parse(&actor.full_jid)?;
    let to = CanonicalJid::parse_bare(request.contact)?;
    let local_target = match request.target {
        SubscriptionRetryTarget::Local(target) if from.domainpart() == to.domainpart() => {
            Some(target)
        }
        SubscriptionRetryTarget::Federated { .. } if from.domainpart() != to.domainpart() => None,
        _ => return Ok(SubscriptionRetryAdmission::Stale),
    };
    let mut accounts = vec![actor.account_id];
    if let Some(target) = local_target {
        accounts.push(target.id);
        accounts.sort_unstable();
        accounts.dedup();
    }
    let mut transaction = pool.begin().await?;
    // Match subscription transition order: account identities, roster item,
    // block-policy fences, then federation outbox admission.
    let locked = sqlx::query(
        "SELECT id,username,auth_generation FROM northstar_lock_user_rows_update($1)
          WHERE NOT is_disabled",
    )
    .bind(&accounts)
    .fetch_all(&mut *transaction)
    .await?;
    let current_account = |id, generation, username: Option<&str>| {
        locked.iter().any(|row| {
            row.get::<Uuid, _>("id") == id
                && row.get::<i64, _>("auth_generation") == generation
                && Some(row.get::<&str, _>("username")) == username
        })
    };
    if actor.connection_id.is_nil()
        || from.resourcepart().is_none()
        || !current_account(actor.account_id, actor.auth_generation, from.localpart())
        || local_target.is_some_and(|target| {
            !current_account(target.id, target.auth_generation, to.localpart())
        })
    {
        return Ok(SubscriptionRetryAdmission::Stale);
    }
    sqlx::query(
        "SELECT owner_id FROM roster_items
          WHERE owner_id=$1 AND contact_jid=$2 FOR UPDATE",
    )
    .bind(actor.account_id)
    .bind(request.contact)
    .fetch_all(&mut *transaction)
    .await?;
    if pending_identity_on(&mut *transaction, request).await? != Some(expected) {
        return Ok(SubscriptionRetryAdmission::Stale);
    }
    for owner_id in accounts {
        lock_block_policy_in_transaction(&mut transaction, owner_id).await?;
    }
    if is_blocked_for_account_in_transaction(
        &mut transaction,
        actor.account_id,
        actor.bare_jid(),
        request.contact,
    )
    .await?
        || crate::privacy::session_privacy_denies(
            &mut *transaction,
            actor.account_id,
            Some(actor.connection_id),
            request.expects_active,
            request.contact,
            crate::privacy::PrivacyStanzaKind::PresenceOut,
        )
        .await?
    {
        return Ok(SubscriptionRetryAdmission::Stale);
    }
    let admission = match request.target {
        SubscriptionRetryTarget::Local(target) => {
            if is_blocked_for_account_in_transaction(
                &mut transaction,
                target.id,
                request.contact,
                &actor.full_jid,
            )
            .await?
            {
                return Ok(SubscriptionRetryAdmission::Stale);
            }
            let Some(created_at_micros) = expected.local_created_at_micros else {
                return Ok(SubscriptionRetryAdmission::Stale);
            };
            SubscriptionRetryAdmission::Local { created_at_micros }
        }
        SubscriptionRetryTarget::Federated { policy } => {
            effects
                .enqueue_federated_stanza(
                    &mut transaction,
                    to.domainpart(),
                    minimal_stanza,
                    Some(actor.bare_jid()),
                    policy,
                )
                .await?;
            SubscriptionRetryAdmission::FederatedQueued
        }
    };
    transaction.commit().await?;
    Ok(admission)
}
