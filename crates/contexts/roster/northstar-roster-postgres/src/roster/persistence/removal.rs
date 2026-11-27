use super::*;

pub async fn remove_roster_item_authorized<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    owner_id: Uuid,
    expected_auth_generation: i64,
    jid: &str,
    route: RosterRemovalRoute<'_>,
) -> Result<AuthorizedRosterRemoval> {
    let transaction = pool.begin().await?;
    remove_roster_item_in_transaction(
        effects,
        transaction,
        owner_id,
        Some(expected_auth_generation),
        jid,
        route,
    )
    .await
}

pub async fn remove_roster_item_in_transaction<E: RosterTransactionEffects>(
    effects: &E,
    mut transaction: Transaction<'_, Postgres>,
    owner_id: Uuid,
    expected_auth_generation: Option<i64>,
    jid: &str,
    route: RosterRemovalRoute<'_>,
) -> Result<AuthorizedRosterRemoval> {
    let jid = northstar_xmpp_types::jid::canonicalize_bare(jid)?;

    // Resolve the local account incarnation inside the same transaction which
    // locks and mutates both rosters. The protocol layer must not perform a
    // pre-transaction username lookup which can be invalidated by
    // delete/recreate before commit.
    let local_contact_candidate = match route {
        RosterRemovalRoute::Local {
            contact_username: Some(username),
            ..
        } => sqlx::query("SELECT id,username,auth_generation FROM users WHERE username=$1")
            .bind(username)
            .fetch_optional(&mut *transaction)
            .await?
            .map(|row| {
                Ok::<_, sqlx::Error>(LocalRosterContact {
                    id: row.try_get("id")?,
                    username: row.try_get("username")?,
                    auth_generation: row.try_get("auth_generation")?,
                })
            })
            .transpose()?,
        RosterRemovalRoute::Local {
            contact_username: None,
            ..
        }
        | RosterRemovalRoute::Remote { .. } => None,
    };
    let mut lock_ids = vec![owner_id];
    if let Some(contact) = local_contact_candidate
        .as_ref()
        .filter(|contact| contact.id != owner_id)
    {
        lock_ids.push(contact.id);
        lock_ids.sort_unstable();
    }
    let locked =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM northstar_lock_user_rows_update($1)")
            .bind(&lock_ids)
            .fetch_all(&mut *transaction)
            .await?;
    if !locked.contains(&owner_id) {
        transaction.rollback().await?;
        return Ok(AuthorizedRosterRemoval::Missing);
    }
    if let Some(expected_auth_generation) = expected_auth_generation {
        let authorized = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND auth_generation=$2 AND NOT is_disabled)",
        )
        .bind(owner_id)
        .bind(expected_auth_generation)
        .fetch_one(&mut *transaction)
        .await?;
        if !authorized {
            transaction.rollback().await?;
            return Ok(AuthorizedRosterRemoval::Unauthorized);
        }
    }
    let locked_contact = if let Some(candidate) =
        local_contact_candidate.filter(|contact| locked.contains(&contact.id))
    {
        sqlx::query(
            "SELECT id,username,auth_generation,is_disabled FROM users
              WHERE id=$1 AND username=$2",
        )
        .bind(candidate.id)
        .bind(&candidate.username)
        .fetch_optional(&mut *transaction)
        .await?
        .map(|row| {
            (
                LocalRosterContact {
                    id: row.get("id"),
                    username: row.get("username"),
                    auth_generation: row.get("auth_generation"),
                },
                row.get::<bool, _>("is_disabled"),
            )
        })
    } else {
        None
    };
    let durable_contact = locked_contact.as_ref().map(|(contact, _)| contact);

    let owner_row = sqlx::query(
        "SELECT subscription,ask FROM roster_items WHERE owner_id=$1 AND contact_jid=$2 FOR UPDATE",
    )
    .bind(owner_id)
    .bind(&jid)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(owner_row) = owner_row else {
        transaction.commit().await?;
        return Ok(AuthorizedRosterRemoval::Missing);
    };
    let owner_subscription: String = owner_row.try_get("subscription")?;
    let owner_ask: Option<String> = owner_row.try_get("ask")?;

    let (pending_outbound, pending_inbound) = match (&route, durable_contact) {
        (RosterRemovalRoute::Local { .. }, Some(contact)) if contact.id != owner_id => {
            let pending_outbound = sqlx::query_scalar::<_, i32>(
                "SELECT 1 FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2 FOR UPDATE",
            )
            .bind(owner_id)
            .bind(contact.id)
            .fetch_optional(&mut *transaction)
            .await?
            .is_some();
            let pending_inbound = sqlx::query_scalar::<_, i32>(
                "SELECT 1 FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2 FOR UPDATE",
            )
            .bind(contact.id)
            .bind(owner_id)
            .fetch_optional(&mut *transaction)
            .await?
            .is_some();
            (pending_outbound, pending_inbound)
        }
        (RosterRemovalRoute::Remote { .. }, _) => {
            let pending_inbound = sqlx::query_scalar::<_, i32>(
                "SELECT 1 FROM federated_presence_pending WHERE recipient_id=$1 AND from_jid=$2 FOR UPDATE",
            )
            .bind(owner_id)
            .bind(&jid)
            .fetch_optional(&mut *transaction)
            .await?
            .is_some();
            (owner_ask.as_deref() == Some("subscribe"), pending_inbound)
        }
        _ => (owner_ask.as_deref() == Some("subscribe"), false),
    };
    let send_unsubscribe = matches!(owner_subscription.as_str(), "to" | "both")
        || owner_ask.as_deref() == Some("subscribe")
        || pending_outbound;
    let send_unsubscribed =
        matches!(owner_subscription.as_str(), "from" | "both") || pending_inbound;

    let mut contact_change = None;
    if let (RosterRemovalRoute::Local { owner_jid, .. }, Some(contact)) = (route, durable_contact) {
        let contact_id = contact.id;
        if contact_id != owner_id && locked.contains(&contact_id) {
            let owner_jid = northstar_xmpp_types::jid::canonicalize_bare(owner_jid)?;
            let contact_row = sqlx::query(
                "SELECT subscription,ask,approved FROM roster_items WHERE owner_id=$1 AND contact_jid=$2 FOR UPDATE",
            )
            .bind(contact_id)
            .bind(&owner_jid)
            .fetch_optional(&mut *transaction)
            .await?;
            let contact_subscription = contact_row
                .as_ref()
                .map(|row| row.try_get::<String, _>("subscription"))
                .transpose()?
                .unwrap_or_else(|| "none".to_owned());
            let contact_ask = contact_row
                .as_ref()
                .map(|row| row.try_get::<Option<String>, _>("ask"))
                .transpose()?
                .flatten();
            let contact_approved = contact_row
                .as_ref()
                .map(|row| row.try_get::<bool, _>("approved"))
                .transpose()?
                .unwrap_or(false);
            let mut next_subscription = contact_subscription.clone();
            let mut next_ask = contact_ask.clone();
            if send_unsubscribe {
                next_subscription =
                    remove_subscription_direction(&next_subscription, "from").to_owned();
            }
            if send_unsubscribed {
                next_subscription =
                    remove_subscription_direction(&next_subscription, "to").to_owned();
                next_ask = None;
            }
            let changed = contact_row.as_ref().is_some_and(|_| {
                next_subscription != contact_subscription || next_ask != contact_ask
            });
            if changed {
                contact_change = Some(
                    update_subscription_in_transaction(
                        effects,
                        &mut transaction,
                        contact_id,
                        &owner_jid,
                        &next_subscription,
                        next_ask.as_deref(),
                        Some(contact_approved),
                    )
                    .await?,
                );
            }
            if send_unsubscribe {
                sqlx::query(
                    "DELETE FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2",
                )
                .bind(owner_id)
                .bind(contact_id)
                .execute(&mut *transaction)
                .await?;
            }
            if send_unsubscribed {
                sqlx::query(
                    "DELETE FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2",
                )
                .bind(contact_id)
                .bind(owner_id)
                .execute(&mut *transaction)
                .await?;
            }
        }
    }

    if let RosterRemovalRoute::Remote {
        target_domain,
        unsubscribe_stanza,
        unsubscribed_stanza,
        bounce_to,
        policy,
    } = route
    {
        if send_unsubscribe {
            effects
                .enqueue_federated_stanza(
                    &mut transaction,
                    target_domain,
                    unsubscribe_stanza,
                    bounce_to,
                    policy,
                )
                .await?;
        }
        if send_unsubscribed {
            effects
                .enqueue_federated_stanza(
                    &mut transaction,
                    target_domain,
                    unsubscribed_stanza,
                    bounce_to,
                    policy,
                )
                .await?;
            sqlx::query(
                "DELETE FROM federated_presence_pending WHERE recipient_id=$1 AND from_jid=$2",
            )
            .bind(owner_id)
            .bind(&jid)
            .execute(&mut *transaction)
            .await?;
        }
    }

    sqlx::query("DELETE FROM roster_items WHERE owner_id=$1 AND contact_jid=$2")
        .bind(owner_id)
        .bind(&jid)
        .execute(&mut *transaction)
        .await?;
    effects
        .cancel_inaccessible_pep_subscriptions(&mut transaction, owner_id, &jid)
        .await?;
    let version: i64 = sqlx::query_scalar("SELECT northstar_user_bump_roster_version($1)")
        .bind(owner_id)
        .fetch_one(&mut *transaction)
        .await?;
    let mut owner_change =
        record_roster_change(&mut transaction, owner_id, version, &jid, true).await?;
    if let Some(generation) = expected_auth_generation {
        owner_change.owner_authority = Some((owner_id, generation));
    }
    transaction.commit().await?;
    Ok(AuthorizedRosterRemoval::Removed(Box::new(
        RosterRemovalTransition {
            owner_change,
            contact_change,
            local_contact: locked_contact
                .and_then(|(contact, disabled)| (!disabled).then_some(contact)),
            send_unsubscribe,
            send_unsubscribed,
        },
    )))
}
