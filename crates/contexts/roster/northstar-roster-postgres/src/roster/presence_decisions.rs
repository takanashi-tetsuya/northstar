use super::roster_item;
use crate::privacy::read_communication_policies;
use anyhow::Result;
use northstar_roster_application::probe_decision::{
    BroadcastFacts, BroadcastQuery, ProbeDecision, ProbeDelivery, ProbeQuery,
};
use northstar_roster_application::{
    CommunicationDecision, CommunicationPolicyQuery, PolicyDirection, PolicySubject,
};
use northstar_roster_core::PresenceAccount;
use northstar_xep_0016::PrivacyStanzaKind;
use northstar_xmpp_types::jid::CanonicalJid;
use sqlx::{PgPool, Postgres, Row, Transaction};

async fn snapshot(pool: &PgPool) -> Result<Transaction<'_, Postgres>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

async fn policies(
    transaction: &mut Transaction<'_, Postgres>,
    queries: &[CommunicationPolicyQuery],
) -> Result<Vec<CommunicationDecision>> {
    let mut decisions = Vec::with_capacity(queries.len());
    for batch in queries.chunks(128) {
        decisions.extend(read_communication_policies(&mut **transaction, batch).await?);
    }
    Ok(decisions)
}

async fn account_is_current(
    transaction: &mut Transaction<'_, Postgres>,
    id: uuid::Uuid,
    username: &str,
    generation: i64,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND username=$2
                       AND auth_generation=$3 AND NOT is_disabled)",
    )
    .bind(id)
    .bind(username)
    .bind(generation)
    .fetch_one(&mut **transaction)
    .await?)
}

pub async fn read_broadcast_facts(
    pool: &PgPool,
    query: BroadcastQuery<'_>,
) -> Result<Vec<BroadcastFacts>> {
    let mut transaction = snapshot(pool).await?;
    let actor = CanonicalJid::parse(&query.actor.full_jid)?;
    anyhow::ensure!(
        actor.domainpart() == query.local_domain
            && account_is_current(
                &mut transaction,
                query.actor.account_id,
                actor.localpart().unwrap_or_default(),
                query.actor.auth_generation,
            )
            .await?,
        "broadcast presence account authority expired"
    );
    let mut facts = Vec::new();
    for batch in query.candidates.chunks(128) {
        let keys: Vec<_> = batch
            .iter()
            .map(|candidate| candidate.jid.clone())
            .collect();
        let rows = sqlx::query(
            "SELECT roster.contact_jid, roster.subscription, roster.ask,
                    recipient.id, recipient.username, recipient.auth_generation
               FROM roster_items roster
               JOIN users owner ON owner.id = roster.owner_id
                   AND owner.auth_generation = $2 AND NOT owner.is_disabled
               LEFT JOIN users recipient ON recipient.username = split_part(roster.contact_jid, '@', 1)
                   AND split_part(roster.contact_jid, '@', 2) = $3
                   AND NOT recipient.is_disabled
              WHERE roster.owner_id = $1 AND roster.contact_jid = ANY($4)
              ORDER BY roster.contact_jid",
        )
        .bind(query.actor.account_id)
        .bind(query.actor.auth_generation)
        .bind(query.local_domain)
        .bind(&keys)
        .fetch_all(&mut *transaction)
        .await?;

        let mut checks = Vec::new();
        let mut pending = Vec::new();
        for row in rows {
            let jid: String = row.try_get("contact_jid")?;
            let Some(candidate) = batch.iter().find(|candidate| candidate.jid == jid) else {
                continue;
            };
            let peer = CanonicalJid::parse_bare(&jid)?;
            let account = row
                .try_get::<Option<uuid::Uuid>, _>("id")?
                .map(|id| -> Result<_> {
                    Ok(PresenceAccount {
                        id,
                        username: row.try_get("username")?,
                        auth_generation: row.try_get("auth_generation")?,
                    })
                })
                .transpose()?;
            if peer.domainpart() == query.local_domain
                && (account.is_none() || account != candidate.account)
            {
                continue;
            }

            let subscription: String = row.try_get("subscription")?;
            let first = checks.len();
            checks.push(CommunicationPolicyQuery {
                account_id: query.actor.account_id,
                expected_auth_generation: Some(query.actor.auth_generation),
                subject: PolicySubject::Connection {
                    connection_id: query.actor.connection_id,
                    expects_active: query.expects_active,
                },
                peer: jid.clone(),
                kind: PrivacyStanzaKind::PresenceOut,
                direction: PolicyDirection::Outbound,
                check_owner_block: jid != query.actor.bare_jid(),
                check_peer_block: false,
            });
            if let Some(account) = &account {
                // Reverse block screening also applies when the recipient
                // has no available route (pending subscription recovery).
                checks.push(CommunicationPolicyQuery {
                    account_id: account.id,
                    expected_auth_generation: Some(account.auth_generation),
                    subject: PolicySubject::AccountDefault,
                    peer: query.actor.full_jid.clone(),
                    kind: PrivacyStanzaKind::PresenceIn,
                    direction: PolicyDirection::Inbound,
                    check_owner_block: jid != query.actor.bare_jid(),
                    check_peer_block: false,
                });
            }
            let offset = checks.len();
            let routes: Vec<_> = candidate
                .routes
                .iter()
                .filter(|route| {
                    matches!(subscription.as_str(), "from" | "both")
                        && account.as_ref().is_some_and(|account| {
                            route.exact.account_id == account.id
                                && route.exact.auth_generation == account.auth_generation
                                && northstar_xmpp_types::jid_text::bare_jid(&route.exact.full_jid)
                                    == jid
                        })
                })
                .collect();
            checks.extend(routes.iter().map(|route| {
                let mut policy = route.policy(&query.actor.full_jid, PolicyDirection::Inbound);
                policy.check_owner_block = jid != query.actor.bare_jid();
                policy
            }));
            pending.push((
                BroadcastFacts {
                    jid,
                    subscription,
                    ask: row.try_get("ask")?,
                    account,
                    recipients: Vec::new(),
                },
                first,
                offset..checks.len(),
                routes,
            ));
        }
        let decisions = policies(&mut transaction, &checks).await?;
        for (mut fact, first, recipient_range, routes) in pending {
            if !decisions[first].allows()
                || (recipient_range.start == first + 2
                    && matches!(
                        decisions[first + 1],
                        CommunicationDecision::OwnerBlocks | CommunicationDecision::StaleAccount
                    ))
            {
                continue;
            }
            fact.recipients = routes
                .into_iter()
                .zip(&decisions[recipient_range])
                .filter(|(_, decision)| decision.allows())
                .map(|(route, _)| route.clone())
                .collect();
            facts.push(fact);
        }
    }
    transaction.commit().await?;
    Ok(facts)
}

pub async fn decide_probe(pool: &PgPool, query: ProbeQuery<'_>) -> Result<ProbeDecision> {
    let mut transaction = snapshot(pool).await?;
    let decision = probe_in_snapshot(&mut transaction, query).await?;
    transaction.commit().await?;
    Ok(decision)
}

async fn probe_in_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    query: ProbeQuery<'_>,
) -> Result<ProbeDecision> {
    let target = CanonicalJid::parse(query.target)?;
    let requester = CanonicalJid::parse(query.requester)?;
    let same_account = target.to_bare() == requester.to_bare();
    let local = target.domainpart() == requester.domainpart();
    // Local decisions need a captured recipient connection. The federation
    // host authenticates the peer before supplying a request without routes.
    if target.localpart() != Some(query.owner.username.as_str())
        || local == query.recipients.is_empty()
        || query
            .recipients
            .iter()
            .any(|route| !address_matches(&requester, &route.exact.full_jid))
    {
        return Ok(ProbeDecision::Silent);
    }
    if !account_is_current(
        transaction,
        query.owner.id,
        &query.owner.username,
        query.owner.auth_generation,
    )
    .await?
    {
        return Ok(ProbeDecision::Silent);
    }
    let owner_gate = CommunicationPolicyQuery {
        account_id: query.owner.id,
        expected_auth_generation: Some(query.owner.auth_generation),
        subject: PolicySubject::AccountDefault,
        peer: query.requester.to_owned(),
        kind: PrivacyStanzaKind::PresenceIn,
        direction: PolicyDirection::Inbound,
        check_owner_block: !same_account,
        check_peer_block: false,
    };
    let mut checks = vec![owner_gate];
    for recipient in query.recipients {
        let mut check = recipient.policy(query.target, PolicyDirection::Outbound);
        check.check_owner_block = !same_account;
        checks.push(check);
    }
    let mut pairs = Vec::new();
    for (owner, candidate) in query.candidates.iter().enumerate() {
        let route = &candidate.route;
        if route.exact.account_id != query.owner.id
            || route.exact.auth_generation != query.owner.auth_generation
            || !address_matches(&target, &route.exact.full_jid)
        {
            continue;
        }
        let begin = checks.len();
        let mut check = route.policy(query.requester, PolicyDirection::Outbound);
        check.check_owner_block = !same_account;
        checks.push(check);
        if query.explicit && !local {
            checks.push(route.policy(query.requester, PolicyDirection::Inbound));
        }
        let owner_end = checks.len();
        for recipient in query.recipients {
            let mut check = recipient.policy(&route.exact.full_jid, PolicyDirection::Inbound);
            check.check_owner_block = !same_account;
            checks.push(check);
        }
        pairs.push((owner, begin, owner_end, checks.len()));
    }
    let decisions = policies(transaction, &checks).await?;
    if matches!(
        decisions[0],
        CommunicationDecision::StaleAccount | CommunicationDecision::OwnerBlocks
    ) || (local
        && decisions[1..=query.recipients.len()]
            .iter()
            .all(|decision| {
                if query.explicit {
                    !decision.allows()
                } else {
                    matches!(decision, CommunicationDecision::StaleAccount)
                }
            }))
    {
        return Ok(ProbeDecision::Silent);
    }
    let subscribed = roster_item(&mut **transaction, query.owner.id, &requester.bare())
        .await?
        .is_some_and(|item| matches!(item.2.as_str(), "from" | "both"));
    let mut directed_authority = None;
    let mut any_available = false;
    let mut deliveries = Vec::new();
    for (owner, begin, owner_end, end) in pairs {
        let candidate = &query.candidates[owner];
        let directed =
            !subscribed && query.explicit && target.resourcepart().is_some() && candidate.directed;
        if !subscribed && !directed {
            continue;
        }
        if directed {
            directed_authority = Some(owner);
        }
        if !candidate.available {
            continue;
        }
        any_available = true;
        if !decisions[begin..owner_end]
            .iter()
            .all(CommunicationDecision::allows)
        {
            continue;
        }
        if !local {
            deliveries.push(ProbeDelivery {
                owner,
                recipient: None,
                directed,
            });
        }
        for (recipient, decision) in decisions[owner_end..end].iter().enumerate() {
            if decision.allows() && (!query.explicit || decisions[1 + recipient].allows()) {
                deliveries.push(ProbeDelivery {
                    owner,
                    recipient: Some(recipient),
                    directed,
                });
            }
        }
    }
    if !deliveries.is_empty() {
        Ok(ProbeDecision::Available(deliveries))
    } else if !query.explicit || any_available {
        Ok(ProbeDecision::Silent)
    } else if !subscribed && directed_authority.is_none() {
        Ok(ProbeDecision::Unsubscribed)
    } else if local {
        let status_peer = target.bare();
        let checks: Vec<_> = query
            .recipients
            .iter()
            .map(|route| {
                let mut policy = route.policy(&status_peer, PolicyDirection::Inbound);
                policy.check_owner_block = !same_account;
                policy
            })
            .collect();
        if policies(transaction, &checks)
            .await?
            .iter()
            .any(CommunicationDecision::allows)
        {
            Ok(ProbeDecision::Unavailable {
                directed: directed_authority,
            })
        } else {
            Ok(ProbeDecision::Silent)
        }
    } else if decisions[0].allows() {
        Ok(ProbeDecision::Unavailable {
            directed: directed_authority,
        })
    } else {
        Ok(ProbeDecision::Silent)
    }
}

fn address_matches(address: &CanonicalJid, full: &str) -> bool {
    if address.resourcepart().is_some() {
        address.to_string() == full
    } else {
        address.bare() == northstar_xmpp_types::jid_text::bare_jid(full)
    }
}
