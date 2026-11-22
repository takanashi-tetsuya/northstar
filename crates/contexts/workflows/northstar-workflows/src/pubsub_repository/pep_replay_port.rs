//! Resolve a page of replay authority and last items in one PEP snapshot.

use super::pep_snapshot_port::{node_access, read_requester, SnapshotRequester};
use super::{map_database_busy, PostgresPubSubRepository};
use anyhow::{bail, ensure, Result};
use northstar_auth_postgres::users::{find_enabled_user, EnabledUser};
use northstar_pubsub_application::{
    pep_replay_local_owner, pep_replay_origin, pep_replay_request_allowed,
    PepReplayQueryRepository, PepRequester,
};
use northstar_pubsub_core::{
    PepReplayCursor, PepReplayEntry, PepReplayMode, PepReplayPage, PepReplayQuery, PubSubAccount,
};
use northstar_pubsub_postgres::{
    begin_pep_snapshot, pep_node, pep_replay_caps_subscriptions, pep_replay_explicit_page,
    pep_replay_latest_item, pep_subscribers,
};
use northstar_roster_postgres::roster::roster_page_after;
use sqlx::{Postgres, Transaction};
use std::collections::{BTreeMap, HashMap, HashSet};
use uuid::Uuid;

impl PepReplayQueryRepository for PostgresPubSubRepository {
    async fn pep_replay_page(&self, query: &PepReplayQuery) -> Result<PepReplayPage> {
        if query.local_domain != self.domain || !pep_replay_request_allowed(query) {
            return Ok(PepReplayPage::default());
        }
        let result = async {
            let mut tx = begin_pep_snapshot(&self.pool).await?;
            let page = if let PepReplayMode::AfterSubscribe { owner, node, .. } = &query.mode {
                ensure!(
                    query.after.is_none(),
                    "direct PEP replay does not take a cursor"
                );
                self.pep_replay_after_subscribe(&mut tx, query, owner, node)
                    .await?
            } else {
                self.pep_replay_presence_page(&mut tx, query).await?
            };
            tx.commit().await?;
            Ok(page)
        }
        .await;
        result.map_err(map_database_busy)
    }
}

struct Candidate {
    cursor: PepReplayCursor,
    username: String,
    explicit_nodes: Vec<String>,
}

impl Candidate {
    fn caps(cursor: PepReplayCursor, username: String) -> Self {
        Self {
            cursor,
            username,
            explicit_nodes: Vec::new(),
        }
    }
}

impl PostgresPubSubRepository {
    async fn pep_replay_presence_page(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        query: &PepReplayQuery,
    ) -> Result<PepReplayPage> {
        let limit = query.limit.max(1);
        let (candidates, has_more) = presence_candidates(tx, query, limit).await?;
        let mut page = PepReplayPage {
            scanned: candidates.len(),
            next: candidates
                .last()
                .filter(|_| has_more)
                .map(|candidate| candidate.cursor.clone()),
            ..PepReplayPage::default()
        };
        let mut owners = Vec::new();
        for candidate in candidates {
            if let Some(owner) = find_enabled_user(&mut **tx, &candidate.username).await? {
                if matches!(candidate.cursor, PepReplayCursor::Explicit(id) if id != owner.id) {
                    continue;
                }
                owners.push((owner, candidate.explicit_nodes));
            }
        }
        let wanted = match &query.mode {
            PepReplayMode::LocalCaps { wanted } | PepReplayMode::FederatedCaps { wanted } => {
                Some(wanted)
            }
            _ => None,
        };
        let mut explicit = HashMap::<Uuid, HashSet<String>>::new();
        if wanted.is_some() && !owners.is_empty() {
            let owner_ids = owners.iter().map(|(owner, _)| owner.id).collect::<Vec<_>>();
            for subscription in
                pep_replay_caps_subscriptions(&mut **tx, &query.requester, &owner_ids).await?
            {
                explicit
                    .entry(subscription.owner_id)
                    .or_default()
                    .insert(subscription.node);
            }
        }
        let requester_jid = query.requester.to_string();
        for (owner, explicit_nodes) in owners {
            let owner_jid = self.pep_owner_jid(&owner.username)?;
            let requester =
                read_requester(tx, owner.id, &owner_jid, PepRequester::Jid(&requester_jid)).await?;
            let subscriptions = explicit.get(&owner.id);
            for node in wanted.unwrap_or(&explicit_nodes) {
                let has_explicit = wanted.is_none()
                    || subscriptions.is_some_and(|subscriptions| subscriptions.contains(node));
                if let Some(entry) =
                    read_entry(tx, &owner, &requester, &query.mode, node, has_explicit).await?
                {
                    page.entries.push(entry);
                }
            }
        }
        Ok(page)
    }

    async fn pep_replay_after_subscribe(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        query: &PepReplayQuery,
        captured: &PubSubAccount,
        node: &str,
    ) -> Result<PepReplayPage> {
        let Some(owner) = find_enabled_user(&mut **tx, &captured.username)
            .await?
            .filter(|owner| {
                owner.id == captured.id && owner.auth_generation == captured.auth_generation
            })
        else {
            return Ok(PepReplayPage::default());
        };
        let requester_jid = query.requester.to_string();
        let has_explicit = pep_subscribers(&mut **tx, owner.id, node)
            .await?
            .iter()
            .any(|sub| sub.jid == requester_jid);
        let owner_jid = self.pep_owner_jid(&owner.username)?;
        let requester =
            read_requester(tx, owner.id, &owner_jid, PepRequester::Jid(&requester_jid)).await?;
        let entry = read_entry(tx, &owner, &requester, &query.mode, node, has_explicit).await?;
        Ok(PepReplayPage {
            entries: entry.into_iter().collect(),
            next: None,
            scanned: 1,
        })
    }
}

async fn presence_candidates(
    tx: &mut Transaction<'_, Postgres>,
    query: &PepReplayQuery,
    limit: usize,
) -> Result<(Vec<Candidate>, bool)> {
    let fetch_limit = limit.saturating_add(1);
    let sql_limit = i64::try_from(fetch_limit).unwrap_or(i64::MAX);
    let mut candidates = match (&query.mode, &query.after) {
        (PepReplayMode::Explicit, None | Some(PepReplayCursor::Explicit(_))) => {
            let after = match &query.after {
                Some(PepReplayCursor::Explicit(after)) => Some(*after),
                _ => None,
            };
            let mut owners = BTreeMap::new();
            let (subscriptions, has_more) = pep_replay_explicit_page(
                &mut **tx,
                &query.requester,
                after,
                i64::try_from(limit).unwrap_or(i64::MAX),
            )
            .await?;
            for subscription in subscriptions {
                owners
                    .entry(subscription.owner_id)
                    .or_insert_with(|| Candidate {
                        cursor: PepReplayCursor::Explicit(subscription.owner_id),
                        username: subscription.owner_username,
                        explicit_nodes: Vec::new(),
                    })
                    .explicit_nodes
                    .push(subscription.node);
            }
            return Ok((owners.into_values().collect(), has_more));
        }
        (
            PepReplayMode::LocalCaps { .. },
            None | Some(PepReplayCursor::LocalSelf | PepReplayCursor::LocalRoster(_)),
        ) => local_candidates(tx, query, fetch_limit).await?,
        (PepReplayMode::FederatedCaps { .. }, None | Some(PepReplayCursor::Federated(_))) => {
            let after = match &query.after {
                Some(PepReplayCursor::Federated(after)) => Some(after.as_str()),
                _ => None,
            };
            crate::pep_roster::pep_presence_owner_page(
                &mut **tx,
                &query.requester.bare().to_string(),
                after,
                sql_limit,
            )
            .await?
            .into_iter()
            .map(|username| Candidate::caps(PepReplayCursor::Federated(username.clone()), username))
            .collect()
        }
        _ => bail!("cursor does not match PEP replay mode"),
    };
    let has_more = candidates.len() > limit;
    candidates.truncate(limit);
    Ok((candidates, has_more))
}

async fn local_candidates(
    tx: &mut Transaction<'_, Postgres>,
    query: &PepReplayQuery,
    fetch_limit: usize,
) -> Result<Vec<Candidate>> {
    let Some(username) = pep_replay_local_owner(query, None) else {
        return Ok(Vec::new());
    };
    let Some(subscriber) = find_enabled_user(&mut **tx, &username).await? else {
        return Ok(Vec::new());
    };
    let mut candidates = Vec::new();
    if query.after.is_none() {
        candidates.push(Candidate::caps(
            PepReplayCursor::LocalSelf,
            subscriber.username,
        ));
    }
    let mut after = match &query.after {
        Some(PepReplayCursor::LocalRoster(contact)) => Some(contact.clone()),
        _ => None,
    };
    while candidates.len() < fetch_limit {
        let remaining = fetch_limit - candidates.len();
        let rows = roster_page_after(
            &mut **tx,
            subscriber.id,
            after.as_deref(),
            i64::try_from(remaining).unwrap_or(i64::MAX),
        )
        .await?;
        let exhausted = rows.len() < remaining;
        for (contact, _, subscription, _) in rows {
            after = Some(contact.clone());
            if let Some(username) = pep_replay_local_owner(query, Some((&contact, &subscription))) {
                candidates.push(Candidate::caps(
                    PepReplayCursor::LocalRoster(contact),
                    username,
                ));
            }
        }
        if exhausted {
            break;
        }
    }
    Ok(candidates)
}

async fn read_entry(
    tx: &mut Transaction<'_, Postgres>,
    owner: &EnabledUser,
    requester: &SnapshotRequester,
    mode: &PepReplayMode,
    node: &str,
    has_explicit: bool,
) -> Result<Option<PepReplayEntry>> {
    let Some(config) = pep_node(&mut **tx, owner.id, node).await? else {
        return Ok(None);
    };
    let config = config.into();
    let Some(origin) = pep_replay_origin(mode, &config, has_explicit) else {
        return Ok(None);
    };
    if node_access(tx, owner.id, requester, &config)
        .await?
        .is_err()
    {
        return Ok(None);
    }
    let item = pep_replay_latest_item(&mut **tx, owner.id, node).await?;
    Ok(item.map(|item| PepReplayEntry {
        owner_id: owner.id,
        owner_username: owner.username.clone(),
        node: node.to_owned(),
        item_id: item.item_id,
        payload: item.payload,
        updated_at: item.updated_at,
        origin,
    }))
}
