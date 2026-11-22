//! Read PEP and the relevant account and roster facts on the same connection.

use super::{map_database_busy, PostgresPubSubRepository};
use anyhow::Result;
use northstar_auth_postgres::users::find_enabled_user;
use northstar_pubsub_application::{
    PepAccountItemsRead, PepAccountQuery, PepItemQuery, PepItemRead, PepNodeInfoRead,
    PepNodeItemsRead, PepNodeQuery, PepOwnerQuery, PepOwnerSubscriptionsRead, PepRequester,
    PepSnapshotRepository,
};
use northstar_pubsub_core::{
    pep_read_access, CanonicalJid, PepAccessDenial, PepAccessFacts, PepBlockFacts, PepNodeConfig,
    PepRequesterRelation,
};
use northstar_pubsub_postgres::{
    begin_pep_snapshot, pep_items, pep_items_by_ids, pep_node, pep_nodes, pep_subscribers,
};
use northstar_roster_postgres::roster::{is_blocked, roster_item};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

impl PepSnapshotRepository for PostgresPubSubRepository {
    async fn pep_items_read(&self, query: &PepItemQuery<'_>) -> Result<PepItemRead> {
        let result = async {
            let mut tx = begin_pep_snapshot(&self.pool).await?;
            let view = self
                .pep_node_view(
                    &mut tx,
                    &PepNodeQuery {
                        owner_username: query.owner_username,
                        node: query.node,
                        requester: PepRequester::Jid(query.requester_jid),
                    },
                )
                .await?;
            let outcome = match view {
                PepNodeView::OwnerMissing => PepItemRead::OwnerMissing,
                PepNodeView::NodeMissing => PepItemRead::NodeMissing,
                PepNodeView::Denied(reason) => PepItemRead::Denied(reason),
                PepNodeView::Visible { owner_id, config } => {
                    let items = match &query.selection {
                        None => Vec::new(),
                        Some(selection) if selection.item_ids.is_empty() => {
                            pep_items(&mut *tx, owner_id, query.node, None, selection.max_items)
                                .await?
                        }
                        Some(selection) => {
                            pep_items_by_ids(
                                &mut *tx,
                                owner_id,
                                query.node,
                                &selection.item_ids,
                                selection.max_items,
                            )
                            .await?
                        }
                    };
                    PepItemRead::Items { config, items }
                }
            };
            tx.commit().await?;
            Ok(outcome)
        }
        .await;
        result.map_err(map_database_busy)
    }

    async fn pep_node_info(&self, query: &PepNodeQuery<'_>) -> Result<PepNodeInfoRead> {
        let result = async {
            let mut tx = begin_pep_snapshot(&self.pool).await?;
            let view = self.pep_node_view(&mut tx, query).await?;
            tx.commit().await?;
            Ok(match view {
                PepNodeView::OwnerMissing => PepNodeInfoRead::OwnerMissing,
                PepNodeView::NodeMissing => PepNodeInfoRead::NodeMissing,
                PepNodeView::Denied(reason) => PepNodeInfoRead::Denied(reason),
                PepNodeView::Visible { config, .. } => PepNodeInfoRead::Info { config },
            })
        }
        .await;
        result.map_err(map_database_busy)
    }

    async fn pep_node_items(&self, query: &PepNodeQuery<'_>) -> Result<PepNodeItemsRead> {
        Ok(match self.pep_node_info(query).await? {
            PepNodeInfoRead::OwnerMissing => PepNodeItemsRead::OwnerMissing,
            PepNodeInfoRead::NodeMissing => PepNodeItemsRead::NodeMissing,
            PepNodeInfoRead::Denied(_) => PepNodeItemsRead::Denied,
            PepNodeInfoRead::Info { .. } => PepNodeItemsRead::Visible,
        })
    }

    async fn pep_account_items(&self, query: &PepAccountQuery<'_>) -> Result<PepAccountItemsRead> {
        let result = async {
            let mut tx = begin_pep_snapshot(&self.pool).await?;
            let Some(owner) = find_enabled_user(&mut *tx, query.owner_username).await? else {
                tx.commit().await?;
                return Ok(PepAccountItemsRead::OwnerMissing);
            };
            let owner_jid = self.pep_owner_jid(&owner.username)?;
            let candidates = pep_nodes(&mut *tx, owner.id).await?;
            let requester = read_requester(&mut tx, owner.id, &owner_jid, query.requester).await?;
            let mut nodes = Vec::new();
            for node in candidates {
                let Some(config) = pep_node(&mut *tx, owner.id, &node).await? else {
                    continue;
                };
                let config = config.into();
                if node_access(&mut tx, owner.id, &requester, &config)
                    .await?
                    .is_ok()
                {
                    nodes.push(node);
                }
            }
            tx.commit().await?;
            Ok(PepAccountItemsRead::Nodes {
                owner_jid: owner_jid.to_string(),
                nodes,
            })
        }
        .await;
        result.map_err(map_database_busy)
    }

    async fn pep_owner_subscriptions(
        &self,
        query: &PepOwnerQuery<'_>,
    ) -> Result<PepOwnerSubscriptionsRead> {
        let result = async {
            let mut tx = begin_pep_snapshot(&self.pool).await?;
            let owner = query.owner;
            let current = find_enabled_user(&mut *tx, &owner.username).await?;
            let outcome = if current.is_some_and(|user| user.id == owner.id)
                && pep_node(&mut *tx, owner.id, query.node).await?.is_some()
            {
                let subscriptions = pep_subscribers(&mut *tx, owner.id, query.node)
                    .await?
                    .into_iter()
                    .map(Into::into)
                    .collect();
                PepOwnerSubscriptionsRead::Subscribers(subscriptions)
            } else {
                PepOwnerSubscriptionsRead::NodeMissing
            };
            tx.commit().await?;
            Ok(outcome)
        }
        .await;
        result.map_err(map_database_busy)
    }
}

enum PepNodeView {
    OwnerMissing,
    NodeMissing,
    Denied(PepAccessDenial),
    Visible {
        owner_id: Uuid,
        config: PepNodeConfig,
    },
}

impl PostgresPubSubRepository {
    pub(super) fn pep_owner_jid(&self, username: &str) -> Result<CanonicalJid> {
        CanonicalJid::parse_bare(&format!("{username}@{}", self.domain))
    }

    async fn pep_node_view(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        query: &PepNodeQuery<'_>,
    ) -> Result<PepNodeView> {
        let Some(owner) = find_enabled_user(&mut **tx, query.owner_username).await? else {
            return Ok(PepNodeView::OwnerMissing);
        };
        let Some(config) = pep_node(&mut **tx, owner.id, query.node).await? else {
            return Ok(PepNodeView::NodeMissing);
        };
        let config = config.into();
        let owner_jid = self.pep_owner_jid(&owner.username)?;
        let requester = read_requester(tx, owner.id, &owner_jid, query.requester).await?;
        Ok(
            match node_access(tx, owner.id, &requester, &config).await? {
                Ok(()) => PepNodeView::Visible {
                    owner_id: owner.id,
                    config,
                },
                Err(reason) => PepNodeView::Denied(reason),
            },
        )
    }
}

pub(super) enum SnapshotRequester {
    Owner,
    Other {
        bare_jid: String,
        blocks: PepBlockFacts,
    },
    LocalAnonymous,
    Invalid,
}

pub(super) async fn read_requester(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    owner_jid: &CanonicalJid,
    requester: PepRequester<'_>,
) -> Result<SnapshotRequester> {
    let PepRequester::Jid(jid) = requester else {
        return Ok(SnapshotRequester::LocalAnonymous);
    };
    let Ok(requester) = CanonicalJid::parse(jid) else {
        return Ok(SnapshotRequester::Invalid);
    };
    let bare_jid = requester.bare();
    let owner_bare = owner_jid.bare();
    if bare_jid == owner_bare {
        return Ok(SnapshotRequester::Owner);
    }
    let owner_blocks_requester = is_blocked(&mut **tx, owner_id, &bare_jid).await?;
    let local_username = requester
        .localpart()
        .filter(|_| requester.domainpart() == owner_jid.domainpart());
    let local_requester = match local_username {
        Some(username) => find_enabled_user(&mut **tx, username).await?,
        None => None,
    };
    let requester_blocks_owner = match local_requester {
        Some(account) => is_blocked(&mut **tx, account.id, &owner_bare).await?,
        None => false,
    };
    Ok(SnapshotRequester::Other {
        bare_jid,
        blocks: PepBlockFacts {
            owner_blocks_requester,
            requester_blocks_owner,
        },
    })
}

pub(super) async fn node_access(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    requester: &SnapshotRequester,
    config: &PepNodeConfig,
) -> Result<Result<(), PepAccessDenial>> {
    let mut facts = PepAccessFacts {
        requester: match requester {
            SnapshotRequester::Owner => PepRequesterRelation::Owner,
            SnapshotRequester::Other { bare_jid, .. } => PepRequesterRelation::Other(bare_jid),
            SnapshotRequester::LocalAnonymous => PepRequesterRelation::LocalAnonymous,
            SnapshotRequester::Invalid => PepRequesterRelation::Invalid,
        },
        blocks: PepBlockFacts::default(),
        roster_subscription: None,
        roster_groups: &[],
        config: Some(config),
    };
    let (mut subscription, mut groups) = (None, Vec::new());
    if let SnapshotRequester::Other { bare_jid, blocks } = requester {
        facts.blocks = *blocks;
        if !blocks.owner_blocks_requester {
            match config.access_model.as_str() {
                "presence" => {
                    subscription = roster_item(&mut **tx, owner_id, bare_jid)
                        .await?
                        .map(|(_, _, subscription, _)| subscription);
                }
                "roster" => {
                    groups = crate::pep_roster::roster_matching_groups(
                        &mut **tx,
                        owner_id,
                        bare_jid,
                        &config.roster_groups_allowed,
                    )
                    .await?;
                }
                _ => {}
            }
        }
    }
    facts.roster_subscription = subscription.as_deref();
    facts.roster_groups = &groups;
    Ok(pep_read_access(&facts))
}
