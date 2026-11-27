use super::{expects_active, wire::SnapshotEntry, ClusterListenerBlocking};
use crate::ClusterAdapters;
use northstar_roster_application::{
    blocking::matches, blocking_mutation::BlockingRouteCandidate, ExactPresenceRoute,
};
use northstar_xmpp_types::jid_text::bare_jid;
use std::{collections::BTreeMap, sync::atomic::Ordering};

impl<A: ClusterAdapters> ClusterListenerBlocking<A> {
    pub(crate) fn snapshot_entries(
        &self,
        owner: &str,
        patterns: Option<&[String]>,
        after: Option<(&str, Option<&str>)>,
        limit: Option<usize>,
    ) -> Vec<SnapshotEntry> {
        let covered = |jid: &str| {
            patterns.is_none_or(|patterns| patterns.iter().any(|key| matches(key, jid)))
        };
        let mut entries = Vec::new();
        let mut sessions = self
            .sessions
            .iter()
            .filter_map(|session| {
                let full = session.key();
                if !session.routable.load(Ordering::Acquire)
                    || session.disconnect.is_cancelled()
                    || (bare_jid(full) != owner && !covered(full))
                    || after.is_some_and(|(cursor, _)| full.as_str() < cursor)
                {
                    return None;
                }
                Some((full.clone(), session.value().clone()))
            })
            .collect::<Vec<_>>();
        sessions.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        for (full, session) in sessions {
            let available = session.available.load(Ordering::Acquire);
            let route = ExactPresenceRoute {
                account_id: session.user_id,
                auth_generation: session.auth_generation,
                connection_id: session.connection_id,
                full_jid: full.clone(),
                node_id: limit.map(|_| self.cluster.node_id.clone()),
            };
            let expects_active = expects_active(&session);
            if after.is_none_or(|cursor| (full.as_str(), None) > cursor) {
                entries.push(SnapshotEntry {
                    route: route.clone(),
                    available,
                    expects_active,
                    directed: None,
                });
            }
            if bare_jid(&full) == owner && available {
                let mut directed = session
                    .directed_presence
                    .iter()
                    .filter(|key| {
                        patterns.is_none_or(|patterns| {
                            patterns.iter().any(|pattern| {
                                matches(pattern, key.key()) || matches(key.key(), pattern)
                            })
                        })
                    })
                    .map(|key| key.key().clone())
                    .filter(|key| {
                        after.is_none_or(|cursor| (full.as_str(), Some(key.as_str())) > cursor)
                    })
                    .collect::<Vec<_>>();
                directed.sort_unstable();
                entries.extend(directed.into_iter().map(|directed| SnapshotEntry {
                    route: route.clone(),
                    available,
                    expects_active,
                    directed: Some(directed),
                }));
            }
            if let Some(limit) = limit.filter(|limit| entries.len() >= *limit) {
                entries.truncate(limit);
                break;
            }
        }
        entries
    }
}

pub(super) fn assemble_candidates(entries: Vec<SnapshotEntry>) -> Vec<BlockingRouteCandidate> {
    let mut candidates = BTreeMap::new();
    for entry in entries {
        let key = (entry.route.full_jid.clone(), entry.route.node_id.clone());
        if let Some(grant) = entry.directed {
            if let Some(candidate) = candidates.get_mut(&key) {
                let candidate: &mut BlockingRouteCandidate = candidate;
                if candidate.route == entry.route {
                    candidate.directed.push(grant);
                }
            }
        } else {
            candidates.insert(
                key,
                BlockingRouteCandidate {
                    route: entry.route,
                    available: entry.available,
                    expects_active: entry.expects_active,
                    directed: Vec::new(),
                },
            );
        }
    }
    candidates.into_values().collect()
}
