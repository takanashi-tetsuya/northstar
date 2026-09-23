//! Live, verified MIX capability admission for the cluster listener.

use super::{local_caps_route_epoch_matches, AppState, OnlineSession};
use dashmap::DashMap;
use northstar_protocol_runtime::caps::{CapsObservationOwner, CapsResourceIndex, PendingCapsIndex};
use std::sync::{atomic::Ordering, Arc};

pub(crate) struct ClusterListenerMixCaps {
    sessions: Arc<DashMap<String, OnlineSession>>,
    verified: Arc<CapsResourceIndex>,
    pending: Arc<PendingCapsIndex>,
}

pub(crate) enum ClusterMixCapability {
    Supported,
    Unsupported,
    Unknown,
}

impl AppState {
    pub(crate) fn cluster_listener_mix_caps(&self) -> ClusterListenerMixCaps {
        ClusterListenerMixCaps {
            sessions: Arc::clone(&self.sessions),
            verified: Arc::clone(&self.caps_by_jid),
            pending: Arc::clone(&self.pending_caps),
        }
    }
}

impl ClusterListenerMixCaps {
    pub(crate) fn capability(&self, full_jid: &str) -> ClusterMixCapability {
        let Ok(full_jid) = crate::jid::canonical_session_key(full_jid) else {
            return ClusterMixCapability::Unknown;
        };
        let Some(observation) = self.verified.snapshot(&full_jid) else {
            return ClusterMixCapability::Unknown;
        };
        if let CapsObservationOwner::Local(epoch) = observation.owner {
            let current = self.sessions.get(&full_jid).is_some_and(|session| {
                local_caps_route_epoch_matches(
                    session.connection_id,
                    session.caps_observation_generation.load(Ordering::Acquire),
                    session.routable.load(Ordering::Acquire),
                    session.disconnect.is_cancelled(),
                    session.lifecycle.load(Ordering::Acquire),
                    true,
                    epoch,
                )
            });
            if !current {
                // These are exact-epoch compare-removes. A new bind using the
                // same full JID keeps its own observation and pending query.
                self.pending.remove_local_epoch(&full_jid, epoch);
                self.verified.remove_local_epoch(&full_jid, epoch);
                return ClusterMixCapability::Unknown;
            }
        }
        match observation.summary {
            Some(summary)
                if summary.has_feature(crate::xmpp::protocol::mix::CORE_NS)
                    || summary.has_feature(crate::xmpp::protocol::mix::PAM_NS) =>
            {
                ClusterMixCapability::Supported
            }
            Some(_) => ClusterMixCapability::Unsupported,
            None => ClusterMixCapability::Unknown,
        }
    }
}
