//! Live, verified MIX capability admission for the cluster listener.

use crate::ClusterMixCapability;
use dashmap::DashMap;
use northstar_protocol_runtime::caps::{CapsObservationOwner, CapsResourceIndex, PendingCapsIndex};
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::local_routes::session_table::local_caps_route_epoch_matches;
use std::sync::{atomic::Ordering, Arc};

pub struct ClusterListenerMixCaps {
    pub sessions: Arc<DashMap<String, OnlineSession>>,
    pub verified: Arc<CapsResourceIndex>,
    pub pending: Arc<PendingCapsIndex>,
}

impl ClusterListenerMixCaps {
    pub fn capability(&self, full_jid: &str) -> ClusterMixCapability {
        let Ok(full_jid) = northstar_xmpp_types::jid::canonical_session_key(full_jid) else {
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
                if summary.has_feature(northstar_room_core::mix::CORE_NS)
                    || summary.has_feature(northstar_room_core::mix::PAM_NS) =>
            {
                ClusterMixCapability::Supported
            }
            Some(_) => ClusterMixCapability::Unsupported,
            None => ClusterMixCapability::Unknown,
        }
    }
}
