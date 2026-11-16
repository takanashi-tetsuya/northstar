//! Builds the cluster listener's MIX capability admission (`cluster::listener_mix_caps`).

use crate::cluster::listener_mix_caps::ClusterListenerMixCaps;
use crate::node::ServerNode;
use std::sync::Arc;

impl ServerNode {
    pub(crate) fn cluster_listener_mix_caps(&self) -> ClusterListenerMixCaps {
        ClusterListenerMixCaps {
            sessions: Arc::clone(&self.sessions),
            verified: Arc::clone(&self.caps_by_jid),
            pending: Arc::clone(&self.pending_caps),
        }
    }
}
