//! Builds the cluster listener's MIX capability admission (`cluster::listener_mix_caps`).

use crate::node::ServerNode;
use northstar_cluster::listener_mix_caps::ClusterListenerMixCaps;
use std::sync::Arc;

impl ServerNode {
    pub(crate) fn cluster_listener_mix_caps(&self) -> ClusterListenerMixCaps {
        ClusterListenerMixCaps {
            sessions: Arc::clone(self.session.live().sessions()),
            verified: Arc::clone(self.session.live().caps_by_jid()),
            pending: Arc::clone(self.session.live().pending_caps()),
        }
    }
}
