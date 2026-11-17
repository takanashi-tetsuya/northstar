//! Bind context shutdown effects to the process runtime supervisor.

use crate::node::ServerNode;
use northstar_runtime::process_shutdown::ProcessShutdownPorts;
use std::{future::Future, time::Duration};

impl ProcessShutdownPorts for ServerNode {
    fn muc_shutdown_notifications(&self) -> impl Future<Output = usize> + '_ {
        let muc_delivery = self.muc_delivery_context();
        async move { northstar_muc_xmpp::shutdown::notify_muc_system_shutdown(&muc_delivery).await }
    }

    fn begin_cluster_shutdown(&self) {
        ServerNode::begin_cluster_shutdown(self);
    }

    fn release_cluster_after_publication_quiescence(
        &self,
        quiesce_timeout: Duration,
    ) -> impl Future<Output = Option<anyhow::Result<()>>> + '_ {
        self.release_cluster_instance_after_publication_quiescence(quiesce_timeout)
    }
}
