use crate::node::ServerNode;
use northstar_operations_application::admin_presence::{AdminPresenceSources, AnnouncementRoutes};
use std::collections::BTreeSet;
use std::time::Duration;

impl ServerNode {
    pub(crate) fn admin_remote_announcement_enabled(&self) -> bool {
        self.cluster.is_enabled()
    }
}

impl AdminPresenceSources for ServerNode {
    fn local_online_bare_jids(&self) -> BTreeSet<String> {
        self.sessions.local_online_bare_jids()
    }

    fn local_activity_bare_jids(&self, idle: Duration) -> (BTreeSet<String>, BTreeSet<String>) {
        self.sessions.local_activity_bare_jids(idle)
    }

    async fn cluster_online_bare_jids(&self) -> anyhow::Result<BTreeSet<String>> {
        self.cluster.online_bare_jids().await
    }

    async fn cluster_activity_bare_jids(
        &self,
        idle_seconds: u64,
        active: bool,
    ) -> anyhow::Result<BTreeSet<String>> {
        self.cluster.activity_bare_jids(idle_seconds, active).await
    }
}

impl AnnouncementRoutes for ServerNode {
    fn local_node_id(&self) -> &str {
        &self.cluster.node_id
    }

    async fn account_nodes(&self, account: &str) -> anyhow::Result<Vec<String>> {
        self.cluster.lookup_nodes(account).await
    }

    async fn send_to_node_available(
        &self,
        node_id: &str,
        account: &str,
        stanza: &str,
    ) -> anyhow::Result<bool> {
        self.cluster
            .send_to_node_available(node_id, account, stanza)
            .await
    }
}
