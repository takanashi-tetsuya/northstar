use super::AppState;
use std::collections::BTreeSet;
use std::time::Duration;

impl AppState {
    pub(crate) fn admin_remote_announcement_enabled(&self) -> bool {
        self.cluster.is_enabled()
    }

    /// A headline announcement reaches every remote node with an eligible
    /// resource; count the account only if one node accepted it.
    pub(crate) async fn send_remote_announcement_to_account(
        &self,
        account: &str,
        stanza: &str,
    ) -> anyhow::Result<bool> {
        let mut delivered = false;
        for node_id in self.cluster.lookup_nodes(account).await? {
            if node_id != self.cluster.node_id
                && self
                    .cluster
                    .send_to_node_available(&node_id, account, stanza)
                    .await?
            {
                delivered = true;
            }
        }
        Ok(delivered)
    }

    pub(crate) async fn admin_online_bare_jids(&self) -> anyhow::Result<BTreeSet<String>> {
        let mut users = self.local_online_bare_jids();
        users.extend(self.cluster.online_bare_jids().await?);
        Ok(users)
    }

    pub(crate) async fn admin_activity_bare_jids(
        &self,
    ) -> anyhow::Result<(BTreeSet<String>, BTreeSet<String>)> {
        let idle_seconds = self.admin_activity_idle_seconds();
        let (mut online, mut active) =
            self.local_activity_bare_jids(Duration::from_secs(idle_seconds));
        active.extend(self.cluster.activity_bare_jids(idle_seconds, true).await?);
        online.extend(active.iter().cloned());
        online.extend(self.cluster.activity_bare_jids(idle_seconds, false).await?);
        let idle = online.difference(&active).cloned().collect();
        Ok((active, idle))
    }
}
