//! The node's side of the operations context's session handlers.

use super::AppState;
use northstar_operations_application::admin_commands::{
    AdminCommandRepository, AdminCommandService, AdminScramPolicy,
};
use northstar_operations_xmpp::OperationsSessionHost;
use std::collections::BTreeSet;

impl OperationsSessionHost for AppState {
    fn command_service(&self) -> &AdminCommandService<impl AdminCommandRepository> {
        self.admin_command_service()
    }

    fn command_local_domain(&self) -> &str {
        self.local_domain()
    }

    fn command_scram_policy(&self) -> AdminScramPolicy {
        self.admin_scram_policy()
    }

    fn command_service_control_available(&self) -> bool {
        self.xmpp_service_control_enabled() && self.service_control_available()
    }

    fn command_send_local_announcement(&self, stanza: &str) -> BTreeSet<String> {
        self.send_local_announcement(stanza)
    }

    fn command_remote_announcement_enabled(&self) -> bool {
        self.admin_remote_announcement_enabled()
    }

    fn command_replace_federation_rules(&self, blacklist: Vec<String>, whitelist: Vec<String>) {
        self.replace_runtime_federation_cache(blacklist, whitelist);
    }

    async fn command_send_remote_announcement(
        &self,
        bare: &str,
        stanza: &str,
    ) -> anyhow::Result<bool> {
        self.send_remote_announcement_to_account(bare, stanza).await
    }

    async fn command_online_bare_jids(&self) -> anyhow::Result<BTreeSet<String>> {
        self.admin_online_bare_jids().await
    }

    async fn command_activity_bare_jids(
        &self,
    ) -> anyhow::Result<(BTreeSet<String>, BTreeSet<String>)> {
        self.admin_activity_bare_jids().await
    }
}
