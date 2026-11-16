//! The node's side of the operations context's session handlers.

use crate::node::ServerNode;
use northstar_operations_application::admin_commands::{
    AdminCommandRepository, AdminCommandService, AdminScramPolicy,
};
use northstar_operations_xmpp::OperationsSessionHost;
use std::collections::BTreeSet;

impl OperationsSessionHost for ServerNode {
    fn command_service(&self) -> &AdminCommandService<impl AdminCommandRepository> {
        self.operations.admin_command_service()
    }

    fn command_local_domain(&self) -> &str {
        self.config.domain.as_str()
    }

    fn command_scram_policy(&self) -> AdminScramPolicy {
        northstar_operations_application::admin_commands::AdminScramPolicy {
            iterations: self.config.scram_iterations,
            sha1_enabled: self.config.scram_sha1_enabled,
        }
    }

    fn command_service_control_available(&self) -> bool {
        self.config.enable_xmpp_service_control && self.service_control_available()
    }

    fn command_send_local_announcement(&self, stanza: &str) -> BTreeSet<String> {
        self.sessions.send_local_announcement(stanza)
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
