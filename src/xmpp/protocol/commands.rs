//! Binds the administrative command handlers to the client session.

use super::ProtocolSession;
use northstar_operations_application::admin_commands::{
    AdminActor, AdminCommandRepository, AdminCommandService, AdminScramPolicy,
};
use northstar_operations_xmpp::commands::CommandSession;
use std::collections::BTreeSet;

impl CommandSession for ProtocolSession {
    fn command_service(&self) -> &AdminCommandService<impl AdminCommandRepository> {
        self.state.admin_command_service()
    }

    fn command_cached_admin(&self) -> Option<AdminActor> {
        self.authenticated.as_ref().map(|cached| {
            AdminActor::new(cached.id, cached.username.clone(), cached.auth_generation)
        })
    }

    fn command_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn command_local_domain(&self) -> &str {
        self.state.local_domain()
    }

    fn command_scram_policy(&self) -> AdminScramPolicy {
        self.state.admin_scram_policy()
    }

    fn command_service_control_available(&self) -> bool {
        self.state.xmpp_service_control_enabled() && self.state.service_control_available()
    }

    fn command_send_local_announcement(&self, stanza: &str) -> BTreeSet<String> {
        self.state.send_local_announcement(stanza)
    }

    fn command_remote_announcement_enabled(&self) -> bool {
        self.state.admin_remote_announcement_enabled()
    }

    fn command_replace_federation_rules(&self, blacklist: Vec<String>, whitelist: Vec<String>) {
        self.state
            .replace_runtime_federation_cache(blacklist, whitelist);
    }

    async fn command_send_remote_announcement(
        &self,
        bare: &str,
        stanza: &str,
    ) -> anyhow::Result<bool> {
        self.state
            .send_remote_announcement_to_account(bare, stanza)
            .await
    }

    async fn command_online_bare_jids(&self) -> anyhow::Result<BTreeSet<String>> {
        self.state.admin_online_bare_jids().await
    }

    async fn command_activity_bare_jids(
        &self,
    ) -> anyhow::Result<(BTreeSet<String>, BTreeSet<String>)> {
        self.state.admin_activity_bare_jids().await
    }
}
