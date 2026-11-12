//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`.

use crate::commands::CommandSession;
use crate::OperationsSessionHost;
use northstar_operations_application::admin_commands::{
    AdminActor, AdminCommandRepository, AdminCommandService, AdminScramPolicy,
};
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use std::collections::BTreeSet;

// From src/xmpp/protocol/commands.rs.
impl<H: SessionHost + OperationsSessionHost> CommandSession for ProtocolSession<H> {
    fn command_service(&self) -> &AdminCommandService<impl AdminCommandRepository> {
        self.host().command_service()
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
        self.host().command_local_domain()
    }

    fn command_scram_policy(&self) -> AdminScramPolicy {
        self.host().command_scram_policy()
    }

    fn command_service_control_available(&self) -> bool {
        self.host().command_service_control_available()
    }

    fn command_send_local_announcement(&self, stanza: &str) -> BTreeSet<String> {
        self.host().command_send_local_announcement(stanza)
    }

    fn command_remote_announcement_enabled(&self) -> bool {
        self.host().command_remote_announcement_enabled()
    }

    fn command_replace_federation_rules(&self, blacklist: Vec<String>, whitelist: Vec<String>) {
        self.host()
            .command_replace_federation_rules(blacklist, whitelist);
    }

    async fn command_send_remote_announcement(
        &self,
        bare: &str,
        stanza: &str,
    ) -> anyhow::Result<bool> {
        self.host()
            .command_send_remote_announcement(bare, stanza)
            .await
    }

    async fn command_online_bare_jids(&self) -> anyhow::Result<BTreeSet<String>> {
        self.host().command_online_bare_jids().await
    }

    async fn command_activity_bare_jids(
        &self,
    ) -> anyhow::Result<(BTreeSet<String>, BTreeSet<String>)> {
        self.host().command_activity_bare_jids().await
    }
}
