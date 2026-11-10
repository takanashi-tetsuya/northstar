//! What the node provides to the session side of the operations context.

use anyhow::Result;
use northstar_operations_application::admin_commands::{
    AdminCommandRepository, AdminCommandService, AdminScramPolicy,
};
use std::collections::BTreeSet;

/// What the node provides to the administrative command handlers of a client session. The composition root
/// implements it.
pub trait OperationsSessionHost: Send + Sync {
    /// The command service, over the repository the composition root binds.
    fn command_service(&self) -> &AdminCommandService<impl AdminCommandRepository>;
    /// The server's local domain.
    fn command_local_domain(&self) -> &str;
    /// The verifier policy of accounts the commands create or update.
    fn command_scram_policy(&self) -> AdminScramPolicy;
    /// Whether the restart and shutdown commands are configured and can take effect.
    fn command_service_control_available(&self) -> bool;
    /// Sends `stanza` to the eligible local sessions and returns the delivered account identities.
    fn command_send_local_announcement(&self, stanza: &str) -> BTreeSet<String>;
    /// Whether announcements also reach accounts through the durable offline path.
    fn command_remote_announcement_enabled(&self) -> bool;
    /// Replaces this node's cached federation rules after a committed edit.
    fn command_replace_federation_rules(&self, blacklist: Vec<String>, whitelist: Vec<String>);
    /// Sends `stanza` to `bare` on the other nodes, returning whether any session took it.
    fn command_send_remote_announcement(
        &self,
        bare: &str,
        stanza: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    /// The bare JIDs online anywhere in the cluster.
    fn command_online_bare_jids(
        &self,
    ) -> impl std::future::Future<Output = Result<BTreeSet<String>>> + Send;
    /// The active and the idle bare JIDs of the cluster.
    fn command_activity_bare_jids(
        &self,
    ) -> impl std::future::Future<Output = Result<(BTreeSet<String>, BTreeSet<String>)>> + Send;
}
