//! What the node provides to the session side of the roster context.

use anyhow::Result;
use northstar_roster_application::blocking::{BlockingRepository, BlockingService};
use northstar_roster_application::{RosterRepository, RosterService, S2sOutboxPolicy};
use northstar_roster_core::{LocalRosterContact, PresenceAccount, RosterChange};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// One post-commit delivery failure counter shared by roster, blocking and
/// privacy pushes. Each caller retains its own recovery/disconnect decision.
pub struct PostAcceptFailureTelemetry {
    failures: Arc<AtomicU64>,
}

impl PostAcceptFailureTelemetry {
    /// A handle on the node's post-accept side-effect failure counter.
    pub fn new(failures: Arc<AtomicU64>) -> Self {
        Self { failures }
    }

    /// Counts one post-commit delivery failure.
    pub fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// What the node provides to the roster, blocking and privacy handlers of a client session, beyond the session
/// core's host. The composition root implements it.
pub trait RosterSessionHost: Send + Sync {
    /// The roster service, over the repository the composition root binds.
    fn roster_service(&self) -> &RosterService<impl RosterRepository<Error = anyhow::Error>>;
    /// The blocking service, over the repository the composition root binds.
    fn blocking_service(&self) -> &BlockingService<impl BlockingRepository>;
    /// The post-accept side-effect failure counter.
    fn post_accept_failure_telemetry(&self) -> PostAcceptFailureTelemetry;
    /// The federation outbox admission policy of roster subscription traffic.
    fn roster_outbox_policy(&self) -> S2sOutboxPolicy;
    /// Wakes the federation outbox after a roster transition queued remote traffic.
    fn roster_wake_outbox(&self);
    /// Delivers a committed roster change to the owner's interested resources on every node.
    fn deliver_committed_roster_change(
        &self,
        owner_id: Uuid,
        owner: &str,
        change: &RosterChange,
        participant_id: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Delivers the presence of a subscription removal to the recipient's available resources on every node.
    fn deliver_roster_removal_presence(
        &self,
        owner: &PresenceAccount,
        recipient: &LocalRosterContact,
        target_bare: &str,
        stanza: &str,
    ) -> impl Future<Output = ()> + Send;
    /// Pushes a committed blocklist change to the owner's resources that requested the blocklist, on every node.
    fn push_blocklist_change(&self, owner: &str, payload: &str) -> impl Future<Output = ()> + Send;
    /// Delivers the polite-blocking presence transitions of a blocklist change, on every node.
    fn deliver_blocking_presence_change(
        &self,
        owner: &str,
        targets: &[String],
        changed_patterns: &[String],
        available: bool,
    ) -> impl Future<Output = ()> + Send;
    /// The number of local resources of `account`.
    fn local_resource_count(&self, account: &str) -> usize;
    /// Whether another cluster node holds a resource of `account`.
    fn account_has_remote_resources(
        &self,
        account: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Whether a local resource of `account` has the privacy list `name` active.
    fn privacy_list_active_locally(&self, account: &str, name: &str) -> bool;
    /// Pushes a committed privacy list change to the account's resources that requested privacy lists, on every
    /// node. The push for the resource of connection `current_connection` is returned instead of queued.
    fn push_privacy_change(
        &self,
        account: &str,
        name: &str,
        base: &str,
        current_connection: Uuid,
    ) -> impl Future<Output = Option<String>> + Send;
}
