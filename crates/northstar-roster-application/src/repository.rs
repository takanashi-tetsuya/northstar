//! Repository port traits for Roster persistence and state manipulation.

use northstar_roster_core::{RosterChange, RosterReadSnapshot};
use uuid::Uuid;

use crate::{RosterGetCommand, RosterRemoveCommand, RosterUpsertCommand};

pub type RosterRepoResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Repository port for persistent roster items and versioning.
pub trait RosterRepository: Send + Sync {
    /// Fetch the full or incremental roster snapshot for an authenticated user.
    fn get_roster(
        &self,
        command: &RosterGetCommand,
    ) -> impl std::future::Future<Output = RosterRepoResult<RosterReadSnapshot>> + Send;

    /// Add or update a roster item, returning the change result and incremented version.
    fn upsert_item(
        &self,
        command: &RosterUpsertCommand,
    ) -> impl std::future::Future<Output = RosterRepoResult<RosterChange>> + Send;

    /// Remove a roster item, returning the change result and incremented version.
    fn remove_item(
        &self,
        command: &RosterRemoveCommand,
    ) -> impl std::future::Future<Output = RosterRepoResult<RosterChange>> + Send;

    /// Update inbound/outbound subscription state for a roster item.
    fn set_subscription_state(
        &self,
        owner_id: Uuid,
        contact_jid: &str,
        subscription: &str,
        ask: Option<&str>,
    ) -> impl std::future::Future<Output = RosterRepoResult<()>> + Send;
}
