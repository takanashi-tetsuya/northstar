//! Atomic roster operations, including authorization and notification records.

use northstar_roster_core::{
    RosterAuthorization, RosterChange, RosterReadSnapshot, RosterRemovalTransition,
};

use crate::{RosterGetCommand, RosterRemoveCommand, RosterUpsertCommand};

pub trait RosterRepository: Send + Sync {
    type Error;

    fn get_roster(
        &self,
        command: &RosterGetCommand,
    ) -> impl std::future::Future<
        Output = Result<RosterAuthorization<RosterReadSnapshot>, Self::Error>,
    > + Send;

    fn upsert_item(
        &self,
        command: &RosterUpsertCommand,
    ) -> impl std::future::Future<Output = Result<RosterAuthorization<RosterChange>, Self::Error>> + Send;

    /// Removal and its local or federated notifications share one commit.
    fn remove_item(
        &self,
        command: &RosterRemoveCommand<'_>,
    ) -> impl std::future::Future<
        Output = Result<RosterAuthorization<Option<RosterRemovalTransition>>, Self::Error>,
    > + Send;
}
