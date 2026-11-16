//! Ordered background-worker composition for the application state.

mod abuse;
mod cluster;
mod maintenance;
mod operations;
mod session;
mod upload;

use super::ServerNode;
use crate::runtime::subservers::ProcessRole;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

impl ServerNode {
    pub(crate) fn start_workers(
        self: &Arc<Self>,
        cancel: &CancellationToken,
        process_role: ProcessRole,
    ) {
        abuse::start(self, cancel);
        session::start(self, cancel);
        maintenance::start_background(self, cancel);
        maintenance::start_account_deletion_recovery(self, cancel);
        upload::start(self, cancel);
        maintenance::start_retention(self, cancel, process_role);
        operations::start(self, cancel);
        cluster::start(self, cancel);
    }

    pub(crate) fn worker_registry(&self) -> &Arc<northstar_runtime::workers::WorkerRegistry> {
        &self.workers
    }
}
