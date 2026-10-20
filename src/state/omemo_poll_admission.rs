//! OMEMO recovery polling: the recovery service and the poll context accessors.

use super::*;

impl AppState {
    pub(crate) fn omemo_recovery_service(
        &self,
    ) -> &crate::services::omemo_recovery::OmemoRecoveryService<
        db::omemo_recovery_repository::PostgresOmemoRecoveryRepository,
    > {
        &self.omemo_recovery_service
    }
    pub(crate) fn omemo_recovery_poll_context(&self) -> OmemoRecoveryPollContext {
        self.omemo_recovery_poll_context.clone()
    }
}
