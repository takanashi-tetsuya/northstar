//! OMEMO recovery polling: the recovery service and the poll context accessors.

use super::*;

impl AppState {
    pub(crate) fn omemo_recovery_service(
        &self,
    ) -> &northstar_auth_application::omemo_recovery::OmemoRecoveryService<
        northstar_auth_postgres::omemo_recovery_repository::PostgresOmemoRecoveryRepository,
    > {
        &self.omemo_recovery_service
    }
    pub(crate) fn omemo_recovery_poll_context(&self) -> OmemoRecoveryPollContext {
        self.omemo_recovery_poll_context.clone()
    }
}
