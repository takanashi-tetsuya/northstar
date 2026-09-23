//! Account Passkey HTTP capability for credential listing and registration
//! completion. Bearer lookup remains with the API query context.

use super::{AppState, PasskeyService};
use crate::services::passkeys::{PasskeyActor, PasskeyError, PasskeySummary};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::RegisterPublicKeyCredential;

#[derive(Clone)]
pub(crate) struct PasskeyAccountHttpContext {
    service: Arc<PasskeyService>,
}

impl axum::extract::FromRef<Arc<AppState>> for PasskeyAccountHttpContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: Arc::clone(&state.passkey_service),
        }
    }
}

impl PasskeyAccountHttpContext {
    pub(crate) fn allowed_origin(&self) -> Result<String, PasskeyError> {
        self.service.allowed_origin()
    }

    pub(crate) async fn list(
        &self,
        actor: PasskeyActor<'_>,
    ) -> Result<Vec<PasskeySummary>, PasskeyError> {
        self.service.list(actor).await
    }

    pub(crate) async fn register_finish(
        &self,
        actor: PasskeyActor<'_>,
        challenge_id: Uuid,
        credential: RegisterPublicKeyCredential,
    ) -> Result<Uuid, PasskeyError> {
        self.service
            .register_finish(actor, challenge_id, credential)
            .await
    }
}
