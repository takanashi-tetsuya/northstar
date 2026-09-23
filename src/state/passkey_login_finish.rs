//! Passkey login completion can verify the origin and commit a login, but has
//! no bearer-session, anti-abuse, proxy, or broader application authority.

use super::PasskeyService;
use crate::services::passkeys::{PasskeyError, PasskeyLoginOutcome};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::PublicKeyCredential;

#[derive(Clone)]
pub(crate) struct PasskeyLoginFinishContext {
    service: Arc<PasskeyService>,
}

impl PasskeyLoginFinishContext {
    pub(super) fn new(service: Arc<PasskeyService>) -> Self {
        Self { service }
    }

    pub(crate) fn allowed_origin(&self) -> Result<String, PasskeyError> {
        self.service.allowed_origin()
    }

    pub(crate) async fn finish(
        &self,
        challenge_id: Uuid,
        credential: PublicKeyCredential,
    ) -> Result<PasskeyLoginOutcome, PasskeyError> {
        self.service.login_finish(challenge_id, credential).await
    }
}
