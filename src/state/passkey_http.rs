//! Passkey HTTP capabilities. Bearer lookup remains with the API query context.

use super::{AppState, PasskeyService};
use crate::{
    abuse::{GuardError, PowIntent, PowProof, WorkRequirement},
    db::login_abuse_repository::PostgresPasskeyLoginAbuseRepository,
    services::{
        login_abuse::PasskeyLoginAbuseService,
        passkeys::{PasskeyActor, PasskeyError, PasskeyOptions, PasskeySummary},
    },
};
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, RegisterPublicKeyCredential, RequestChallengeResponse,
};

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

    pub(crate) async fn remove(
        &self,
        actor: PasskeyActor<'_>,
        password: &str,
        id: Uuid,
    ) -> Result<i64, PasskeyError> {
        self.service.remove(actor, password, id).await
    }
}

#[derive(Clone)]
pub(crate) struct PasskeyStartHttpContext {
    service: Arc<PasskeyService>,
    abuse: Arc<PasskeyLoginAbuseService<PostgresPasskeyLoginAbuseRepository>>,
    trusted_proxies: Arc<[IpAddr]>,
}

impl axum::extract::FromRef<Arc<AppState>> for PasskeyStartHttpContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: Arc::clone(&state.passkey_service),
            abuse: Arc::clone(&state.passkey_login_abuse_service),
            trusted_proxies: state
                .http_transport_policy()
                .trusted_proxies()
                .to_vec()
                .into(),
        }
    }
}

impl PasskeyStartHttpContext {
    pub(crate) fn allowed_origin(&self) -> Result<String, PasskeyError> {
        self.service.allowed_origin()
    }

    pub(crate) fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub(crate) async fn verify_start(
        &self,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: &PowIntent,
    ) -> anyhow::Result<Result<WorkRequirement, GuardError>> {
        self.abuse.verify(subject, actors, proof, intent).await
    }

    pub(crate) async fn register_start(
        &self,
        actor: PasskeyActor<'_>,
        password: &str,
        label: String,
    ) -> Result<PasskeyOptions<CreationChallengeResponse>, PasskeyError> {
        self.service.register_start(actor, password, label).await
    }

    pub(crate) async fn login_start(
        &self,
        username: &str,
        device_id: Uuid,
    ) -> Result<PasskeyOptions<RequestChallengeResponse>, PasskeyError> {
        self.service.login_start(username, device_id).await
    }
}
