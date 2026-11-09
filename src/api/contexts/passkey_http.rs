//! Passkey HTTP capabilities. Bearer lookup remains with the API query context.

use super::PasskeyService;
use crate::api::postgres_repositories::PostgresHttpRepositories;
use crate::api::repositories::HttpRepositories;
use northstar_abuse_application::login::PasskeyLoginAbuseService;
use northstar_abuse_policy::{GuardError, PowIntent, PowProof, WorkRequirement};
use northstar_auth_application::passkeys::{
    PasskeyActor, PasskeyError, PasskeyOptions, PasskeySummary,
};
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, RegisterPublicKeyCredential, RequestChallengeResponse,
};

#[derive(Clone)]
pub(crate) struct PasskeyAccountHttpContext<R: HttpRepositories = PostgresHttpRepositories> {
    pub(crate) service: Arc<PasskeyService<R>>,
}

impl<R: HttpRepositories> PasskeyAccountHttpContext<R> {
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

pub(crate) struct PasskeyStartHttpContext<R: HttpRepositories = PostgresHttpRepositories> {
    pub(crate) service: Arc<PasskeyService<R>>,
    pub(crate) abuse: Arc<PasskeyLoginAbuseService<R::PasskeyLogins>>,
    pub(crate) trusted_proxies: Arc<[IpAddr]>,
}

// A derived Clone would demand that the repository itself be Clone.
impl<R: HttpRepositories> Clone for PasskeyStartHttpContext<R> {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
            abuse: Arc::clone(&self.abuse),
            trusted_proxies: Arc::clone(&self.trusted_proxies),
        }
    }
}

impl<R: HttpRepositories> PasskeyStartHttpContext<R> {
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
