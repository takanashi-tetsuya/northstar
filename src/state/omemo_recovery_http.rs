//! Bearer identity and recovery transfer authority for authenticated REST routes.

use super::AppState;
use crate::{
    api::bearer_token,
    db::{
        api_queries::PostgresApiQueryRepository,
        omemo_recovery_repository::PostgresOmemoRecoveryRepository,
    },
    error::AppError,
    metrics::Metrics,
    services::{
        api_queries::ApiQueryService,
        omemo_recovery::{OmemoRecoveryActor, OmemoRecoveryService},
    },
};
use axum::{extract::FromRef, http::HeaderMap};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct OmemoRecoveryHttpContext {
    queries: ApiQueryService<PostgresApiQueryRepository>,
    recovery: OmemoRecoveryService<PostgresOmemoRecoveryRepository>,
    domain: String,
    metrics: Arc<Metrics>,
}

pub(crate) struct OmemoRecoveryHttpUser {
    pub(crate) id: Uuid,
    pub(crate) username: String,
    pub(crate) auth_generation: i64,
    session_token: Zeroizing<String>,
}

impl OmemoRecoveryHttpUser {
    pub(crate) fn session_token(&self) -> &str {
        self.session_token.as_str()
    }

    pub(crate) fn actor(&self) -> OmemoRecoveryActor<'_> {
        OmemoRecoveryActor {
            user_id: self.id,
            auth_generation: self.auth_generation,
            session_token: self.session_token(),
        }
    }
}

impl FromRef<Arc<AppState>> for OmemoRecoveryHttpContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            queries: state.api_query_service().clone(),
            recovery: state.omemo_recovery_service().clone(),
            domain: state.public_discovery_context().policy().domain.clone(),
            metrics: Arc::clone(&state.metrics),
        }
    }
}

impl OmemoRecoveryHttpContext {
    pub(crate) async fn current_user(
        &self,
        headers: &HeaderMap,
    ) -> Result<OmemoRecoveryHttpUser, AppError> {
        let _authentication_timer = self.metrics.authentication_duration_seconds.start_timer();
        let token = bearer_token(headers)?;
        let _database_timer = self
            .metrics
            .database_operation_duration_seconds
            .start_timer();
        let principal = self
            .queries
            .principal(token)
            .await?
            .ok_or(AppError::Unauthorized)?;
        Ok(OmemoRecoveryHttpUser {
            id: principal.id,
            username: principal.username,
            auth_generation: principal.auth_generation,
            session_token: Zeroizing::new(token.to_owned()),
        })
    }

    pub(crate) fn service(&self) -> &OmemoRecoveryService<PostgresOmemoRecoveryRepository> {
        &self.recovery
    }

    pub(crate) fn canonical_account(&self, user: &OmemoRecoveryHttpUser) -> String {
        format!("{}@{}", user.username, self.domain)
    }
}
