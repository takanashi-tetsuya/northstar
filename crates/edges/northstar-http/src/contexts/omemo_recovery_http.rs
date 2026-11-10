//! Bearer identity and recovery transfer authority for authenticated REST routes.

use crate::bearer_token;
use crate::error::AppError;
use crate::repositories::HttpRepositories;
use axum::http::HeaderMap;
use northstar_auth_application::omemo_recovery::{OmemoRecoveryActor, OmemoRecoveryService};
use northstar_operations_application::api_queries::ApiQueryService;
use northstar_telemetry::metrics::Metrics;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct OmemoRecoveryHttpContext<R: HttpRepositories> {
    pub queries: ApiQueryService<R::ApiQueries>,
    pub recovery: OmemoRecoveryService<R::OmemoRecovery>,
    pub domain: String,
    pub metrics: Arc<Metrics>,
}

pub struct OmemoRecoveryHttpUser {
    pub id: Uuid,
    pub username: String,
    pub auth_generation: i64,
    session_token: Zeroizing<String>,
}

impl OmemoRecoveryHttpUser {
    pub fn session_token(&self) -> &str {
        self.session_token.as_str()
    }

    pub fn actor(&self) -> OmemoRecoveryActor<'_> {
        OmemoRecoveryActor {
            user_id: self.id,
            auth_generation: self.auth_generation,
            session_token: self.session_token(),
        }
    }
}

impl<R: HttpRepositories> OmemoRecoveryHttpContext<R> {
    pub async fn current_user(
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

    pub fn service(&self) -> &OmemoRecoveryService<R::OmemoRecovery> {
        &self.recovery
    }

    pub fn canonical_account(&self, user: &OmemoRecoveryHttpUser) -> String {
        format!("{}@{}", user.username, self.domain)
    }
}
