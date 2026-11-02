//! PostgreSQL reads for durable SM unavailable presence authorization.

use anyhow::Result;
use northstar_session_application::sm_teardown_presence::*;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresSmTeardownPresenceRepository {
    pool: PgPool,
}

impl PostgresSmTeardownPresenceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SmTeardownPresenceRepository for PostgresSmTeardownPresenceRepository {
    async fn roster_contacts(&self, owner_id: Uuid) -> Result<Vec<RosterPresenceContact>> {
        Ok(
            northstar_roster_postgres::roster::roster(&self.pool, owner_id)
                .await?
                .into_iter()
                .map(|(jid, _, subscription, _)| RosterPresenceContact { jid, subscription })
                .collect(),
        )
    }

    async fn is_blocked(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> Result<bool> {
        northstar_roster_postgres::roster::is_blocked_for_account(
            &self.pool,
            owner_id,
            owner_bare_jid,
            candidate,
        )
        .await
    }

    async fn outbound_privacy_denies(
        &self,
        owner_id: Uuid,
        active_list: Option<&str>,
        candidate: &str,
    ) -> Result<bool> {
        northstar_roster_postgres::privacy::privacy_denies(
            &self.pool,
            owner_id,
            active_list,
            candidate,
            northstar_xep_0016::PrivacyStanzaKind::PresenceOut,
        )
        .await
    }

    async fn enabled_user_id(&self, username: &str) -> Result<Option<Uuid>> {
        Ok(
            northstar_auth_postgres::users::find_enabled_user(&self.pool, username)
                .await?
                .map(|recipient| recipient.id),
        )
    }
}
