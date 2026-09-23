//! PostgreSQL reads for durable SM unavailable presence authorization.

use crate::{db, services::sm_teardown_presence::*};
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresSmTeardownPresenceRepository {
    pool: PgPool,
}

impl PostgresSmTeardownPresenceRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SmTeardownPresenceRepository for PostgresSmTeardownPresenceRepository {
    async fn roster_contacts(&self, owner_id: Uuid) -> Result<Vec<RosterPresenceContact>> {
        Ok(db::roster(&self.pool, owner_id)
            .await?
            .into_iter()
            .map(|(jid, _, subscription, _)| RosterPresenceContact { jid, subscription })
            .collect())
    }

    async fn is_blocked(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> Result<bool> {
        db::is_blocked_for_account(&self.pool, owner_id, owner_bare_jid, candidate).await
    }

    async fn outbound_privacy_denies(
        &self,
        owner_id: Uuid,
        active_list: Option<&str>,
        candidate: &str,
    ) -> Result<bool> {
        db::privacy_denies(
            &self.pool,
            owner_id,
            active_list,
            candidate,
            db::PrivacyStanzaKind::PresenceOut,
        )
        .await
    }

    async fn enabled_user_id(&self, username: &str) -> Result<Option<Uuid>> {
        Ok(db::find_enabled_user(&self.pool, username)
            .await?
            .map(|recipient| recipient.id))
    }
}
