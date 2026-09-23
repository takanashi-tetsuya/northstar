//! PostgreSQL adapter for MUC blocklists and suspended SM delivery.

use crate::{db, services::muc_delivery::MucDeliveryRepository};
use anyhow::Result;
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresMucDeliveryRepository {
    pool: PgPool,
}

impl PostgresMucDeliveryRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl MucDeliveryRepository for PostgresMucDeliveryRepository {
    async fn blocked_local_accounts(
        &self,
        local_domain: &str,
        occupant_jids: &[String],
        stanza_senders: &[String],
    ) -> Result<HashSet<String>> {
        db::blocked_local_accounts_for_candidates(
            &self.pool,
            local_domain,
            occupant_jids,
            stanza_senders,
        )
        .await
    }

    async fn suspended_privacy_denies(
        &self,
        session_id: Uuid,
        candidate: &str,
        kind: db::PrivacyStanzaKind,
    ) -> Result<Option<bool>> {
        db::privacy_denies_for_sm_session(&self.pool, session_id, candidate, kind).await
    }

    async fn append_suspended_stanza(
        &self,
        session_id: Uuid,
        volatile_source_id: Uuid,
        stanza: &str,
        max_stanzas: usize,
        max_bytes: usize,
    ) -> Result<bool> {
        db::append_suspended_sm_stanza(
            &self.pool,
            session_id,
            volatile_source_id,
            stanza,
            max_stanzas,
            max_bytes,
        )
        .await
    }
}
