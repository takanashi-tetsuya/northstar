//! PostgreSQL adapter for MUC blocklists and suspended SM delivery.

use anyhow::Result;
use northstar_room_application::muc_delivery::MucDeliveryRepository;
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresMucDeliveryRepository {
    pool: PgPool,
}

impl PostgresMucDeliveryRepository {
    pub fn new(pool: PgPool) -> Self {
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
        northstar_roster_postgres::roster::blocked_local_accounts_for_candidates(
            &self.pool,
            local_domain,
            occupant_jids,
            stanza_senders,
        )
        .await
    }

    async fn privacy_allows_session(
        &self,
        user_id: Uuid,
        connection_id: Uuid,
        active_privacy_list: Option<&str>,
        peer: &str,
        kind: northstar_xep_0016::PrivacyStanzaKind,
    ) -> Result<bool> {
        if active_privacy_list.is_some() {
            northstar_roster_postgres::privacy::refresh_active_privacy_session(
                &self.pool,
                user_id,
                connection_id,
            )
            .await?;
        }
        Ok(!northstar_roster_postgres::privacy::privacy_denies(
            &self.pool,
            user_id,
            active_privacy_list,
            peer,
            kind,
        )
        .await?)
    }

    async fn suspended_privacy_denies(
        &self,
        session_id: Uuid,
        candidate: &str,
        kind: northstar_xep_0016::PrivacyStanzaKind,
    ) -> Result<Option<bool>> {
        crate::privacy::privacy_denies_for_sm_session(&self.pool, session_id, candidate, kind).await
    }

    async fn append_suspended_stanza(
        &self,
        session_id: Uuid,
        volatile_source_id: Uuid,
        stanza: &str,
        max_stanzas: usize,
        max_bytes: usize,
    ) -> Result<bool> {
        crate::sm::append_suspended_sm_stanza(
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
