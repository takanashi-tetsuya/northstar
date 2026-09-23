//! Storage operations required by MUC endpoint delivery.

use crate::db::PrivacyStanzaKind;
use anyhow::Result;
use std::{collections::HashSet, future::Future};
use uuid::Uuid;

pub(crate) trait MucDeliveryRepository: Send + Sync {
    fn blocked_local_accounts(
        &self,
        local_domain: &str,
        occupant_jids: &[String],
        stanza_senders: &[String],
    ) -> impl Future<Output = Result<HashSet<String>>> + Send;

    fn suspended_privacy_denies(
        &self,
        session_id: Uuid,
        candidate: &str,
        kind: PrivacyStanzaKind,
    ) -> impl Future<Output = Result<Option<bool>>> + Send;

    fn append_suspended_stanza(
        &self,
        session_id: Uuid,
        volatile_source_id: Uuid,
        stanza: &str,
        max_stanzas: usize,
        max_bytes: usize,
    ) -> impl Future<Output = Result<bool>> + Send;
}
