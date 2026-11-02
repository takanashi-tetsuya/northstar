//! Storage operations required by MUC endpoint delivery.

use anyhow::Result;
use northstar_xep_0016::PrivacyStanzaKind;
use std::{collections::HashSet, future::Future};
use uuid::Uuid;

pub trait MucDeliveryRepository: Send + Sync {
    fn blocked_local_accounts(
        &self,
        local_domain: &str,
        occupant_jids: &[String],
        stanza_senders: &[String],
    ) -> impl Future<Output = Result<HashSet<String>>> + Send;

    /// Whether one session's privacy lists let `peer` reach it with a stanza of `kind`. With an active list the
    /// session's active-list lease is refreshed first.
    fn privacy_allows_session(
        &self,
        user_id: Uuid,
        connection_id: Uuid,
        active_privacy_list: Option<&str>,
        peer: &str,
        kind: PrivacyStanzaKind,
    ) -> impl Future<Output = Result<bool>> + Send;

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
