//! Storage operations required by MUC endpoint delivery.

use anyhow::Result;
use northstar_xep_0016::PrivacyStanzaKind;
use std::{collections::HashSet, future::Future};
use uuid::Uuid;

pub trait MucDeliveryRepository: crate::room_delivery_policy::RoomDeliveryPolicyReader {
    fn current_muc_moderators(
        &self,
        room_localpart: &str,
        candidates: &[northstar_room_core::occupancy::MucOccupantRoute],
    ) -> impl Future<Output = Result<Vec<northstar_room_core::occupancy::MucOccupantRoute>>> + Send;

    fn blocked_local_accounts(
        &self,
        local_domain: &str,
        occupant_jids: &[String],
        stanza_senders: &[String],
    ) -> impl Future<Output = Result<HashSet<String>>> + Send;

    /// Read one session's privacy policy for this peer and stanza kind.
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
