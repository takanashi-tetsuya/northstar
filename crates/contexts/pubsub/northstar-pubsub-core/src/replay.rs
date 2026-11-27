//! Inputs and results of an authorized generic presence replay page.

use crate::{PubSubAddress, PubSubBareJid, PubSubItem, PubSubSubscription};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct PresenceReplayQuery {
    pub recipient: PubSubAddress,
    pub recipient_id: Uuid,
    pub expected_auth_generation: Option<i64>,
    pub connection_id: Uuid,
    pub active_privacy_list: Option<String>,
    pub service: PubSubBareJid,
    pub show: String,
    pub after: Option<PresenceReplayCursor>,
    /// Zero selects the service default.
    pub limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresenceReplayCursor {
    pub node: String,
    pub jid: String,
}

#[derive(Clone, Debug)]
pub struct PresenceReplayCandidate {
    pub subscription: PubSubSubscription,
    pub node_id: Uuid,
    pub node: String,
    pub deliver_payloads: bool,
    pub item: PubSubItem,
}

#[derive(Debug)]
pub enum PresenceReplayPage {
    Denied,
    Candidates {
        candidates: Vec<PresenceReplayCandidate>,
        next: Option<PresenceReplayCursor>,
        scanned: usize,
    },
}

#[derive(Clone, Debug)]
pub struct ReplayDigestIntent {
    pub node_id: Uuid,
    pub subid: String,
    pub subscriber_jid: PubSubAddress,
    pub digest_frequency: i32,
    pub item_id: String,
    pub children: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDigestOutcome {
    Enqueued,
    NotDigest,
    Stale,
}
