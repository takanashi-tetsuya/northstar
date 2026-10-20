//! The XEP-0227 account records shared by the PIE import tool and their PostgreSQL persistence.

use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConflictPolicy {
    Fail,
    Skip,
    Replace,
}

#[derive(Default)]
pub(crate) struct PieUser {
    pub(crate) username: String,
    pub(crate) plaintext_password: Option<String>,
    pub(crate) scram: Option<ScramCredential>,
    pub(crate) roster: Vec<RosterItem>,
    pub(crate) offline: Vec<OfflineMessage>,
    pub(crate) private_xml: Vec<PrivateXml>,
    pub(crate) vcard: Option<String>,
    pub(crate) blocked: Vec<String>,
    pub(crate) pending: Vec<PendingPresence>,
    pub(crate) pep_nodes: BTreeMap<String, PepNode>,
    pub(crate) archive: Vec<ArchiveItem>,
}

pub(crate) struct ScramCredential {
    pub(crate) iterations: u32,
    pub(crate) salt: Vec<u8>,
    pub(crate) stored_key: Vec<u8>,
    pub(crate) server_key: Vec<u8>,
}

pub(crate) struct RosterItem {
    pub(crate) jid: String,
    pub(crate) name: Option<String>,
    pub(crate) subscription: String,
    pub(crate) ask: Option<String>,
    pub(crate) groups: Vec<String>,
    pub(crate) approved: bool,
}

pub(crate) struct OfflineMessage {
    pub(crate) sender: String,
    pub(crate) stanza: String,
    /// Derived from the validated stanza, never accepted as an independent
    /// PIE field.
    pub(crate) target_resource: Option<String>,
    pub(crate) encrypted: bool,
    pub(crate) created_at: Option<DateTime<Utc>>,
}

pub(crate) struct PrivateXml {
    pub(crate) name: String,
    pub(crate) namespace: String,
    pub(crate) xml: String,
}

pub(crate) struct PendingPresence {
    pub(crate) from: String,
    pub(crate) stanza: String,
}

pub(crate) struct PepNode {
    pub(crate) access_model: String,
    pub(crate) max_items: i32,
    pub(crate) persist_items: bool,
    pub(crate) send_last: String,
    pub(crate) deliver_notifications: bool,
    pub(crate) roster_groups_allowed: Vec<String>,
    pub(crate) access_whitelist: Vec<String>,
    pub(crate) subscriptions: Vec<PepSubscription>,
    pub(crate) items: Vec<PepItem>,
}

impl Default for PepNode {
    fn default() -> Self {
        Self {
            access_model: "presence".to_owned(),
            max_items: 100,
            persist_items: true,
            send_last: "on_sub".to_owned(),
            deliver_notifications: true,
            roster_groups_allowed: Vec::new(),
            access_whitelist: Vec::new(),
            subscriptions: Vec::new(),
            items: Vec::new(),
        }
    }
}

pub(crate) struct PepSubscription {
    pub(crate) jid: String,
    pub(crate) subid: String,
    pub(crate) state: String,
}

pub(crate) struct PepItem {
    pub(crate) id: String,
    pub(crate) payload: String,
}

pub(crate) struct ArchiveItem {
    pub(crate) result_id: String,
    pub(crate) peer_jid: String,
    pub(crate) peer_full_jid: String,
    pub(crate) stanza: String,
    pub(crate) encrypted: bool,
    pub(crate) created_at: DateTime<Utc>,
}

pub(crate) struct PreparedUser {
    pub(crate) data: PieUser,
    pub(crate) password_hash: String,
    pub(crate) scram: ScramCredential,
}
