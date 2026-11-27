//! Queries and authorized entries for PEP send-last replay.

use crate::{PubSubAccount, PubSubAddress};
use northstar_time::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct PepReplayQuery {
    pub requester: PubSubAddress,
    pub mode: PepReplayMode,
    pub local_domain: String,
    pub after: Option<PepReplayCursor>,
    /// Maximum owners per page. Zero uses the application service's default.
    pub limit: usize,
}

#[derive(Clone, Debug)]
pub enum PepReplayMode {
    Explicit,
    LocalCaps {
        wanted: Vec<String>,
    },
    FederatedCaps {
        wanted: Vec<String>,
    },
    /// A direct send after subscribe. The addressed subscription may be bare.
    AfterSubscribe {
        owner: PubSubAccount,
        node: String,
        on_presence: bool,
    },
}

/// The last scanned owner in the corresponding mode's order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PepReplayCursor {
    Explicit(Uuid),
    LocalSelf,
    LocalRoster(String),
    Federated(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepReplayOrigin {
    Explicit,
    Automatic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PepReplayEntry {
    pub owner_id: Uuid,
    pub owner_username: String,
    pub node: String,
    pub item_id: String,
    pub payload: String,
    pub updated_at: DateTime<Utc>,
    pub origin: PepReplayOrigin,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PepReplayPage {
    /// Incarnation of a local recipient read in the same snapshot as this page.
    pub recipient_account_id: Option<Uuid>,
    pub entries: Vec<PepReplayEntry>,
    pub next: Option<PepReplayCursor>,
    /// Candidates examined on this page, including owners that yielded no entry.
    pub scanned: usize,
}
