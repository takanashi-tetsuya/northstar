//! Capability-free lifecycle for XMPP stream negotiation and session routing domain models.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StreamNegotiation {
    opened: bool,
    sasl_attempts: u8,
    registration_completed: bool,
    stream_from: Option<String>,
    language: Option<String>,
}

impl StreamNegotiation {
    pub const fn is_open(&self) -> bool {
        self.opened
    }

    pub fn open(&mut self, stream_from: Option<String>, language: Option<String>) {
        self.opened = true;
        self.stream_from = stream_from;
        self.language = language;
    }

    /// Require a fresh opening entity without changing account-level facts.
    pub fn require_new_stream(&mut self) {
        self.opened = false;
        self.stream_from = None;
        self.language = None;
    }

    pub fn close(&mut self) {
        self.require_new_stream();
    }

    /// STARTTLS creates a new stream and a new SASL-attempt budget.
    pub fn restart_after_transport_upgrade(&mut self) {
        self.require_new_stream();
        self.sasl_attempts = 0;
    }

    pub fn reserve_sasl_attempt(&mut self, maximum: u8) -> bool {
        if self.sasl_attempts >= maximum {
            return false;
        }
        self.sasl_attempts += 1;
        true
    }

    pub const fn registration_completed(&self) -> bool {
        self.registration_completed
    }

    pub fn mark_registration_completed(&mut self) {
        self.registration_completed = true;
    }

    pub fn stream_from(&self) -> Option<&str> {
        self.stream_from.as_deref()
    }

    pub fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }
}

/// Exact authority for one local XEP-0115 observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LocalCapsEpoch {
    pub connection_id: Uuid,
    pub generation: u64,
}

impl LocalCapsEpoch {
    pub fn new(connection_id: Uuid, generation: u64) -> Self {
        Self {
            connection_id,
            generation,
        }
    }
}

/// Exact MUC occupancy record owned by a live session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JoinedMucMembership {
    pub nick: String,
    pub cluster_epoch: Uuid,
}

impl JoinedMucMembership {
    pub fn new(nick: String, cluster_epoch: Uuid) -> Self {
        Self {
            nick,
            cluster_epoch,
        }
    }
}

/// Identity facts for a staged route before database commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StagedRouteIdentity {
    pub connection_id: Uuid,
    pub user_id: Uuid,
    pub auth_generation: i64,
}

impl StagedRouteIdentity {
    pub fn new(connection_id: Uuid, user_id: Uuid, auth_generation: i64) -> Self {
        Self {
            connection_id,
            user_id,
            auth_generation,
        }
    }
}

/// Staged route activation check parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedRouteActivationCheck {
    pub session: StagedRouteIdentity,
    pub expected: StagedRouteIdentity,
    pub same_lifecycle: bool,
    pub lifecycle_state: u8,
    pub session_cancelled: bool,
    pub owner_cancelled: bool,
}

/// Pure determination of whether a staged route is permitted to activate.
pub fn staged_route_activation_allowed(check: StagedRouteActivationCheck) -> bool {
    check.session.connection_id == check.expected.connection_id
        && check.session.user_id == check.expected.user_id
        && check.session.auth_generation == check.expected.auth_generation
        && check.same_lifecycle
        && check.lifecycle_state == 0
        && !check.session_cancelled
        && !check.owner_cancelled
}

/// Application-layer proof that one already-authorized C2S lifecycle may claim a cluster route.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SessionRouteClaimProof {
    Binding,
    SmResume { session_id: Uuid, claim_token: Uuid },
}

/// Lightweight snapshot of a MUC membership preserved across SM suspension.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SmMucMembership {
    pub room_jid: String,
    pub nick: String,
}

impl SmMucMembership {
    pub fn new(room_jid: String, nick: String) -> Self {
        Self { room_jid, nick }
    }
}

/// Encoded XMPP `<show/>`: 0 unavailable, 1 online, 2 away, 3 chat, 4 dnd, 5 xa.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SessionShowState {
    Unavailable = 0,
    Online = 1,
    Away = 2,
    Chat = 3,
    Dnd = 4,
    Xa = 5,
}

impl SessionShowState {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Online,
            2 => Self::Away,
            3 => Self::Chat,
            4 => Self::Dnd,
            5 => Self::Xa,
            _ => Self::Unavailable,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Online => "online",
            Self::Away => "away",
            Self::Chat => "chat",
            Self::Dnd => "dnd",
            Self::Xa => "xa",
        }
    }
}

/// A candidate resource for in-memory route selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteCandidate {
    pub resource: String,
    pub priority: i16,
    pub show: SessionShowState,
    pub available: bool,
}

/// Pure algorithm to select the highest priority available route among candidates.
pub fn select_highest_priority_route<'a>(
    candidates: impl IntoIterator<Item = &'a RouteCandidate>,
) -> Option<&'a RouteCandidate> {
    candidates
        .into_iter()
        .filter(|c| c.available && c.priority >= 0)
        .max_by_key(|c| c.priority)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_upgrade_clears_stream_identity_and_sasl_budget() {
        let mut state = StreamNegotiation::default();
        state.open(Some("alice".to_owned()), Some("en".to_owned()));
        assert!(state.reserve_sasl_attempt(1));
        assert!(!state.reserve_sasl_attempt(1));
        state.restart_after_transport_upgrade();
        assert!(!state.is_open());
        assert_eq!(state.stream_from(), None);
        assert_eq!(state.language(), None);
        assert!(state.reserve_sasl_attempt(1));
    }

    #[test]
    fn legacy_authentication_requires_a_fresh_stream_but_keeps_account_facts() {
        let mut state = StreamNegotiation::default();
        state.mark_registration_completed();
        state.open(Some("alice".to_owned()), Some("ja".to_owned()));
        state.require_new_stream();
        assert!(!state.is_open());
        assert!(state.registration_completed());
    }

    #[test]
    fn sasl_limit_is_exact_and_saturating() {
        let mut state = StreamNegotiation::default();
        for _ in 0..5 {
            assert!(state.reserve_sasl_attempt(5));
        }
        assert!(!state.reserve_sasl_attempt(5));
        assert!(!state.reserve_sasl_attempt(5));
    }

    #[test]
    fn staged_route_activation_decision() {
        let id1 = Uuid::new_v4();
        let u1 = Uuid::new_v4();
        let session = StagedRouteIdentity::new(id1, u1, 1);
        let expected = session;
        let check = StagedRouteActivationCheck {
            session,
            expected,
            same_lifecycle: true,
            lifecycle_state: 0,
            session_cancelled: false,
            owner_cancelled: false,
        };
        assert!(staged_route_activation_allowed(check));

        let mut fail_cancelled = check;
        fail_cancelled.session_cancelled = true;
        assert!(!staged_route_activation_allowed(fail_cancelled));

        let mut fail_mismatch = check;
        fail_mismatch.expected.connection_id = Uuid::new_v4();
        assert!(!staged_route_activation_allowed(fail_mismatch));
    }

    #[test]
    fn show_state_and_route_selection() {
        assert_eq!(SessionShowState::from_u8(1), SessionShowState::Online);
        assert_eq!(SessionShowState::from_u8(4), SessionShowState::Dnd);
        assert_eq!(SessionShowState::from_u8(99), SessionShowState::Unavailable);

        let c1 = RouteCandidate {
            resource: "mobile".to_string(),
            priority: 5,
            show: SessionShowState::Online,
            available: true,
        };
        let c2 = RouteCandidate {
            resource: "desktop".to_string(),
            priority: 10,
            show: SessionShowState::Chat,
            available: true,
        };
        let c3 = RouteCandidate {
            resource: "tablet".to_string(),
            priority: 20,
            show: SessionShowState::Away,
            available: false, // unavailable
        };
        let c4 = RouteCandidate {
            resource: "bot".to_string(),
            priority: -1, // negative priority
            show: SessionShowState::Online,
            available: true,
        };

        let list = vec![c1, c2, c3, c4];
        let best = select_highest_priority_route(&list);
        assert!(best.is_some());
        assert_eq!(best.unwrap().resource, "desktop");
    }
}
