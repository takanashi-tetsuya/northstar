use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The authenticated account incarnation and exact connection issuing a roster,
/// presence, privacy or blocking command.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct RosterActor {
    pub account_id: Uuid,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    /// The canonical full JID stored by the session.
    pub full_jid: String,
}

impl RosterActor {
    pub fn bare_jid(&self) -> &str {
        self.full_jid
            .split_once('/')
            .map_or(self.full_jid.as_str(), |(bare, _)| bare)
    }
}

/// A sampled transport for one resource. It grants no permission to route to
/// a later holder of the same JID.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ExactPresenceRoute {
    pub account_id: Uuid,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    pub full_jid: String,
    /// `None` identifies a transport on this node.
    pub node_id: Option<String>,
}

/// One version of an account's roster journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RosterVersion(pub i64);

impl RosterVersion {
    pub fn get(self) -> i64 {
        self.0
    }

    /// Returns the next journal version.
    ///
    /// # Panics
    ///
    /// Panics when the current version is `i64::MAX`.
    pub fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("roster version overflow"))
    }
}

#[cfg(test)]
mod tests {
    use super::{ExactPresenceRoute, RosterActor, RosterVersion};
    use uuid::Uuid;

    #[test]
    fn actor_bare_jid_ends_before_the_resource() {
        let actor = RosterActor {
            account_id: Uuid::from_u128(1),
            auth_generation: 2,
            connection_id: Uuid::from_u128(3),
            full_jid: "alice@example.test/Phone/Work".to_owned(),
        };

        assert_eq!(actor.bare_jid(), "alice@example.test");
    }

    #[test]
    fn exact_route_distinguishes_later_holders_of_the_same_jid() {
        let captured = ExactPresenceRoute {
            account_id: Uuid::from_u128(1),
            auth_generation: 2,
            connection_id: Uuid::from_u128(3),
            full_jid: "alice@example.test/Phone".to_owned(),
            node_id: None,
        };
        let reconnected = ExactPresenceRoute {
            connection_id: Uuid::from_u128(4),
            ..captured.clone()
        };
        let reauthenticated = ExactPresenceRoute {
            auth_generation: 3,
            ..captured.clone()
        };

        assert_ne!(captured, reconnected);
        assert_ne!(captured, reauthenticated);
    }

    #[test]
    fn roster_version_advances_by_one() {
        let version = RosterVersion(41);
        assert_eq!(version.get(), 41);
        assert_eq!(version.next(), RosterVersion(42));
        assert!(version.next() > version);
    }

    #[test]
    #[should_panic(expected = "roster version overflow")]
    fn roster_version_cannot_advance_past_the_journal_limit() {
        RosterVersion(i64::MAX).next();
    }
}
