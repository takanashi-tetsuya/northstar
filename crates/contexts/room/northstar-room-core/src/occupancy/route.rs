//! Exact occupant routes for addressed and live-audience MUC delivery.
//!
//! A route names one occupancy incarnation inside a room that its context (a
//! committed authority result or a cluster envelope's `target`) identifies.
//! Routes are internal routing state and are never rendered into a stanza.

use super::LocalMucOccupantIdentity;

/// Version of the cluster MUC fan-out envelope that carries exact routes in
/// `target_route` (private delivery) or `audience` (room delivery). A decoder
/// treats an envelope without `envelope_version` as the legacy form, which
/// resolves its recipients by room and nickname.
pub const MUC_EXACT_ROUTE_ENVELOPE_VERSION: u64 = 2;

/// Most routes one cluster envelope may carry. A larger audience is split
/// into several envelopes; an envelope never falls back to the room roster.
pub const MUC_ROUTE_ENVELOPE_LIMIT: usize = 512;

/// One occupancy incarnation. Delivery through a route succeeds only while
/// the occupant held under `nick` in the room still has this full JID,
/// connection and occupancy epoch, so a nickname reused by a later occupant
/// never matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MucOccupantRoute {
    pub nick: String,
    pub full_jid: String,
    pub connection_id: uuid::Uuid,
    pub cluster_epoch: uuid::Uuid,
}

impl MucOccupantRoute {
    /// Both incarnation fences are set; local route tables never match a
    /// route that lacks one.
    pub fn is_exact(&self) -> bool {
        !self.connection_id.is_nil() && !self.cluster_epoch.is_nil()
    }

    /// The identity local route tables match exactly
    /// (`with_local_muc_occupant_exact` and its peers).
    pub fn identity<'a>(&'a self, room_jid: &'a str) -> LocalMucOccupantIdentity<'a> {
        LocalMucOccupantIdentity {
            room_jid,
            nick: &self.nick,
            full_jid: &self.full_jid,
            connection_id: self.connection_id,
            cluster_epoch: self.cluster_epoch,
        }
    }
}

impl From<LocalMucOccupantIdentity<'_>> for MucOccupantRoute {
    fn from(identity: LocalMucOccupantIdentity<'_>) -> Self {
        Self {
            nick: identity.nick.to_owned(),
            full_jid: identity.full_jid.to_owned(),
            connection_id: identity.connection_id,
            cluster_epoch: identity.cluster_epoch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route() -> MucOccupantRoute {
        MucOccupantRoute {
            nick: "Alice".to_owned(),
            full_jid: "alice@example.com/phone".to_owned(),
            connection_id: uuid::Uuid::from_u128(1),
            cluster_epoch: uuid::Uuid::from_u128(2),
        }
    }

    #[test]
    fn route_round_trips_through_its_identity_and_wire_form() {
        let route = route();
        let identity = route.identity("room@conference.example.com");
        assert_eq!(identity.room_jid, "room@conference.example.com");
        assert_eq!(MucOccupantRoute::from(identity), route);
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "nick": "Alice",
                "full_jid": "alice@example.com/phone",
                "connection_id": "00000000-0000-0000-0000-000000000001",
                "cluster_epoch": "00000000-0000-0000-0000-000000000002",
            })
        );
        assert_eq!(
            serde_json::from_value::<MucOccupantRoute>(json).unwrap(),
            route
        );
    }

    #[test]
    fn a_route_without_both_fences_is_not_exact() {
        assert!(route().is_exact());
        let mut missing_connection = route();
        missing_connection.connection_id = uuid::Uuid::nil();
        assert!(!missing_connection.is_exact());
        let mut missing_epoch = route();
        missing_epoch.cluster_epoch = uuid::Uuid::nil();
        assert!(!missing_epoch.is_exact());
    }
}
