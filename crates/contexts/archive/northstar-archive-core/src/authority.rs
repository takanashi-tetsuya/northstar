use uuid::Uuid;

/// The account identity installed by authentication on the local stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MamLocalAuthority {
    pub id: Uuid,
    pub username: String,
    pub auth_generation: i64,
}

/// An exact occupancy and transport incarnation to verify in the room snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MamOccupancyProof {
    pub occupant_incarnation: Uuid,
    pub connection_uuid: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MamRoomReadAuthority {
    pub full_jid: String,
    pub occupancy: Option<MamOccupancyProof>,
}

impl MamRoomReadAuthority {
    /// Federated actor identity uses canonical full-JID equality.
    pub fn matches_remote_actor(&self, full_jid: &str) -> bool {
        use northstar_xmpp_types::jid::canonicalize;

        matches!(
            (canonicalize(full_jid), canonicalize(&self.full_jid)),
            (Ok(occupant), Ok(actor)) if occupant == actor
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MamAccountOutcome<T> {
    Authorized(T),
    StaleAccount,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MamMetadataResult, MamRoomReadOutcome};

    #[test]
    fn room_metadata_preserves_the_stale_account_decision() {
        assert_eq!(
            MamMetadataResult::from_room_read(MamRoomReadOutcome::StaleAccount),
            MamMetadataResult::StaleAccount
        );
    }

    #[test]
    fn federated_room_authority_matches_only_the_canonical_full_actor() {
        let viewer = MamRoomReadAuthority {
            full_jid: "alice@remote.test/Phone".to_owned(),
            occupancy: None,
        };

        assert!(viewer.matches_remote_actor("Alice@REMOTE.test/Phone"));
        assert!(!viewer.matches_remote_actor("alice@remote.test/phone"));
        assert!(!viewer.matches_remote_actor("alice@remote.test"));
        assert!(!viewer.matches_remote_actor("bob@remote.test/Phone"));
        assert!(!viewer.matches_remote_actor("alice@@remote.test/Phone"));
    }
}
