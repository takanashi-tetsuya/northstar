//! Room occupants for discovery: the cluster cache merged with this node's occupants.

use northstar_room_core::occupancy::SerializableMucOccupant;

/// Discovery combines the disposable cluster cache with this node's
/// current occupants, then returns a stable nickname order for paging.
pub fn merge_discovery_occupants(
    cached_json: impl IntoIterator<Item = String>,
    local: impl IntoIterator<Item = SerializableMucOccupant>,
) -> Vec<SerializableMucOccupant> {
    let mut occupants = cached_json
        .into_iter()
        .filter_map(|json| serde_json::from_str::<SerializableMucOccupant>(&json).ok())
        .map(|occupant| (occupant.nick.clone(), occupant))
        .collect::<std::collections::HashMap<_, _>>();
    for occupant in local {
        occupants.insert(occupant.nick.clone(), occupant);
    }
    let mut occupants = occupants.into_values().collect::<Vec<_>>();
    occupants.sort_by(|left, right| left.nick.cmp(&right.nick));
    occupants
}

#[cfg(test)]
mod tests {
    use super::*;

    fn occupant(nick: &str, full_jid: &str) -> SerializableMucOccupant {
        SerializableMucOccupant {
            full_jid: full_jid.to_owned(),
            room_jid: "room@muc.example.test".to_owned(),
            nick: nick.to_owned(),
            affiliation: "member".to_owned(),
            role: "participant".to_owned(),
            room_non_anonymous: false,
            occupant_id: String::new(),
            cluster_epoch: uuid::Uuid::new_v4(),
            connection_id: uuid::Uuid::new_v4(),
            federated_domain: None,
            sm_session_id: None,
            payload: String::new(),
        }
    }

    #[test]
    fn local_replaces_cached_occupant_with_same_nick() {
        let cached = occupant("Alice", "alice@example.test/Old");
        let local = occupant("Alice", "alice@example.test/New");
        let result =
            merge_discovery_occupants([serde_json::to_string(&cached).unwrap()], [local.clone()]);
        assert_eq!(result.len(), 1);
        assert_eq!(
            serde_json::to_value(&result[0]).unwrap(),
            serde_json::to_value(&local).unwrap()
        );
    }

    #[test]
    fn malformed_cached_json_is_dropped() {
        let cached = occupant("Alice", "alice@example.test/Phone");
        let result = merge_discovery_occupants(
            [
                "not json".to_owned(),
                "{}".to_owned(),
                serde_json::to_string(&cached).unwrap(),
            ],
            [],
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].nick, "Alice");
    }

    #[test]
    fn discovery_occupants_are_sorted_by_nick() {
        let result = merge_discovery_occupants(
            [
                serde_json::to_string(&occupant("Zoe", "zoe@example.test/Phone")).unwrap(),
                serde_json::to_string(&occupant("Alice", "alice@example.test/Phone")).unwrap(),
            ],
            [occupant("Bob", "bob@example.test/Phone")],
        );
        assert_eq!(
            result
                .iter()
                .map(|occupant| occupant.nick.as_str())
                .collect::<Vec<_>>(),
            ["Alice", "Bob", "Zoe"]
        );
    }
}
