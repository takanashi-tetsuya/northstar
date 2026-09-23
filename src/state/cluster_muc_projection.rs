//! Exact process-local projections of committed cluster MUC policy events.

use super::{
    with_local_muc_occupant_exact, AppState, LocalMucOccupantIdentity, MucOccupant,
    MucOccupantEndpoint, SerializableMucOccupant,
};
use dashmap::DashMap;

impl AppState {
    /// Take a reconciliation snapshot without holding map guards across the
    /// PostgreSQL authority check. Subsequent removals still compare the
    /// exact occupancy and connection incarnations.
    pub(crate) fn local_cluster_muc_projection_snapshot(&self) -> Vec<MucOccupant> {
        local_cluster_muc_projection_snapshot_in(&self.muc_occupants)
    }

    /// Identify only federated occupants owned by the closing authenticated
    /// transport. The caller later removes each exact incarnation, so a
    /// rebind that happens after this snapshot cannot be removed by cleanup.
    pub(crate) fn federated_muc_occupants_for_closed_connection(
        &self,
        authenticated_domain: &str,
        connection_id: uuid::Uuid,
    ) -> Vec<MucOccupant> {
        federated_muc_occupants_for_closed_connection_in(
            &self.muc_occupants,
            authenticated_domain,
            connection_id,
        )
    }

    /// Update only the local incarnation named by the committed outbox snapshot.
    /// A resumed or rejoined occupant can reuse the nickname before delivery;
    /// compare and update must therefore happen under the same map guard.
    pub(crate) fn apply_cluster_muc_policy_projection_exact(
        &self,
        snapshot: &SerializableMucOccupant,
    ) -> bool {
        apply_cluster_muc_policy_projection_exact_in(&self.muc_occupants, snapshot)
    }

    /// A committed role event does not change room anonymity policy.
    pub(crate) fn apply_cluster_muc_role_projection_exact(
        &self,
        snapshot: &SerializableMucOccupant,
    ) -> bool {
        apply_cluster_muc_role_projection_exact_in(&self.muc_occupants, snapshot)
    }
}

fn local_cluster_muc_projection_snapshot_in(
    occupants: &DashMap<String, MucOccupant>,
) -> Vec<MucOccupant> {
    occupants
        .iter()
        .map(|entry| entry.value().clone())
        .collect()
}

fn federated_muc_occupants_for_closed_connection_in(
    occupants: &DashMap<String, MucOccupant>,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
) -> Vec<MucOccupant> {
    let Ok(expected_domain) = crate::jid::prepare_domainpart(authenticated_domain) else {
        return Vec::new();
    };
    occupants
        .iter()
        .filter_map(|entry| {
            let MucOccupantEndpoint::Federated {
                authenticated_domain,
                connection_id: bound_connection,
            } = &entry.value().endpoint
            else {
                return None;
            };
            (crate::jid::prepare_domainpart(authenticated_domain)
                .is_ok_and(|domain| domain == expected_domain)
                && *bound_connection == connection_id)
                .then(|| entry.value().clone())
        })
        .collect()
}

fn apply_cluster_muc_policy_projection_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    snapshot: &SerializableMucOccupant,
) -> bool {
    apply_cluster_muc_projection_exact_in(occupants, snapshot, true)
}

fn apply_cluster_muc_role_projection_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    snapshot: &SerializableMucOccupant,
) -> bool {
    apply_cluster_muc_projection_exact_in(occupants, snapshot, false)
}

fn apply_cluster_muc_projection_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    snapshot: &SerializableMucOccupant,
    update_anonymity: bool,
) -> bool {
    with_local_muc_occupant_exact(
        occupants,
        LocalMucOccupantIdentity::from(snapshot),
        |current| {
            current.affiliation.clone_from(&snapshot.affiliation);
            current.role.clone_from(&snapshot.role);
            if update_anonymity {
                current.room_non_anonymous = snapshot.room_non_anonymous;
            }
        },
    )
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::MucOccupantEndpoint;
    use uuid::Uuid;

    fn occupant(connection_id: Uuid, cluster_epoch: Uuid) -> MucOccupant {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        MucOccupant {
            full_jid: "alice@example.test/Phone".to_owned(),
            room_jid: "room@conference.example.test".to_owned(),
            nick: "Alice".to_owned(),
            endpoint: MucOccupantEndpoint::Local(crate::outbound::OutboundSender::new(sender)),
            affiliation: "member".to_owned(),
            role: "participant".to_owned(),
            room_non_anonymous: false,
            occupant_id: "opaque".to_owned(),
            cluster_epoch,
            connection_id,
            sm_session_id: None,
            payload: String::new(),
        }
    }

    #[test]
    fn policy_projection_requires_exact_authority_and_cannot_overwrite_rejoined_occupant() {
        let occupants = DashMap::new();
        let first = occupant(Uuid::new_v4(), Uuid::new_v4());
        let key = crate::xmpp::xml_util::muc_occupant_key(&first.room_jid, &first.nick);
        occupants.insert(key.clone(), first.clone());

        let mut snapshot = SerializableMucOccupant::from(&first);
        snapshot.affiliation = "admin".to_owned();
        snapshot.role = "moderator".to_owned();
        snapshot.room_non_anonymous = true;

        let mut stale = snapshot.clone();
        stale.connection_id = Uuid::new_v4();
        assert!(!apply_cluster_muc_policy_projection_exact_in(
            &occupants, &stale
        ));
        stale = snapshot.clone();
        stale.cluster_epoch = Uuid::new_v4();
        assert!(!apply_cluster_muc_policy_projection_exact_in(
            &occupants, &stale
        ));
        stale = snapshot.clone();
        stale.full_jid = "mallory@example.test/Phone".to_owned();
        assert!(!apply_cluster_muc_policy_projection_exact_in(
            &occupants, &stale
        ));
        stale = snapshot.clone();
        stale.room_jid = "other@conference.example.test".to_owned();
        assert!(!apply_cluster_muc_policy_projection_exact_in(
            &occupants, &stale
        ));
        stale = snapshot.clone();
        stale.nick = "Mallory".to_owned();
        assert!(!apply_cluster_muc_policy_projection_exact_in(
            &occupants, &stale
        ));
        stale = snapshot.clone();
        stale.cluster_epoch = Uuid::nil();
        assert!(!apply_cluster_muc_policy_projection_exact_in(
            &occupants, &stale
        ));
        assert_eq!(occupants.get(&key).unwrap().role, "participant");

        assert!(apply_cluster_muc_policy_projection_exact_in(
            &occupants, &snapshot
        ));
        let updated = occupants.get(&key).unwrap();
        assert_eq!(updated.affiliation, "admin");
        assert_eq!(updated.role, "moderator");
        assert!(updated.room_non_anonymous);
        drop(updated);

        let replacement = occupant(Uuid::new_v4(), Uuid::new_v4());
        occupants.insert(key.clone(), replacement.clone());
        assert!(!apply_cluster_muc_policy_projection_exact_in(
            &occupants, &snapshot
        ));
        let current = occupants.get(&key).unwrap();
        assert_eq!(current.connection_id, replacement.connection_id);
        assert_eq!(current.cluster_epoch, replacement.cluster_epoch);
        assert_eq!(current.role, "participant");
    }

    #[test]
    fn role_projection_preserves_anonymity_and_rejects_late_old_connection() {
        let occupants = DashMap::new();
        let first = occupant(Uuid::new_v4(), Uuid::new_v4());
        let key = crate::xmpp::xml_util::muc_occupant_key(&first.room_jid, &first.nick);
        occupants.insert(key.clone(), first.clone());
        let captured = local_cluster_muc_projection_snapshot_in(&occupants);
        assert_eq!(captured.len(), 1);

        let mut role_event = SerializableMucOccupant::from(&first);
        role_event.role = "visitor".to_owned();
        role_event.affiliation = "none".to_owned();
        role_event.room_non_anonymous = true;
        assert!(apply_cluster_muc_role_projection_exact_in(
            &occupants,
            &role_event
        ));
        let current = occupants.get(&key).unwrap();
        assert_eq!(current.role, "visitor");
        assert_eq!(current.affiliation, "none");
        assert!(!current.room_non_anonymous);
        drop(current);

        let replacement = occupant(Uuid::new_v4(), first.cluster_epoch);
        occupants.insert(key.clone(), replacement.clone());
        assert!(!apply_cluster_muc_role_projection_exact_in(
            &occupants,
            &role_event
        ));
        assert_eq!(occupants.get(&key).unwrap().role, "participant");
        assert_eq!(captured[0].connection_id, first.connection_id);
    }

    #[test]
    fn federated_disconnect_snapshot_selects_exact_endpoint_and_cannot_remove_rebind() {
        let occupants = DashMap::new();
        let closing_connection = Uuid::new_v4();
        let mut first = occupant(closing_connection, Uuid::new_v4());
        first.endpoint = MucOccupantEndpoint::Federated {
            authenticated_domain: "Remote.Example".to_owned(),
            connection_id: closing_connection,
        };
        let key = crate::xmpp::xml_util::muc_occupant_key(&first.room_jid, &first.nick);
        occupants.insert(key.clone(), first.clone());

        let mut other_connection = occupant(Uuid::new_v4(), Uuid::new_v4());
        other_connection.nick = "Bob".to_owned();
        other_connection.endpoint = MucOccupantEndpoint::Federated {
            authenticated_domain: "remote.example".to_owned(),
            connection_id: other_connection.connection_id,
        };
        occupants.insert(
            crate::xmpp::xml_util::muc_occupant_key(
                &other_connection.room_jid,
                &other_connection.nick,
            ),
            other_connection,
        );

        let departed = federated_muc_occupants_for_closed_connection_in(
            &occupants,
            "remote.example",
            closing_connection,
        );
        assert_eq!(departed.len(), 1);
        assert_eq!(departed[0].connection_id, closing_connection);
        assert!(federated_muc_occupants_for_closed_connection_in(
            &occupants,
            "other.example",
            closing_connection,
        )
        .is_empty());

        let mut rebound = occupant(Uuid::new_v4(), Uuid::new_v4());
        rebound.endpoint = MucOccupantEndpoint::Federated {
            authenticated_domain: "remote.example".to_owned(),
            connection_id: rebound.connection_id,
        };
        occupants.insert(key.clone(), rebound.clone());
        assert!(crate::state::remove_local_muc_occupant_exact_from(
            &occupants,
            (&departed[0]).into(),
        )
        .is_none());
        assert_eq!(
            occupants.get(&key).unwrap().connection_id,
            rebound.connection_id
        );
    }
}
