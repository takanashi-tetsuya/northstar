use super::*;

#[test]
fn registration_outcomes_preserve_authorization_distinctions() {
    assert_eq!(
        MucRegistrationOutcome::from(crate::muc::MucRegistrationOutcome::Registered {
            affiliation_changed: true,
        }),
        MucRegistrationOutcome::Registered {
            affiliation_changed: true,
        }
    );
    assert_eq!(
        ClusterMucRegistrationOutcome::from(
            crate::cluster_muc::ClusterMucRegistrationOutcome::NotAllowed
        ),
        ClusterMucRegistrationOutcome::NotAllowed
    );
    assert_eq!(
        ClusterMucRegistrationOutcome::from(
            crate::cluster_muc::ClusterMucRegistrationOutcome::Stale
        ),
        ClusterMucRegistrationOutcome::Stale
    );
}

#[test]
fn durable_delivery_outcomes_do_not_collapse_security_failures() {
    assert_eq!(
        DurableMucInviteOutcome::from(crate::muc::DurableMucInviteOutcome::RecipientUnavailable),
        DurableMucInviteOutcome::RecipientUnavailable
    );
    assert_eq!(
        DurableMucInviteOutcome::from(crate::muc::DurableMucInviteOutcome::AuthorityRejected),
        DurableMucInviteOutcome::AuthorityRejected
    );
}

#[test]
fn cluster_transition_mapping_keeps_stale_and_unauthorized_separate() {
    assert_eq!(
        ClusterMucTransitionOutcome::from(crate::cluster_muc::ClusterMucTransitionOutcome::Stale),
        ClusterMucTransitionOutcome::Stale
    );
    assert_eq!(
        ClusterMucTransitionOutcome::from(
            crate::cluster_muc::ClusterMucTransitionOutcome::Unauthorized
        ),
        ClusterMucTransitionOutcome::Unauthorized
    );
    assert_eq!(
        ClusterMucConfigurationOutcome::from(
            crate::cluster_muc::ClusterMucConfigurationOutcome::LockedByAnother
        ),
        ClusterMucConfigurationOutcome::LockedByAnother
    );
}

#[test]
fn occupancy_target_conversion_preserves_all_fencing_fields() {
    let target = ClusterMucOccupancyTarget {
        room_id: Uuid::new_v4(),
        room_epoch: Uuid::new_v4(),
        occupant_incarnation: Uuid::new_v4(),
        occupancy_epoch: 37,
        full_jid: "alice@example.test/desktop".to_owned(),
        nick: "Alice".to_owned(),
        connection_uuid: Uuid::new_v4(),
        connection_epoch: 19,
    };
    let repository: crate::cluster_muc::ClusterMucOccupancyTarget = (&target).into();
    assert_eq!(occupancy_target_from_db(repository), target);
}

#[test]
fn federated_authority_conversion_preserves_domain_and_outbox_limits() {
    let principal = ClusterMucPrincipal::Federated {
        bare_jid: "alice@remote.test".to_owned(),
        authenticated_domain: "remote.test".to_owned(),
    };
    assert_eq!(
        crate::cluster_muc::ClusterMucPrincipal::from(&principal),
        crate::cluster_muc::ClusterMucPrincipal::Federated {
            bare_jid: "alice@remote.test".to_owned(),
            authenticated_domain: "remote.test".to_owned(),
        }
    );

    let policy = FederatedInvitePolicy {
        ttl_seconds: 3600,
        max_rows: 100,
        max_bytes: 1_048_576,
        max_per_domain: 10,
    };
    let repository: northstar_federation_core::S2sOutboxPolicy = policy;
    assert_eq!(repository.ttl_seconds, 3600);
    assert_eq!(repository.max_rows, 100);
    assert_eq!(repository.max_bytes, 1_048_576);
    assert_eq!(repository.max_per_domain, 10);
}
