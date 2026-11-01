use super::*;

#[test]
fn resource_addresses_keep_the_authenticated_muc_account() {
    let principal = ClusterMucPrincipal::Local {
        user_id: Uuid::new_v4(),
        bare_jid: "alice@example.test".into(),
    };
    principal.validate().unwrap();
    for address in [
        "alice@example.test/desktop",
        "alice@example.test/desktop/other@example.test",
    ] {
        assert_eq!(muc_address_bare_jid(address).unwrap(), "alice@example.test");
        assert!(muc_principal_owns_address(address, &principal).unwrap());
    }
}

#[test]
fn a_muc_resource_cannot_impersonate_another_principal() {
    let principal = ClusterMucPrincipal::Federated {
        bare_jid: "alice@example.test".into(),
        authenticated_domain: "example.test".into(),
    };
    principal.validate().unwrap();
    for address in [
        "bob@example.test/alice@example.test",
        "alice@other.example/desktop",
    ] {
        assert!(!muc_principal_owns_address(address, &principal).unwrap());
    }
}

#[test]
fn actor_projection_preserves_existing_bare_address_inputs() {
    let principal = ClusterMucPrincipal::Local {
        user_id: Uuid::new_v4(),
        bare_jid: "alice@example.test".into(),
    };
    assert!(muc_principal_owns_address("alice@example.test", &principal).unwrap());
    assert_eq!(
        muc_address_bare_jid("alice@example.test").unwrap(),
        "alice@example.test"
    );
}

#[test]
fn muc_actor_projection_still_rejects_malformed_addresses() {
    for address in ["", "alice@example.test/", "alice@example.test/\n"] {
        assert!(muc_address_bare_jid(address).is_err());
    }
}

#[test]
fn authenticated_muc_principals_still_require_strict_bare_jids() {
    let principal = ClusterMucPrincipal::Local {
        user_id: Uuid::new_v4(),
        bare_jid: "alice@example.test/desktop".into(),
    };
    assert!(principal.validate().is_err());
    assert!(!muc_principal_owns_address("alice@example.test/desktop", &principal).unwrap());
    assert!(northstar_xmpp_types::jid::canonicalize_bare("alice@example.test/desktop").is_err());
}

fn occupancy(nick: &str, incarnation: Uuid, connection: Uuid) -> ClusterMucOccupancy {
    ClusterMucOccupancy {
        room_id: Uuid::from_u128(1),
        room_epoch: Uuid::from_u128(2),
        occupant_incarnation: incarnation,
        occupancy_epoch: 9,
        config_version: 3,
        identity_kind: "local".into(),
        local_user_id: Some(Uuid::from_u128(8)),
        bare_jid: "alice@example.test".into(),
        full_jid: "alice@example.test/phone".into(),
        nick: nick.into(),
        authenticated_domain: None,
        owner_node_id: "node-a".into(),
        connection_uuid: connection,
        connection_epoch: 4,
        sm_session_id: None,
        role: "participant".into(),
        affiliation: "member".into(),
        state: "active".into(),
        presence_payload: String::new(),
        lease_until: Utc::now(),
    }
}

#[test]
fn delayed_kick_cannot_match_a_reused_nickname() {
    let old = occupancy("Alice", Uuid::from_u128(10), Uuid::from_u128(11));
    let delayed = ClusterMucOccupancyTarget::from(&old);
    let replacement = occupancy("Alice", Uuid::from_u128(12), Uuid::from_u128(13));
    assert!(!exact_target_matches_row(&delayed, &replacement));
}

#[test]
fn actor_principal_is_bound_to_the_occupancy_identity() {
    let current = occupancy("Alice", Uuid::from_u128(10), Uuid::from_u128(11));
    let valid = ClusterMucPrincipal::Local {
        user_id: Uuid::from_u128(8),
        bare_jid: "alice@example.test".into(),
    };
    let stale_account = ClusterMucPrincipal::Local {
        user_id: Uuid::from_u128(9),
        bare_jid: "alice@example.test".into(),
    };
    let forged_remote = ClusterMucPrincipal::Federated {
        bare_jid: "alice@example.test".into(),
        authenticated_domain: "example.test".into(),
    };
    assert!(principal_matches_occupancy(&valid, &current));
    assert!(!principal_matches_occupancy(&stale_account, &current));
    assert!(!principal_matches_occupancy(&forged_remote, &current));
}

#[test]
fn affiliation_subject_does_not_forge_invitee_domain_authority() {
    let local = ClusterMucPrincipal::Local {
        user_id: Uuid::from_u128(8),
        bare_jid: "alice@example.test".into(),
    };
    let remote = ClusterMucPrincipal::Federated {
        bare_jid: "alice@remote.test".into(),
        authenticated_domain: "remote.test".into(),
    };
    let local_subject = ClusterMucAffiliationSubject::Local {
        user_id: Uuid::from_u128(8),
        bare_jid: "alice@example.test".into(),
    };
    let invited_remote = ClusterMucAffiliationSubject::Federated {
        bare_jid: "guest@elsewhere.test".into(),
    };
    assert!(local_subject.matches_principal(&local));
    assert!(!invited_remote.matches_principal(&local));
    assert!(!invited_remote.matches_principal(&remote));
    assert!(invited_remote.validate().is_ok());
}

#[test]
fn registration_and_invitation_share_the_immutable_affiliation_journal() {
    let source = module_source();
    assert!(source.contains("self_register"));
    assert!(source.contains("self_unregister"));
    assert!(source.contains("ClusterMucAffiliationMutation::Invitation"));
    assert!(source.contains("offline_affiliation"));
    assert!(source.contains("MAX_OPERATION_AUDIENCE + 1"));
}

#[test]
fn module_source_lists_every_child_module() {
    let (_, parent) = MODULE_SOURCE[0];
    let declared: std::collections::BTreeSet<&str> = parent
        .lines()
        .filter_map(|line| line.strip_prefix("mod ")?.strip_suffix(';'))
        .filter(|name| *name != "tests")
        .collect();
    let listed: std::collections::BTreeSet<&str> =
        MODULE_SOURCE[1..].iter().map(|(name, _)| *name).collect();
    assert_eq!(declared, listed);
}

#[test]
fn terminal_and_capacity_sql_fences_fail_closed() {
    let migration = include_str!("../../../../../../migrations/0089_cluster_muc_authority.sql");
    assert!(migration.contains("terminal MUC occupancy cannot be revived"));
    assert!(migration.contains("cluster_muc_outbox_capacity_underflow"));
    assert!(migration.contains("cluster_muc_room_outbox_capacity_underflow"));
    assert!(migration.contains("cluster_muc_dead_letter_capacity_underflow"));
    assert!(migration.contains("full dead-letter shard fails closed"));
    assert!(migration.contains("octet_length(actor_authorization_snapshot::TEXT) <= 1048576"));
    assert!(migration.contains("octet_length(audience_snapshot::TEXT) <= 16777216"));
    assert!(migration.contains("jsonb_path_exists(audience_snapshot, '$[*].presence_payload')"));
    assert!(migration.contains("jsonb_path_exists(audience_snapshot, '$[*].private_key')"));
}

#[test]
fn event_retry_identity_is_stable_and_capacity_is_sharded() {
    let event_id = Uuid::from_u128(42);
    let payload = json!({"event_id":event_id,"event_sequence":7});
    let first = serde_json::to_string(&payload).unwrap();
    let second = serde_json::to_string(&payload).unwrap();
    assert_eq!(payload_digest(&first), payload_digest(&second));
    assert!((0..64).contains(&capacity_shard(event_id)));
}

#[test]
fn destroyed_room_recreation_and_retention_are_epoch_fenced() {
    let authority = include_str!("../../../../../../migrations/0089_cluster_muc_authority.sql");
    let capacity = include_str!("../../../../../../migrations/0090_deployment_capacity_ledger.sql");
    let source = crate::muc::module_source();
    assert!(authority.contains("DROP CONSTRAINT IF EXISTS muc_rooms_localpart_key"));
    assert!(authority.contains("muc_rooms_live_localpart_unique"));
    assert!(source.contains("ON CONFLICT (localpart) WHERE destroyed_at IS NULL DO NOTHING"));
    assert!(authority.contains("CHECK (event_id = operation_id)"));
    assert!(authority.contains("northstar_purge_cluster_muc_history"));
    assert!(authority.contains("northstar.cluster_muc_retention_cleanup"));
    assert!(authority.contains("remove_destroyed_muc_live_associations"));
    assert!(capacity.contains("northstar_muc_capacity_destroy_update"));
    assert!(capacity.contains("WHERE destroyed_at IS NULL ORDER BY id"));
    assert!(capacity.contains("ELSIF OLD.destroyed_at IS NULL"));
}

#[test]
fn committed_audience_is_immutable_and_omits_presence_soft_state() {
    let mut current = occupancy("Alice", Uuid::from_u128(10), Uuid::from_u128(11));
    current.presence_payload = "<show>away</show>".into();
    let committed = ClusterMucAudienceSnapshot::from(&current);
    current.nick = "Alice-After-Resume".into();
    current.connection_uuid = Uuid::from_u128(99);
    current.connection_epoch += 1;

    assert_eq!(committed.nick, "Alice");
    assert_eq!(committed.connection_uuid, Uuid::from_u128(11));
    let encoded = serde_json::to_string(&committed).unwrap();
    assert!(!encoded.contains("presence_payload"));
    assert!(!encoded.contains("<show>away</show>"));
}

#[test]
fn sql_shapes_use_database_time_and_exact_fences() {
    let migration = include_str!("../../../../../../migrations/0089_cluster_muc_authority.sql");
    assert!(migration.contains("clock_timestamp()"));
    assert!(migration.contains("destroyed MUC room incarnation is fenced"));
    assert!(migration.contains("target_occupant_incarnation"));
    assert!(migration.contains("cluster_muc_outbox_capacity"));
    assert!(migration.contains("cluster MUC operations are append-only"));
}

#[test]
fn cluster_runtime_authorities_are_bounded_schema_local_and_capability_only() {
    let migration = include_str!(
        "../../../../../../migrations/0112_cluster_runtime_capacity_and_authority.sql"
    );
    for required in [
        "active_rows BETWEEN 0 AND 8192",
        "capacity_shard BETWEEN 0 AND 63",
        "northstar_cluster_replay_capacity_healthy",
        "northstar_cluster_session_authority_healthy",
        "pg_catalog.split_part(p_full_jid,'/',1)<>p_bare_jid",
        "pg_catalog.split_part(p_bare_jid,'@',2)<>p_namespace",
        "FROM deployment_session_leases lease",
        "FOR SHARE OF claim,stream",
        "stream.claim_token=p_sm_claim_token",
        "claim_proof_kind='lease'",
        "northstar_cluster_session_route_authorized",
        "REVOKE ALL ON TABLE cluster_signed_envelope_replays",
        "SET search_path TO pg_catalog, %I, pg_temp",
    ] {
        assert!(
            migration.contains(required),
            "missing 0112 fence: {required}"
        );
    }
    assert!(
        !migration.to_ascii_lowercase().contains("public."),
        "cluster authority migration must remain isolated-schema safe"
    );
}
