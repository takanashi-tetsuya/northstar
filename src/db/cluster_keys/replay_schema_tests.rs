use super::*;

#[test]
fn replay_validation_classifier_requires_exact_sqlstate_and_text() {
    for message in [
        "cluster replay identity conflict",
        "cluster replay source instance is not authoritative",
        "cluster replay validity window rejected",
    ] {
        assert!(replay_validation_rejection_fields(Some("P0001"), message));
    }
    for (code, message) in [
        (
            Some("P0001"),
            "cluster replay destination instance is not authoritative",
        ),
        (
            Some("P0001"),
            "cluster replay authority capacity is exhausted",
        ),
        (Some("23505"), "cluster replay identity conflict"),
        (None, "cluster replay identity conflict"),
    ] {
        assert!(!replay_validation_rejection_fields(code, message));
    }
    let non_database = anyhow::anyhow!("cluster replay identity conflict");
    assert!(!cluster_replay_validation_rejection(&non_database));
}

#[test]
fn replay_fence_binds_both_process_instances_and_has_bounded_cleanup() {
    let migration = include_str!("../../../migrations/0095_cluster_replay_fence.sql");
    for required in [
        "source_instance_uuid",
        "source_key_epoch",
        "destination_instance_uuid",
        "existing.destination_instance_uuid<>p_destination_uuid",
        "existing.destination_instance_epoch<>p_destination_epoch",
        "destination_key_epoch",
        "payload_sha256",
        "ON CONFLICT DO NOTHING",
        "MATERIALIZED",
        "FOR UPDATE SKIP LOCKED",
    ] {
        assert!(
            migration.contains(required),
            "missing replay invariant {required}"
        );
    }
}
