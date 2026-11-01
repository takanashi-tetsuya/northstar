//! Source contracts of personal admission records.

#[test]
fn personal_message_admission_identity_index_is_bounded_and_exactly_rechecked() {
    let migration = include_str!(
        "../../../../../../migrations/0130_personal_message_admission_scope_lookup.sql"
    );
    let unique_index = migration
        .split("CREATE UNIQUE INDEX personal_message_admission_identity_key")
        .nth(1)
        .expect("bounded personal-admission identity index");
    assert!(unique_index.contains("personal-admission-actor-scope:v1:"));
    assert!(unique_index.contains("personal-admission-target-scope:v1:"));
    assert!(unique_index.contains("pg_catalog.md5"));
    assert!(
        !unique_index.contains("(identity_kind, actor_scope, target_scope, identity_digest)"),
        "a schema-valid 3071-octet scope must not be placed directly in a B-tree key"
    );

    let source = include_str!("../personal_history.rs");
    let replay_path = source
        .split("let exact_replay =")
        .nth(1)
        .expect("personal-admission exact replay path");
    for exact_field in [
        "row.get::<String, _>(\"actor_scope\") == actor_scope",
        "row.get::<String, _>(\"target_scope\") == target_scope",
        "row.get::<String, _>(\"actor_scope_raw\") == identity.actor_scope_raw",
        "row.get::<String, _>(\"identity_value\") == identity.identity_value",
    ] {
        assert!(
            replay_path.contains(exact_field),
            "a bounded-index conflict must recheck {exact_field} exactly"
        );
    }
}
