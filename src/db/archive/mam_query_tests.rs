//! MAM query construction tests and source contracts of the archive module.

use super::*;

fn query(with_jid: &str) -> MamArchiveQuery {
    MamArchiveQuery {
        with_jid: Some(with_jid.to_owned()),
        start: None,
        end: None,
        before_id: None,
        after_id: None,
        ids: Vec::new(),
        page: MamRsmPage::First,
        max: 50,
    }
}

#[test]
fn personal_with_filter_distinguishes_bare_and_full_jids() {
    let owner = Uuid::nil();
    let mut bare = QueryBuilder::<Postgres>::new("SELECT id FROM message_archive");
    push_mam_scope(
        &mut bare,
        MamArchiveSource::User(owner),
        &query("bob@example.test"),
        &[],
        MamQueryBounds {
            after: None,
            before: None,
        },
    );
    assert!(bare.sql().contains("peer_jid ="));
    assert!(!bare.sql().contains("lower(peer_jid)"));
    assert!(!bare.sql().contains("peer_full_jid"));

    let mut full = QueryBuilder::<Postgres>::new("SELECT id FROM message_archive");
    push_mam_scope(
        &mut full,
        MamArchiveSource::User(owner),
        &query("bob@example.test/phone"),
        &[],
        MamQueryBounds {
            after: None,
            before: None,
        },
    );
    assert!(full.sql().contains("peer_full_jid ="));
    assert!(!full.sql().contains("lower(peer_full_jid)"));
}

#[test]
fn mam_scope_is_parameterized_and_keyset_only() {
    let owner = Uuid::nil();
    let anchor = (
        DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
        Uuid::from_u128(7),
    );
    let mut builder = QueryBuilder::<Postgres>::new("SELECT id FROM message_archive");
    push_mam_scope(
        &mut builder,
        MamArchiveSource::User(owner),
        &query("mallory@example.test/' OR true --"),
        &[],
        MamQueryBounds {
            after: Some(anchor),
            before: None,
        },
    );
    let sql = builder.sql();
    assert!(!sql.contains("mallory"));
    assert!(!sql.to_ascii_uppercase().contains("OFFSET"));
    assert!(sql.contains("(created_at, id) >"));
}

#[test]
fn personal_message_admission_identity_index_is_bounded_and_exactly_rechecked() {
    let migration =
        include_str!("../../../migrations/0130_personal_message_admission_scope_lookup.sql");
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

    let source = module_source();
    let replay_path = source
        .split("let exact_replay =")
        .nth(1)
        .expect("personal-admission exact replay path");
    for exact_field in [
        "row.get::<String, _>(\"actor_scope\").as_str() == actor_scope.as_str()",
        "row.get::<String, _>(\"target_scope\").as_str() == target_scope.as_str()",
        "row.get::<String, _>(\"actor_scope_raw\") == identity.actor_scope_raw",
        "row.get::<String, _>(\"identity_value\") == identity.identity_value",
    ] {
        assert!(
            replay_path.contains(exact_field),
            "a bounded-index conflict must recheck {exact_field} exactly"
        );
    }
}

#[test]
fn module_source_lists_every_child_module() {
    let (_, parent) = MODULE_SOURCE[0];
    let declared: std::collections::BTreeSet<&str> = parent
        .lines()
        .filter_map(|line| line.strip_prefix("mod ")?.strip_suffix(';'))
        .filter(|name| !name.ends_with("_tests"))
        .collect();
    let listed: std::collections::BTreeSet<&str> =
        MODULE_SOURCE[1..].iter().map(|(name, _)| *name).collect();
    assert_eq!(declared, listed);
}
