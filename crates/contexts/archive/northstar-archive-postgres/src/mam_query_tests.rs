//! MAM query construction tests.

use super::*;
use chrono::{DateTime, Utc};

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
