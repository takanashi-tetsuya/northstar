//! Personal history admission and the offline queue (message context), room MAM authorization and MIX reflection
//! archiving (room context). The personal archive, its preferences and the MAM queries are
//! northstar-archive-postgres, re-exported here.

use anyhow::Result;
use chrono::{DateTime, Utc};
use northstar_abuse_policy::ContentIdentityAuthenticators;
use northstar_archive_core::{decide_mam_room_read, MamRoomReadDecision};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::{pool::PoolConnection, Acquire, PgPool, Postgres, Row, Transaction};
use std::collections::HashSet;
#[cfg(test)]
use std::time::Duration;
use subtle::ConstantTimeEq;
use uuid::Uuid;

mod mam_room;
mod mix_archive;
mod offline;
mod personal_history;

pub use self::mam_room::*;
pub use self::mix_archive::*;
pub use self::offline::*;
pub use self::personal_history::*;
pub use northstar_archive_postgres::*;

#[cfg(test)]
#[test]
fn offline_resource_affinity_is_derived_from_authoritative_message_routing() {
    assert_eq!(
        normalized_offline_target_resource(
            "<message to='alice@example.test/Phone'/>",
            Some("alice@example.test")
        )
        .unwrap(),
        (
            Some("alice@example.test".to_owned()),
            Some("Phone".to_owned())
        )
    );
    for stanza in [
        "<message to='alice@example.test'/>",
        "<message type='chat' to='alice@example.test/Phone'/>",
        "<message/>",
    ] {
        assert_eq!(
            normalized_offline_target_resource(stanza, Some("alice@example.test"))
                .unwrap()
                .1,
            None
        );
    }
    assert!(
        normalized_offline_target_resource("<message to='alice@example.test/Phone'/>", None)
            .is_err()
    );
    assert!(normalized_offline_target_resource(
        "<message to='alice@evil.test/Phone'/>",
        Some("alice@example.test")
    )
    .is_err());
}

/// Production source of this module: the file itself followed by each
/// production child module file, so source-contract tests keep reading the
/// whole module after code moves between them. The children are listed in
/// the order their code had in the former single file, because some
/// contracts split the source on a marker that occurs in more than one child.
/// `module_source_lists_every_child_module` keeps this list in step with the
/// non-test `mod` declarations above.
#[cfg(test)]
const MODULE_SOURCE: &[(&str, &str)] = &[
    ("archive", include_str!("archive.rs")),
    (
        "personal_history",
        include_str!("archive/personal_history.rs"),
    ),
    ("mix_archive", include_str!("archive/mix_archive.rs")),
    ("mam_room", include_str!("archive/mam_room.rs")),
    ("offline", include_str!("archive/offline.rs")),
];

#[cfg(test)]
fn module_source() -> String {
    MODULE_SOURCE
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod offline_queue_tests;

#[cfg(test)]
mod source_contract_tests;

#[cfg(test)]
mod history_identity_pg_tests;
