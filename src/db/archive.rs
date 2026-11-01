//! Personal history admission and the offline queue (message context), room MAM authorization and MIX reflection
//! archiving (room context). The personal archive, its preferences and the MAM queries are
//! northstar-archive-postgres, re-exported here.

use anyhow::Result;
#[cfg(test)]
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::HashSet;
#[cfg(test)]
use std::time::Duration;
use uuid::Uuid;

mod mam_room;
mod mix_archive;
mod personal_history;

pub use self::mam_room::*;
pub use self::mix_archive::*;
pub use self::personal_history::*;
pub use northstar_archive_postgres::*;
#[cfg(test)]
use northstar_message_postgres::{offline::*, personal_history::*};

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
];

#[cfg(test)]
mod offline_queue_tests;

#[cfg(test)]
mod source_contract_tests;

#[cfg(test)]
use northstar_room_postgres::mam_authorization::*;
#[cfg(test)]
mod history_identity_pg_tests;

/// Deliver queued offline messages without deleting a stanza until it has
/// been accepted by the connection's outbound queue. The per-recipient
/// advisory lock prevents two resources that announce presence concurrently
/// from claiming the same rows. If the connection closes or remains
/// backpressured, the unsent suffix stays durable for the next availability
/// transition.
#[cfg(test)]
pub async fn deliver_offline(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &crate::xmpp::outbound::OutboundSender,
    active_privacy_list: Option<&str>,
) -> Result<usize> {
    deliver_offline_mode(
        pool,
        recipient_id,
        ttl_days,
        outbound,
        false,
        active_privacy_list,
    )
    .await
}

/// Bind 2 MAM catch-up consumes permanently archived queue duplicates but
/// still delivers temporary-only XEP-0334 no-permanent-store messages.
#[cfg(test)]
pub async fn deliver_bind2_offline(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &crate::xmpp::outbound::OutboundSender,
    active_privacy_list: Option<&str>,
) -> Result<usize> {
    deliver_offline_mode(
        pool,
        recipient_id,
        ttl_days,
        outbound,
        true,
        active_privacy_list,
    )
    .await
}

#[cfg(test)]
pub(super) async fn deliver_offline_mode(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &crate::xmpp::outbound::OutboundSender,
    bind2_mam_catchup: bool,
    active_privacy_list: Option<&str>,
) -> Result<usize> {
    super::replay::deliver_offline_leased(
        pool,
        recipient_id,
        ttl_days,
        outbound,
        bind2_mam_catchup,
        active_privacy_list,
    )
    .await
}
