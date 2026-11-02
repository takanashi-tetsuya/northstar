//! Cross-context history tests and the offline delivery fixtures they share.

use anyhow::Result;
use chrono::{DateTime, Utc};
use northstar_archive_postgres::*;
use northstar_message_postgres::{offline::*, personal_history::*};
use northstar_room_postgres::mam_authorization::*;
use northstar_workflows::{mam_room::*, mix_archive::*, personal_history::*};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

mod history_identity_pg_tests;
mod offline_queue_tests;

/// Deliver queued offline messages without deleting a stanza until it has
/// been accepted by the connection's outbound queue. The per-recipient
/// advisory lock prevents two resources that announce presence concurrently
/// from claiming the same rows. If the connection closes or remains
/// backpressured, the unsent suffix stays durable for the next availability
/// transition.
pub async fn deliver_offline(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &northstar_stream::outbound::OutboundSender,
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
pub async fn deliver_bind2_offline(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &northstar_stream::outbound::OutboundSender,
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

pub(super) async fn deliver_offline_mode(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &northstar_stream::outbound::OutboundSender,
    bind2_mam_catchup: bool,
    active_privacy_list: Option<&str>,
) -> Result<usize> {
    northstar_session_postgres::replay::deliver_offline_leased(
        pool,
        recipient_id,
        ttl_days,
        outbound,
        bind2_mam_catchup,
        active_privacy_list,
    )
    .await
}
