use anyhow::{Context, Result};
use sqlx::PgPool;
use std::path::Path;

pub mod archive;
pub mod muc;
pub mod pep;
pub mod private;
pub mod reports;
pub mod roster;
pub mod upload;
pub mod users;

pub use archive::*;
pub use muc::*;
pub use pep::*;
pub use private::*;
pub use reports::*;
pub use roster::*;
pub use upload::*;
pub use users::*;

pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::migrate::Migrator::new(Path::new("migrations"))
        .await
        .context("could not load database migrations")?
        .run(pool)
        .await
        .context("database migration failed")
}

pub async fn nuke_everything(pool: &PgPool) -> Result<()> {
    // TRUNCATE all relevant tables to completely factory reset the database.
    sqlx::query(
        "TRUNCATE TABLE 
            users, api_sessions, vcards, private_xml,
            roster_items, pending_presence_subscriptions, federated_presence_pending,
            muc_rooms, muc_affiliations, muc_messages,
            pep_nodes, pep_items,
            message_archive, offline_messages,
            upload_slots,
            abuse_reports, abuse_report_evidence, abuse_appeals,
            blocked_jids, push_subscriptions,
            invitation_tokens, audit_log
        CASCADE",
    )
    .execute(pool)
    .await?;
    Ok(())
}
