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
