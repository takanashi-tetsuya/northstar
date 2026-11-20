use anyhow::Result;
use northstar_archive_core::{MamAccountOutcome, MamLocalAuthority};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};

const MAM_ACCOUNT: &str = "SELECT TRUE FROM users
    WHERE id=$1 AND username=$2 AND auth_generation=$3 AND NOT is_disabled";

/// A personal MAM form has no archive data. Its account check is the entire
/// read snapshot.
pub async fn authorize_mam_account(
    pool: &PgPool,
    authority: &MamLocalAuthority,
) -> Result<MamAccountOutcome<()>> {
    let mut connection = pool.acquire().await?;
    Ok(
        if account_matches(&mut connection, MAM_ACCOUNT, authority).await? {
            MamAccountOutcome::Authorized(())
        } else {
            MamAccountOutcome::StaleAccount
        },
    )
}

pub async fn mam_account_is_current(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &MamLocalAuthority,
) -> Result<bool> {
    account_matches(transaction, MAM_ACCOUNT, authority).await
}

pub(super) async fn lock_mam_account(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &MamLocalAuthority,
) -> Result<bool> {
    let statement = format!("{MAM_ACCOUNT} FOR SHARE");
    account_matches(transaction, &statement, authority).await
}

async fn account_matches(
    connection: &mut PgConnection,
    statement: &str,
    authority: &MamLocalAuthority,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(statement))
            .bind(authority.id)
            .bind(&authority.username)
            .bind(authority.auth_generation)
            .fetch_optional(connection)
            .await?
            .is_some(),
    )
}
