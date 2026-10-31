use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
pub struct AccountRevocation {
    pub user_id: Uuid,
    pub username: String,
    pub before_generation: i64,
    pub account_deleted: bool,
    pub revision: Uuid,
}

pub async fn pending(
    pool: &PgPool,
    domain: &str,
    node: &str,
    instance: Uuid,
    epoch: i64,
) -> Result<Vec<AccountRevocation>> {
    Ok(
        sqlx::query_as("SELECT * FROM northstar_pending_account_revocations($1,$2,$3,$4,256)")
            .bind(domain)
            .bind(node)
            .bind(instance)
            .bind(epoch)
            .fetch_all(pool)
            .await?,
    )
}

pub async fn acknowledge(
    pool: &PgPool,
    domain: &str,
    node: &str,
    instance: Uuid,
    epoch: i64,
    revisions: &[Uuid],
) -> Result<()> {
    sqlx::query_scalar::<_, i64>("SELECT northstar_ack_account_revocations($1,$2,$3,$4,$5)")
        .bind(domain)
        .bind(node)
        .bind(instance)
        .bind(epoch)
        .bind(revisions)
        .fetch_one(pool)
        .await?;
    Ok(())
}

pub async fn cleanup(pool: &PgPool) -> Result<()> {
    sqlx::query_scalar::<_, i64>("SELECT northstar_cleanup_account_revocations(1000)")
        .fetch_one(pool)
        .await?;
    Ok(())
}
