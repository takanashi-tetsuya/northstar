//! The options every Northstar connection pool starts from.
//!
//! SQLx 0.8 counts a transaction only after the server answers BEGIN. When the
//! future that sent BEGIN is dropped first (a client disconnect, a timeout, a
//! shutdown select), its rollback guard sees a depth of zero and does nothing:
//! the connection goes back to the pool inside a transaction no one owns. The
//! next borrower's statements then run in that transaction, and a later BEGIN
//! only draws a warning, so its isolation level can no longer be set and its
//! commit also commits whatever the earlier borrowers wrote.
//!
//! A released connection is therefore checked with one simple-protocol query.
//! A simple query is a single command message, so its statement timestamp
//! equals its transaction timestamp exactly when it starts its own
//! transaction. Any other connection is closed instead of reused.

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, Row};

pub fn options() -> PgPoolOptions {
    PgPoolOptions::new().after_release(|connection, _| {
        Box::pin(async move {
            // Executor::fetch_one returns a boxed future, which keeps this
            // closure general over the connection lifetime.
            let row = connection
                .fetch_one(sqlx::raw_sql(
                    "SELECT pg_catalog.statement_timestamp() = pg_catalog.transaction_timestamp()",
                ))
                .await?;
            let reusable: bool = row.try_get(0)?;
            if !reusable {
                tracing::warn!(
                    "closing a pooled PostgreSQL connection released inside a transaction"
                );
            }
            Ok(reusable)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    async fn backend(pool: &PgPool) -> i32 {
        sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Leaves what a cancelled BEGIN leaves: the server is inside a
    /// transaction that has run a statement, and SQLx counts none.
    async fn release_inside_a_transaction(pool: &PgPool) -> i32 {
        let mut connection = pool.acquire().await.unwrap();
        let backend = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        sqlx::raw_sql("BEGIN; SELECT 1")
            .execute(&mut *connection)
            .await
            .unwrap();
        backend
    }

    async fn repeatable_read(pool: &PgPool) -> Result<i32, sqlx::Error> {
        let mut transaction = pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *transaction)
            .await?;
        let backend = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
            .fetch_one(&mut *transaction)
            .await?;
        transaction.rollback().await?;
        Ok(backend)
    }

    #[tokio::test]
    #[ignore = "requires a random-schema TEST_DATABASE_URL"]
    async fn a_connection_released_inside_a_transaction_is_closed_not_reused() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to a disposable random-schema xmpp_test URL");

        // Plain SQLx options hand the open transaction to the next borrower.
        let plain = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        release_inside_a_transaction(&plain).await;
        let error = repeatable_read(&plain).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must be called before any query"),
            "{error}"
        );
        plain.close().await;

        let pool = options().max_connections(1).connect(&url).await.unwrap();
        let clean = backend(&pool).await;
        assert_eq!(backend(&pool).await, clean, "a clean connection is reused");
        let leaked = release_inside_a_transaction(&pool).await;
        let fresh = repeatable_read(&pool).await.unwrap();
        assert_ne!(
            fresh, leaked,
            "the connection left in a transaction was reused"
        );
        pool.close().await;
    }
}
