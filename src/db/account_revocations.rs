use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
pub(crate) struct AccountRevocation {
    pub user_id: Uuid,
    pub username: String,
    pub before_generation: i64,
    pub account_deleted: bool,
    pub revision: Uuid,
}

pub(crate) async fn pending(
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

pub(crate) async fn acknowledge(
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

pub(crate) async fn cleanup(pool: &PgPool) -> Result<()> {
    sqlx::query_scalar::<_, i64>("SELECT northstar_cleanup_account_revocations(1000)")
        .fetch_one(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::str::FromStr;

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL for a disposable PostgreSQL schema"]
    async fn committed_revocations_survive_lost_wakes_and_stale_acknowledgements() {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
        let options = PgConnectOptions::from_str(&url).unwrap();
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options.clone())
            .await
            .unwrap();
        let schema = format!("northstar_revocations_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options.options([("search_path", schema.as_str())]))
            .await
            .unwrap();
        crate::db::MIGRATOR.run(&pool).await.unwrap();

        let instance = Uuid::new_v4();
        for node in ["one", "two"] {
            sqlx::query(
                "INSERT INTO cluster_key_deployments
                (xmpp_domain,node_id,epoch,current_key_id,current_public_key_sha256)
                VALUES ('example.test',$1,1,repeat('a',16),repeat('b',43))",
            )
            .bind(node)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query("INSERT INTO cluster_node_instances
                (xmpp_domain,node_id,instance_uuid,instance_epoch,signing_key_id,
                 signing_key_epoch,lease_until)
                VALUES ('example.test',$1,$2,1,repeat('a',16),1,clock_timestamp()+interval '1 minute')")
                .bind(node).bind(instance).execute(&pool).await.unwrap();
        }
        let user = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id,username,password_hash) VALUES ($1,'alice','unused')")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();

        // A rolled-back password change must not leave a revocation behind.
        let mut transaction = pool.begin().await.unwrap();
        sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
            .bind(user)
            .execute(&mut *transaction)
            .await
            .unwrap();
        assert!(pending(&pool, "example.test", "one", instance, 1)
            .await
            .unwrap()
            .is_empty());
        transaction.rollback().await.unwrap();
        assert!(pending(&pool, "example.test", "one", instance, 1)
            .await
            .unwrap()
            .is_empty());

        sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        let first = pending(&pool, "example.test", "one", instance, 1)
            .await
            .unwrap();
        assert_eq!(first.len(), 1);
        let generation = first[0].before_generation;
        assert_eq!(first[0].user_id, user);
        assert!(!first[0].account_deleted);
        assert_eq!(
            pending(&pool, "example.test", "two", instance, 1)
                .await
                .unwrap()
                .len(),
            1
        );

        // Simulate disconnect after the read, followed by another change.
        sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        acknowledge(
            &pool,
            "example.test",
            "one",
            instance,
            1,
            &[first[0].revision],
        )
        .await
        .unwrap();
        let second = pending(&pool, "example.test", "one", instance, 1)
            .await
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].before_generation, generation + 1);
        assert_ne!(first[0].revision, second[0].revision);
        acknowledge(
            &pool,
            "example.test",
            "one",
            instance,
            1,
            &[second[0].revision],
        )
        .await
        .unwrap();
        assert!(pending(&pool, "example.test", "one", instance, 1)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            pending(&pool, "example.test", "two", instance, 1)
                .await
                .unwrap()
                .len(),
            1
        );

        // Lease expiry is not evidence that the original process has exited.
        sqlx::query(
            "UPDATE cluster_node_instances SET lease_until=clock_timestamp()-interval '1 second'",
        )
        .execute(&pool)
        .await
        .unwrap();
        cleanup(&pool).await.unwrap();
        assert_eq!(
            pending(&pool, "example.test", "two", instance, 1)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(pending(&pool, "example.test", "two", Uuid::new_v4(), 1)
            .await
            .is_err());

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        let deleted = pending(&pool, "example.test", "one", instance, 1)
            .await
            .unwrap();
        assert!(deleted[0].account_deleted);
        assert_eq!(deleted[0].username, "alice");
        sqlx::query("UPDATE cluster_node_instances SET instance_uuid=$1,instance_epoch=2")
            .bind(Uuid::new_v4())
            .execute(&pool)
            .await
            .unwrap();
        cleanup(&pool).await.unwrap();
        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM account_revocation_outbox")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 0);

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
