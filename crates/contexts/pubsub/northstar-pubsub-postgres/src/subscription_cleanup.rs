//! Physical subscription garbage collection over the existing PubSub pool.

use northstar_pubsub_application::SubscriptionCleanupRepository;
use sqlx::PgPool;

#[derive(Clone)]
pub struct PostgresSubscriptionCleanupRepository {
    pool: PgPool,
}

impl PostgresSubscriptionCleanupRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SubscriptionCleanupRepository for PostgresSubscriptionCleanupRepository {
    async fn cleanup_expired_subscriptions(&self, batch_size: i64) -> anyhow::Result<u64> {
        crate::cleanup_expired_subscriptions(&self.pool, batch_size).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_pubsub_application::subscription_cleanup::{
        SubscriptionCleanupContext, CLEANUP_BUDGET,
    };
    use northstar_telemetry::metrics::SubscriptionCleanupMetrics;
    use std::sync::{atomic::Ordering, Arc};
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_cleanup_preserves_live_subscriptions_and_event_snapshots_and_is_bounded() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        // A single ordinary connection owns all temporary fixtures. Any
        // replacement connection is pinned away from persistent relations.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("SET search_path TO pg_temp, pg_catalog")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE pubsub_subscriptions (
                node_id UUID NOT NULL, jid TEXT NOT NULL, expire TIMESTAMPTZ,
                PRIMARY KEY(node_id,jid));
             CREATE TEMP TABLE pubsub_digest_queue (
                id UUID PRIMARY KEY, subscription_node_id UUID NOT NULL,
                subscriber_jid TEXT NOT NULL, source_delivery_id UUID);
             INSERT INTO pubsub_subscriptions(node_id,jid,expire)
                SELECT md5(sequence::text)::uuid, 'expired@example.test',
                       NOW()-INTERVAL '1 hour'
                  FROM generate_series(1,1001) sequence;
             INSERT INTO pubsub_subscriptions(node_id,jid,expire) VALUES
                (md5('future')::uuid,'future@example.test',NOW()+INTERVAL '1 hour'),
                (md5('permanent')::uuid,'permanent@example.test',NULL);
             INSERT INTO pubsub_digest_queue(id,subscription_node_id,subscriber_jid,source_delivery_id)
                SELECT md5('legacy')::uuid,node_id,jid,NULL
                  FROM pubsub_subscriptions WHERE expire<NOW()
                 ORDER BY expire,node_id,jid LIMIT 1;
             INSERT INTO pubsub_digest_queue(id,subscription_node_id,subscriber_jid,source_delivery_id)
                SELECT md5('snapshot')::uuid,node_id,jid,md5('delivery')::uuid
                  FROM pubsub_subscriptions WHERE expire<NOW()
                 ORDER BY expire,node_id,jid LIMIT 1;"
        ).execute(&pool).await.unwrap();
        let metrics = Arc::new(SubscriptionCleanupMetrics::default());
        let context = SubscriptionCleanupContext::new(
            PostgresSubscriptionCleanupRepository::new(pool.clone()),
            Arc::clone(&metrics),
        );
        let readiness = context.readiness();
        let cancel = CancellationToken::new();
        assert!(!readiness.is_ready());
        let first = context
            .run_once(&cancel, Instant::now() + CLEANUP_BUDGET)
            .await
            .unwrap();
        assert_eq!(first, Some(1_000));
        assert!(readiness.is_ready());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM pubsub_subscriptions WHERE expire<NOW()"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM pubsub_subscriptions WHERE expire IS NULL OR expire>NOW()"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            2
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM pubsub_digest_queue WHERE source_delivery_id IS NULL"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM pubsub_digest_queue WHERE source_delivery_id IS NOT NULL"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1,
            "committed event snapshots survive physical subscription removal"
        );
        let second = context
            .run_once(&cancel, Instant::now() + CLEANUP_BUDGET)
            .await
            .unwrap();
        assert_eq!(second, Some(1));
        assert_eq!(metrics.deleted_total.load(Ordering::Relaxed), 1_001);
        // A prior successful cleanup cannot conceal a later repository error.
        sqlx::query("DROP TABLE pubsub_digest_queue")
            .execute(&pool)
            .await
            .unwrap();
        let failure = context
            .run_once(&cancel, Instant::now() + CLEANUP_BUDGET)
            .await;
        assert!(failure.is_err());
        assert!(!readiness.is_ready());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM pubsub_subscriptions")
                .fetch_one(&pool)
                .await
                .unwrap(),
            2
        );
        pool.close().await;
    }
}
